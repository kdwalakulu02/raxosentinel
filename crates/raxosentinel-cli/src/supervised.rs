use super::{print_human_report, ScanArgs};
use raxosentinel_core::{ScanReport, ScanStatus, TargetMetadata};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAX_RESPONSE: u64 = 2 * 1024 * 1024;

fn error_report(args: &ScanArgs, message: String) -> ScanReport {
    ScanReport::new(
        TargetMetadata {
            path: Some(args.target.display().to_string()),
            file_name: args
                .target
                .file_name()
                .map(|v| v.to_string_lossy().into_owned()),
            file_size_bytes: 0,
            sha256: String::new(),
            detected_mime: "application/unknown".into(),
            declared_mime: None,
        },
        ScanStatus::Failed,
        Vec::new(),
        Vec::new(),
        0,
        Some(message),
    )
}

pub fn run(args: &ScanArgs) -> i32 {
    let result = run_inner(args);
    let report = result.unwrap_or_else(|e| error_report(args, e));
    if args.json {
        match report.to_json_pretty() {
            Ok(json) => println!("{json}"),
            Err(_) => return 3,
        }
    } else {
        print_human_report(&report, None);
    }
    report.status.exit_code()
}

fn run_inner(args: &ScanArgs) -> Result<ScanReport, String> {
    if args.worker_internal || args.db.is_some() || args.db_store.is_some() {
        return Err(
            "Supervised scans do not accept legacy database options or nested workers".into(),
        );
    }
    if args.worker_timeout_ms == 0 || args.worker_memory == 0 {
        return Err("Worker limits must be positive".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&args.target)
        .map_err(|e| format!("Cannot open target: {e}"))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("Cannot stat target: {e}"))?;
    if !metadata.is_file() {
        return Err("Target is not a regular file".into());
    }
    if metadata.len() > args.max_size.unwrap_or(50 * 1024 * 1024) {
        return Err("Target exceeds file size limit".into());
    }
    let mut command = Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
    command
        .arg("scan")
        .arg(&args.target)
        .arg("--worker-internal")
        .arg("--json");
    if let Some(v) = args.max_size {
        command.arg("--max-size").arg(v.to_string());
    }
    if let Some(v) = args.timeout {
        command.arg("--timeout").arg(v.to_string());
    }
    if let Some(v) = args.max_depth {
        command.arg("--max-depth").arg(v.to_string());
    }
    if let Some(v) = &args.rules {
        command.arg("--rules").arg(v);
    }
    if let Some(v) = &args.private_db_root {
        command.arg("--private-db-root").arg(v);
    }
    if let Some(v) = &args.private_generation {
        command.arg("--private-generation").arg(v);
    }
    if let Some(v) = &args.public_release {
        command.arg("--public-release").arg(v);
    }
    if let Some(v) = &args.public_key {
        command.arg("--public-key").arg(v);
    }
    if let Some(v) = &args.public_approval_key {
        command.arg("--public-approval-key").arg(v);
    }
    if let Some(v) = &args.public_state {
        command.arg("--public-state").arg(v);
    }
    if command
        .get_args()
        .map(|v| v.as_bytes().len() + 1)
        .sum::<usize>()
        > 65536
    {
        return Err("Worker request exceeds argument limit".into());
    }
    command
        .stdin(Stdio::from(file))
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let limit = args.worker_memory;
    // pre_exec runs in the child immediately before exec; setrlimit is async-signal-safe.
    unsafe {
        command.pre_exec(move || {
            let value = libc::rlimit {
                rlim_cur: limit as libc::rlim_t,
                rlim_max: limit as libc::rlim_t,
            };
            if libc::setrlimit(libc::RLIMIT_AS, &value) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let start = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|e| format!("Worker startup failed: {e}"))?;
    let mut stdout = child.stdout.take().ok_or("Missing worker response pipe")?;
    // Nonblocking reads ensure a worker or descendant holding the pipe cannot block the parent.
    let flags = unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err("Cannot configure worker response pipe".into());
    }
    let deadline = Duration::from_millis(args.worker_timeout_ms);
    let mut bytes = Vec::new();
    let mut eof = false;
    let status = loop {
        if start.elapsed() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Worker deadline exceeded; worker terminated".into());
        }
        let mut chunk = [0u8; 16384];
        loop {
            match stdout.read(&mut chunk) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(n) => {
                    if bytes.len() + n > MAX_RESPONSE as usize {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err("Worker response exceeds limit".into());
                    }
                    bytes.extend_from_slice(&chunk[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("Worker response failed: {e}"));
                }
            }
        }
        match child.try_wait() {
            Ok(Some(status)) if eof => break status,
            Ok(Some(_)) => thread::sleep(Duration::from_millis(2)),
            Ok(None) => thread::sleep(Duration::from_millis(2)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("Worker wait failed: {e}"));
            }
        }
    };
    if status.code().is_none() {
        return Err(format!("Worker terminated abnormally: {status}"));
    }
    let report: ScanReport =
        serde_json::from_slice(&bytes).map_err(|_| "Malformed worker response")?;
    if status.code() != Some(report.status.exit_code()) {
        return Err(format!("Worker exited abnormally: {status}"));
    }
    Ok(report)
}
