use super::{print_human_report, ScanArgs};
use raxosentinel_core::{ScanReport, ScanStatus, TargetMetadata};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAX_RESPONSE: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct SupervisedWorkerConfig {
    pub worker_memory: u64,
    pub worker_timeout_ms: u64,
    pub max_size: Option<u64>,
    pub timeout: Option<u64>,
    pub max_depth: Option<usize>,
    pub rules: Option<PathBuf>,
    pub private_db_root: Option<PathBuf>,
    pub private_generation: Option<String>,
    pub public_release: Option<PathBuf>,
    pub public_key: Option<PathBuf>,
    pub public_approval_key: Option<PathBuf>,
    pub public_state: Option<PathBuf>,
    #[cfg(debug_assertions)]
    pub test_worker_action: Option<String>,
}

/// Once trusted database loading is complete, deny new filesystem access during parsing.
pub fn restrict_worker_filesystem() -> Result<(), String> {
    #[repr(C)]
    struct Ruleset {
        handled_access_fs: u64,
    }
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(format!(
            "Cannot set no_new_privs: {}",
            std::io::Error::last_os_error()
        ));
    }
    if unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) } != 0 {
        return Err(format!(
            "Cannot close worker descriptors: {}",
            std::io::Error::last_os_error()
        ));
    }
    // ABI 1 rights: execute, read, write, remove and create objects.
    let ruleset = Ruleset {
        handled_access_fs: (1 << 13) - 1,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &ruleset,
            std::mem::size_of::<Ruleset>(),
            0,
        )
    };
    if fd < 0 {
        return Err(format!(
            "Landlock unavailable: {}",
            std::io::Error::last_os_error()
        ));
    }
    let result = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, fd as i32, 0) };
    let error = std::io::Error::last_os_error();
    unsafe {
        libc::close(fd as i32);
    }
    if result != 0 {
        return Err(format!("Landlock restriction failed: {error}"));
    }
    Ok(())
}

pub fn error_report(target: &Path, message: String) -> ScanReport {
    ScanReport::new(
        TargetMetadata {
            path: Some(target.display().to_string()),
            file_name: target.file_name().map(|v| v.to_string_lossy().into_owned()),
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
    let report = result.unwrap_or_else(|e| error_report(&args.target, e));
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

// Snapshot bytes into a sealed anonymous file before the worker is created.
pub fn sealed_snapshot(mut source: File, max_size: u64) -> Result<File, String> {
    let name = c"raxosentinel-input";
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err(format!(
            "Cannot create snapshot: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut snapshot = unsafe { File::from_raw_fd(fd) };
    let mut total = 0u64;
    let mut buf = [0u8; 65536];
    loop {
        let n = source
            .read(&mut buf)
            .map_err(|e| format!("Snapshot read failed: {e}"))?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .ok_or("Snapshot size overflow")?;
        if total > max_size {
            return Err("Target exceeds file size limit while snapshotting".into());
        }
        snapshot
            .write_all(&buf[..n])
            .map_err(|e| format!("Snapshot write failed: {e}"))?;
    }
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if unsafe { libc::fcntl(snapshot.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
        return Err(format!(
            "Cannot seal snapshot: {}",
            std::io::Error::last_os_error()
        ));
    }
    snapshot
        .seek(SeekFrom::Start(0))
        .map_err(|e| format!("Cannot rewind snapshot: {e}"))?;
    Ok(snapshot)
}

fn terminate_group(child: &mut std::process::Child) {
    // The child is started in a dedicated process group; kill before reaping the leader.
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
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
    let file = sealed_snapshot(file, args.max_size.unwrap_or(50 * 1024 * 1024))?;
    let config = SupervisedWorkerConfig {
        worker_memory: args.worker_memory,
        worker_timeout_ms: args.worker_timeout_ms,
        max_size: args.max_size,
        timeout: args.timeout,
        max_depth: args.max_depth,
        rules: args.rules.clone(),
        private_db_root: args.private_db_root.clone(),
        private_generation: args.private_generation.clone(),
        public_release: args.public_release.clone(),
        public_key: args.public_key.clone(),
        public_approval_key: args.public_approval_key.clone(),
        public_state: args.public_state.clone(),
        #[cfg(debug_assertions)]
        test_worker_action: None,
    };
    execute_worker_on_snapshot(file, &args.target, &config)
}

pub fn execute_worker_on_snapshot(
    snapshot: File,
    target_name: &Path,
    config: &SupervisedWorkerConfig,
) -> Result<ScanReport, String> {
    let mut command = Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
    command
        .arg("scan")
        .arg(target_name)
        .arg("--worker-internal")
        .arg("--json");
    if let Some(v) = config.max_size {
        command.arg("--max-size").arg(v.to_string());
    }
    if let Some(v) = config.timeout {
        command.arg("--timeout").arg(v.to_string());
    }
    if let Some(v) = config.max_depth {
        command.arg("--max-depth").arg(v.to_string());
    }
    if let Some(v) = &config.rules {
        command.arg("--rules").arg(v);
    }
    if let Some(v) = &config.private_db_root {
        command.arg("--private-db-root").arg(v);
    }
    if let Some(v) = &config.private_generation {
        command.arg("--private-generation").arg(v);
    }
    if let Some(v) = &config.public_release {
        command.arg("--public-release").arg(v);
    }
    if let Some(v) = &config.public_key {
        command.arg("--public-key").arg(v);
    }
    if let Some(v) = &config.public_approval_key {
        command.arg("--public-approval-key").arg(v);
    }
    if let Some(v) = &config.public_state {
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
    command.env_clear();
    #[cfg(debug_assertions)]
    if let Some(ref action) = config.test_worker_action {
        command.env("RAXOSENTINEL_TEST_WORKER_ACTION", action);
    } else if let Some(action) = std::env::var_os("RAXOSENTINEL_TEST_WORKER_ACTION") {
        command.env("RAXOSENTINEL_TEST_WORKER_ACTION", action);
    }
    command
        .stdin(Stdio::from(snapshot))
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let limit = config.worker_memory;
    // pre_exec runs in the child immediately before exec; setrlimit is async-signal-safe.
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::syscall(
                libc::SYS_close_range,
                3u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
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
        terminate_group(&mut child);
        return Err("Cannot configure worker response pipe".into());
    }
    let deadline = Duration::from_millis(config.worker_timeout_ms);
    let mut bytes = Vec::new();
    let mut eof = false;
    let status = loop {
        if start.elapsed() >= deadline {
            terminate_group(&mut child);
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
                        terminate_group(&mut child);
                        return Err("Worker response exceeds limit".into());
                    }
                    bytes.extend_from_slice(&chunk[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    terminate_group(&mut child);
                    return Err(format!("Worker response failed: {e}"));
                }
            }
        }
        match child.try_wait() {
            Ok(Some(status)) if eof => break status,
            Ok(Some(_)) => thread::sleep(Duration::from_millis(2)),
            Ok(None) => thread::sleep(Duration::from_millis(2)),
            Err(e) => {
                terminate_group(&mut child);
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshot_is_sealed_and_caps_bytes() {
        let mut original = tempfile::tempfile().unwrap();
        original.write_all(b"original").unwrap();
        original.seek(SeekFrom::Start(0)).unwrap();
        assert!(sealed_snapshot(original.try_clone().unwrap(), 3).is_err());
        original.seek(SeekFrom::Start(0)).unwrap();
        let mut snapshot = sealed_snapshot(original.try_clone().unwrap(), 8).unwrap();
        original.seek(SeekFrom::Start(0)).unwrap();
        original.write_all(b"modified").unwrap();
        let mut bytes = Vec::new();
        snapshot.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"original");
        assert!(snapshot.write_all(b"x").is_err());
    }
}
