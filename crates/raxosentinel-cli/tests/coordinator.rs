#![cfg(target_os = "linux")]

/*
 * RaxoSentinel Core — Malware Detection Engine
 * Copyright (C) 2026 RaxoSentinel Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

use raxosentinel_signatures::rsidb::malwarebazaar::private_store;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const SYNTHETIC_SIGNATURE: &[u8] = b"synthetic private signature";
const SYNTHETIC_NAME: &str = "SyntheticFixture";

fn setup_test_db(dir: &Path) -> (PathBuf, &'static str) {
    let db_root = dir.join("db_root");
    std::fs::create_dir_all(&db_root).unwrap();
    std::fs::set_permissions(&db_root, std::fs::Permissions::from_mode(0o700)).unwrap();

    let hash = hex::encode(Sha256::digest(SYNTHETIC_SIGNATURE));
    let response = serde_json::json!({
        "query_status": "ok",
        "data": [{
            "sha256_hash": hash,
            "file_size": SYNTHETIC_SIGNATURE.len(),
            "first_seen": "2024-02-29 00:00:00",
            "signature": SYNTHETIC_NAME
        }]
    })
    .to_string();

    private_store::publish(&db_root, "fixture", response.as_bytes(), 1).unwrap();
    (db_root, "fixture")
}

struct CoordinatorProcess {
    child: Child,
    socket_path: PathBuf,
}

impl CoordinatorProcess {
    fn spawn(socket_path: &Path, db_root: &Path, generation: &str, extra_args: &[&str]) -> Self {
        let parent = socket_path.parent().unwrap_or_else(|| Path::new("."));
        let _ = std::fs::create_dir_all(parent);
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_raxosentinel"));
        cmd.arg("serve")
            .arg("--socket")
            .arg(socket_path)
            .arg("--private-db-root")
            .arg(db_root)
            .arg("--private-generation")
            .arg(generation)
            .args(extra_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().expect("failed to spawn coordinator");
        let stdout = child.stdout.take().expect("piped stdout");
        use std::io::BufRead;
        let mut reader = std::io::BufReader::new(stdout);
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .expect("failed to read coordinator stdout");
        if n == 0 || !line.contains("RAXOSENTINEL_COORDINATOR_READY") {
            panic!("coordinator failed to start, output: {line}");
        }

        Self {
            child,
            socket_path: socket_path.to_path_buf(),
        }
    }

    fn stop(&mut self) -> std::process::ExitStatus {
        unsafe {
            libc::kill(self.child.id() as i32, libc::SIGTERM);
        }
        self.child.wait().expect("failed to wait on coordinator")
    }
}

impl Drop for CoordinatorProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

fn run_client(
    socket: &Path,
    target: &Path,
    extra_args: &[&str],
    env_vars: &[(&str, &str)],
) -> (i32, serde_json::Value) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_raxosentinel"));
    cmd.arg("client")
        .arg("--socket")
        .arg(socket)
        .arg(target)
        .arg("--json")
        .args(extra_args);

    for (k, v) in env_vars {
        cmd.env(k, v);
    }

    let output = cmd.output().expect("failed to execute client");
    let exit_code = output.status.code().unwrap_or(-1);
    let val: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or(serde_json::json!({
            "status": "RAW_ERROR",
            "raw_stdout": String::from_utf8_lossy(&output.stdout).to_string(),
            "raw_stderr": String::from_utf8_lossy(&output.stderr).to_string(),
        }));
    (exit_code, val)
}

fn run_scan_socket(socket: &Path, target: &Path) -> (i32, serde_json::Value) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_raxosentinel"));
    cmd.arg("scan")
        .arg("--socket")
        .arg(socket)
        .arg(target)
        .arg("--json");

    let output = cmd.output().expect("failed to execute scan --socket");
    let exit_code = output.status.code().unwrap_or(-1);
    let val: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or(serde_json::json!({
            "status": "RAW_ERROR",
            "raw_stdout": String::from_utf8_lossy(&output.stdout).to_string(),
            "raw_stderr": String::from_utf8_lossy(&output.stderr).to_string(),
        }));
    (exit_code, val)
}

fn send_raw_fd_message(stream: &UnixStream, fds: &[RawFd], payload: &[u8]) -> Result<(), String> {
    let len_prefix = (payload.len() as u32).to_be_bytes();
    let mut message = Vec::with_capacity(4 + payload.len());
    message.extend_from_slice(&len_prefix);
    message.extend_from_slice(payload);

    let mut iov = libc::iovec {
        iov_base: message.as_mut_ptr() as *mut libc::c_void,
        iov_len: message.len(),
    };

    let cmsg_space = if fds.is_empty() {
        0
    } else {
        unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) as usize }
    };

    let cmsg_words = cmsg_space.div_ceil(std::mem::size_of::<usize>());
    let mut cmsg_buf = vec![0usize; cmsg_words.max(1)];

    let msg = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: if fds.is_empty() {
            std::ptr::null_mut()
        } else {
            cmsg_buf.as_mut_ptr() as *mut libc::c_void
        },
        msg_controllen: cmsg_space,
        msg_flags: 0,
    };

    if !fds.is_empty() {
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            if cmsg.is_null() {
                return Err("null cmsg header".into());
            }
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as u32) as usize;
            std::ptr::copy_nonoverlapping(
                fds.as_ptr() as *const u8,
                libc::CMSG_DATA(cmsg),
                std::mem::size_of_val(fds),
            );
        }
    }

    let ret = unsafe { libc::sendmsg(stream.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
    if ret < 0 {
        return Err(format!(
            "sendmsg failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn recv_raw_response(stream: &mut UnixStream) -> Result<serde_json::Value, String> {
    let mut len_prefix = [0u8; 4];
    stream
        .read_exact(&mut len_prefix)
        .map_err(|e| format!("cannot read length: {e}"))?;
    let len = u32::from_be_bytes(len_prefix) as usize;
    if len > 2 * 1024 * 1024 {
        return Err("response exceeds 2 MiB".into());
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .map_err(|e| format!("cannot read body: {e}"))?;
    serde_json::from_slice(&buf).map_err(|e| format!("malformed response JSON: {e}"))
}

// ---------------------------------------------------------------------------
// Mandatory Test 1 & 2: Start coordinator and connect client; Submit a clean synthetic file.
// ---------------------------------------------------------------------------
#[test]
fn test_01_and_02_start_coordinator_and_clean_file() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    let _coord = CoordinatorProcess::spawn(&socket, &db_root, gen, &[]);

    let clean_file = d.path().join("clean.txt");
    std::fs::write(&clean_file, b"completely harmless content").unwrap();

    let (code, report) = run_client(&socket, &clean_file, &[], &[]);
    assert_eq!(code, 0, "Clean file should return exit code 0");
    assert_eq!(
        report["status"].as_str().unwrap(),
        "CLEAN",
        "Report status must be CLEAN"
    );

    // Verify `scan --socket` also works seamlessly
    let (code2, report2) = run_scan_socket(&socket, &clean_file);
    assert_eq!(code2, 0);
    assert_eq!(report2["status"].as_str().unwrap(), "CLEAN");
}

// ---------------------------------------------------------------------------
// Mandatory Test 3: Detect a harmless synthetic signature.
// ---------------------------------------------------------------------------
#[test]
fn test_03_detect_harmless_synthetic_signature() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    let _coord = CoordinatorProcess::spawn(&socket, &db_root, gen, &[]);

    let infected_file = d.path().join("infected.bin");
    std::fs::write(&infected_file, SYNTHETIC_SIGNATURE).unwrap();

    let (code, report) = run_client(&socket, &infected_file, &[], &[]);
    assert_eq!(code, 1, "Detected file must exit with code 1");
    assert_eq!(
        report["status"].as_str().unwrap(),
        "DETECTED",
        "Report status must be DETECTED"
    );
    assert!(
        report["threats"].to_string().contains(SYNTHETIC_NAME),
        "Threats should list the detected synthetic rule name"
    );
}

// ---------------------------------------------------------------------------
// Mandatory Test 4: Detect content inside ZIP.
// ---------------------------------------------------------------------------
#[test]
fn test_04_detect_content_inside_zip() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    let _coord = CoordinatorProcess::spawn(&socket, &db_root, gen, &[]);

    let zip_path = d.path().join("archive.zip");
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("sample.dat", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(SYNTHETIC_SIGNATURE).unwrap();
    zip.finish().unwrap();

    let (code, report) = run_client(&socket, &zip_path, &[], &[]);
    assert_eq!(code, 1, "ZIP containing detected content must exit 1");
    assert_eq!(report["status"].as_str().unwrap(), "DETECTED");
}

// ---------------------------------------------------------------------------
// Mandatory Test 5: Reject invalid descriptors (directory, missing, extra, pipe).
// ---------------------------------------------------------------------------
#[test]
fn test_05_reject_invalid_descriptors() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    let _coord = CoordinatorProcess::spawn(&socket, &db_root, gen, &[]);

    let req_json = serde_json::to_vec(&serde_json::json!({
        "file_name": "test.txt",
        "max_size": 1048576,
    }))
    .unwrap();

    // 1. Directory descriptor
    {
        let mut stream = UnixStream::connect(&socket).unwrap();
        let dir = File::open(d.path()).unwrap();
        send_raw_fd_message(&stream, &[dir.as_raw_fd()], &req_json).unwrap();
        let resp = recv_raw_response(&mut stream).unwrap();
        assert_eq!(resp["status"].as_str().unwrap(), "ERROR");
        assert!(
            resp["error"]
                .as_str()
                .unwrap()
                .contains("not a regular file"),
            "Directory descriptor must be rejected"
        );
    }

    // 2. Missing descriptor (0 FDs passed)
    {
        let mut stream = UnixStream::connect(&socket).unwrap();
        send_raw_fd_message(&stream, &[], &req_json).unwrap();
        let resp = recv_raw_response(&mut stream).unwrap();
        assert_eq!(resp["status"].as_str().unwrap(), "ERROR");
        assert!(
            resp["error"]
                .as_str()
                .unwrap()
                .contains("Missing file descriptor"),
            "Missing descriptor must be rejected"
        );
    }

    // 3. Extra descriptors (2 FDs passed)
    {
        let mut stream = UnixStream::connect(&socket).unwrap();
        let regular_file = d.path().join("dummy.txt");
        std::fs::write(&regular_file, b"test").unwrap();
        let f1 = File::open(&regular_file).unwrap();
        let f2 = File::open(&regular_file).unwrap();
        send_raw_fd_message(&stream, &[f1.as_raw_fd(), f2.as_raw_fd()], &req_json).unwrap();
        let resp = recv_raw_response(&mut stream).unwrap();
        assert_eq!(resp["status"].as_str().unwrap(), "ERROR");
        assert!(
            resp["error"]
                .as_str()
                .unwrap()
                .contains("Extra file descriptors rejected"),
            "Extra descriptors must be rejected"
        );
    }

    // 4. Pipe descriptor
    {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let mut stream = UnixStream::connect(&socket).unwrap();
        send_raw_fd_message(&stream, &[fds[0]], &req_json).unwrap();
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        let resp = recv_raw_response(&mut stream).unwrap();
        assert_eq!(resp["status"].as_str().unwrap(), "ERROR");
        assert!(
            resp["error"]
                .as_str()
                .unwrap()
                .contains("not a regular file"),
            "Pipe descriptor must be rejected"
        );
    }

    // Coordinator remains fully operational after all invalid descriptor rejections
    let clean_file = d.path().join("post_check.txt");
    std::fs::write(&clean_file, b"healthy coordinator").unwrap();
    let (code, report) = run_client(&socket, &clean_file, &[], &[]);
    assert_eq!(code, 0);
    assert_eq!(report["status"].as_str().unwrap(), "CLEAN");
}

// ---------------------------------------------------------------------------
// Mandatory Test 6: Reject malformed and oversized messages.
// ---------------------------------------------------------------------------
#[test]
fn test_06_reject_malformed_and_oversized_messages() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    let _coord = CoordinatorProcess::spawn(&socket, &db_root, gen, &[]);

    let test_file = d.path().join("file.txt");
    std::fs::write(&test_file, b"data").unwrap();
    let file = File::open(&test_file).unwrap();

    // 1. Oversized length header (> 65,536 bytes)
    {
        let mut stream = UnixStream::connect(&socket).unwrap();
        let oversized_len: u32 = 70_000;
        let mut msg_bytes = Vec::new();
        msg_bytes.extend_from_slice(&oversized_len.to_be_bytes());
        msg_bytes.extend_from_slice(&[b'x'; 100]); // send prefix

        let mut iov = libc::iovec {
            iov_base: msg_bytes.as_mut_ptr() as *mut libc::c_void,
            iov_len: msg_bytes.len(),
        };
        let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize };
        let mut cmsg_buf = vec![0usize; cmsg_space.div_ceil(8)];
        let msg = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: cmsg_buf.as_mut_ptr() as *mut libc::c_void,
            msg_controllen: cmsg_space,
            msg_flags: 0,
        };
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize;
            let fd = file.as_raw_fd();
            std::ptr::copy_nonoverlapping(
                &fd as *const RawFd as *const u8,
                libc::CMSG_DATA(cmsg),
                std::mem::size_of::<RawFd>(),
            );
            libc::sendmsg(stream.as_raw_fd(), &msg, libc::MSG_NOSIGNAL);
        }
        let resp = recv_raw_response(&mut stream).unwrap();
        assert_eq!(resp["status"].as_str().unwrap(), "ERROR");
        assert!(resp["error"]
            .as_str()
            .unwrap()
            .contains("Invalid request payload length"));
    }

    // 2. Malformed JSON payload
    {
        let mut stream = UnixStream::connect(&socket).unwrap();
        let bad_json = b"{ not a valid json object";
        send_raw_fd_message(&stream, &[file.as_raw_fd()], bad_json).unwrap();
        let resp = recv_raw_response(&mut stream).unwrap();
        assert_eq!(resp["status"].as_str().unwrap(), "ERROR");
        assert!(resp["error"]
            .as_str()
            .unwrap()
            .contains("Malformed request JSON"));
    }

    // 3. Truncated message (claim 500 bytes, send 4 and close)
    {
        let stream = UnixStream::connect(&socket).unwrap();
        let len: u32 = 500;
        let mut buf = Vec::new();
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(b"abcd");
        let _ = send_raw_fd_message(&stream, &[file.as_raw_fd()], &buf);
        drop(stream); // Disconnect immediately
    }

    // Verify coordinator is still fully responsive
    let (code, report) = run_client(&socket, &test_file, &[], &[]);
    assert_eq!(code, 0);
    assert_eq!(report["status"].as_str().unwrap(), "CLEAN");
}

// ---------------------------------------------------------------------------
// Mandatory Test 7: Reject unauthorized peer credentials where test environment permits.
// ---------------------------------------------------------------------------
#[test]
fn test_07_reject_unauthorized_peer_credentials() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    let current_uid = unsafe { libc::geteuid() };
    let unauthorized_uid = current_uid.wrapping_add(1000);

    // Run coordinator permitting only unauthorized_uid
    let uid_arg = format!("--authorized-uid={unauthorized_uid}");
    let _coord = CoordinatorProcess::spawn(&socket, &db_root, gen, &[&uid_arg]);

    let clean_file = d.path().join("clean.txt");
    std::fs::write(&clean_file, b"data").unwrap();

    let (code, report) = run_client(&socket, &clean_file, &[], &[]);
    assert_eq!(
        code, 3,
        "Unauthorized client must be rejected with exit code 3"
    );
    assert_eq!(report["status"].as_str().unwrap(), "ERROR");
    assert!(
        report["error"]
            .as_str()
            .unwrap()
            .contains("Unauthorized peer credentials"),
        "Error message must specify unauthorized peer credentials"
    );
}

// ---------------------------------------------------------------------------
// Mandatory Test 8: Demonstrate bounded overload behavior.
// ---------------------------------------------------------------------------
#[cfg(debug_assertions)]
#[test]
fn test_08_bounded_overload_behavior() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    // Coordinator configured with max_pending = 1 (1 active scan + 1 queued scan)
    let _coord = CoordinatorProcess::spawn(&socket, &db_root, gen, &["--max-pending=1"]);

    let target_slow = d.path().join("slow.txt");
    std::fs::write(&target_slow, b"slow scan file").unwrap();

    let target_queued = d.path().join("queued.txt");
    std::fs::write(&target_queued, b"queued file").unwrap();

    let target_busy = d.path().join("busy.txt");
    std::fs::write(&target_busy, b"busy file").unwrap();

    let sock1 = socket.clone();
    let t1 = target_slow.clone();
    // Request 1: active scan holding the runner with a delay
    let h1 = std::thread::spawn(move || {
        run_client(
            &sock1,
            &t1,
            &[],
            &[("RAXOSENTINEL_TEST_WORKER_ACTION", "delay")],
        )
    });

    // Wait briefly to ensure request 1 has acquired the runner thread
    std::thread::sleep(Duration::from_millis(50));

    // Request 2: occupies the single pending channel slot
    let sock2 = socket.clone();
    let t2 = target_queued.clone();
    let h2 = std::thread::spawn(move || run_client(&sock2, &t2, &[], &[]));

    // Wait briefly to ensure request 2 is admitted to the pending channel
    std::thread::sleep(Duration::from_millis(50));

    // Request 3: channel is full; must be immediately rejected with BUSY
    let start_busy = Instant::now();
    let (code3, report3) = run_client(&socket, &target_busy, &[], &[]);
    let busy_elapsed = start_busy.elapsed();

    assert_eq!(code3, 3, "Overloaded request must exit with code 3");
    assert_eq!(
        report3["status"].as_str().unwrap(),
        "BUSY",
        "Overloaded request must receive status BUSY"
    );
    assert!(
        busy_elapsed < Duration::from_millis(400),
        "BUSY rejection must be immediate and non-blocking, took {:?}",
        busy_elapsed
    );

    // Wait for the earlier requests to finish
    let (code1, report1) = h1.join().unwrap();
    let (code2, report2) = h2.join().unwrap();
    assert_eq!(code1, 0);
    assert_eq!(report1["status"].as_str().unwrap(), "CLEAN");
    assert_eq!(code2, 0);
    assert_eq!(report2["status"].as_str().unwrap(), "CLEAN");

    // Subsequent request succeeds normally
    let (code4, report4) = run_client(&socket, &target_busy, &[], &[]);
    assert_eq!(code4, 0);
    assert_eq!(report4["status"].as_str().unwrap(), "CLEAN");
}

// ---------------------------------------------------------------------------
// Mandatory Test 9: Recover after worker crash.
// ---------------------------------------------------------------------------
#[cfg(debug_assertions)]
#[test]
fn test_09_recover_after_worker_crash() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    let _coord = CoordinatorProcess::spawn(&socket, &db_root, gen, &[]);

    let target = d.path().join("crash_target.txt");
    std::fs::write(&target, b"trigger crash").unwrap();

    let (code, report) = run_client(
        &socket,
        &target,
        &[],
        &[("RAXOSENTINEL_TEST_WORKER_ACTION", "crash")],
    );
    assert_eq!(code, 3, "Worker crash must result in exit code 3");
    assert_eq!(report["status"].as_str().unwrap(), "ERROR");

    // Coordinator must survive and handle subsequent scans
    let clean_file = d.path().join("after_crash.txt");
    std::fs::write(&clean_file, b"clean data").unwrap();
    let (code2, report2) = run_client(&socket, &clean_file, &[], &[]);
    assert_eq!(code2, 0);
    assert_eq!(report2["status"].as_str().unwrap(), "CLEAN");
}

// ---------------------------------------------------------------------------
// Mandatory Test 10: Recover after worker timeout.
// ---------------------------------------------------------------------------
#[cfg(debug_assertions)]
#[test]
fn test_10_recover_after_worker_timeout() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    let _coord = CoordinatorProcess::spawn(&socket, &db_root, gen, &["--worker-timeout-ms=400"]);

    let target = d.path().join("hang_target.txt");
    std::fs::write(&target, b"trigger hang").unwrap();

    let (code, report) = run_client(
        &socket,
        &target,
        &[],
        &[("RAXOSENTINEL_TEST_WORKER_ACTION", "hang")],
    );
    assert_eq!(code, 3, "Timed out worker must result in exit code 3");
    assert_eq!(report["status"].as_str().unwrap(), "ERROR");

    // Coordinator must survive and handle subsequent scans
    let clean_file = d.path().join("after_timeout.txt");
    std::fs::write(&clean_file, b"clean data").unwrap();
    let (code2, report2) = run_client(&socket, &clean_file, &[], &[]);
    assert_eq!(code2, 0);
    assert_eq!(report2["status"].as_str().unwrap(), "CLEAN");
}

// ---------------------------------------------------------------------------
// Mandatory Test 11: Confirm a modified original does not change an already sealed snapshot.
// ---------------------------------------------------------------------------
#[cfg(debug_assertions)]
#[test]
fn test_11_sealed_snapshot_unaffected_by_original_modification() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    let _coord = CoordinatorProcess::spawn(&socket, &db_root, gen, &[]);

    let target = d.path().join("mutable_original.txt");
    std::fs::write(&target, b"original harmless content").unwrap();

    let sock = socket.clone();
    let t = target.clone();

    // Submit target with worker delay hook
    let h = std::thread::spawn(move || {
        run_client(
            &sock,
            &t,
            &[],
            &[("RAXOSENTINEL_TEST_WORKER_ACTION", "delay")],
        )
    });

    // Wait until snapshot is sealed and worker is delayed
    std::thread::sleep(Duration::from_millis(100));

    // Overwrite the original on disk with the synthetic malware signature
    std::fs::write(&target, SYNTHETIC_SIGNATURE).unwrap();

    // The in-flight scan was sealed before modification; it MUST report CLEAN
    let (code, report) = h.join().unwrap();
    assert_eq!(code, 0, "Sealed snapshot must report CLEAN");
    assert_eq!(report["status"].as_str().unwrap(), "CLEAN");

    // A fresh scan of the now-modified file on disk MUST report DETECTED
    let (code_new, report_new) = run_client(&socket, &target, &[], &[]);
    assert_eq!(code_new, 1, "Modified file must now report DETECTED");
    assert_eq!(report_new["status"].as_str().unwrap(), "DETECTED");
}

// ---------------------------------------------------------------------------
// Mandatory Test 12: Shut down and restart cleanly.
// ---------------------------------------------------------------------------
#[test]
fn test_12_shutdown_and_restart_cleanly() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    // 1. Start and verify running
    let mut coord = CoordinatorProcess::spawn(&socket, &db_root, gen, &[]);
    let test_file = d.path().join("test.txt");
    std::fs::write(&test_file, b"test").unwrap();
    let (code, report) = run_client(&socket, &test_file, &[], &[]);
    assert_eq!(code, 0);
    assert_eq!(report["status"].as_str().unwrap(), "CLEAN");

    // 2. Shut down with SIGTERM and confirm clean exit
    let status = coord.stop();
    assert!(status.success(), "Coordinator should exit with status 0");
    assert!(
        !socket.exists(),
        "Socket file must be cleaned up on clean exit"
    );

    // 3. Restart coordinator on the exact same socket path
    let _coord2 = CoordinatorProcess::spawn(&socket, &db_root, gen, &[]);
    let (code2, report2) = run_client(&socket, &test_file, &[], &[]);
    assert_eq!(code2, 0);
    assert_eq!(report2["status"].as_str().unwrap(), "CLEAN");

    // 4. Stale socket recovery: create a dummy dead socket file and verify bind recovers
    drop(_coord2); // Stops coord2
                   // Create an unlistening socket at the path to simulate an unclean kill
    let dead_listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    drop(dead_listener); // Socket file remains, but no process is listening (connect fails ECONNREFUSED)
    assert!(socket.exists());

    // Starting coordinator on the stale socket must recover and remove the dead socket
    let _coord3 = CoordinatorProcess::spawn(&socket, &db_root, gen, &[]);
    let (code3, report3) = run_client(&socket, &test_file, &[], &[]);
    assert_eq!(code3, 0);
    assert_eq!(report3["status"].as_str().unwrap(), "CLEAN");
}

// ---------------------------------------------------------------------------
// Mandatory Test 13: Reject invalid database generation at startup.
// ---------------------------------------------------------------------------
#[test]
fn test_13_reject_invalid_database_at_startup() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, _) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");
    let _ = std::fs::create_dir_all(socket.parent().unwrap());

    // 1. Missing database options (silent fallback prohibited)
    let out1 = Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
        .arg("serve")
        .arg("--socket")
        .arg(&socket)
        .output()
        .unwrap();
    assert_eq!(out1.status.code().unwrap(), 3);
    let err1 = String::from_utf8_lossy(&out1.stderr);
    assert!(
        err1.contains("Coordinator requires an explicitly selected, verified private generation"),
        "Missing DB must be rejected"
    );
    assert!(!socket.exists(), "Socket must not be created on DB error");

    // 2. Legacy database options rejected
    let out2 = Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
        .arg("serve")
        .arg("--socket")
        .arg(&socket)
        .arg("--db")
        .arg(d.path().join("legacy.rsidb"))
        .output()
        .unwrap();
    assert_eq!(out2.status.code().unwrap(), 3);
    let err2 = String::from_utf8_lossy(&out2.stderr);
    assert!(
        err2.contains("Coordinator rejects legacy database options"),
        "Legacy DB must be rejected"
    );

    // 3. Invalid / non-existent generation
    let out3 = Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
        .arg("serve")
        .arg("--socket")
        .arg(&socket)
        .arg("--private-db-root")
        .arg(&db_root)
        .arg("--private-generation")
        .arg("non_existent_generation")
        .output()
        .unwrap();
    assert_eq!(out3.status.code().unwrap(), 3);
    let err3 = String::from_utf8_lossy(&out3.stderr);
    assert!(
        err3.contains("Private database verification failed"),
        "Unverified generation must fail startup"
    );
    assert!(!socket.exists());
}

// ---------------------------------------------------------------------------
// Mandatory Test 14: Preserve direct CLI compatibility.
// ---------------------------------------------------------------------------
#[test]
fn test_14_preserve_direct_cli_compatibility() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());

    let clean_file = d.path().join("clean.txt");
    std::fs::write(&clean_file, b"harmless direct file").unwrap();

    let sig_file = d.path().join("sig.txt");
    std::fs::write(&sig_file, SYNTHETIC_SIGNATURE).unwrap();

    // 1. Direct scan: clean
    let out_direct_clean = Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
        .arg("scan")
        .arg(&clean_file)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(out_direct_clean.status.code().unwrap(), 0);

    // 2. Direct scan: detected
    let out_direct_detected = Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
        .arg("scan")
        .arg(&sig_file)
        .arg("--json")
        .arg("--private-db-root")
        .arg(&db_root)
        .arg("--private-generation")
        .arg(gen)
        .output()
        .unwrap();
    assert_eq!(out_direct_detected.status.code().unwrap(), 1);

    // 3. Supervised scan: clean
    let out_sup_clean = Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
        .arg("scan")
        .arg(&clean_file)
        .arg("--supervised")
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(out_sup_clean.status.code().unwrap(), 0);

    // 4. Supervised scan: detected
    let out_sup_detected = Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
        .arg("scan")
        .arg(&sig_file)
        .arg("--supervised")
        .arg("--json")
        .arg("--private-db-root")
        .arg(&db_root)
        .arg("--private-generation")
        .arg(gen)
        .output()
        .unwrap();
    assert_eq!(out_sup_detected.status.code().unwrap(), 1);
}
