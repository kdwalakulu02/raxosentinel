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

use ed25519_dalek::SigningKey;
use raxosentinel_signatures::rsidb::malwarebazaar::private_store;
use raxosentinel_signatures::rsidb::{
    public_release::{self, Artifact, Manifest, Source},
    HashAlgorithm, RsidbCompiler, SignatureEntry,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

fn setup_public_release(dir: &Path) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let release = dir.join("release");
    let state = dir.join("state");
    for p in [&release, &state] {
        std::fs::create_dir_all(p).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let sig_content = b"synthetic signed release scanner fixture";
    let db = RsidbCompiler::new()
        .with_directory(false)
        .compile(vec![SignatureEntry::new(
            HashAlgorithm::Sha256,
            sig_content.len() as u64,
            Sha256::digest(sig_content).to_vec(),
            "SyntheticPublicFixture",
        )])
        .unwrap();
    let artifacts: BTreeMap<String, Vec<u8>> = BTreeMap::from([
        ("database.rsidb".into(), db),
        ("registry.json".into(), b"synthetic registry".to_vec()),
        (
            "associations.json".into(),
            b"synthetic associations".to_vec(),
        ),
    ]);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let manifest = Manifest {
        format: 1,
        database_version: "1.0.0".into(),
        release_id: "fixture".into(),
        release_number: 1,
        created_unix: now - 1,
        expires_unix: now + 600,
        artifacts: artifacts
            .iter()
            .map(|(n, v)| Artifact {
                name: n.clone(),
                sha256: hex::encode(Sha256::digest(v)),
                bytes: v.len() as u64,
            })
            .collect(),
        sources: vec![Source {
            id: "synthetic_test".into(),
            provenance: "synthetic fixture".into(),
            classification: "synthetic".into(),
            redistribution: "permitted".into(),
        }],
        minimum_scanner: "0.1.0".into(),
        previous_manifest_sha256: None,
        key_id: hex::encode(Sha256::digest(key.verifying_key().as_bytes())),
        algorithm: "ed25519".into(),
    };
    let (manifest_bytes, sig) = public_release::sign(&manifest, &key).unwrap();
    let save = |name: &str, data: &[u8]| {
        let p = release.join(name);
        std::fs::write(&p, data).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
    };
    for (name, data) in &artifacts {
        save(name, data);
    }
    save("manifest.json", &manifest_bytes);
    save("manifest.sig", &sig);
    let reviewer = SigningKey::generate(&mut rand::rngs::OsRng);
    let (approval, approval_signature) =
        public_release::approve(&manifest_bytes, now + 300, &reviewer).unwrap();
    save("approval.json", &approval);
    save("approval.sig", &approval_signature);
    let approval_public = dir.join("approval.key");
    std::fs::write(
        &approval_public,
        hex::encode(reviewer.verifying_key().as_bytes()),
    )
    .unwrap();
    public_release::local::initialize(&state).unwrap();
    let public_key_path = dir.join("public.key");
    std::fs::write(
        &public_key_path,
        hex::encode(key.verifying_key().as_bytes()),
    )
    .unwrap();

    (release, public_key_path, approval_public, state)
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

    fn spawn_public(
        socket_path: &Path,
        release_root: &Path,
        public_key: &Path,
        public_approval_key: &Path,
        public_state: &Path,
        extra_args: &[&str],
    ) -> Self {
        let parent = socket_path.parent().unwrap_or_else(|| Path::new("."));
        let _ = std::fs::create_dir_all(parent);
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_raxosentinel"));
        cmd.arg("serve")
            .arg("--socket")
            .arg(socket_path)
            .arg("--public-release")
            .arg(release_root)
            .arg("--public-key")
            .arg(public_key)
            .arg("--public-approval-key")
            .arg(public_approval_key)
            .arg("--public-state")
            .arg(public_state)
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
            panic!("coordinator failed to start with public release, output: {line}");
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

// ===========================================================================
// Phase 3B.3 Mandatory Concurrency Integration Tests (1 through 14)
// ===========================================================================

// ---------------------------------------------------------------------------
// Mandatory Test 1: Two concurrent clean scans.
// ---------------------------------------------------------------------------
#[test]
fn test_01_two_concurrent_clean_scans() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    let _coord = CoordinatorProcess::spawn(
        &socket,
        &db_root,
        gen,
        &["--max-workers=2", "--max-pending=2"],
    );

    let file1 = d.path().join("clean1.txt");
    let file2 = d.path().join("clean2.txt");
    std::fs::write(&file1, b"clean file 1").unwrap();
    std::fs::write(&file2, b"clean file 2").unwrap();

    let sock1 = socket.clone();
    let f1 = file1.clone();
    let h1 = std::thread::spawn(move || run_client(&sock1, &f1, &[], &[]));

    let sock2 = socket.clone();
    let f2 = file2.clone();
    let h2 = std::thread::spawn(move || run_client(&sock2, &f2, &[], &[]));

    let (c1, r1) = h1.join().unwrap();
    let (c2, r2) = h2.join().unwrap();

    assert_eq!(c1, 0, "Scan 1 must succeed with CLEAN");
    assert_eq!(r1["status"].as_str().unwrap(), "CLEAN");
    assert_eq!(c2, 0, "Scan 2 must succeed with CLEAN");
    assert_eq!(r2["status"].as_str().unwrap(), "CLEAN");
}

// ---------------------------------------------------------------------------
// Mandatory Test 2: Four concurrent scans.
// ---------------------------------------------------------------------------
#[test]
fn test_02_four_concurrent_scans() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    let _coord = CoordinatorProcess::spawn(
        &socket,
        &db_root,
        gen,
        &["--max-workers=4", "--max-pending=4"],
    );

    let mut handles = Vec::new();
    for i in 0..4 {
        let file = d.path().join(format!("clean_{i}.txt"));
        std::fs::write(&file, format!("clean file {i}")).unwrap();
        let sock = socket.clone();
        handles.push(std::thread::spawn(move || {
            run_client(&sock, &file, &[], &[])
        }));
    }

    for (i, h) in handles.into_iter().enumerate() {
        let (code, rep) = h.join().unwrap();
        assert_eq!(code, 0, "Scan {i} must succeed with CLEAN");
        assert_eq!(rep["status"].as_str().unwrap(), "CLEAN");
    }
}

// ---------------------------------------------------------------------------
// Mandatory Test 3: Eight simultaneous clients with bounded admission.
// ---------------------------------------------------------------------------
#[cfg(debug_assertions)]
#[test]
fn test_03_eight_simultaneous_clients_bounded_admission() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    // 4 active workers + 2 pending queue = 6 total capacity; 7th and 8th must receive BUSY
    let _coord = CoordinatorProcess::spawn(
        &socket,
        &db_root,
        gen,
        &["--max-workers=4", "--max-pending=2"],
    );

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let mut handles = Vec::new();

    for i in 0..8 {
        let file = d.path().join(format!("file_{i}.txt"));
        std::fs::write(&file, format!("data {i}")).unwrap();
        let sock = socket.clone();
        let b = std::sync::Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            b.wait();
            run_client(
                &sock,
                &file,
                &[],
                &[("RAXOSENTINEL_TEST_WORKER_ACTION", "delay")],
            )
        }));
    }

    let mut clean_count = 0;
    let mut busy_count = 0;
    let mut other_count = 0;

    for h in handles {
        let (code, rep) = h.join().unwrap();
        match rep["status"].as_str() {
            Some("CLEAN") if code == 0 => clean_count += 1,
            Some("BUSY") if code == 3 => busy_count += 1,
            other => {
                eprintln!("Unexpected response: code {code}, status {other:?}, rep: {rep}");
                other_count += 1;
            }
        }
    }

    assert_eq!(other_count, 0, "All 8 clients must be either CLEAN or BUSY");
    assert_eq!(
        clean_count, 6,
        "Exactly 6 clients should be admitted (4 active + 2 pending)"
    );
    assert_eq!(
        busy_count, 2,
        "Exactly 2 clients should be rejected with BUSY"
    );
}

// ---------------------------------------------------------------------------
// Mandatory Test 4: Mixed CLEAN and DETECTED results.
// ---------------------------------------------------------------------------
#[test]
fn test_04_mixed_clean_and_detected_results() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    let _coord = CoordinatorProcess::spawn(
        &socket,
        &db_root,
        gen,
        &["--max-workers=4", "--max-pending=4"],
    );

    let clean1 = d.path().join("clean1.txt");
    let clean2 = d.path().join("clean2.txt");
    let detected1 = d.path().join("detected1.txt");
    let detected2 = d.path().join("detected2.txt");

    std::fs::write(&clean1, b"clean file alpha").unwrap();
    std::fs::write(&clean2, b"clean file beta").unwrap();
    std::fs::write(&detected1, SYNTHETIC_SIGNATURE).unwrap();
    std::fs::write(&detected2, SYNTHETIC_SIGNATURE).unwrap();

    let s1 = socket.clone();
    let h1 = std::thread::spawn(move || run_client(&s1, &clean1, &[], &[]));
    let s2 = socket.clone();
    let h2 = std::thread::spawn(move || run_client(&s2, &detected1, &[], &[]));
    let s3 = socket.clone();
    let h3 = std::thread::spawn(move || run_client(&s3, &clean2, &[], &[]));
    let s4 = socket.clone();
    let h4 = std::thread::spawn(move || run_client(&s4, &detected2, &[], &[]));

    let (c1, r1) = h1.join().unwrap();
    let (c2, r2) = h2.join().unwrap();
    let (c3, r3) = h3.join().unwrap();
    let (c4, r4) = h4.join().unwrap();

    assert_eq!(c1, 0);
    assert_eq!(r1["status"].as_str().unwrap(), "CLEAN");
    assert_eq!(c2, 1);
    assert_eq!(r2["status"].as_str().unwrap(), "DETECTED");
    assert_eq!(c3, 0);
    assert_eq!(r3["status"].as_str().unwrap(), "CLEAN");
    assert_eq!(c4, 1);
    assert_eq!(r4["status"].as_str().unwrap(), "DETECTED");
}

// ---------------------------------------------------------------------------
// Mandatory Test 5: Concurrent ZIP detections.
// ---------------------------------------------------------------------------
#[test]
fn test_05_concurrent_zip_detections() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    let _coord = CoordinatorProcess::spawn(
        &socket,
        &db_root,
        gen,
        &["--max-workers=4", "--max-pending=4"],
    );

    let zip_path = d.path().join("archive.zip");
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("sample.dat", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(SYNTHETIC_SIGNATURE).unwrap();
    zip.finish().unwrap();

    let mut handles = Vec::new();
    for _ in 0..4 {
        let s = socket.clone();
        let z = zip_path.clone();
        handles.push(std::thread::spawn(move || run_client(&s, &z, &[], &[])));
    }

    for (i, h) in handles.into_iter().enumerate() {
        let (code, rep) = h.join().unwrap();
        assert_eq!(code, 1, "ZIP scan {i} must exit 1 for DETECTED");
        assert_eq!(rep["status"].as_str().unwrap(), "DETECTED");
    }
}

// ---------------------------------------------------------------------------
// Mandatory Test 6: One worker crash without affecting other scans.
// ---------------------------------------------------------------------------
#[cfg(debug_assertions)]
#[test]
fn test_06_worker_crash_without_affecting_other_scans() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    let _coord = CoordinatorProcess::spawn(
        &socket,
        &db_root,
        gen,
        &["--max-workers=2", "--max-pending=2"],
    );

    let crash_file = d.path().join("crash.txt");
    let clean_file = d.path().join("clean.txt");
    std::fs::write(&crash_file, b"crash payload").unwrap();
    std::fs::write(&clean_file, b"clean payload").unwrap();

    let s1 = socket.clone();
    let f1 = crash_file.clone();
    let h1 = std::thread::spawn(move || {
        run_client(
            &s1,
            &f1,
            &[],
            &[("RAXOSENTINEL_TEST_WORKER_ACTION", "crash")],
        )
    });

    let s2 = socket.clone();
    let f2 = clean_file.clone();
    let h2 = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        run_client(&s2, &f2, &[], &[])
    });

    let (c1, r1) = h1.join().unwrap();
    let (c2, r2) = h2.join().unwrap();

    assert_eq!(c1, 3, "Crashing worker must exit code 3");
    assert_eq!(r1["status"].as_str().unwrap(), "ERROR");

    assert_eq!(c2, 0, "Concurrent clean scan must succeed with exit code 0");
    assert_eq!(r2["status"].as_str().unwrap(), "CLEAN");
}

// ---------------------------------------------------------------------------
// Mandatory Test 7: One worker timeout without affecting other scans.
// ---------------------------------------------------------------------------
#[cfg(debug_assertions)]
#[test]
fn test_07_worker_timeout_without_affecting_other_scans() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    let _coord = CoordinatorProcess::spawn(
        &socket,
        &db_root,
        gen,
        &[
            "--max-workers=2",
            "--max-pending=2",
            "--worker-timeout-ms=300",
        ],
    );

    let hang_file = d.path().join("hang.txt");
    let clean_file = d.path().join("clean.txt");
    std::fs::write(&hang_file, b"hang file").unwrap();
    std::fs::write(&clean_file, b"clean file").unwrap();

    let s1 = socket.clone();
    let f1 = hang_file.clone();
    let h1 = std::thread::spawn(move || {
        run_client(
            &s1,
            &f1,
            &[],
            &[("RAXOSENTINEL_TEST_WORKER_ACTION", "hang")],
        )
    });

    let s2 = socket.clone();
    let f2 = clean_file.clone();
    let h2 = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(30));
        run_client(&s2, &f2, &[], &[])
    });

    let (c1, r1) = h1.join().unwrap();
    let (c2, r2) = h2.join().unwrap();

    assert_eq!(c1, 3, "Timed out worker must return ERROR exit code 3");
    assert_eq!(r1["status"].as_str().unwrap(), "ERROR");

    assert_eq!(c2, 0, "Concurrent scan must complete with CLEAN");
    assert_eq!(r2["status"].as_str().unwrap(), "CLEAN");
}

// ---------------------------------------------------------------------------
// Mandatory Test 8: Client disconnection and resource release.
// ---------------------------------------------------------------------------
#[cfg(debug_assertions)]
#[test]
fn test_08_client_disconnection_and_resource_release() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    // Coordinator with 1 worker and 500 KB total snapshot budget
    let _coord = CoordinatorProcess::spawn(
        &socket,
        &db_root,
        gen,
        &[
            "--max-workers=1",
            "--max-pending=1",
            "--max-total-snapshot-bytes=524288",
        ],
    );

    let large_file = d.path().join("large.dat");
    std::fs::write(&large_file, vec![0x41u8; 300_000]).unwrap(); // 300 KB file

    // Client connects, submits file with delay, then abruptly disconnects
    {
        let file = File::open(&large_file).unwrap();
        let stream = UnixStream::connect(&socket).unwrap();
        let req = serde_json::json!({
            "file_name": "large.dat",
            "test_worker_action": "delay"
        });
        let payload = serde_json::to_vec(&req).unwrap();
        let _ = send_raw_fd_message(&stream, &[file.as_raw_fd()], &payload);
        // Abruptly drop stream without reading response
        drop(stream);
    }

    // Wait for worker to finish (delay is 500ms)
    std::thread::sleep(Duration::from_millis(700));

    // Now submit another 300 KB file; if snapshot memory or worker slot wasn't released,
    // this would fail or report BUSY/over capacity.
    let (code, report) = run_client(&socket, &large_file, &[], &[]);
    assert_eq!(
        code, 0,
        "Subsequent scan must succeed after client disconnect"
    );
    assert_eq!(report["status"].as_str().unwrap(), "CLEAN");
}

// ---------------------------------------------------------------------------
// Mandatory Test 9: Slow or incomplete protocol messages.
// ---------------------------------------------------------------------------
#[test]
fn test_09_slow_or_incomplete_protocol_messages() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    // Short client timeout of 1 second
    let _coord = CoordinatorProcess::spawn(
        &socket,
        &db_root,
        gen,
        &[
            "--max-workers=1",
            "--max-pending=1",
            "--client-timeout-secs=1",
        ],
    );

    // Client sends only 2 bytes and stalls
    let mut stream = UnixStream::connect(&socket).unwrap();
    stream.write_all(&[0x00, 0x00]).unwrap();
    stream.flush().unwrap();

    // Sleep for 1.5 seconds, exceeding client_timeout_secs
    std::thread::sleep(Duration::from_millis(1500));

    // Reading should return EOF or connection reset
    let mut buf = [0u8; 16];
    let _ = stream.read(&mut buf);
    drop(stream);

    // Verify coordinator is completely healthy for next request
    let clean_file = d.path().join("clean.txt");
    std::fs::write(&clean_file, b"clean content").unwrap();
    let (code, rep) = run_client(&socket, &clean_file, &[], &[]);
    assert_eq!(
        code, 0,
        "Coordinator must remain healthy after slow client timed out"
    );
    assert_eq!(rep["status"].as_str().unwrap(), "CLEAN");
}

// ---------------------------------------------------------------------------
// Mandatory Test 10: Queue saturation with immediate BUSY.
// ---------------------------------------------------------------------------
#[cfg(debug_assertions)]
#[test]
fn test_10_queue_saturation_with_immediate_busy() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    let _coord = CoordinatorProcess::spawn(
        &socket,
        &db_root,
        gen,
        &["--max-workers=1", "--max-pending=1"],
    );

    let slow_file = d.path().join("slow.txt");
    let queued_file = d.path().join("queued.txt");
    let busy_file = d.path().join("busy.txt");
    std::fs::write(&slow_file, b"slow").unwrap();
    std::fs::write(&queued_file, b"queued").unwrap();
    std::fs::write(&busy_file, b"busy").unwrap();

    // Request 1: occupies the single worker
    let s1 = socket.clone();
    let f1 = slow_file.clone();
    let h1 = std::thread::spawn(move || {
        run_client(
            &s1,
            &f1,
            &[],
            &[("RAXOSENTINEL_TEST_WORKER_ACTION", "delay")],
        )
    });

    std::thread::sleep(Duration::from_millis(50));

    // Request 2: occupies the single pending queue slot
    let s2 = socket.clone();
    let f2 = queued_file.clone();
    let h2 = std::thread::spawn(move || run_client(&s2, &f2, &[], &[]));

    std::thread::sleep(Duration::from_millis(50));

    // Request 3: queue is saturated; must immediately return BUSY
    let t0 = Instant::now();
    let (code3, rep3) = run_client(&socket, &busy_file, &[], &[]);
    let elapsed = t0.elapsed();

    assert_eq!(code3, 3);
    assert_eq!(rep3["status"].as_str().unwrap(), "BUSY");
    assert!(
        elapsed < Duration::from_millis(150),
        "BUSY rejection took too long: {:?}",
        elapsed
    );

    let (c1, r1) = h1.join().unwrap();
    let (c2, r2) = h2.join().unwrap();
    assert_eq!(c1, 0);
    assert_eq!(r1["status"].as_str().unwrap(), "CLEAN");
    assert_eq!(c2, 0);
    assert_eq!(r2["status"].as_str().unwrap(), "CLEAN");
}

// ---------------------------------------------------------------------------
// Mandatory Test 11: Signed-public verification and rollback-state correctness under concurrency.
// ---------------------------------------------------------------------------
#[test]
fn test_11_signed_public_verification_and_rollback_state_concurrency() {
    let d = tempfile::tempdir().unwrap();
    let (release, pubkey, approval, state) = setup_public_release(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    let _coord = CoordinatorProcess::spawn_public(
        &socket,
        &release,
        &pubkey,
        &approval,
        &state,
        &["--max-workers=4", "--max-pending=4"],
    );

    let sig_content = b"synthetic signed release scanner fixture";
    let detected_file = d.path().join("detected.dat");
    std::fs::write(&detected_file, sig_content).unwrap();

    let clean_file = d.path().join("clean.dat");
    std::fs::write(&clean_file, b"clean data here").unwrap();

    let mut handles = Vec::new();
    for i in 0..4 {
        let s = socket.clone();
        let target = if i % 2 == 0 {
            detected_file.clone()
        } else {
            clean_file.clone()
        };
        let expect_detected = i % 2 == 0;
        handles.push(std::thread::spawn(move || {
            let (code, rep) = run_client(&s, &target, &[], &[]);
            (expect_detected, code, rep)
        }));
    }

    for h in handles {
        let (expect_detected, code, rep) = h.join().unwrap();
        let (exp_code, exp_verdict) = if expect_detected {
            (1, "DETECTED")
        } else {
            (0, "CLEAN")
        };
        assert_eq!(code, exp_code);
        assert_eq!(rep["status"].as_str().unwrap(), exp_verdict);
    }

    // Verify rollback state file has sequence 1
    let state_file = state.join("public-release-state");
    let state_bytes = std::fs::read(&state_file).expect("state file must exist");
    assert_eq!(state_bytes.len(), 40, "State file must be 40 bytes");
    let seq = u64::from_le_bytes(state_bytes[..8].try_into().unwrap());
    assert_eq!(seq, 1, "Rollback state sequence must be 1");
}

// ---------------------------------------------------------------------------
// Mandatory Test 12: Graceful shutdown with active work.
// ---------------------------------------------------------------------------
#[cfg(debug_assertions)]
#[test]
fn test_12_graceful_shutdown_with_active_work() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    let mut coord = CoordinatorProcess::spawn(
        &socket,
        &db_root,
        gen,
        &["--max-workers=2", "--max-pending=2"],
    );

    let f1 = d.path().join("work1.txt");
    let f2 = d.path().join("work2.txt");
    std::fs::write(&f1, b"active work 1").unwrap();
    std::fs::write(&f2, b"active work 2").unwrap();

    let s1 = socket.clone();
    let h1 = std::thread::spawn(move || {
        run_client(
            &s1,
            &f1,
            &[],
            &[("RAXOSENTINEL_TEST_WORKER_ACTION", "delay")],
        )
    });

    let s2 = socket.clone();
    let h2 = std::thread::spawn(move || {
        run_client(
            &s2,
            &f2,
            &[],
            &[("RAXOSENTINEL_TEST_WORKER_ACTION", "delay")],
        )
    });

    // Wait briefly so both requests are active
    std::thread::sleep(Duration::from_millis(50));

    // Send SIGTERM to initiate graceful shutdown
    let status = coord.stop();
    assert_eq!(
        status.code().unwrap_or(0),
        0,
        "Coordinator must exit 0 on graceful shutdown"
    );

    // Both in-flight clients must receive their reports
    let (c1, r1) = h1.join().unwrap();
    let (c2, r2) = h2.join().unwrap();
    assert_eq!(c1, 0, "In-flight client 1 must receive CLEAN");
    assert_eq!(r1["status"].as_str().unwrap(), "CLEAN");
    assert_eq!(c2, 0, "In-flight client 2 must receive CLEAN");
    assert_eq!(r2["status"].as_str().unwrap(), "CLEAN");

    // Socket must be cleaned up
    assert!(!socket.exists(), "Socket must be removed on shutdown");
}

// ---------------------------------------------------------------------------
// Mandatory Test 13: No descriptor leaks across repeated requests.
// ---------------------------------------------------------------------------
#[test]
fn test_13_no_descriptor_leaks_across_repeated_requests() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    let coord = CoordinatorProcess::spawn(
        &socket,
        &db_root,
        gen,
        &["--max-workers=2", "--max-pending=2"],
    );

    let count_fds = || -> usize {
        std::fs::read_dir(format!("/proc/{}/fd", coord.child.id()))
            .expect("read /proc/pid/fd")
            .count()
    };

    let clean = d.path().join("clean.txt");
    std::fs::write(&clean, b"harmless file").unwrap();

    let detected = d.path().join("detected.txt");
    std::fs::write(&detected, SYNTHETIC_SIGNATURE).unwrap();

    // Warmup request to stabilize any lazily-opened descriptors
    let _ = run_client(&socket, &clean, &[], &[]);

    let initial_fds = count_fds();

    // Execute 30 varied requests: clean, detected, errors
    for i in 0..30 {
        if i % 2 == 0 {
            let (code, _) = run_client(&socket, &clean, &[], &[]);
            assert_eq!(code, 0);
        } else {
            let (code, _) = run_client(&socket, &detected, &[], &[]);
            assert_eq!(code, 1);
        }
    }

    let final_fds = count_fds();
    assert_eq!(
        initial_fds, final_fds,
        "Descriptor count changed from {} to {}! Descriptors were leaked.",
        initial_fds, final_fds
    );
}

// ---------------------------------------------------------------------------
// Mandatory Test 14: Preserve direct CLI compatibility.
// ---------------------------------------------------------------------------
#[test]
fn test_14_preserve_direct_cli_compatibility() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    // Single-worker default
    let _coord = CoordinatorProcess::spawn(&socket, &db_root, gen, &[]);

    let clean_file = d.path().join("clean.txt");
    std::fs::write(&clean_file, b"harmless direct file").unwrap();

    let sig_file = d.path().join("sig.txt");
    std::fs::write(&sig_file, SYNTHETIC_SIGNATURE).unwrap();

    // Client via socket
    let (c_clean, r_clean) = run_client(&socket, &clean_file, &[], &[]);
    assert_eq!(c_clean, 0);
    assert_eq!(r_clean["status"].as_str().unwrap(), "CLEAN");

    let (c_det, r_det) = run_client(&socket, &sig_file, &[], &[]);
    assert_eq!(c_det, 1);
    assert_eq!(r_det["status"].as_str().unwrap(), "DETECTED");

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

// ===========================================================================
// Additional Phase 3B.2 Security and Validation Tests Preserved
// ===========================================================================

// ---------------------------------------------------------------------------
// Security Test: Reject invalid descriptors (directory, missing, extra, pipe).
// ---------------------------------------------------------------------------
#[test]
fn test_security_reject_invalid_descriptors() {
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
// Security Test: Reject malformed and oversized messages.
// ---------------------------------------------------------------------------
#[test]
fn test_security_reject_malformed_and_oversized_messages() {
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
// Security Test: Reject unauthorized peer credentials where test environment permits.
// ---------------------------------------------------------------------------
#[test]
fn test_security_reject_unauthorized_peer_credentials() {
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
// Security Test: Confirm a modified original does not change an already sealed snapshot.
// ---------------------------------------------------------------------------
#[cfg(debug_assertions)]
#[test]
fn test_security_sealed_snapshot_unaffected_by_original_modification() {
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
// Security Test: Reject invalid database generation at startup.
// ---------------------------------------------------------------------------
#[test]
fn test_security_reject_invalid_database_at_startup() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, _) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    // 1. Silent fallback to built-in rules prohibited
    let out1 = Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
        .arg("serve")
        .arg("--socket")
        .arg(&socket)
        .output()
        .unwrap();
    assert_eq!(
        out1.status.code().unwrap(),
        3,
        "Startup without verified DB must exit code 3"
    );
    let err1 = String::from_utf8_lossy(&out1.stderr);
    assert!(
        err1.contains("Silent fallback to built-in rules is prohibited"),
        "Error must explain requirement"
    );

    // 2. Legacy database option --db rejected
    let dummy_db = d.path().join("rules.rsidb");
    std::fs::write(&dummy_db, b"dummy").unwrap();
    let out2 = Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
        .arg("serve")
        .arg("--socket")
        .arg(&socket)
        .arg("--db")
        .arg(&dummy_db)
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
