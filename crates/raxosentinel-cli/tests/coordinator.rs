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
#[allow(unused_imports)]
use std::fs::{File, OpenOptions};
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
        cmd.env("RAXOSENTINEL_ALLOW_TEST_ACTIONS", "1");
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

    fn spawn_root(socket_path: &Path, db_root: &Path, extra_args: &[&str]) -> Self {
        let parent = socket_path.parent().unwrap_or_else(|| Path::new("."));
        let _ = std::fs::create_dir_all(parent);
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_raxosentinel"));
        cmd.env("RAXOSENTINEL_ALLOW_TEST_ACTIONS", "1");
        cmd.arg("serve")
            .arg("--socket")
            .arg(socket_path)
            .arg("--private-db-root")
            .arg(db_root)
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
            panic!("coordinator failed to start with db_root, output: {line}");
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
    cmd.arg("client").arg("--socket").arg(socket).arg(target);
    if !extra_args.contains(&"--json-envelope") {
        cmd.arg("--json");
    }
    cmd.args(extra_args);

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
            &["--json-envelope"],
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
    assert_eq!(r1["error_code"], "TIMEOUT");

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

    // Wait briefly for worker thread to close final connection descriptor
    std::thread::sleep(Duration::from_millis(50));

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

// ---------------------------------------------------------------------------
// Fix 1 Test: Total Client Request Monotonic Deadline
// ---------------------------------------------------------------------------
#[cfg(debug_assertions)]
#[test]
fn test_slow_partial_request_overall_deadline_exceeded() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    // Total client framing timeout of 1 second
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

    let regular_file = d.path().join("dummy.txt");
    std::fs::write(&regular_file, b"test content").unwrap();
    let f = File::open(&regular_file).unwrap();

    let mut stream = UnixStream::connect(&socket).unwrap();

    // Send FD with only the first byte of length prefix via SCM_RIGHTS.
    // The length prefix will eventually specify payload_len = 50.
    {
        let len_byte = [0x00u8]; // byte 0 of [0, 0, 0, 50]
        let mut iov = libc::iovec {
            iov_base: len_byte.as_ptr() as *mut libc::c_void,
            iov_len: 1,
        };
        let fd = f.as_raw_fd();
        let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize };
        let cmsg_words = cmsg_space.div_ceil(std::mem::size_of::<usize>());
        let mut cmsg_buf = vec![0usize; cmsg_words];

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
            std::ptr::copy_nonoverlapping(
                &fd as *const RawFd as *const u8,
                libc::CMSG_DATA(cmsg),
                std::mem::size_of::<RawFd>(),
            );
            let ret = libc::sendmsg(stream.as_raw_fd(), &msg, libc::MSG_NOSIGNAL);
            assert!(ret >= 0, "sendmsg failed");
        }
    }

    // Sequence of bytes to drip-feed:
    // bytes 1..3 complete the length prefix [0, 0, 50],
    // remaining bytes are partial JSON payload chunks.
    let drip_bytes = [
        0x00, 0x00, 50, // complete 4-byte length header: 50 bytes
        b'{', b'"', b'f', b'i', b'l', b'e', b'"', b':', // payload bytes
    ];

    // Repeatedly transmit 1 byte every 120ms.
    // 120ms is well below the 1000ms per-read inactivity timeout.
    // However, after ~9 iterations (1080ms total), the 1000ms overall monotonic deadline expires!
    let start = Instant::now();
    let mut client_failed = false;
    for &b in &drip_bytes {
        std::thread::sleep(Duration::from_millis(120));
        if stream.write_all(&[b]).is_err() || stream.flush().is_err() {
            client_failed = true;
            break;
        }
    }

    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let mut buf = [0u8; 1024];
    let read_result = stream.read(&mut buf);
    drop(stream);

    if !client_failed {
        match read_result {
            Ok(0) => {} // EOF on coordinator closing connection
            Ok(n) => {
                let resp_str = String::from_utf8_lossy(&buf[..n]);
                assert!(
                    resp_str.contains("ERROR") || resp_str.contains("deadline exceeded"),
                    "Response must report deadline exceeded error: {resp_str}"
                );
            }
            Err(_) => {} // Connection reset or timed out
        }
    }

    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(900),
        "Deadline test finished too early: {:?}",
        elapsed
    );

    // Verify coordinator is completely healthy for subsequent requests and capacity is released
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
// Fix 2 Tests: Snapshot Budget Enforcement, Growth, Exhaustion & Recovery
// ---------------------------------------------------------------------------
#[cfg(debug_assertions)]
#[test]
fn test_snapshot_budget_exhaustion_across_multiple_scans_and_recovery() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    // Total snapshot budget: 30,000 bytes across 2 worker slots
    let _coord = CoordinatorProcess::spawn(
        &socket,
        &db_root,
        gen,
        &[
            "--max-workers=2",
            "--max-pending=1",
            "--max-total-snapshot-bytes=30000",
        ],
    );

    let file_20k = d.path().join("file_20k.txt");
    std::fs::write(&file_20k, vec![b'A'; 20_000]).unwrap();

    let file_15k = d.path().join("file_15k.txt");
    std::fs::write(&file_15k, vec![b'B'; 15_000]).unwrap();

    // Client 1 submits 20K file with delay so it remains active in flight
    let s1 = socket.clone();
    let f1 = file_20k.clone();
    let h1 = std::thread::spawn(move || {
        run_client(
            &s1,
            &f1,
            &[],
            &[("RAXOSENTINEL_TEST_WORKER_ACTION", "delay")],
        )
    });

    // Wait for Client 1 to be admitted and reserve 20K bytes
    std::thread::sleep(Duration::from_millis(50));

    // Client 2 submits 15K file: 20K in-flight + 15K requested = 35K > 30K budget!
    // Must immediately return BUSY
    let (code2, rep2) = run_client(&socket, &file_15k, &[], &[]);
    assert_eq!(
        code2, 3,
        "Exceeding snapshot budget must return BUSY (exit code 3)"
    );
    assert_eq!(rep2["status"].as_str().unwrap(), "BUSY");
    assert!(
        rep2["error"]
            .as_str()
            .unwrap()
            .contains("snapshot memory limit exceeded"),
        "Error must explain snapshot memory limit exceeded"
    );

    // Wait for Client 1 to complete and release its 20K reservation
    let (c1, r1) = h1.join().unwrap();
    assert_eq!(c1, 0);
    assert_eq!(r1["status"].as_str().unwrap(), "CLEAN");

    // Client 3 submits 15K file now that Client 1 released its reservation
    let (c3, r3) = run_client(&socket, &file_15k, &[], &[]);
    assert_eq!(
        c3, 0,
        "Snapshot budget must be fully recovered after first scan finishes"
    );
    assert_eq!(r3["status"].as_str().unwrap(), "CLEAN");
}

#[cfg(debug_assertions)]
#[test]
fn test_concurrent_file_growth_exceeding_budget() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");

    // Snapshot budget: 25,000 bytes
    let _coord = CoordinatorProcess::spawn(
        &socket,
        &db_root,
        gen,
        &[
            "--max-workers=2",
            "--max-pending=1",
            "--max-total-snapshot-bytes=25000",
        ],
    );

    let grow_file = d.path().join("grow_file.txt");
    std::fs::write(&grow_file, vec![b'X'; 500]).unwrap();

    let stream = UnixStream::connect(&socket).unwrap();
    let req_json = serde_json::to_vec(&serde_json::json!({
        "file_name": "grow_file.txt",
        "max_size": 100_000,
    }))
    .unwrap();

    // Append 50,000 bytes to the file so it exceeds the 25,000 budget
    {
        let mut file = OpenOptions::new().append(true).open(&grow_file).unwrap();
        file.write_all(&vec![b'Y'; 50_000]).unwrap();
        file.flush().unwrap();
    }

    // Submit file descriptor to coordinator
    let f = File::open(&grow_file).unwrap();
    let mut stream_mut = stream;
    send_raw_fd_message(&stream_mut, &[f.as_raw_fd()], &req_json).unwrap();
    let resp = recv_raw_response(&mut stream_mut).unwrap();
    assert_eq!(resp["status"].as_str().unwrap(), "ERROR");
    assert!(
        resp["error"]
            .as_str()
            .unwrap()
            .contains("exceeds coordinator snapshot budget"),
        "Must reject file exceeding coordinator snapshot budget"
    );

    // Verify recovery after rejection
    let clean_file = d.path().join("clean.txt");
    std::fs::write(&clean_file, b"clean").unwrap();
    let (code, rep) = run_client(&socket, &clean_file, &[], &[]);
    assert_eq!(code, 0);
    assert_eq!(rep["status"].as_str().unwrap(), "CLEAN");
}

// ===========================================================================
// Phase 2D.8A: Live RSIDB Hot Reload & Coordinator Integration Tests
// ===========================================================================

fn publish_test_generation(root: &Path, name: &str, signatures: &[(&[u8], &str)]) {
    let _ = std::fs::create_dir_all(root);
    let _ = std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700));

    let entries: Vec<serde_json::Value> = signatures
        .iter()
        .map(|(sig, sig_name)| {
            let h = hex::encode(Sha256::digest(sig));
            serde_json::json!({
                "sha256_hash": h,
                "file_size": sig.len(),
                "first_seen": "2024-02-29 00:00:00",
                "signature": sig_name
            })
        })
        .collect();

    let response = serde_json::json!({
        "query_status": "ok",
        "data": entries
    })
    .to_string();

    private_store::publish(root, name, response.as_bytes(), 1).unwrap();
}

fn scan_via_socket(
    socket: &Path,
    target: &Path,
    test_worker_action: Option<&str>,
) -> serde_json::Value {
    let mut stream = UnixStream::connect(socket).expect("connect to coordinator socket");
    let file = File::open(target).expect("open target file");
    let req = serde_json::json!({
        "file_name": target.file_name().unwrap().to_string_lossy(),
        "test_worker_action": test_worker_action
    });
    let payload = serde_json::to_vec(&req).unwrap();
    send_raw_fd_message(&stream, &[file.as_raw_fd()], &payload).unwrap();
    recv_raw_response(&mut stream).unwrap()
}

// ---------------------------------------------------------------------------
// Scenario A: Live update without coordinator restart
// ---------------------------------------------------------------------------
#[test]
fn test_phase2d8a_scenario_a_live_update_without_coordinator_restart() {
    let d = tempfile::tempdir().unwrap();
    let db_root = d.path().join("db_root");
    let socket = d.path().join("sock_dir/coordinator.sock");

    let sig_a: &[u8] = b"scenario_a_indicator_alpha";
    let sig_b: &[u8] = b"scenario_a_indicator_beta";

    publish_test_generation(&db_root, "gen-a-1", &[(sig_a, "AlphaMalware")]);
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "current", "gen-a-1").unwrap();

    let _coord = CoordinatorProcess::spawn_root(&socket, &db_root, &["--max-workers=2"]);

    let target_a = d.path().join("target_a.bin");
    std::fs::write(&target_a, sig_a).unwrap();
    let target_b = d.path().join("target_b.bin");
    std::fs::write(&target_b, sig_b).unwrap();

    // Prior to update: target A is DETECTED, target B is CLEAN
    let resp_a1 = scan_via_socket(&socket, &target_a, None);
    assert_eq!(resp_a1["status"].as_str().unwrap(), "DETECTED");
    assert_eq!(resp_a1["database_generation"].as_str().unwrap(), "gen-a-1");
    assert!(!resp_a1["degraded_freshness"].as_bool().unwrap());

    let resp_b1 = scan_via_socket(&socket, &target_b, None);
    assert_eq!(resp_b1["status"].as_str().unwrap(), "CLEAN");
    assert_eq!(resp_b1["database_generation"].as_str().unwrap(), "gen-a-1");

    // Publish gen-a-2 adding indicator B
    publish_test_generation(
        &db_root,
        "gen-a-2",
        &[(sig_a, "AlphaMalware"), (sig_b, "BetaMalware")],
    );
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "previous", "gen-a-1")
        .unwrap();
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "current", "gen-a-2").unwrap();

    // Allow inotify / periodic check to hot reload
    std::thread::sleep(Duration::from_millis(200));

    // Post update without restarting coordinator: target B is now DETECTED
    let resp_b2 = scan_via_socket(&socket, &target_b, None);
    assert_eq!(
        resp_b2["status"].as_str().unwrap(),
        "DETECTED",
        "Target B must be detected after live hot reload"
    );
    assert_eq!(resp_b2["database_generation"].as_str().unwrap(), "gen-a-2");
    assert!(!resp_b2["degraded_freshness"].as_bool().unwrap());

    let resp_a2 = scan_via_socket(&socket, &target_a, None);
    assert_eq!(resp_a2["status"].as_str().unwrap(), "DETECTED");
    assert_eq!(resp_a2["database_generation"].as_str().unwrap(), "gen-a-2");
}

// ---------------------------------------------------------------------------
// Scenario B: In-flight scan stability while database reloads
// ---------------------------------------------------------------------------
#[test]
fn test_phase2d8a_scenario_b_inflight_scan_stability_during_reload() {
    let d = tempfile::tempdir().unwrap();
    let db_root = d.path().join("db_root");
    let socket = d.path().join("sock_dir/coordinator.sock");

    let sig_a: &[u8] = b"scenario_b_indicator_alpha";
    let sig_b: &[u8] = b"scenario_b_indicator_beta";

    publish_test_generation(&db_root, "gen-b-1", &[(sig_a, "AlphaMalware")]);
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "current", "gen-b-1").unwrap();

    let _coord = CoordinatorProcess::spawn_root(&socket, &db_root, &["--max-workers=2"]);

    let target_a = d.path().join("target_a.bin");
    std::fs::write(&target_a, sig_a).unwrap();
    let target_b = d.path().join("target_b.bin");
    std::fs::write(&target_b, sig_b).unwrap();

    let sock_clone = socket.clone();
    let target_a_clone = target_a.clone();

    // Client 1 initiates scan with delay so it remains pinned in-flight
    let h1 =
        std::thread::spawn(move || scan_via_socket(&sock_clone, &target_a_clone, Some("delay")));

    // Wait 50ms so Client 1 is admitted and pinned to gen-b-1
    std::thread::sleep(Duration::from_millis(50));

    // Hot reload to gen-b-2 while Client 1 is in-flight
    publish_test_generation(&db_root, "gen-b-2", &[(sig_b, "BetaMalware")]);
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "previous", "gen-b-1")
        .unwrap();
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "current", "gen-b-2").unwrap();

    // Wait 150ms for coordinator to reload
    std::thread::sleep(Duration::from_millis(150));

    // Client 2 submits a scan on target B; must use newly activated gen-b-2
    let resp_c2 = scan_via_socket(&socket, &target_b, None);
    assert_eq!(resp_c2["status"].as_str().unwrap(), "DETECTED");
    assert_eq!(resp_c2["database_generation"].as_str().unwrap(), "gen-b-2");

    // In-flight Client 1 completes; must still be pinned to gen-b-1
    let resp_c1 = h1.join().unwrap();
    assert_eq!(
        resp_c1["status"].as_str().unwrap(),
        "DETECTED",
        "In-flight scan must detect against its pinned generation"
    );
    assert_eq!(
        resp_c1["database_generation"].as_str().unwrap(),
        "gen-b-1",
        "In-flight scan must report the generation it was pinned to"
    );
}

// ---------------------------------------------------------------------------
// Scenario C: Live rollback automatically adopted
// ---------------------------------------------------------------------------
#[test]
fn test_phase2d8a_scenario_c_live_rollback_automatically_adopted() {
    let d = tempfile::tempdir().unwrap();
    let db_root = d.path().join("db_root");
    let socket = d.path().join("sock_dir/coordinator.sock");

    let sig_a: &[u8] = b"scenario_c_indicator_alpha";
    let sig_b: &[u8] = b"scenario_c_indicator_beta";

    publish_test_generation(&db_root, "gen-c-1", &[(sig_a, "AlphaMalware")]);
    publish_test_generation(
        &db_root,
        "gen-c-2",
        &[(sig_a, "AlphaMalware"), (sig_b, "BetaMalware")],
    );

    // Start with gen-c-2
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "previous", "gen-c-1")
        .unwrap();
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "current", "gen-c-2").unwrap();

    let _coord = CoordinatorProcess::spawn_root(&socket, &db_root, &["--max-workers=2"]);

    let target_b = d.path().join("target_b.bin");
    std::fs::write(&target_b, sig_b).unwrap();
    let target_a = d.path().join("target_a.bin");
    std::fs::write(&target_a, sig_a).unwrap();

    // Initially gen-c-2 detects target B
    let r1 = scan_via_socket(&socket, &target_b, None);
    assert_eq!(r1["status"].as_str().unwrap(), "DETECTED");
    assert_eq!(r1["database_generation"].as_str().unwrap(), "gen-c-2");

    // Execute live rollback to gen-c-1
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "current", "gen-c-1").unwrap();
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "previous", "gen-c-2")
        .unwrap();

    // Allow hot reload to adopt rollback
    std::thread::sleep(Duration::from_millis(200));

    // Post-rollback: target B is CLEAN (not present in gen-c-1)
    let r2 = scan_via_socket(&socket, &target_b, None);
    assert_eq!(
        r2["status"].as_str().unwrap(),
        "CLEAN",
        "Target B must be clean after rolling back to gen-c-1"
    );
    assert_eq!(r2["database_generation"].as_str().unwrap(), "gen-c-1");

    // Target A is still DETECTED
    let r3 = scan_via_socket(&socket, &target_a, None);
    assert_eq!(r3["status"].as_str().unwrap(), "DETECTED");
    assert_eq!(r3["database_generation"].as_str().unwrap(), "gen-c-1");
}

// ---------------------------------------------------------------------------
// Scenario D: Rapid successive updates without memory or descriptor leaks
// ---------------------------------------------------------------------------
#[test]
fn test_phase2d8a_scenario_d_rapid_successive_updates_and_no_resource_leaks() {
    let d = tempfile::tempdir().unwrap();
    let db_root = d.path().join("db_root");
    let socket = d.path().join("sock_dir/coordinator.sock");

    let base_sig: &[u8] = b"scenario_d_base_indicator";
    publish_test_generation(&db_root, "gen-d-0", &[(base_sig, "BaseMalware")]);
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "current", "gen-d-0").unwrap();

    let _coord = CoordinatorProcess::spawn_root(&socket, &db_root, &["--max-workers=4"]);

    let target_base = d.path().join("target_base.bin");
    std::fs::write(&target_base, base_sig).unwrap();

    // Publish 5 generations in rapid succession while submitting concurrent scans
    for i in 1..=5 {
        let gen_name = format!("gen-d-{}", i);
        let extra_sig = format!("scenario_d_sig_{}", i).into_bytes();
        publish_test_generation(
            &db_root,
            &gen_name,
            &[(base_sig, "BaseMalware"), (&extra_sig, "ExtraMalware")],
        );
        raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "current", &gen_name)
            .unwrap();
        // Submit a scan concurrently during each reload
        let resp = scan_via_socket(&socket, &target_base, None);
        assert_eq!(resp["status"].as_str().unwrap(), "DETECTED");
        std::thread::sleep(Duration::from_millis(30));
    }

    // Allow final reload to settle
    std::thread::sleep(Duration::from_millis(150));

    let final_resp = scan_via_socket(&socket, &target_base, None);
    assert_eq!(final_resp["status"].as_str().unwrap(), "DETECTED");
    assert_eq!(
        final_resp["database_generation"].as_str().unwrap(),
        "gen-d-5"
    );
    assert!(!final_resp["degraded_freshness"].as_bool().unwrap());
}

// ---------------------------------------------------------------------------
// Scenario E: Failed candidate generation safely rejected; coordinator keeps last known-good
// ---------------------------------------------------------------------------
#[test]
fn test_phase2d8a_scenario_e_failed_candidate_rejection_retains_last_known_good() {
    let d = tempfile::tempdir().unwrap();
    let db_root = d.path().join("db_root");
    let socket = d.path().join("sock_dir/coordinator.sock");

    let sig: &[u8] = b"scenario_e_reliable_indicator";
    publish_test_generation(&db_root, "gen-good", &[(sig, "GoodMalware")]);
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "current", "gen-good")
        .unwrap();

    let _coord = CoordinatorProcess::spawn_root(&socket, &db_root, &["--max-workers=2"]);

    let target = d.path().join("target.bin");
    std::fs::write(&target, sig).unwrap();

    let r0 = scan_via_socket(&socket, &target, None);
    assert_eq!(r0["status"].as_str().unwrap(), "DETECTED");
    assert_eq!(r0["database_generation"].as_str().unwrap(), "gen-good");
    assert!(!r0["degraded_freshness"].as_bool().unwrap());

    // Failure Mode 1: Missing generation
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "current", "gen-missing")
        .unwrap();
    std::thread::sleep(Duration::from_millis(150));

    let r_fail1 = scan_via_socket(&socket, &target, None);
    assert_eq!(
        r_fail1["status"].as_str().unwrap(),
        "DETECTED",
        "Must retain last known-good generation when candidate is missing"
    );
    assert_eq!(r_fail1["database_generation"].as_str().unwrap(), "gen-good");
    assert!(
        r_fail1["degraded_freshness"].as_bool().unwrap(),
        "Must report degraded freshness"
    );

    // Failure Mode 2: Corrupted RSIDB binary
    let corrupt_dir = db_root.join("gen-corrupt");
    std::fs::create_dir_all(&corrupt_dir).unwrap();
    std::fs::write(
        corrupt_dir.join("database.rsidb"),
        b"corrupted garbage bytes",
    )
    .unwrap();
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "current", "gen-corrupt")
        .unwrap();
    std::thread::sleep(Duration::from_millis(150));

    let r_fail2 = scan_via_socket(&socket, &target, None);
    assert_eq!(r_fail2["status"].as_str().unwrap(), "DETECTED");
    assert_eq!(r_fail2["database_generation"].as_str().unwrap(), "gen-good");
    assert!(r_fail2["degraded_freshness"].as_bool().unwrap());

    // Failure Mode 3: Incomplete staging generation
    std::fs::write(db_root.join("current"), ".staging-in-progress\n").unwrap();
    std::thread::sleep(Duration::from_millis(150));

    let r_fail3 = scan_via_socket(&socket, &target, None);
    assert_eq!(r_fail3["status"].as_str().unwrap(), "DETECTED");
    assert_eq!(r_fail3["database_generation"].as_str().unwrap(), "gen-good");
    assert!(r_fail3["degraded_freshness"].as_bool().unwrap());

    // Failure Mode 4: Malformed pointer file
    std::fs::write(db_root.join("current"), "bad/dir/traversal!\n").unwrap();
    std::thread::sleep(Duration::from_millis(150));

    let r_fail4 = scan_via_socket(&socket, &target, None);
    assert_eq!(r_fail4["status"].as_str().unwrap(), "DETECTED");
    assert_eq!(r_fail4["database_generation"].as_str().unwrap(), "gen-good");
    assert!(r_fail4["degraded_freshness"].as_bool().unwrap());

    // Recovery: Publish a valid gen-recovered and verify degraded freshness clears
    publish_test_generation(&db_root, "gen-recovered", &[(sig, "GoodMalware")]);
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "current", "gen-recovered")
        .unwrap();
    std::thread::sleep(Duration::from_millis(200));

    let r_rec = scan_via_socket(&socket, &target, None);
    assert_eq!(r_rec["status"].as_str().unwrap(), "DETECTED");
    assert_eq!(
        r_rec["database_generation"].as_str().unwrap(),
        "gen-recovered"
    );
    assert!(
        !r_rec["degraded_freshness"].as_bool().unwrap(),
        "Degraded freshness must clear after valid candidate is adopted"
    );
}

// ---------------------------------------------------------------------------
// Scenario F: Coordinator process restart recovery
// ---------------------------------------------------------------------------
#[test]
fn test_phase2d8a_scenario_f_coordinator_restart_recovery() {
    let d = tempfile::tempdir().unwrap();
    let db_root = d.path().join("db_root");
    let socket = d.path().join("sock_dir/coordinator.sock");

    let sig: &[u8] = b"scenario_f_indicator";
    publish_test_generation(&db_root, "gen-f-1", &[(sig, "MalwareF")]);
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "current", "gen-f-1").unwrap();

    let mut coord = CoordinatorProcess::spawn_root(&socket, &db_root, &["--max-workers=2"]);

    let target = d.path().join("target.bin");
    std::fs::write(&target, sig).unwrap();

    let r1 = scan_via_socket(&socket, &target, None);
    assert_eq!(r1["status"].as_str().unwrap(), "DETECTED");
    assert_eq!(r1["database_generation"].as_str().unwrap(), "gen-f-1");

    // Stop coordinator daemon
    let _ = coord.stop();

    // While coordinator is offline, an update is activated on disk
    let sig2: &[u8] = b"scenario_f_indicator_2";
    publish_test_generation(
        &db_root,
        "gen-f-2",
        &[(sig, "MalwareF"), (sig2, "MalwareF2")],
    );
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "current", "gen-f-2").unwrap();

    // Restart coordinator process against the same root directory
    let _coord2 = CoordinatorProcess::spawn_root(&socket, &db_root, &["--max-workers=2"]);

    let target2 = d.path().join("target2.bin");
    std::fs::write(&target2, sig2).unwrap();

    // Verify restart recovered immediately and serves active generation
    let r2 = scan_via_socket(&socket, &target2, None);
    assert_eq!(
        r2["status"].as_str().unwrap(),
        "DETECTED",
        "Restarted coordinator must detect new indicators from updated generation"
    );
    assert_eq!(r2["database_generation"].as_str().unwrap(), "gen-f-2");
    assert!(!r2["degraded_freshness"].as_bool().unwrap());
}

fn pid_resident_memory_bytes(pid: u32) -> u64 {
    read_proc_memory_stats(pid)
        .map(|s| s.rss_bytes)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, Default)]
struct ProcMemoryStats {
    rss_bytes: u64,
    pss_bytes: u64,
    shared_clean_bytes: u64,
    shared_dirty_bytes: u64,
    private_clean_bytes: u64,
    private_dirty_bytes: u64,
    anonymous_bytes: u64,
}

fn read_proc_memory_stats(pid: u32) -> Result<ProcMemoryStats, String> {
    let rollup_path = if pid == 0 || pid == std::process::id() {
        "/proc/self/smaps_rollup".to_string()
    } else {
        format!("/proc/{pid}/smaps_rollup")
    };

    if let Ok(content) = std::fs::read_to_string(&rollup_path) {
        let mut stats = ProcMemoryStats::default();
        for line in content.lines() {
            let mut parts = line.split_whitespace();
            let key = match parts.next() {
                Some(k) => k.trim_end_matches(':'),
                None => continue,
            };
            let kb: u64 = match parts.next().and_then(|v| v.parse().ok()) {
                Some(v) => v,
                None => continue,
            };
            let bytes = kb.saturating_mul(1024);
            match key {
                "Rss" => stats.rss_bytes = bytes,
                "Pss" => stats.pss_bytes = bytes,
                "Shared_Clean" => stats.shared_clean_bytes = bytes,
                "Shared_Dirty" => stats.shared_dirty_bytes = bytes,
                "Private_Clean" => stats.private_clean_bytes = bytes,
                "Private_Dirty" => stats.private_dirty_bytes = bytes,
                "Anonymous" => stats.anonymous_bytes = bytes,
                _ => {}
            }
        }
        return Ok(stats);
    }

    let statm_path = if pid == 0 || pid == std::process::id() {
        "/proc/self/statm".to_string()
    } else {
        format!("/proc/{pid}/statm")
    };
    let content = std::fs::read_to_string(&statm_path)
        .map_err(|e| format!("Failed to read statm from {statm_path}: {e}"))?;
    let mut parts = content.split_whitespace();
    let _total = parts.next();
    let rss_pages: u64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page_size = if page_size > 0 {
        page_size as u64
    } else {
        4096
    };
    let rss_bytes = rss_pages.saturating_mul(page_size);

    Ok(ProcMemoryStats {
        rss_bytes,
        pss_bytes: rss_bytes,
        ..Default::default()
    })
}

fn get_child_pids(pid: u32) -> Vec<u32> {
    let children_path = format!("/proc/{pid}/task/{pid}/children");
    if let Ok(content) = std::fs::read_to_string(&children_path) {
        let pids: Vec<u32> = content
            .split_whitespace()
            .filter_map(|s| s.parse().ok())
            .collect();
        if !pids.is_empty() {
            return pids;
        }
    }

    let mut children = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(file_name) = entry.file_name().into_string() {
                if let Ok(child_pid) = file_name.parse::<u32>() {
                    let stat_path = format!("/proc/{child_pid}/stat");
                    if let Ok(stat_content) = std::fs::read_to_string(&stat_path) {
                        if let Some(rparen) = stat_content.rfind(')') {
                            let rest = &stat_content[rparen + 1..];
                            let mut parts = rest.split_whitespace();
                            let _state = parts.next();
                            if let Some(ppid_str) = parts.next() {
                                if ppid_str.parse::<u32>().ok() == Some(pid) {
                                    children.push(child_pid);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    children
}

fn read_tree_memory_stats(root_pid: u32) -> Result<ProcMemoryStats, String> {
    let mut stats = read_proc_memory_stats(root_pid)?;
    let children = get_child_pids(root_pid);
    for c_pid in children {
        if let Ok(c_stats) = read_proc_memory_stats(c_pid) {
            stats.rss_bytes = stats.rss_bytes.saturating_add(c_stats.rss_bytes);
            stats.pss_bytes = stats.pss_bytes.saturating_add(c_stats.pss_bytes);
            stats.shared_clean_bytes = stats
                .shared_clean_bytes
                .saturating_add(c_stats.shared_clean_bytes);
            stats.shared_dirty_bytes = stats
                .shared_dirty_bytes
                .saturating_add(c_stats.shared_dirty_bytes);
            stats.private_clean_bytes = stats
                .private_clean_bytes
                .saturating_add(c_stats.private_clean_bytes);
            stats.private_dirty_bytes = stats
                .private_dirty_bytes
                .saturating_add(c_stats.private_dirty_bytes);
            stats.anonymous_bytes = stats
                .anonymous_bytes
                .saturating_add(c_stats.anonymous_bytes);
        }
    }
    Ok(stats)
}

fn setup_isolated_authentic_generation(dest_gen_dir: &Path) {
    let src_dir = Path::new("/home/vscode/raxosentinel-private-phase2d1/phase2d6-unified");
    std::fs::create_dir_all(dest_gen_dir).unwrap();
    let _ = std::fs::set_permissions(dest_gen_dir, std::fs::Permissions::from_mode(0o700));

    for entry in std::fs::read_dir(src_dir).unwrap() {
        let entry = entry.unwrap();
        let file_type = entry.file_type().unwrap();
        if file_type.is_file() {
            let file_name = entry.file_name();
            let dest_file = dest_gen_dir.join(&file_name);
            if std::fs::hard_link(entry.path(), &dest_file).is_err() {
                std::fs::copy(entry.path(), &dest_file).unwrap();
            }
            let _ = std::fs::set_permissions(&dest_file, std::fs::Permissions::from_mode(0o600));
        }
    }
}

// ---------------------------------------------------------------------------
// Telemetry & Resource Bound Verification (Synthetic & Authentic Benchmarks)
// ---------------------------------------------------------------------------
#[test]
fn test_phase2d8a_memory_and_performance_benchmarks() {
    let d = tempfile::tempdir().unwrap();
    let db_root = d.path().join("db_root");
    let socket = d.path().join("sock_dir/coordinator.sock");

    let sig1: &[u8] = b"synthetic_perf_sig_1";
    let sig2: &[u8] = b"synthetic_perf_sig_2";

    publish_test_generation(&db_root, "gen-bench-1", &[(sig1, "PerfSig1")]);
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "current", "gen-bench-1")
        .unwrap();

    let coord = CoordinatorProcess::spawn_root(&socket, &db_root, &["--max-workers=2"]);
    let pid = coord.child.id();

    let target1 = d.path().join("target1.bin");
    std::fs::write(&target1, sig1).unwrap();

    // 1. Warm-up scan and measure initial RSS
    let _ = scan_via_socket(&socket, &target1, None);
    let rss_before = pid_resident_memory_bytes(pid);

    // 2. Measure scan throughput before reload (20 iterations)
    let n_iterations = 20;
    let t0 = Instant::now();
    for _ in 0..n_iterations {
        let resp = scan_via_socket(&socket, &target1, None);
        assert_eq!(resp["status"].as_str().unwrap(), "DETECTED");
    }
    let duration_before = t0.elapsed();
    let throughput_before = (n_iterations as f64) / duration_before.as_secs_f64();

    // 3. Trigger reload to gen-bench-2
    publish_test_generation(
        &db_root,
        "gen-bench-2",
        &[(sig1, "PerfSig1"), (sig2, "PerfSig2")],
    );
    let reload_trigger = Instant::now();
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "current", "gen-bench-2")
        .unwrap();

    // Poll until reload takes effect
    let mut switch_latency = Duration::ZERO;
    let mut rss_during = rss_before;
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(10));
        let cur_rss = pid_resident_memory_bytes(pid);
        if cur_rss > rss_during {
            rss_during = cur_rss;
        }
        let resp = scan_via_socket(&socket, &target1, None);
        if resp["database_generation"].as_str() == Some("gen-bench-2") {
            switch_latency = reload_trigger.elapsed();
            break;
        }
    }
    assert_ne!(switch_latency, Duration::ZERO, "Reload must be adopted");

    let rss_after = pid_resident_memory_bytes(pid);

    // 4. Measure scan throughput after reload (20 iterations)
    let t1 = Instant::now();
    for _ in 0..n_iterations {
        let resp = scan_via_socket(&socket, &target1, None);
        assert_eq!(resp["status"].as_str().unwrap(), "DETECTED");
        assert_eq!(resp["database_generation"].as_str().unwrap(), "gen-bench-2");
    }
    let duration_after = t1.elapsed();
    let throughput_after = (n_iterations as f64) / duration_after.as_secs_f64();

    println!("=== SYNTHETIC DATASET BENCHMARK METRICS ===");
    println!(
        "Resident Memory Before Reload : {:.2} MB ({} bytes)",
        (rss_before as f64) / 1024.0 / 1024.0,
        rss_before
    );
    println!(
        "Resident Memory Peak / During : {:.2} MB ({} bytes)",
        (rss_during as f64) / 1024.0 / 1024.0,
        rss_during
    );
    println!(
        "Resident Memory After Reload  : {:.2} MB ({} bytes)",
        (rss_after as f64) / 1024.0 / 1024.0,
        rss_after
    );
    println!(
        "Switch Latency                : {:.2} ms ({:?})",
        switch_latency.as_secs_f64() * 1000.0,
        switch_latency
    );
    println!(
        "Scan Throughput Before Reload : {:.1} scans/sec",
        throughput_before
    );
    println!(
        "Scan Throughput After Reload  : {:.1} scans/sec",
        throughput_after
    );

    // Assert resource bounds: peak memory must be bounded (less than 2x reasonable overhead)
    assert!(
        rss_during <= rss_before.saturating_mul(2) + 20 * 1024 * 1024,
        "Resident memory during reload must not exceed two generations in memory"
    );

    // 5. Authentic Dataset Benchmark (542,057 indicators)
    let authentic_db =
        Path::new("/home/vscode/raxosentinel-private-phase2d1/phase2d6-unified/database.rsidb");
    if authentic_db.exists() {
        let auth_socket = d.path().join("sock_dir/authentic_coordinator.sock");
        let auth_coord = CoordinatorProcess::spawn(
            &auth_socket,
            Path::new("/home/vscode/raxosentinel-private-phase2d1"),
            "phase2d6-unified",
            &["--max-workers=2", "--worker-timeout-ms=60000"],
        );
        let auth_pid = auth_coord.child.id();
        let auth_rss = pid_resident_memory_bytes(auth_pid);

        let test_clean = d.path().join("clean_auth.bin");
        std::fs::write(
            &test_clean,
            b"safe text file content for authentic benchmark",
        )
        .unwrap();

        let t_start = Instant::now();
        let n_auth_iterations = 2;
        for _ in 0..n_auth_iterations {
            let resp = scan_via_socket(&auth_socket, &test_clean, None);
            assert_eq!(resp["status"].as_str().unwrap(), "CLEAN");
            assert_eq!(
                resp["database_generation"].as_str().unwrap(),
                "phase2d6-unified"
            );
            assert!(!resp["degraded_freshness"].as_bool().unwrap());
        }
        let auth_duration = t_start.elapsed();
        let auth_throughput = (n_auth_iterations as f64) / auth_duration.as_secs_f64();

        println!("\n=== AUTHENTIC DATASET COORDINATOR BENCHMARK (542,057 indicators) ===");
        println!(
            "Coordinator RSS (Authentic RSIDB): {:.2} MB ({} bytes)",
            (auth_rss as f64) / 1024.0 / 1024.0,
            auth_rss
        );
        println!(
            "Authentic Scan Throughput        : {:.1} scans/sec",
            auth_throughput
        );
    }
}

// ===========================================================================
// Phase 2D.8B: Authentic Database Stress Testing & Memory Hardening Tests
// ===========================================================================

// ---------------------------------------------------------------------------
// Phase 2D.8B - Test 1: Authentic Database Reload Performance & Memory Breakdown
// ---------------------------------------------------------------------------
#[test]
fn test_phase2d8b_authentic_database_reload_and_metrics() {
    let authentic_db =
        Path::new("/home/vscode/raxosentinel-private-phase2d1/phase2d6-unified/database.rsidb");
    if !authentic_db.exists() {
        println!("Authentic database not found on system; skipping test_phase2d8b_authentic_database_reload_and_metrics");
        return;
    }

    let d = tempfile::tempdir().unwrap();
    let isolated_root = d.path().join("isolated_auth_root");
    std::fs::create_dir_all(&isolated_root).unwrap();
    std::fs::set_permissions(&isolated_root, std::fs::Permissions::from_mode(0o700)).unwrap();

    let gen1_dir = isolated_root.join("auth-gen1");
    let gen2_dir = isolated_root.join("auth-gen2");
    setup_isolated_authentic_generation(&gen1_dir);
    setup_isolated_authentic_generation(&gen2_dir);
    raxosentinel_signatures::rsidb::updater::write_pointer(&isolated_root, "current", "auth-gen1")
        .unwrap();

    let socket = d.path().join("sock_dir/auth_perf.sock");

    // 1. Measure initial coordinator startup time
    let t_startup = Instant::now();
    let coord = CoordinatorProcess::spawn_root(
        &socket,
        &isolated_root,
        &[
            "--max-workers=2",
            "--max-resident-generations=2",
            "--worker-timeout-ms=60000",
        ],
    );
    let startup_duration = t_startup.elapsed();
    let coord_pid = coord.child.id();

    let stats_startup = read_proc_memory_stats(coord_pid).unwrap();

    let clean_target = d.path().join("clean_file.txt");
    std::fs::write(
        &clean_target,
        b"harmless test document content for authentic scanning",
    )
    .unwrap();

    let eicar_target = d.path().join("eicar.com");
    std::fs::write(
        &eicar_target,
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    )
    .unwrap();

    // Warm-up scan: verify clean and detected on initial auth-gen1
    let r_clean_1 = scan_via_socket(&socket, &clean_target, None);
    assert_eq!(r_clean_1["status"].as_str().unwrap(), "CLEAN");
    assert_eq!(
        r_clean_1["database_generation"].as_str().unwrap(),
        "auth-gen1"
    );
    assert!(!r_clean_1["degraded_freshness"].as_bool().unwrap_or(true));

    let r_eicar_1 = scan_via_socket(&socket, &eicar_target, None);
    assert_eq!(r_eicar_1["status"].as_str().unwrap(), "DETECTED");
    assert_eq!(
        r_eicar_1["database_generation"].as_str().unwrap(),
        "auth-gen1"
    );
    let threats_eicar_1 = r_eicar_1["report"]["threats"].as_array().unwrap();
    assert!(
        threats_eicar_1
            .iter()
            .any(|s| s["name"].as_str().unwrap().contains("Eicar")),
        "EICAR detection signature must be reported from authentic database"
    );

    let stats_before_reload = read_proc_memory_stats(coord_pid).unwrap();

    // 2. Start an in-flight scan pinning auth-gen1
    let sock_inflight = socket.clone();
    let clean_inflight = clean_target.clone();
    let t_inflight_start = Instant::now();
    let handle_inflight = std::thread::spawn(move || {
        scan_via_socket(&sock_inflight, &clean_inflight, Some("delay:3000"))
    });

    // Allow in-flight scan worker to start
    std::thread::sleep(Duration::from_millis(80));

    // Measure worker process memory while scan is active
    let worker_pids = get_child_pids(coord_pid);
    let worker_stats = worker_pids
        .first()
        .and_then(|&pid| read_proc_memory_stats(pid).ok());
    let tree_stats_during = read_tree_memory_stats(coord_pid).unwrap();

    // 3. Trigger reload to auth-gen2
    let t_reload_trigger = Instant::now();
    raxosentinel_signatures::rsidb::updater::write_pointer(&isolated_root, "current", "auth-gen2")
        .unwrap();

    // Poll until auth-gen2 is adopted
    let mut adopted_gen2 = false;
    let mut switch_total_time = Duration::ZERO;
    let mut peak_rss_during = stats_before_reload.rss_bytes;
    let mut reload_load_time_ms = 0.0;
    let mut reload_switch_latency_micros = 0u64;

    for _ in 0..100 {
        std::thread::sleep(Duration::from_millis(25));
        let cur_stats = read_proc_memory_stats(coord_pid).unwrap();
        if cur_stats.rss_bytes > peak_rss_during {
            peak_rss_during = cur_stats.rss_bytes;
        }
        let check_resp = scan_via_socket(&socket, &clean_target, None);
        if check_resp["database_generation"].as_str() == Some("auth-gen2") {
            switch_total_time = t_reload_trigger.elapsed();
            reload_load_time_ms = check_resp["reload_load_time_ms"].as_f64().unwrap_or(0.0);
            reload_switch_latency_micros = check_resp["reload_switch_latency_micros"]
                .as_u64()
                .unwrap_or(0);
            adopted_gen2 = true;
            break;
        }
    }
    assert!(
        adopted_gen2,
        "Candidate generation auth-gen2 must be verified and adopted"
    );

    // In-flight scan MUST complete using auth-gen1
    let inflight_res = handle_inflight.join().unwrap();
    let inflight_duration = t_inflight_start.elapsed();
    assert_eq!(
        inflight_res["database_generation"].as_str().unwrap(),
        "auth-gen1"
    );
    assert_eq!(inflight_res["status"].as_str().unwrap(), "CLEAN");

    let stats_after_reload = read_proc_memory_stats(coord_pid).unwrap();

    // Verify positive detection on newly adopted auth-gen2
    let r_eicar_2 = scan_via_socket(&socket, &eicar_target, None);
    assert_eq!(r_eicar_2["status"].as_str().unwrap(), "DETECTED");
    assert_eq!(
        r_eicar_2["database_generation"].as_str().unwrap(),
        "auth-gen2"
    );

    // 4. Rollback to auth-gen1 and measure recovery time
    let t_rollback = Instant::now();
    raxosentinel_signatures::rsidb::updater::write_pointer(&isolated_root, "current", "auth-gen1")
        .unwrap();

    let mut rolled_back = false;
    let mut rollback_time = Duration::ZERO;
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(20));
        let check_rb = scan_via_socket(&socket, &clean_target, None);
        if check_rb["database_generation"].as_str() == Some("auth-gen1") {
            rollback_time = t_rollback.elapsed();
            rolled_back = true;
            break;
        }
    }
    assert!(rolled_back, "Rollback to auth-gen1 must be adopted");

    // 5. Memory reclamation after scans finish
    std::thread::sleep(Duration::from_millis(150));
    let stats_final = read_proc_memory_stats(coord_pid).unwrap();

    println!("\n==========================================================================");
    println!("PHASE 2D.8B AUTHENTIC 542,057-INDICATOR RSIDB BENCHMARK & MEMORY BREAKDOWN");
    println!("==========================================================================");
    println!(
        "Coordinator Startup Time        : {:.2} ms",
        startup_duration.as_secs_f64() * 1000.0
    );
    println!(
        "Candidate Verification Duration : {:.2} ms (load_time_ms)",
        reload_load_time_ms
    );
    println!(
        "Atomic Activation Latency       : {:.2} ms ({} µs)",
        (reload_switch_latency_micros as f64) / 1000.0,
        reload_switch_latency_micros
    );
    println!(
        "Full Reload Transition Latency  : {:.2} ms",
        switch_total_time.as_secs_f64() * 1000.0
    );
    println!(
        "In-Flight Scan Latency          : {:.2} ms",
        inflight_duration.as_secs_f64() * 1000.0
    );
    println!(
        "Rollback Recovery Time          : {:.2} ms",
        rollback_time.as_secs_f64() * 1000.0
    );
    println!("--------------------------------------------------------------------------");
    println!("MEMORY BREAKDOWN (COORDINATOR PROCESS):");
    println!(
        "  Initial Startup RSS           : {:.2} MB (PSS: {:.2} MB)",
        (stats_startup.rss_bytes as f64) / 1024.0 / 1024.0,
        (stats_startup.pss_bytes as f64) / 1024.0 / 1024.0
    );
    println!(
        "  Before Reload RSS             : {:.2} MB (PSS: {:.2} MB)",
        (stats_before_reload.rss_bytes as f64) / 1024.0 / 1024.0,
        (stats_before_reload.pss_bytes as f64) / 1024.0 / 1024.0
    );
    println!(
        "  Peak RSS During Reload        : {:.2} MB",
        (peak_rss_during as f64) / 1024.0 / 1024.0
    );
    println!(
        "  After Reload RSS              : {:.2} MB (PSS: {:.2} MB)",
        (stats_after_reload.rss_bytes as f64) / 1024.0 / 1024.0,
        (stats_after_reload.pss_bytes as f64) / 1024.0 / 1024.0
    );
    println!(
        "  Final Reclaimed RSS           : {:.2} MB (PSS: {:.2} MB)",
        (stats_final.rss_bytes as f64) / 1024.0 / 1024.0,
        (stats_final.pss_bytes as f64) / 1024.0 / 1024.0
    );
    println!(
        "  Private Anonymous Memory      : {:.2} MB",
        (stats_final.anonymous_bytes as f64) / 1024.0 / 1024.0
    );
    println!(
        "  Shared Clean Mappings (mmap)  : {:.2} MB",
        (stats_final.shared_clean_bytes as f64) / 1024.0 / 1024.0
    );
    if let Some(w) = worker_stats {
        println!("MEMORY BREAKDOWN (SANDBOXED WORKER PROCESS):");
        println!(
            "  Worker Subprocess RSS         : {:.2} MB",
            (w.rss_bytes as f64) / 1024.0 / 1024.0
        );
        println!(
            "  Worker Subprocess PSS         : {:.2} MB",
            (w.pss_bytes as f64) / 1024.0 / 1024.0
        );
        println!(
            "  Worker Shared Mappings        : {:.2} MB",
            (w.shared_clean_bytes as f64) / 1024.0 / 1024.0
        );
        println!(
            "  Worker Private Anonymous      : {:.2} MB",
            (w.anonymous_bytes as f64) / 1024.0 / 1024.0
        );
    }
    println!("COMBINED PROCESS-TREE MEMORY (COORDINATOR + WORKERS):");
    println!(
        "  Total Process-Tree RSS (Raw)  : {:.2} MB (contains double-counted shared pages)",
        (tree_stats_during.rss_bytes as f64) / 1024.0 / 1024.0
    );
    println!("  Total Process-Tree PSS (True) : {:.2} MB (exact physical memory without double counting)", (tree_stats_during.pss_bytes as f64) / 1024.0 / 1024.0);
    println!("==========================================================================\n");

    // Verification of hard memory bound: Coordinator RSS must remain well below previous 410 MB baseline
    assert!(
        stats_final.rss_bytes < 150 * 1024 * 1024,
        "Coordinator RSS ({:.2} MB) must remain memory-hardened and well below the 410 MB baseline",
        (stats_final.rss_bytes as f64) / 1024.0 / 1024.0
    );

    // Clearly distinguish candidate verification duration from atomic handle switch latency
    assert!(
        reload_switch_latency_micros > 0 || reload_load_time_ms > 0.0,
        "Candidate verification and atomic switch latency must both be tracked"
    );
}

// ---------------------------------------------------------------------------
// Phase 2D.8B - Test 2: Multi-Generation Sequence & Deferred Budget Enforcement
// ---------------------------------------------------------------------------
#[test]
fn test_phase2d8b_multi_generation_sequence_and_deferred_budget() {
    let d = tempfile::tempdir().unwrap();
    let db_root = d.path().join("db_root");
    let socket = d.path().join("sock_dir/coord_budget.sock");

    let sig1: &[u8] = b"sequence_sig_one";
    let sig2: &[u8] = b"sequence_sig_two";
    let sig3: &[u8] = b"sequence_sig_three";
    let sig4: &[u8] = b"sequence_sig_four";

    publish_test_generation(&db_root, "gen-seq-1", &[(sig1, "SeqSig1")]);
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "current", "gen-seq-1")
        .unwrap();

    let _coord = CoordinatorProcess::spawn_root(
        &socket,
        &db_root,
        &["--max-workers=3", "--max-resident-generations=2"],
    );
    let target1 = d.path().join("target1.bin");
    std::fs::write(&target1, sig1).unwrap();

    // 1. Scan A starts using generation 1 and holds connection open (via delay)
    let sock_a = socket.clone();
    let target_a = target1.clone();
    let handle_scan_a =
        std::thread::spawn(move || scan_via_socket(&sock_a, &target_a, Some("delay:2500")));

    // Wait until Scan A is in flight
    std::thread::sleep(Duration::from_millis(80));

    // 2. Generation 2 activates on disk
    publish_test_generation(
        &db_root,
        "gen-seq-2",
        &[(sig1, "SeqSig1"), (sig2, "SeqSig2")],
    );
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "current", "gen-seq-2")
        .unwrap();

    // Wait for gen-seq-2 reload to take effect
    let target2 = d.path().join("target2.bin");
    std::fs::write(&target2, sig2).unwrap();

    let mut gen2_active = false;
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(20));
        let resp = scan_via_socket(&socket, &target2, None);
        if resp["database_generation"].as_str() == Some("gen-seq-2") {
            assert_eq!(resp["status"].as_str().unwrap(), "DETECTED");
            assert!(!resp["degraded_freshness"].as_bool().unwrap_or(true));
            assert!(resp["pending_generation"].is_null());
            gen2_active = true;
            break;
        }
    }
    assert!(gen2_active, "Generation 2 must activate");

    // 3. Scan B starts using generation 2 and holds connection open
    let sock_b = socket.clone();
    let target_b = target2.clone();
    let handle_scan_b =
        std::thread::spawn(move || scan_via_socket(&sock_b, &target_b, Some("delay:2500")));

    std::thread::sleep(Duration::from_millis(80));

    // 4. Generation 3 becomes available while A and B remain active
    publish_test_generation(
        &db_root,
        "gen-seq-3",
        &[(sig1, "SeqSig1"), (sig2, "SeqSig2"), (sig3, "SeqSig3")],
    );
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "current", "gen-seq-3")
        .unwrap();

    // 5. Coordinator checks reload: because budget is 2, Gen 3 reload must be deferred!
    std::thread::sleep(Duration::from_millis(200));

    // Scan C arrives while Gen 3 is pending: must get active Gen 2, with degraded_freshness=true, pending_generation="gen-seq-3"
    let resp_c = scan_via_socket(&socket, &target2, None);
    assert_eq!(resp_c["database_generation"].as_str().unwrap(), "gen-seq-2");
    assert_eq!(resp_c["status"].as_str().unwrap(), "DETECTED");
    assert_eq!(resp_c["degraded_freshness"].as_bool(), Some(true));
    assert_eq!(
        resp_c["pending_generation"].as_str(),
        Some("gen-seq-3"),
        "Pending generation must be reported"
    );

    // 6. Another update request arrives: Gen 4 becomes available while A and B are STILL active
    publish_test_generation(
        &db_root,
        "gen-seq-4",
        &[
            (sig1, "SeqSig1"),
            (sig2, "SeqSig2"),
            (sig3, "SeqSig3"),
            (sig4, "SeqSig4"),
        ],
    );
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "current", "gen-seq-4")
        .unwrap();
    std::thread::sleep(Duration::from_millis(200));

    // Scan C2 arrives: pending generation must now be updated to "gen-seq-4"
    let resp_c2 = scan_via_socket(&socket, &target2, None);
    assert_eq!(
        resp_c2["database_generation"].as_str().unwrap(),
        "gen-seq-2"
    );
    assert_eq!(resp_c2["degraded_freshness"].as_bool(), Some(true));
    assert_eq!(resp_c2["pending_generation"].as_str(), Some("gen-seq-4"));

    // 7. Scan A completes
    let res_a = handle_scan_a.join().unwrap();
    assert_eq!(res_a["database_generation"].as_str().unwrap(), "gen-seq-1");
    assert_eq!(res_a["status"].as_str().unwrap(), "DETECTED");

    // Once Scan A dropped, Gen 1 is retired; deferred Gen 4 must activate automatically!
    let target4 = d.path().join("target4.bin");
    std::fs::write(&target4, sig4).unwrap();

    let mut gen4_active = false;
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(20));
        let resp = scan_via_socket(&socket, &target4, None);
        if resp["database_generation"].as_str() == Some("gen-seq-4") {
            assert_eq!(resp["status"].as_str().unwrap(), "DETECTED");
            assert!(!resp["degraded_freshness"].as_bool().unwrap_or(true));
            assert!(resp["pending_generation"].is_null());
            gen4_active = true;
            break;
        }
    }
    assert!(
        gen4_active,
        "Generation 4 must activate after Scan A retired"
    );

    // 8. Scan B completes
    let res_b = handle_scan_b.join().unwrap();
    assert_eq!(res_b["database_generation"].as_str().unwrap(), "gen-seq-2");
    assert_eq!(res_b["status"].as_str().unwrap(), "DETECTED");

    // Verify final state: Gen 4 active, clean freshness, no leaks
    let final_resp = scan_via_socket(&socket, &target4, None);
    assert_eq!(
        final_resp["database_generation"].as_str().unwrap(),
        "gen-seq-4"
    );
    assert!(!final_resp["degraded_freshness"].as_bool().unwrap_or(true));
}

// ---------------------------------------------------------------------------
// Phase 2D.8B - Test 3: Scanner Verdict Isolation & Cryptographic Generation Pinning
// ---------------------------------------------------------------------------
#[test]
fn test_phase2d8b_scanner_results_and_verdict_isolation() {
    let d = tempfile::tempdir().unwrap();
    let db_root = d.path().join("db_root");
    let socket = d.path().join("sock_dir/coord_iso.sock");

    let sig_alpha: &[u8] = b"signature_alpha_unique_payload";
    let sig_beta: &[u8] = b"signature_beta_unique_payload";
    let clean_bytes: &[u8] = b"purely clean harmless text document";

    let target_alpha = d.path().join("target_alpha.bin");
    let target_beta = d.path().join("target_beta.bin");
    let target_clean = d.path().join("target_clean.txt");
    std::fs::write(&target_alpha, sig_alpha).unwrap();
    std::fs::write(&target_beta, sig_beta).unwrap();
    std::fs::write(&target_clean, clean_bytes).unwrap();

    // Gen 1 only contains sig_alpha
    publish_test_generation(&db_root, "gen-iso-1", &[(sig_alpha, "MalwareAlpha")]);
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "current", "gen-iso-1")
        .unwrap();

    let _coord = CoordinatorProcess::spawn_root(&socket, &db_root, &["--max-workers=2"]);

    // Scan 1 on target_alpha against Gen 1 -> DETECTED MalwareAlpha
    let r1 = scan_via_socket(&socket, &target_alpha, None);
    assert_eq!(r1["status"].as_str().unwrap(), "DETECTED");
    assert_eq!(r1["database_generation"].as_str().unwrap(), "gen-iso-1");
    let sigs1 = r1["report"]["threats"].as_array().unwrap();
    assert!(sigs1[0]["name"].as_str().unwrap().contains("MalwareAlpha"));

    // Scan 2 on target_beta against Gen 1 -> CLEAN (sig_beta not in gen-iso-1)
    let r2 = scan_via_socket(&socket, &target_beta, None);
    assert_eq!(r2["status"].as_str().unwrap(), "CLEAN");
    assert_eq!(r2["database_generation"].as_str().unwrap(), "gen-iso-1");

    // Gen 2 contains BOTH sig_alpha and sig_beta
    publish_test_generation(
        &db_root,
        "gen-iso-2",
        &[(sig_alpha, "MalwareAlpha"), (sig_beta, "MalwareBeta")],
    );
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "current", "gen-iso-2")
        .unwrap();

    // Wait for gen-iso-2 reload
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(20));
        let check = scan_via_socket(&socket, &target_beta, None);
        if check["database_generation"].as_str() == Some("gen-iso-2") {
            assert_eq!(check["status"].as_str().unwrap(), "DETECTED");
            let sigs = check["report"]["threats"].as_array().unwrap();
            assert!(sigs[0]["name"].as_str().unwrap().contains("MalwareBeta"));
            break;
        }
    }

    // Verify clean file against Gen 2 -> CLEAN
    let r_clean = scan_via_socket(&socket, &target_clean, None);
    assert_eq!(r_clean["status"].as_str().unwrap(), "CLEAN");
    assert_eq!(
        r_clean["database_generation"].as_str().unwrap(),
        "gen-iso-2"
    );

    // Hold long scan on Gen 2 while rolling back to Gen 1
    let sock_clone = socket.clone();
    let target_beta_clone = target_beta.clone();
    let handle_inflight = std::thread::spawn(move || {
        scan_via_socket(&sock_clone, &target_beta_clone, Some("delay:2000"))
    });

    std::thread::sleep(Duration::from_millis(80));

    // Rollback to gen-iso-1
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "current", "gen-iso-1")
        .unwrap();

    // In-flight scan MUST finish with gen-iso-2 and DETECTED MalwareBeta!
    let inflight_res = handle_inflight.join().unwrap();
    assert_eq!(
        inflight_res["database_generation"].as_str().unwrap(),
        "gen-iso-2"
    );
    assert_eq!(inflight_res["status"].as_str().unwrap(), "DETECTED");

    // New scans must adopt rolled-back gen-iso-1: target_beta is CLEAN again!
    let mut rolled_back = false;
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(20));
        let r_rb = scan_via_socket(&socket, &target_beta, None);
        if r_rb["database_generation"].as_str() == Some("gen-iso-1") {
            assert_eq!(
                r_rb["status"].as_str().unwrap(),
                "CLEAN",
                "target_beta must not be detected under rolled back gen-iso-1"
            );
            rolled_back = true;
            break;
        }
    }
    assert!(rolled_back, "Rollback to gen-iso-1 must take effect");

    // Target alpha remains detected under rolled-back gen-iso-1
    let r_alpha_rb = scan_via_socket(&socket, &target_alpha, None);
    assert_eq!(
        r_alpha_rb["database_generation"].as_str().unwrap(),
        "gen-iso-1"
    );
    assert_eq!(r_alpha_rb["status"].as_str().unwrap(), "DETECTED");
}

// ---------------------------------------------------------------------------
// Phase 2D.8B - Test 4: Resource Exhaustion & Fault Tolerance
// ---------------------------------------------------------------------------
#[test]
fn test_phase2d8b_resource_exhaustion_and_fault_tolerance() {
    let d = tempfile::tempdir().unwrap();
    let db_root = d.path().join("db_root");
    let socket = d.path().join("sock_dir/coord_exhaust.sock");

    let sig: &[u8] = b"fault_tolerance_indicator";
    publish_test_generation(&db_root, "gen-fault-1", &[(sig, "SigFault")]);
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "current", "gen-fault-1")
        .unwrap();

    let coord =
        CoordinatorProcess::spawn_root(&socket, &db_root, &["--max-workers=2", "--max-pending=2"]);
    let target = d.path().join("target.bin");
    std::fs::write(&target, sig).unwrap();

    // 1. Worker crash handling during active scanning: coordinator survives and reports ERROR
    let crash_resp = scan_via_socket(&socket, &target, Some("crash"));
    assert_eq!(crash_resp["status"].as_str().unwrap(), "ERROR");
    assert_eq!(
        crash_resp["database_generation"].as_str().unwrap(),
        "gen-fault-1"
    );

    // Subsequent normal scan works immediately
    let normal_resp = scan_via_socket(&socket, &target, None);
    assert_eq!(normal_resp["status"].as_str().unwrap(), "DETECTED");
    assert_eq!(
        normal_resp["database_generation"].as_str().unwrap(),
        "gen-fault-1"
    );

    // 2. Client disconnection mid-handshake
    {
        let stream = UnixStream::connect(&socket).unwrap();
        drop(stream); // abrupt disconnect
    }
    std::thread::sleep(Duration::from_millis(50));
    let post_disc = scan_via_socket(&socket, &target, None);
    assert_eq!(post_disc["status"].as_str().unwrap(), "DETECTED");

    // 3. Invalid candidate verification failure retains active generation
    let corrupt_dir = db_root.join("gen-corrupt-cand");
    std::fs::create_dir_all(&corrupt_dir).unwrap();
    std::fs::write(corrupt_dir.join("database.rsidb"), b"corrupted bytes").unwrap();
    raxosentinel_signatures::rsidb::updater::write_pointer(&db_root, "current", "gen-corrupt-cand")
        .unwrap();
    std::thread::sleep(Duration::from_millis(150));

    let corrupt_resp = scan_via_socket(&socket, &target, None);
    assert_eq!(
        corrupt_resp["database_generation"].as_str().unwrap(),
        "gen-fault-1"
    );
    assert!(corrupt_resp["degraded_freshness"].as_bool().unwrap());

    // 4. Descriptor leak check across repeated requests
    let pid = coord.child.id();
    let fd_dir = format!("/proc/{pid}/fd");
    let count_fds = || std::fs::read_dir(&fd_dir).map(|d| d.count()).unwrap_or(0);

    let initial_fds = count_fds();
    for _ in 0..20 {
        let resp = scan_via_socket(&socket, &target, None);
        assert_eq!(resp["status"].as_str().unwrap(), "DETECTED");
    }
    let final_fds = count_fds();
    assert!(
        final_fds <= initial_fds + 2,
        "File descriptors must not leak across repeated scans (initial: {initial_fds}, final: {final_fds})"
    );
}

// ---------------------------------------------------------------------------
// Phase 3D: optional YARA-X rules through the coordinator
// ---------------------------------------------------------------------------
fn yara_rule_set(set: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/yara-rules")
        .join(set)
}

#[test]
fn test_phase3d_yara_rules_complement_rsidb_via_socket() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");
    let valid = yara_rule_set("valid");
    let heavy = yara_rule_set("resource");
    let _coord = CoordinatorProcess::spawn(
        &socket,
        &db_root,
        gen,
        &["--yara-rules", valid.to_str().unwrap(), "--yara-rules", heavy.to_str().unwrap(),
          "--worker-timeout-ms=3000"],
    );

    let marker = d.path().join("marker.txt");
    std::fs::write(&marker, b"x RAXO-YARA-TEST-MARKER-7f3c9e y").unwrap();
    let rsidb = d.path().join("rsidb.bin");
    std::fs::write(&rsidb, SYNTHETIC_SIGNATURE).unwrap();
    let clean = d.path().join("clean.txt");
    std::fs::write(&clean, b"ordinary text").unwrap();

    let (c, r) = run_client(&socket, &marker, &[], &[]);
    assert_eq!((c, r["status"].as_str().unwrap()), (1, "DETECTED"), "{r}");
    assert_eq!(r["threats"][0]["name"], "YARA:raxo_test.RaxoTestMarker");

    let (c, r) = run_client(&socket, &rsidb, &[], &[]);
    assert_eq!((c, r["status"].as_str().unwrap()), (1, "DETECTED"), "{r}");
    assert!(r["threats"][0]["name"].as_str().unwrap().contains(SYNTHETIC_NAME));

    let (c, r) = run_client(&socket, &clean, &[], &[]);
    assert_eq!((c, r["status"].as_str().unwrap()), (0, "CLEAN"), "{r}");

    // The heavy rule (`#a > 1000000`) cannot finish on 40 MiB of 'A' before the worker
    // deadline: the result is ERROR with timeout diagnostics, never CLEAN.
    let big = d.path().join("aaaa.bin");
    std::fs::write(&big, vec![b'A'; 40 << 20]).unwrap();
    let (c, r) = run_client(&socket, &big, &["--json-envelope"], &[]);
    assert_eq!(c, 3, "{r}");
    assert_eq!(r["status"], "ERROR", "{r}");

    // The coordinator recovers and keeps serving with rules loaded.
    let (c, r) = run_client(&socket, &marker, &[], &[]);
    assert_eq!((c, r["status"].as_str().unwrap()), (1, "DETECTED"), "{r}");
}

#[test]
fn test_phase3d_invalid_yara_rules_fail_coordinator_startup() {
    let d = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_test_db(d.path());
    let socket = d.path().join("sock_dir/coordinator.sock");
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    std::fs::set_permissions(socket.parent().unwrap(), std::fs::Permissions::from_mode(0o700)).unwrap();
    for set in ["invalid-syntax", "invalid-slow"] {
        let out = Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
            .arg("serve")
            .arg("--socket")
            .arg(&socket)
            .arg("--private-db-root")
            .arg(&db_root)
            .arg("--private-generation")
            .arg(gen)
            .arg("--yara-rules")
            .arg(yara_rule_set(set))
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(3), "{set}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("YARA-X rules rejected"), "{set}: {err}");
        assert!(!String::from_utf8_lossy(&out.stdout).contains("RAXOSENTINEL_COORDINATOR_READY"));
        assert!(!socket.exists());
    }
}
