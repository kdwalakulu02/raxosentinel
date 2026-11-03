#![cfg(target_os = "linux")]
use raxosentinel_signatures::rsidb::malwarebazaar::private_store;
use sha2::{Digest, Sha256};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::process::{Command, Stdio};

fn command(path: &std::path::Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_raxosentinel"));
    c.arg("scan").arg(path).args(["--supervised", "--json"]);
    c
}
fn verdict(output: &std::process::Output) -> String {
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    report["status"].as_str().unwrap().to_owned()
}
#[test]
fn clean_detected_archive_and_existing_cli() {
    use std::io::Write;
    let d = tempfile::tempdir().unwrap();
    let file = d.path().join("file.txt");
    std::fs::write(&file, b"harmless synthetic text").unwrap();
    assert_eq!(verdict(&command(&file).output().unwrap()), "CLEAN");
    let sample = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    std::fs::write(&file, sample).unwrap();
    assert_eq!(verdict(&command(&file).output().unwrap()), "DETECTED");
    let direct = Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
        .arg("scan")
        .arg(&file)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(verdict(&direct), "DETECTED");
    let zip = d.path().join("fixture.zip");
    let mut writer = zip::ZipWriter::new(std::fs::File::create(&zip).unwrap());
    writer
        .start_file("test.txt", zip::write::SimpleFileOptions::default())
        .unwrap();
    writer.write_all(sample).unwrap();
    writer.finish().unwrap();
    assert_eq!(verdict(&command(&zip).output().unwrap()), "DETECTED");
}
#[test]
fn descriptor_validation_and_path_replacement() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("target.txt");
    std::fs::write(&path, b"harmless original").unwrap();
    let open = std::fs::File::open(&path).unwrap();
    std::fs::rename(&path, d.path().join("original")).unwrap();
    std::fs::write(
        &path,
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
        .arg("scan")
        .arg(&path)
        .args(["--worker-internal", "--json"])
        .stdin(Stdio::from(open))
        .output()
        .unwrap();
    assert_eq!(verdict(&out), "CLEAN");
    let invalid = Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
        .arg("scan")
        .arg(&path)
        .args(["--worker-internal", "--json"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(verdict(&invalid), "ERROR");
    let link = d.path().join("link");
    symlink(&path, &link).unwrap();
    assert_eq!(verdict(&command(&link).output().unwrap()), "ERROR");
    assert_eq!(verdict(&command(d.path()).output().unwrap()), "ERROR");
}
#[test]
fn strict_private_generation_is_used_and_failure_is_closed() {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = d.path().join("target");
    let content = b"synthetic private signature";
    std::fs::write(&path, content).unwrap();
    let response = serde_json::json!({"query_status":"ok", "data":[{"sha256_hash":hex::encode(Sha256::digest(content)), "file_size":content.len(), "first_seen":"2024-02-29 00:00:00", "signature":"SyntheticFixture"}]}).to_string();
    private_store::publish(d.path(), "fixture", response.as_bytes(), 1).unwrap();
    let run = || {
        command(&path)
            .arg("--private-db-root")
            .arg(d.path())
            .args(["--private-generation", "fixture"])
            .output()
            .unwrap()
    };
    assert_eq!(verdict(&run()), "DETECTED");
    std::fs::remove_file(d.path().join("fixture/database.rsidb.evidence")).unwrap();
    assert_eq!(verdict(&run()), "ERROR");
}
#[test]
fn resource_limit_fails_closed() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("target");
    std::fs::write(&path, b"test").unwrap();
    let out = command(&path)
        .args(["--worker-memory", "1048576"])
        .output()
        .unwrap();
    assert_eq!(verdict(&out), "ERROR");
}
#[cfg(debug_assertions)]
#[test]
fn failures_timeout_reaped_and_subsequent_scan_works() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("target");
    std::fs::write(&path, b"test").unwrap();
    for action in ["hang", "crash", "malformed", "oversized"] {
        let output = command(&path)
            .args(["--worker-timeout-ms", "300"])
            .env("RAXOSENTINEL_TEST_WORKER_ACTION", action)
            .output()
            .unwrap();
        assert_eq!(verdict(&output), "ERROR", "{action}");
    }
    assert_eq!(verdict(&command(&path).output().unwrap()), "CLEAN");
}

#[cfg(debug_assertions)]
#[test]
fn timed_out_worker_is_reaped() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("target");
    std::fs::write(&path, b"test").unwrap();
    let parent = command(&path)
        .args(["--worker-timeout-ms", "1000"])
        .env("RAXOSENTINEL_TEST_WORKER_ACTION", "hang")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let children = format!("/proc/{}/task/{}/children", parent.id(), parent.id());
    let start = std::time::Instant::now();
    let worker = loop {
        let value = std::fs::read_to_string(&children).unwrap_or_default();
        if let Some(pid) = value.split_whitespace().next() {
            break pid.to_owned();
        }
        assert!(
            start.elapsed() < std::time::Duration::from_millis(800),
            "worker did not start"
        );
        std::thread::sleep(std::time::Duration::from_millis(2));
    };
    let output = parent.wait_with_output().unwrap();
    assert_eq!(verdict(&output), "ERROR");
    assert!(!std::path::Path::new("/proc").join(worker).exists());
}
