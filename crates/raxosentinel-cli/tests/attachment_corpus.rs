#![cfg(target_os = "linux")]
//! Phase 3D attachment corpus and YARA-X command-line behaviour.
//!
//! Every fixture in `tests/attachment-corpus/MANIFEST.tsv` runs through the supervised
//! worker twice: without YARA-X rules (column 2) and with the controlled rule set in
//! `tests/yara-rules/valid` (column 3). Hashes are pinned so a regenerated corpus cannot
//! silently change what is tested.
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const MARKER: &[u8] = b"RAXO-YARA-TEST-MARKER-7f3c9e";

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn rules(set: &str) -> PathBuf {
    repo().join("tests/yara-rules").join(set)
}

fn scan(target: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
        .arg("scan")
        .arg(target)
        .arg("--json")
        .args(extra)
        .output()
        .unwrap()
}

fn json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "invalid JSON ({e}); stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

fn threat_names(report: &serde_json::Value, found: &mut Vec<String>) {
    for t in report["threats"].as_array().into_iter().flatten() {
        found.push(t["name"].as_str().unwrap_or_default().to_string());
    }
    for c in report["sub_targets"].as_array().into_iter().flatten() {
        threat_names(c, found);
    }
}

fn exit_for(status: &str) -> i32 {
    match status {
        "CLEAN" => 0,
        "DETECTED" => 1,
        "UNSCANNED" => 2,
        _ => 3,
    }
}

#[test]
fn attachment_regression_corpus_verdicts() {
    let root = repo().join("tests/attachment-corpus");
    let manifest = std::fs::read_to_string(root.join("MANIFEST.tsv")).unwrap();
    let valid = rules("valid");
    let valid = valid.to_str().unwrap();
    let mut failures = Vec::new();
    let mut count = 0usize;
    for line in manifest
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let fields: Vec<&str> = line.split('\t').collect();
        let (name, expected, expected_yara, sha256) = (fields[0], fields[1], fields[2], fields[5]);
        let path = root.join("fixtures").join(name);
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            sha256,
            "{name}: fixture differs from MANIFEST.tsv"
        );
        for (label, want, extra) in [
            ("no-yara", expected, vec!["--supervised"]),
            ("yara", expected_yara, vec!["--supervised", "--yara-rules", valid]),
        ] {
            let out = scan(&path, &extra);
            let report = json(&out);
            let status = report["status"].as_str().unwrap_or_default();
            if status != want || out.status.code() != Some(exit_for(want)) {
                failures.push(format!(
                    "{name} [{label}]: expected {want}, got {status} exit {:?} ({})",
                    out.status.code(),
                    report["error"]
                ));
            }
            if label == "yara" && want == "DETECTED" && expected != "DETECTED" {
                let mut names = Vec::new();
                threat_names(&report, &mut names);
                if !names.iter().any(|n| n.starts_with("YARA:")) {
                    failures.push(format!("{name}: no YARA rule identifier in {names:?}"));
                }
            }
        }
        count += 1;
    }
    assert!(count >= 60, "corpus unexpectedly small: {count}");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn yara_rule_identifiers_reported_and_rsidb_preserved() {
    let d = tempfile::tempdir().unwrap();
    let marker = d.path().join("marker.txt");
    std::fs::write(&marker, [b"prefix ".as_slice(), MARKER].concat()).unwrap();
    let valid = rules("valid");
    let valid = valid.to_str().unwrap();

    let out = scan(&marker, &["--yara-rules", valid]);
    assert_eq!(out.status.code(), Some(1));
    let report = json(&out);
    let t = &report["threats"][0];
    assert_eq!(t["name"], "YARA:raxo_test.RaxoTestMarker");
    assert_eq!(t["severity"], "high");
    assert_eq!(t["detection_type"], "deterministic");
    assert_eq!(t["matched_by"], "yara-x:raxo_test.RaxoTestMarker");

    // Without rules the marker is unknown content.
    let out = scan(&marker, &[]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(json(&out)["status"], "CLEAN");

    // Built-in/RSIDB detection still applies with rules loaded.
    let eicar = d.path().join("eicar.com");
    std::fs::write(
        &eicar,
        br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    )
    .unwrap();
    let out = scan(&eicar, &["--supervised", "--yara-rules", valid]);
    assert_eq!(out.status.code(), Some(1));
    let mut names = Vec::new();
    threat_names(&json(&out), &mut names);
    assert!(names.iter().all(|n| !n.starts_with("YARA:")), "{names:?}");

    // A single rule file is accepted as well as a directory.
    let single = rules("valid").join("raxo_test.yar");
    let out = scan(&marker, &["--supervised", "--yara-rules", single.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn invalid_yara_rules_fail_closed_with_observable_error() {
    let d = tempfile::tempdir().unwrap();
    let target = d.path().join("t.txt");
    std::fs::write(&target, b"ordinary text").unwrap();
    for (set, file, code) in [
        ("invalid-syntax", "broken.yar", "E001"),
        ("invalid-slow", "slow.yar", "E018"),
    ] {
        let path = rules(set);
        for supervised in [false, true] {
            let mut extra = vec!["--yara-rules", path.to_str().unwrap()];
            if supervised {
                extra.push("--supervised");
            }
            let out = scan(&target, &extra);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(out.status.code(), Some(3), "{set} supervised={supervised}");
            assert!(out.stdout.is_empty(), "no verdict may be printed for {set}");
            assert!(
                stderr.contains("YARA-X rules rejected") && stderr.contains(file) && stderr.contains(code),
                "{set}: {stderr}"
            );
        }
    }
    let missing = d.path().join("missing.yar");
    let out = scan(&target, &["--yara-rules", missing.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(3));
    let empty = d.path().join("empty-dir");
    std::fs::create_dir(&empty).unwrap();
    let out = scan(&target, &["--yara-rules", empty.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(3), "a rule directory without rules is a configuration error");
}

#[test]
fn resource_intensive_yara_rule_hits_deadline_not_clean() {
    let d = tempfile::tempdir().unwrap();
    let big = d.path().join("aaaa.bin");
    std::fs::write(&big, vec![b'A'; 40 << 20]).unwrap();
    let heavy = rules("resource");
    let out = scan(
        &big,
        &["--supervised", "--timeout", "1", "--yara-rules", heavy.to_str().unwrap()],
    );
    let report = json(&out);
    assert_eq!(report["status"], "ERROR", "{report}");
    assert_eq!(out.status.code(), Some(3));
    let err = report["error"].as_str().unwrap();
    assert!(err.contains("timeout") || err.contains("deadline"), "{err}");

    // The next scan runs in a fresh worker and is unaffected.
    let small = d.path().join("small.txt");
    std::fs::write(&small, MARKER).unwrap();
    let out = scan(
        &small,
        &["--supervised", "--yara-rules", rules("valid").to_str().unwrap()],
    );
    assert_eq!(json(&out)["status"], "DETECTED");
}
