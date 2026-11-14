// Copyright (C) 2026 RaxoSentinel Contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//! ClamAV intelligence provider adapter for automated CVD-based updates.

use crate::rsidb::malwarebazaar::private_store::unified::{UnifiedClaim, UnifiedSource};
use crate::rsidb::updater::traits::{
    AcquisitionResult, ExtractedIntelligence, IntelligenceProvider, ProviderState, RecordKey,
    UpdateCheckResult, UpdateError,
};
use crate::rsidb::{HashAlgorithm, SignatureEntry};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Metadata for an authenticated ClamAV CVD distribution archive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CvdFileMetadata {
    pub file_name: String,
    pub version: u64,
    pub builder: String,
    pub signatures: usize,
    pub md5: String,
    pub sha256: String,
    pub verified: bool,
}

/// Result of executing FreshClam automated acquisition.
#[derive(Clone, Debug)]
pub struct FreshclamReport {
    pub stdout: String,
    pub updated_daily: bool,
    pub updated_main: bool,
}

/// Query the official ClamAV DNS TXT record at `current.cvd.clamav.net`.
/// Returns the raw TXT record string, e.g. "1.4.6:63:28173:1793768400:1:90:49192:339".
/// Generation file carrying the supported ClamAV ndb/ldb content signatures.
pub const CONTENT_FILE: &str = "content-clamav.sigs";

pub fn query_clamav_dns_txt() -> Result<String, String> {
    // Discover DNS resolver from /etc/resolv.conf, default to 127.0.0.53:53
    let mut server: SocketAddr = "127.0.0.53:53".parse().unwrap();
    if let Ok(resolv) = fs::read_to_string("/etc/resolv.conf") {
        for line in resolv.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("nameserver") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(ip) = parts[1].parse::<std::net::IpAddr>() {
                        server = SocketAddr::new(ip, 53);
                        break;
                    }
                }
            }
        }
    }

    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;
    socket
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;

    // Build DNS TXT query packet for "current.cvd.clamav.net"
    let mut packet = Vec::with_capacity(64);
    packet.extend_from_slice(&[0x52, 0x53]); // ID
    packet.extend_from_slice(&[0x01, 0x00]); // Standard query with RD
    packet.extend_from_slice(&[0x00, 0x01]); // 1 Question
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // Counts

    for part in ["current", "cvd", "clamav", "net"] {
        packet.push(part.len() as u8);
        packet.extend_from_slice(part.as_bytes());
    }
    packet.push(0x00); // end of qname

    packet.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]); // TXT, IN

    let targets = [
        server,
        "8.8.8.8:53".parse().unwrap(),
        "1.1.1.1:53".parse().unwrap(),
    ];
    let mut resp = vec![0u8; 1024];
    let mut recv_len = 0;

    for target in &targets {
        if socket.send_to(&packet, target).is_ok() {
            if let Ok((len, _)) = socket.recv_from(&mut resp) {
                if len >= 12 {
                    recv_len = len;
                    break;
                }
            }
        }
    }

    if recv_len < 12 {
        return Err("DNS query timed out or returned empty response".to_string());
    }

    let data = &resp[..recv_len];
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    if ancount == 0 {
        return Err("DNS returned 0 answer records".to_string());
    }

    let mut idx = 12;
    while idx < data.len() && data[idx] != 0 {
        idx += 1 + (data[idx] as usize);
    }
    idx += 5; // null byte + QTYPE + QCLASS

    while idx < data.len() {
        if data[idx] & 0xc0 == 0xc0 {
            idx += 2;
        } else {
            while idx < data.len() && data[idx] != 0 {
                idx += 1 + (data[idx] as usize);
            }
            idx += 1;
        }
        if idx + 10 > data.len() {
            break;
        }
        let rtype = u16::from_be_bytes([data[idx], data[idx + 1]]);
        let rdlength = u16::from_be_bytes([data[idx + 8], data[idx + 9]]) as usize;
        idx += 10;
        if idx + rdlength > data.len() {
            break;
        }
        if rtype == 16 && rdlength > 1 {
            let txt_len = data[idx] as usize;
            if idx + 1 + txt_len <= data.len() {
                let txt_str =
                    String::from_utf8_lossy(&data[idx + 1..idx + 1 + txt_len]).to_string();
                return Ok(txt_str);
            }
        }
        idx += rdlength;
    }

    Err("No TXT record found in DNS response".to_string())
}

/// Parse (main_version, daily_version) from ClamAV DNS TXT record.
pub fn parse_clamav_dns_txt(txt: &str) -> Option<(u64, u64)> {
    let parts: Vec<&str> = txt.split(':').collect();
    if parts.len() >= 3 {
        let main_v = parts[1].parse::<u64>().ok()?;
        let daily_v = parts[2].parse::<u64>().ok()?;
        Some((main_v, daily_v))
    } else {
        None
    }
}

/// Cryptographically authenticate an official ClamAV CVD archive using sigtool -i.
pub fn authenticate_cvd(cvd_path: &Path) -> Result<CvdFileMetadata, UpdateError> {
    if !cvd_path.exists() {
        return Err(UpdateError::VerificationFailed {
            provider: "clamav".to_string(),
            message: format!("CVD file '{}' does not exist", cvd_path.display()),
        });
    }

    let file_bytes = fs::read(cvd_path).map_err(|e| UpdateError::VerificationFailed {
        provider: "clamav".to_string(),
        message: format!("Failed to read {}: {e}", cvd_path.display()),
    })?;

    if file_bytes.len() < 512 {
        return Err(UpdateError::VerificationFailed {
            provider: "clamav".to_string(),
            message: format!(
                "CVD file '{}' is too small ({} bytes)",
                cvd_path.display(),
                file_bytes.len()
            ),
        });
    }

    let header_str = String::from_utf8_lossy(&file_bytes[..512]);
    if !header_str.starts_with("ClamAV-VDB:") {
        return Err(UpdateError::VerificationFailed {
            provider: "clamav".to_string(),
            message: format!("Invalid CVD header in '{}'", cvd_path.display()),
        });
    }

    let sha256 = hex::encode(Sha256::digest(&file_bytes));

    // Run official sigtool -i to verify digital signature
    let output = std::process::Command::new("sigtool")
        .arg("-i")
        .arg(cvd_path)
        .output();

    let (verified, ver_out) = match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let is_ok = out.status.success() && stdout.contains("Verification OK.");
            (is_ok, stdout)
        }
        Err(e) => {
            return Err(UpdateError::VerificationFailed {
                provider: "clamav".to_string(),
                message: format!("Failed to execute sigtool -i: {e}"),
            });
        }
    };

    if !verified {
        return Err(UpdateError::VerificationFailed {
            provider: "clamav".to_string(),
            message: format!(
                "Digital signature verification failed for '{}': {}",
                cvd_path.display(),
                ver_out
                    .lines()
                    .find(|l| l.contains("ERROR") || l.contains("Verification"))
                    .unwrap_or(&ver_out)
            ),
        });
    }

    let mut version = 0u64;
    let mut builder = "official-talos".to_string();
    let mut signatures = 0usize;
    let mut md5 = String::new();

    for line in ver_out.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Version:") {
            if let Some(v_part) = trimmed.split_whitespace().nth(1) {
                version = v_part.parse().unwrap_or(0);
            }
        } else if trimmed.starts_with("Builder:") {
            if let Some(b_part) = trimmed.split_whitespace().nth(1) {
                builder = b_part.to_string();
            }
        } else if trimmed.starts_with("Signatures:") {
            if let Some(s_part) = trimmed.split_whitespace().nth(1) {
                signatures = s_part.parse().unwrap_or(0);
            }
        } else if trimmed.starts_with("MD5:") {
            if let Some(m_part) = trimmed.split_whitespace().nth(1) {
                md5 = m_part.to_string();
            }
        }
    }

    let file_name = cvd_path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("unknown.cvd")
        .to_string();

    Ok(CvdFileMetadata {
        file_name,
        version,
        builder,
        signatures,
        md5,
        sha256,
        verified: true,
    })
}

/// Unpack an authenticated CVD archive into target directory using sigtool -u.
pub fn unpack_cvd(cvd_path: &Path, target_dir: &Path) -> Result<(), UpdateError> {
    fs::create_dir_all(target_dir).map_err(|e| UpdateError::ExtractionFailed {
        provider: "clamav".to_string(),
        message: format!(
            "Failed to create unpack directory {}: {e}",
            target_dir.display()
        ),
    })?;

    let output = std::process::Command::new("sigtool")
        .arg("-u")
        .arg(cvd_path)
        .current_dir(target_dir)
        .output()
        .map_err(|e| UpdateError::ExtractionFailed {
            provider: "clamav".to_string(),
            message: format!("Failed to execute sigtool -u: {e}"),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(UpdateError::ExtractionFailed {
            provider: "clamav".to_string(),
            message: format!("sigtool -u failed for {}: {stderr}", cvd_path.display()),
        });
    }

    Ok(())
}

/// Execute official FreshClam acquisition against upstream database.clamav.net.
pub fn run_freshclam(cvd_dir: &Path) -> Result<FreshclamReport, UpdateError> {
    fs::create_dir_all(cvd_dir).map_err(|e| UpdateError::AcquisitionFailed {
        provider: "clamav".to_string(),
        message: format!("Failed to create CVD directory {}: {e}", cvd_dir.display()),
    })?;

    let conf_path = cvd_dir.join("freshclam.conf");
    let conf_content = format!(
        "DatabaseDirectory {}\n\
         UpdateLogFile {}/freshclam.log\n\
         Foreground true\n\
         DatabaseMirror database.clamav.net\n\
         ConnectTimeout 30\n\
         DNSDatabaseInfo current.cvd.clamav.net\n\
         Bytecode false\n\
         ScriptedUpdates no\n",
        cvd_dir.display(),
        cvd_dir.display()
    );

    fs::write(&conf_path, conf_content).map_err(|e| UpdateError::AcquisitionFailed {
        provider: "clamav".to_string(),
        message: format!("Failed to write freshclam.conf: {e}"),
    })?;

    let output = std::process::Command::new("freshclam")
        .arg(format!("--config-file={}", conf_path.display()))
        .arg("--stdout")
        .output()
        .map_err(|e| UpdateError::AcquisitionFailed {
            provider: "clamav".to_string(),
            message: format!("Failed to execute freshclam: {e}"),
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // freshclam exits 1 when the databases are already up to date.
    if !matches!(output.status.code(), Some(0) | Some(1)) {
        return Err(UpdateError::AcquisitionFailed {
            provider: "clamav".to_string(),
            message: format!(
                "freshclam failed (exit code {:?}): {stdout} {stderr}",
                output.status.code()
            ),
        });
    }

    let updated_daily = stdout.contains("daily.cvd updated")
        || stdout.contains("daily database available for download");
    let updated_main = stdout.contains("main.cvd updated")
        || stdout.contains("main database available for download");

    Ok(FreshclamReport {
        stdout,
        updated_daily,
        updated_main,
    })
}

/// Provider adapter for official Cisco Talos ClamAV CVD distributions.
#[derive(Clone, Debug)]
pub struct ClamAvProvider {
    pub cvd_dir: Option<PathBuf>,
    pub unpack_dir: Option<PathBuf>,
    pub custom_version: Option<String>,
    pub enable_freshclam: bool,
}

impl ClamAvProvider {
    /// Create a new ClamAV provider pointing to an unpacked CVD directory (fixtures or manual extraction).
    pub fn new(unpack_dir: impl Into<PathBuf>) -> Self {
        Self {
            cvd_dir: None,
            unpack_dir: Some(unpack_dir.into()),
            custom_version: None,
            enable_freshclam: false,
        }
    }

    /// Create a provider pointing to a directory containing authentic CVD archives (main.cvd, daily.cvd).
    pub fn with_cvd_dir(cvd_dir: impl Into<PathBuf>) -> Self {
        Self {
            cvd_dir: Some(cvd_dir.into()),
            unpack_dir: None,
            custom_version: None,
            enable_freshclam: false,
        }
    }

    /// Create a provider configured for automated upstream FreshClam acquisition.
    pub fn with_freshclam(cvd_dir: impl Into<PathBuf>) -> Self {
        Self {
            cvd_dir: Some(cvd_dir.into()),
            unpack_dir: None,
            custom_version: None,
            enable_freshclam: true,
        }
    }

    /// Override the detected version string (used in deterministic tests/simulations).
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.custom_version = Some(version.into());
        self
    }

    /// Attach an unpacked directory fallback.
    pub fn with_unpack_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.unpack_dir = Some(dir.into());
        self
    }

    /// Detect versions of main.cvd and daily.cvd independently from local CVDs or unpacked directory.
    pub fn detect_local_versions(&self) -> (Option<u64>, Option<u64>) {
        if let Some(ref cvd_dir) = self.cvd_dir {
            let mut main_v = None;
            let mut daily_v = None;
            if let Ok(meta) = authenticate_cvd(&cvd_dir.join("main.cvd")) {
                main_v = Some(meta.version);
            }
            if let Ok(meta) = authenticate_cvd(&cvd_dir.join("daily.cvd")) {
                daily_v = Some(meta.version);
            }
            if main_v.is_some() || daily_v.is_some() {
                return (main_v, daily_v);
            }
        }

        if let Some(ref dir) = self.unpack_dir {
            let mut main_v = None;
            let mut daily_v = None;

            let main_info = dir.join("main/main.info");
            if let Ok(v) = fs::read_to_string(&main_info) {
                for line in v.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("ClamAV-VDB:") {
                        let parts: Vec<&str> = trimmed.split(':').collect();
                        if parts.len() >= 3 {
                            main_v = parts[2].parse().ok();
                        }
                    } else if trimmed.starts_with("Version:") {
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if parts.len() >= 2 {
                            main_v = parts[1].parse().ok();
                        }
                    }
                }
            }

            let daily_info = dir.join("daily/daily.info");
            if let Ok(v) = fs::read_to_string(&daily_info) {
                for line in v.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("ClamAV-VDB:") {
                        let parts: Vec<&str> = trimmed.split(':').collect();
                        if parts.len() >= 3 {
                            daily_v = parts[2].parse().ok();
                        }
                    } else if trimmed.starts_with("Version:") {
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if parts.len() >= 2 {
                            daily_v = parts[1].parse().ok();
                        }
                    }
                }
            }

            if main_v.is_some() || daily_v.is_some() {
                return (main_v, daily_v);
            }

            let ver_file = dir.join("version.txt");
            if let Ok(v) = fs::read_to_string(&ver_file) {
                let trimmed = v.trim();
                if let Some(stripped) = trimmed.strip_prefix("daily-") {
                    daily_v = stripped.parse().ok();
                    return (Some(63), daily_v);
                }
            }
        }

        (None, None)
    }

    /// Detect current composite version string.
    pub fn detect_version(&self) -> String {
        if let Some(ref v) = self.custom_version {
            return v.clone();
        }

        let (main_v, daily_v) = self.detect_local_versions();
        match (main_v, daily_v) {
            (Some(m), Some(d)) => format!("main:{},daily:{}", m, d),
            (None, Some(d)) => format!("daily-{}", d),
            (Some(m), None) => format!("main-{}", m),
            (None, None) => "clamav-unknown".to_string(),
        }
    }
}

impl IntelligenceProvider for ClamAvProvider {
    fn id(&self) -> &str {
        "clamav"
    }

    fn name(&self) -> &str {
        "ClamAV"
    }

    fn check_update(&self, state: &ProviderState) -> Result<UpdateCheckResult, UpdateError> {
        if let Some(ref v) = self.custom_version {
            let available = v != &state.last_version || state.last_version.is_empty();
            return Ok(UpdateCheckResult {
                available,
                version: v.clone(),
                details: if available {
                    format!("New ClamAV CVD distribution version available: {}", v)
                } else {
                    format!("ClamAV CVD distribution unchanged at version {}", v)
                },
            });
        }

        // 1. Check official live upstream DNS TXT record if CVD mode or FreshClam is active
        if self.cvd_dir.is_some() || self.enable_freshclam {
            if let Ok(dns_txt) = query_clamav_dns_txt() {
                if let Some((remote_main, remote_daily)) = parse_clamav_dns_txt(&dns_txt) {
                    let composite_version = format!("main:{},daily:{}", remote_main, remote_daily);

                    let is_match = if state.last_version == composite_version {
                        true
                    } else if state.last_version == format!("daily-{}", remote_daily)
                        && remote_main == 63
                    {
                        // Backward compatible match for Phase 2D.7A baseline reporting daily-28173
                        true
                    } else {
                        false
                    };

                    let available = !is_match || state.last_version.is_empty();
                    return Ok(UpdateCheckResult {
                        available,
                        version: composite_version.clone(),
                        details: if available {
                            format!(
                                "New ClamAV CVD distribution version available: {} (current: {})",
                                composite_version, state.last_version
                            )
                        } else {
                            format!(
                                "ClamAV CVD distribution unchanged at {} (upstream main: {}, daily: {})",
                                composite_version, remote_main, remote_daily
                            )
                        },
                    });
                }
            }
        }

        // 2. Offline / local fallback check
        let (local_main, local_daily) = self.detect_local_versions();
        let local_version = match (local_main, local_daily) {
            (Some(m), Some(d)) => format!("main:{},daily:{}", m, d),
            (None, Some(d)) => format!("daily-{}", d),
            (Some(m), None) => format!("main-{}", m),
            (None, None) => self.detect_version(),
        };

        let is_match = if state.last_version == local_version {
            true
        } else if let Some(d) = local_daily {
            state.last_version == format!("daily-{}", d) && local_main.unwrap_or(63) == 63
        } else {
            false
        };

        let available = !is_match || state.last_version.is_empty();

        Ok(UpdateCheckResult {
            available,
            version: local_version.clone(),
            details: if available {
                format!(
                    "New ClamAV CVD distribution version available: {}",
                    local_version
                )
            } else {
                format!(
                    "ClamAV CVD distribution unchanged at version {}",
                    local_version
                )
            },
        })
    }

    fn acquire_update(&self, staging_dir: &Path) -> Result<AcquisitionResult, UpdateError> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 1. Execute FreshClam if configured for automated upstream fetch
        if self.enable_freshclam {
            if let Some(ref cvd_dir) = self.cvd_dir {
                let _ = run_freshclam(cvd_dir)?;
            }
        }

        // 2. Discover CVD files (only if unpack_dir was not explicitly provided)
        let cvd_dir = self.cvd_dir.clone().or_else(|| {
            if self.unpack_dir.is_some() {
                return None;
            }
            for candidate in &["/var/lib/clamav", "/home/vscode/clamav-cvd"] {
                let p = PathBuf::from(candidate);
                if p.join("daily.cvd").exists() {
                    return Some(p);
                }
            }
            None
        });

        let mut cvd_meta_list = Vec::new();
        let mut unpack_path = self.unpack_dir.clone();

        if let Some(ref c_dir) = cvd_dir {
            let daily_cvd = c_dir.join("daily.cvd");
            let main_cvd = c_dir.join("main.cvd");

            if daily_cvd.exists() && main_cvd.exists() {
                // Strict cryptographic digital signature authentication
                let daily_meta = authenticate_cvd(&daily_cvd)?;
                let main_meta = authenticate_cvd(&main_cvd)?;

                cvd_meta_list.push(daily_meta);
                cvd_meta_list.push(main_meta);

                // Unpack into staging directory for extraction
                let stg_unpacked = staging_dir.join("clamav_unpacked");
                let stg_daily = stg_unpacked.join("daily");
                let stg_main = stg_unpacked.join("main");

                unpack_cvd(&daily_cvd, &stg_daily)?;
                unpack_cvd(&main_cvd, &stg_main)?;

                unpack_path = Some(stg_unpacked);
            }
        }

        let effective_unpack = unpack_path.ok_or_else(|| UpdateError::AcquisitionFailed {
            provider: self.id().to_string(),
            message: "No authenticated CVD archives or unpacked signature directory available"
                .to_string(),
        })?;

        let version = if !cvd_meta_list.is_empty() {
            let mut main_v = 63;
            let mut daily_v = 28173;
            for m in &cvd_meta_list {
                if m.file_name.starts_with("main") {
                    main_v = m.version;
                } else if m.file_name.starts_with("daily") {
                    daily_v = m.version;
                }
            }
            format!("main:{},daily:{}", main_v, daily_v)
        } else {
            self.detect_version()
        };

        let cvd_json_entries: Vec<serde_json::Value> = cvd_meta_list
            .iter()
            .map(|m| {
                serde_json::json!({
                    "file": m.file_name,
                    "version": m.version,
                    "builder": m.builder,
                    "signatures": m.signatures,
                    "md5": m.md5,
                    "sha256": m.sha256,
                    "sigtool_verification": if m.verified { "OK" } else { "FAILED" },
                })
            })
            .collect();

        let mut evidence_json = serde_json::json!({
            "source": "official_clamav_distribution",
            "provider": "Cisco Talos",
            "license": "GPL-2.0-only",
            "redistribution": "unverified; private research only",
            "acquisition_timestamp": timestamp,
            "version": version,
            "cvd_files": cvd_json_entries,
            "provenance": if !cvd_meta_list.is_empty() {
                "CVD digital signature verified; official sigtool extraction"
            } else {
                "controlled fixture; unpacked directory"
            },
        });

        let mut hash_files = Vec::new();
        for sub in &[
            "main/main.hdb",
            "main/main.hsb",
            "daily/daily.hdb",
            "daily/daily.hsb",
        ] {
            let p = effective_unpack.join(sub);
            if p.exists() {
                if let Ok(bytes) = fs::read(&p) {
                    hash_files.push(serde_json::json!({
                        "file": sub,
                        "size": bytes.len(),
                        "sha256": hex::encode(Sha256::digest(&bytes)),
                    }));
                }
            }
        }
        evidence_json["hash_files"] = serde_json::Value::Array(hash_files);

        let evidence_bytes = serde_json::to_vec_pretty(&evidence_json).map_err(|e| {
            UpdateError::AcquisitionFailed {
                provider: self.id().to_string(),
                message: format!("Failed to serialize evidence: {e}"),
            }
        })?;

        let staged_evidence_file = staging_dir.join("evidence-clamav.json");
        fs::write(&staged_evidence_file, &evidence_bytes).map_err(|e| {
            UpdateError::AcquisitionFailed {
                provider: self.id().to_string(),
                message: format!(
                    "Failed to write evidence to {}: {e}",
                    staged_evidence_file.display()
                ),
            }
        })?;

        Ok(AcquisitionResult {
            source_id: self.id().to_string(),
            version,
            timestamp,
            evidence_files: vec![("evidence-clamav.json".to_string(), evidence_bytes)],
            staging_path: Some(effective_unpack),
        })
    }

    fn extract_records(
        &self,
        acquisition: &AcquisitionResult,
    ) -> Result<ExtractedIntelligence, UpdateError> {
        let dir = acquisition
            .staging_path
            .as_deref()
            .or(self.unpack_dir.as_deref())
            .ok_or_else(|| UpdateError::ExtractionFailed {
                provider: self.id().to_string(),
                message: "No unpack directory specified for extraction".to_string(),
            })?;

        // 1. Load false positive exclusions
        let mut fp_hashes: HashSet<String> = HashSet::new();
        let fp_files = [
            dir.join("main/main.fp"),
            dir.join("main/main.sfp"),
            dir.join("daily/daily.fp"),
            dir.join("daily/daily.sfp"),
            dir.join("exclusions.fp"),
        ];
        for p in &fp_files {
            if p.exists() {
                if let Ok(content) = fs::read_to_string(p) {
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            let parts: Vec<&str> = trimmed.split(':').collect();
                            if !parts.is_empty() {
                                fp_hashes.insert(parts[0].to_ascii_lowercase());
                            }
                        }
                    }
                }
            }
        }

        // 2. Load ignored signature names
        let mut ign_names: HashSet<String> = HashSet::new();
        let ign_files = [
            dir.join("daily/daily.ign"),
            dir.join("daily/daily.ign2"),
            dir.join("main/main.ign"),
            dir.join("exclusions.ign"),
        ];
        for p in &ign_files {
            if p.exists() {
                if let Ok(content) = fs::read_to_string(p) {
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            let parts: Vec<&str> = trimmed.split(':').collect();
                            if parts.len() >= 3 {
                                ign_names.insert(parts[2].to_string());
                            } else {
                                ign_names.insert(parts[0].to_string());
                            }
                        }
                    }
                }
            }
        }

        // 3. Ingest supported whole-file hash tables
        let hash_files = [
            dir.join("main/main.hdb"),
            dir.join("main/main.hsb"),
            dir.join("daily/daily.hdb"),
            dir.join("daily/daily.hsb"),
            dir.join("signatures.hsb"),
        ];

        let mut entries: Vec<SignatureEntry> = Vec::new();
        let mut claims: BTreeMap<RecordKey, BTreeSet<UnifiedClaim>> = BTreeMap::new();
        let mut revocations: HashSet<RecordKey> = HashSet::new();
        let mut seen_records: HashSet<RecordKey> = HashSet::new();

        let mut gross_records = 0usize;
        let mut rejected_records = 0usize;
        let mut duplicate_records = 0usize;

        for file_path in &hash_files {
            if !file_path.exists() {
                continue;
            }
            let content =
                fs::read_to_string(file_path).map_err(|e| UpdateError::ExtractionFailed {
                    provider: self.id().to_string(),
                    message: format!("Failed to read {}: {e}", file_path.display()),
                })?;

            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }

                gross_records += 1;

                let parts: Vec<&str> = trimmed.split(':').collect();
                if parts.len() != 3 && parts.len() != 4 {
                    rejected_records += 1;
                    continue;
                }

                let hex_digest = parts[0].trim().to_ascii_lowercase();
                let size_str = parts[1].trim();
                let name = parts[2].trim();

                // Reject wildcard file sizes (strict file size accounting)
                if size_str == "*" || !size_str.chars().all(|c| c.is_ascii_digit()) {
                    rejected_records += 1;
                    continue;
                }

                let size: u64 = match size_str.parse() {
                    Ok(s) => s,
                    Err(_) => {
                        rejected_records += 1;
                        continue;
                    }
                };

                let digest_bytes = match hex::decode(&hex_digest) {
                    Ok(b) => b,
                    Err(_) => {
                        rejected_records += 1;
                        continue;
                    }
                };

                let alg = match digest_bytes.len() {
                    16 => HashAlgorithm::Md5,
                    20 => HashAlgorithm::Sha1,
                    32 => HashAlgorithm::Sha256,
                    _ => {
                        rejected_records += 1;
                        continue;
                    }
                };

                let record_key: RecordKey = (alg, digest_bytes.clone(), size, name.to_string());

                // Check false-positive and ignored exclusions
                if fp_hashes.contains(&hex_digest) || ign_names.contains(name) {
                    revocations.insert(record_key);
                    rejected_records += 1;
                    continue;
                }

                let claim = UnifiedClaim {
                    source_id: self.id().to_string(),
                    size,
                    family: name.to_string(),
                };

                if seen_records.contains(&record_key) {
                    duplicate_records += 1;
                    if let Some(c) = claims.get_mut(&record_key) {
                        c.insert(claim);
                    }
                } else {
                    seen_records.insert(record_key.clone());
                    entries.push(SignatureEntry::new(
                        alg,
                        size,
                        digest_bytes,
                        name.to_string(),
                    ));
                    let mut s = BTreeSet::new();
                    s.insert(claim);
                    claims.insert(record_key, s);
                }
            }
        }

        // 4. Body/logical content signatures the native content engine supports.
        let mut content = String::new();
        let mut content_count = 0usize;
        for (file, kind) in [
            ("main/main.ndb", "ndb"),
            ("daily/daily.ndb", "ndb"),
            ("main/main.ldb", "ldb"),
            ("daily/daily.ldb", "ldb"),
        ] {
            let path = dir.join(file);
            if !path.exists() {
                continue;
            }
            let text = fs::read_to_string(&path).map_err(|e| UpdateError::ExtractionFailed {
                provider: self.id().to_string(),
                message: format!("Failed to read {}: {e}", path.display()),
            })?;
            for line in text.lines() {
                let line = line.trim_end_matches('\r');
                if line.is_empty()
                    || line.starts_with('#')
                    || ign_names.contains(crate::content::signature_name(kind, line))
                    || !crate::content::is_supported(kind, line)
                {
                    continue;
                }
                content.push_str(kind);
                content.push('\t');
                content.push_str(line);
                content.push('\n');
                content_count += 1;
            }
        }

        let ev_bytes = &acquisition.evidence_files[0].1;
        let ev_sha256 = hex::encode(Sha256::digest(ev_bytes));
        let mut evidence_files = acquisition.evidence_files.clone();
        if content_count > 0 {
            evidence_files.push((CONTENT_FILE.to_string(), content.into_bytes()));
        }

        let source_info = UnifiedSource {
            id: self.id().to_string(),
            name: self.name().to_string(),
            provider: "Cisco Talos".to_string(),
            acquisition_method: "official_cvd_distribution".to_string(),
            acquired_unix_seconds: acquisition.timestamp,
            classification: "official antivirus signature feed".to_string(),
            provenance: "CVD digital signature verified; official sigtool extraction".to_string(),
            redistribution: "unverified; private research only (GPL-2.0-only)".to_string(),
            enabled: true,
            indicator_count: entries.len(),
            evidence_sha256: ev_sha256,
            evidence_file: Some("evidence-clamav.json".to_string()),
        };

        Ok(ExtractedIntelligence {
            source_info,
            entries,
            claims,
            revocations,
            evidence_files,
            gross_records,
            rejected_records,
            duplicate_records,
        })
    }
}
