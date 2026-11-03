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

use clap::{Args, Parser, Subcommand};
use raxosentinel_core::{
    MemoryUsage, ResourceLimits, ResourceTracker, ScanReport, ScanStatus, TargetMetadata,
};
use raxosentinel_email::EmailScanner;
use raxosentinel_filetypes::{detect_file_type, detect_type, FileCategory};
use raxosentinel_signatures::rsidb::crypto;
use raxosentinel_signatures::rsidb::ingest::{BuildProfile, IngestPipeline, SourceManifest};
use raxosentinel_signatures::rsidb::lifecycle::DbStore;
use raxosentinel_signatures::rsidb::{MmapCompactDirIndex, RsidbIndex};
use raxosentinel_signatures::{load_rules_from_file, SignatureDatabase};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(
    name = "raxosentinel",
    author = "RaxoSentinel Contributors",
    version,
    about = "Native Rust Malware Detection Engine specializing in Email Security",
    long_about = "RaxoSentinel is an independent native Rust malware scanning engine.\n\
                  It provides bounded-memory file inspection, content-based filetype detection,\n\
                  deep MIME parsing, and native signature matching."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose diagnostic logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan a target file or email message
    Scan(ScanArgs),
    /// RSIDB database management (verify, build, install, rollback)
    #[command(subcommand)]
    Db(DbCommand),
}

#[derive(Subcommand, Debug)]
enum DbCommand {
    /// Fully validate an RSIDB file and print its statistics
    Verify { path: PathBuf },
    /// Initialize trusted local sequence state for the public release prototype.
    InitPublicState {
        #[arg(long)]
        root: PathBuf,
    },
    /// Merge verified private generations into a new generation.
    MergePrivate {
        #[arg(long)]
        root: PathBuf,
        #[arg(long, required = true)]
        input: Vec<String>,
        #[arg(long)]
        output: String,
    },
    /// Publish a new private generation without a selected source.
    RemovePrivateSource {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        input: String,
        #[arg(long)]
        output: String,
        #[arg(long)]
        source: String,
    },
    /// Refresh one source using another verified private generation.
    RefreshPrivateSource {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        input: String,
        #[arg(long)]
        replacement: String,
        #[arg(long)]
        output: String,
        #[arg(long)]
        source: String,
    },
    /// Compare two verified private generations.
    ComparePrivate {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        before: String,
        #[arg(long)]
        after: String,
    },
    /// List the evidence-validated source for a private generation.
    Sources {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        generation: String,
    },
    /// Inspect a SHA-256 claim in a private generation.
    Indicator {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        generation: String,
        sha256: String,
    },
    /// Generate an offline Ed25519 keypair for release signing
    Keygen {
        #[arg(long)]
        out_public: PathBuf,
        #[arg(long)]
        out_private: PathBuf,
    },
    /// Cryptographically sign a release manifest with an Ed25519 private key
    Sign {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        out_sig: PathBuf,
    },
    /// Build a deterministic RSIDB + manifest from approved source manifests
    Build {
        /// Source manifest JSON (repeatable)
        #[arg(long = "source", required = true)]
        sources: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        manifest_out: PathBuf,
        #[arg(long)]
        db_version: String,
        /// RFC 3339 build timestamp (explicit, for reproducible builds)
        #[arg(long)]
        built_at: String,
        /// public | internal
        #[arg(long, default_value = "public")]
        profile: String,
        /// Explicitly authorized source identifier (repeatable; authorizes ingestion)
        #[arg(long = "allow-source")]
        allowed_sources: Vec<String>,
        /// Legacy source assertion (does not establish authenticity)
        #[arg(long = "verify-genuine-source")]
        verified_genuine_sources: Vec<String>,
        /// Permit all sources (development testing mode only)
        #[arg(long)]
        allow_all_sources_dev: bool,
        /// Revoke an indicator hash (repeatable hex hash)
        #[arg(long = "revoke")]
        revocations: Vec<String>,
    },
    /// Verify and atomically activate a database in a store directory
    Install {
        #[arg(long)]
        store: PathBuf,
        path: PathBuf,
        /// Path to release manifest (.manifest.json)
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Path to release signature (.sig)
        #[arg(long)]
        sig: Option<PathBuf>,
        /// Path to trusted Ed25519 public key (.pub)
        #[arg(long)]
        pubkey: Option<PathBuf>,
        /// Expected SHA-256 of the candidate, obtained from a trusted channel
        #[arg(long)]
        sha256: Option<String>,
        /// Explicitly permit installation of an unsigned database (development mode)
        #[arg(long)]
        allow_unsigned: bool,
    },
    /// Re-activate the previous (last known-good) database
    Rollback {
        #[arg(long)]
        store: PathBuf,
    },
}

#[derive(Args, Debug)]
struct ScanArgs {
    /// Run the scan in a supervised Linux worker process.
    #[arg(long)]
    supervised: bool,

    /// Worker address-space limit in bytes (default 1 GiB).
    #[arg(long, default_value_t = 1_073_741_824u64)]
    worker_memory: u64,

    /// Parent-enforced worker deadline in milliseconds (default 10 seconds).
    #[arg(long, default_value_t = 10_000u64)]
    worker_timeout_ms: u64,

    #[arg(long, hide = true)]
    worker_internal: bool,

    /// Target file path to scan
    #[arg(value_name = "FILE_PATH")]
    target: PathBuf,

    /// Output structured JSON scan results
    #[arg(long)]
    json: bool,

    /// Maximum file size limit in bytes (default: 52,428,800 bytes / 50 MiB)
    #[arg(long)]
    max_size: Option<u64>,

    /// Maximum scan timeout in seconds (default: 10s)
    #[arg(long)]
    timeout: Option<u64>,

    /// Maximum MIME email nesting depth (default: 5)
    #[arg(long)]
    max_depth: Option<usize>,

    /// Path to an external JSON rule pack to load
    #[arg(long)]
    rules: Option<PathBuf>,

    /// Display resident memory usage statistics
    #[arg(long)]
    memory: bool,

    /// Explicit unverified legacy/test RSIDB file. Env: RAXOSENTINEL_DB
    #[arg(long, env = "RAXOSENTINEL_DB", conflicts_with_all = ["db_store", "private_db_root"]) ]
    db: Option<PathBuf>,

    /// Owner-controlled signed public-release prototype directory.
    #[arg(long, requires_all = ["public_key", "public_approval_key", "public_state"], conflicts_with_all = ["db", "db_store", "private_db_root"])]
    public_release: Option<PathBuf>,
    /// Explicitly trusted Ed25519 public key for public-release verification.
    #[arg(long, requires = "public_release")]
    public_key: Option<PathBuf>,
    /// Independently trusted reviewer's Ed25519 public key.
    #[arg(long, requires = "public_release")]
    public_approval_key: Option<PathBuf>,
    /// Owner-controlled trusted rollback state directory.
    #[arg(long, requires = "public_release")]
    public_state: Option<PathBuf>,

    /// Owner-controlled private storage root (requires --private-generation).
    #[arg(long, requires = "private_generation", conflicts_with_all = ["db", "db_store"])]
    private_db_root: Option<PathBuf>,

    /// Immutable private generation to verify before scanning.
    #[arg(long, requires = "private_db_root")]
    private_generation: Option<String>,

    /// RSIDB store directory managed by `db install` (uses current, falls back to previous)
    #[arg(long, env = "RAXOSENTINEL_DB_STORE")]
    db_store: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();

    let subscriber_builder = tracing_subscriber::fmt();
    if cli.verbose {
        subscriber_builder
            .with_max_level(tracing::Level::DEBUG)
            .init();
    } else {
        subscriber_builder
            .with_max_level(tracing::Level::WARN)
            .init();
    }

    match cli.command {
        Commands::Scan(args) => {
            let exit_code = run_scan(args);
            process::exit(exit_code);
        }
        Commands::Db(cmd) => process::exit(run_db(cmd)),
    }
}

fn run_scan(args: ScanArgs) -> i32 {
    #[cfg(debug_assertions)]
    if args.worker_internal {
        if let Ok(action) = std::env::var("RAXOSENTINEL_TEST_WORKER_ACTION") {
            match action.as_str() {
                "hang" => loop {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                },
                "crash" => {
                    unsafe {
                        libc::raise(libc::SIGKILL);
                    }
                    return 3;
                }
                "malformed" => {
                    println!("not a scan report");
                    return 0;
                }
                "oversized" => {
                    use std::io::Write;
                    let _ = std::io::stdout().write_all(&vec![b'x'; 2 * 1024 * 1024 + 1]);
                    return 0;
                }
                _ => {}
            }
        }
    }
    if args.supervised {
        return supervised::run(&args);
    }

    let mut limits = ResourceLimits::default();
    if let Some(max_sz) = args.max_size {
        limits.max_file_size = max_sz;
    }
    if let Some(to) = args.timeout {
        limits.max_scan_duration_ms = to.saturating_mul(1000);
    }
    if let Some(depth) = args.max_depth {
        limits.max_email_depth = depth;
    }

    let mut db = SignatureDatabase::with_defaults();
    if let Some(ref rules_path) = args.rules {
        if let Err(e) = load_rules_from_file(rules_path, &mut db) {
            eprintln!(
                "Error loading external rules from '{}': {}",
                rules_path.display(),
                e
            );
            return 3;
        }
    }

    // A configured database that fails validation is a hard error: never scan "without" it.
    if let Some(ref release) = args.public_release {
        let key_path = args.public_key.as_ref().expect("clap requires public key");
        let reviewer_path = args
            .public_approval_key
            .as_ref()
            .expect("clap requires approval key");
        let state = args
            .public_state
            .as_ref()
            .expect("clap requires public state");
        match crypto::load_verifying_key_from_file(key_path)
            .map_err(|e| e.to_string())
            .and_then(|key| {
                raxosentinel_signatures::rsidb::public_release::local::load(
                    release,
                    state,
                    key,
                    crypto::load_verifying_key_from_file(reviewer_path)
                        .map_err(|e| e.to_string())?,
                    env!("CARGO_PKG_VERSION"),
                )
            }) {
            Ok(index) => db.attach_rsidb(Arc::new(index)),
            Err(e) => {
                eprintln!("Error: signed public release rejected: {e}");
                return 3;
            }
        }
    } else if let Some(ref root) = args.private_db_root {
        match raxosentinel_signatures::rsidb::malwarebazaar::private_store::incomplete(root) {
            Ok(entries) if !entries.is_empty() => eprintln!(
                "Warning: incomplete private staging entries require inspection: {}",
                entries.join(", ")
            ),
            Ok(_) => {}
            Err(e) => {
                eprintln!("Error: private database recovery inspection failed: {e}");
                return 3;
            }
        }
        match raxosentinel_signatures::rsidb::malwarebazaar::private_store::load(
            root,
            args.private_generation
                .as_deref()
                .expect("clap requires generation"),
        ) {
            Ok(index) => db.attach_rsidb(Arc::new(index)),
            Err(e) => {
                eprintln!("Error: private database rejected: {e}");
                return 3;
            }
        }
    } else if let Some(ref p) = args.db {
        eprintln!(
            "Warning: loading legacy/test database without acquisition evidence verification"
        );
        match MmapCompactDirIndex::from_file(p) {
            Ok(index) => db.attach_rsidb(Arc::new(index)),
            Err(e) => {
                eprintln!("Error: RSIDB database '{}' rejected: {}", p.display(), e);
                return 3;
            }
        }
    } else if let Some(ref store) = args.db_store {
        eprintln!("Warning: legacy release store does not verify private acquisition evidence");
        match DbStore::new(store).open_active() {
            Ok(active) => {
                if active.fell_back {
                    eprintln!(
                        "Warning: using last known-good database {} ({})",
                        active.release,
                        active.fallback_reason.unwrap_or_default()
                    );
                }
                db.attach_rsidb(Arc::new(active.index));
            }
            Err(e) => {
                eprintln!(
                    "Error: no valid RSIDB database in store '{}': {}",
                    store.display(),
                    e
                );
                return 3;
            }
        }
    }

    let mut tracker = ResourceTracker::new(limits);
    let report = if args.worker_internal {
        scan_descriptor(&args.target, &db, &mut tracker)
    } else {
        scan_path(&args.target, &db, &mut tracker)
    };

    let mem_usage = if args.memory {
        Some(MemoryUsage::capture())
    } else {
        None
    };

    if args.json {
        match report.to_json_pretty() {
            Ok(json_str) => println!("{}", json_str),
            Err(e) => {
                eprintln!("Error serializing scan report to JSON: {}", e);
                return 3;
            }
        }
    } else {
        print_human_report(&report, mem_usage.as_ref());
    }

    report.status.exit_code()
}

fn scan_descriptor(
    path: &Path,
    db: &SignatureDatabase,
    tracker: &mut ResourceTracker,
) -> ScanReport {
    let fail = |message: String| {
        ScanReport::new(
            TargetMetadata {
                path: Some(path.display().to_string()),
                file_name: path.file_name().map(|v| v.to_string_lossy().into_owned()),
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
    };
    #[cfg(target_os = "linux")]
    {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // fd 0 is supplied by the supervisor and must be a regular file.
        if unsafe { libc::fstat(0, stat.as_mut_ptr()) } != 0 {
            return fail("Invalid worker input descriptor".into());
        }
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
            return fail("Worker input descriptor is not a regular file".into());
        }
    }
    let mut input = std::io::stdin().lock();
    let mut data = Vec::new();
    let mut chunk = [0u8; 65536];
    loop {
        let n = match input.read(&mut chunk) {
            Ok(n) => n,
            Err(e) => return fail(format!("Read failed: {e}")),
        };
        if n == 0 {
            break;
        }
        if let Err(e) = tracker.record_bytes_read(n) {
            return fail(e.to_string());
        }
        if data.try_reserve(n).is_err() {
            return fail("Cannot allocate scan buffer".into());
        }
        data.extend_from_slice(&chunk[..n]);
    }
    let file_type = detect_type(&data);
    let is_email = file_type.category == FileCategory::Email
        || file_type.mime_type == "message/rfc822"
        || path
            .extension()
            .map(|e| e.eq_ignore_ascii_case("eml") || e.eq_ignore_ascii_case("msg"))
            .unwrap_or(false);
    let scanner = EmailScanner::new(db);
    let result = if is_email {
        tracker.reset_bytes_read();
        scanner.scan_bytes(&data, path.to_str(), tracker)
    } else {
        scanner.scan_object(
            &data,
            &path
                .file_name()
                .map(|v| v.to_string_lossy().into_owned())
                .unwrap_or_default(),
            None,
            tracker,
            0,
        )
    };
    match result {
        Ok(mut report) => {
            report.target.path = Some(path.display().to_string());
            report
        }
        Err(e) => fail(format!("Scan failed: {e}")),
    }
}

#[cfg(target_os = "linux")]
mod supervised;
#[cfg(not(target_os = "linux"))]
mod supervised {
    pub fn run(_: &super::ScanArgs) -> i32 {
        eprintln!("Supervised scanning requires Linux");
        3
    }
}

fn scan_path(path: &Path, db: &SignatureDatabase, tracker: &mut ResourceTracker) -> ScanReport {
    let start_ms = tracker.elapsed_millis();

    if !path.exists() {
        let duration_ms = tracker.elapsed_millis().saturating_sub(start_ms);
        return ScanReport::new(
            TargetMetadata {
                path: Some(path.display().to_string()),
                file_name: path.file_name().map(|n| n.to_string_lossy().to_string()),
                file_size_bytes: 0,
                sha256: String::new(),
                detected_mime: "application/x-empty".to_string(),
                declared_mime: None,
            },
            ScanStatus::Failed,
            Vec::new(),
            Vec::new(),
            duration_ms,
            Some(format!("File does not exist: {}", path.display())),
        );
    }

    // Pre-check file size
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            let duration_ms = tracker.elapsed_millis().saturating_sub(start_ms);
            return ScanReport::new(
                TargetMetadata {
                    path: Some(path.display().to_string()),
                    file_name: path.file_name().map(|n| n.to_string_lossy().to_string()),
                    file_size_bytes: 0,
                    sha256: String::new(),
                    detected_mime: "application/unknown".to_string(),
                    declared_mime: None,
                },
                ScanStatus::Failed,
                Vec::new(),
                Vec::new(),
                duration_ms,
                Some(format!(
                    "Cannot read metadata for '{}': {}",
                    path.display(),
                    e
                )),
            );
        }
    };
    // Reject non-regular files (directories, fifos, sockets, character/block devices)
    if !metadata.is_file() {
        let duration_ms = tracker.elapsed_millis().saturating_sub(start_ms);
        let mime = if metadata.is_dir() {
            "inode/directory"
        } else {
            "inode/special"
        };
        return ScanReport::new(
            TargetMetadata {
                path: Some(path.display().to_string()),
                file_name: path.file_name().map(|n| n.to_string_lossy().to_string()),
                file_size_bytes: metadata.len(),
                sha256: String::new(),
                detected_mime: mime.to_string(),
                declared_mime: None,
            },
            ScanStatus::Unsupported,
            Vec::new(),
            Vec::new(),
            duration_ms,
            Some(format!(
                "Target is not a regular file (directory or special device): {}",
                path.display()
            )),
        );
    }

    if let Err(e) = tracker.check_file_size(metadata.len()) {
        let duration_ms = tracker.elapsed_millis().saturating_sub(start_ms);
        return ScanReport::new(
            TargetMetadata {
                path: Some(path.display().to_string()),
                file_name: path.file_name().map(|n| n.to_string_lossy().to_string()),
                file_size_bytes: metadata.len(),
                sha256: String::new(),
                detected_mime: "application/unknown".to_string(),
                declared_mime: None,
            },
            ScanStatus::Failed,
            Vec::new(),
            Vec::new(),
            duration_ms,
            Some(e.to_string()),
        );
    }

    // Detect file type
    let file_type = match detect_file_type(path) {
        Ok(ft) => ft,
        Err(e) => {
            let duration_ms = tracker.elapsed_millis().saturating_sub(start_ms);
            return ScanReport::new(
                TargetMetadata {
                    path: Some(path.display().to_string()),
                    file_name: path.file_name().map(|n| n.to_string_lossy().to_string()),
                    file_size_bytes: metadata.len(),
                    sha256: String::new(),
                    detected_mime: "application/unknown".to_string(),
                    declared_mime: None,
                },
                ScanStatus::Failed,
                Vec::new(),
                Vec::new(),
                duration_ms,
                Some(format!("File identification failed: {}", e)),
            );
        }
    };

    // If identified as an Email / MIME message, use deep EmailScanner
    let has_eml_ext = path
        .extension()
        .map(|e| e.eq_ignore_ascii_case("eml") || e.eq_ignore_ascii_case("msg"))
        .unwrap_or(false);

    if file_type.category == FileCategory::Email
        || file_type.mime_type == "message/rfc822"
        || has_eml_ext
    {
        let email_scanner = EmailScanner::new(db);
        match email_scanner.scan_file(path, tracker) {
            Ok(report) => return report,
            Err(e) => {
                let duration_ms = tracker.elapsed_millis().saturating_sub(start_ms);
                return ScanReport::new(
                    TargetMetadata {
                        path: Some(path.display().to_string()),
                        file_name: path.file_name().map(|n| n.to_string_lossy().to_string()),
                        file_size_bytes: metadata.len(),
                        sha256: String::new(),
                        detected_mime: file_type.mime_type,
                        declared_mime: Some("message/rfc822".to_string()),
                    },
                    ScanStatus::Failed,
                    Vec::new(),
                    Vec::new(),
                    duration_ms,
                    Some(format!("Email scanning failed: {}", e)),
                );
            }
        }
    }

    // General file scan: bounded read (TOCTOU-safe cap), then full object inspection
    // (builtin hashes, RSIDB, patterns, ZIP extraction, unsupported-container detection).
    let filename_str = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let fail = |tracker: &ResourceTracker, size: u64, msg: String| {
        ScanReport::new(
            TargetMetadata {
                path: Some(path.display().to_string()),
                file_name: Some(filename_str.clone()),
                file_size_bytes: size,
                sha256: String::new(),
                detected_mime: file_type.mime_type.clone(),
                declared_mime: None,
            },
            ScanStatus::Failed,
            Vec::new(),
            Vec::new(),
            tracker.elapsed_millis().saturating_sub(start_ms),
            Some(msg),
        )
    };

    let mut data = Vec::new();
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(e) => return fail(tracker, metadata.len(), format!("Failed to open file: {e}")),
    };
    let mut chunk = [0u8; 64 * 1024];
    loop {
        if let Err(e) = tracker.check_timeout() {
            return fail(tracker, data.len() as u64, e.to_string());
        }
        let n = match file.read(&mut chunk) {
            Ok(n) => n,
            Err(e) => {
                return fail(
                    tracker,
                    data.len() as u64,
                    format!("Failed to read file: {e}"),
                )
            }
        };
        if n == 0 {
            break;
        }
        if let Err(e) = tracker.record_bytes_read(n) {
            return fail(tracker, data.len() as u64 + n as u64, e.to_string());
        }
        if data.try_reserve(n).is_err() {
            return fail(
                tracker,
                data.len() as u64,
                "Cannot allocate scan buffer".into(),
            );
        }
        data.extend_from_slice(&chunk[..n]);
    }

    let scanner = EmailScanner::new(db);
    match scanner.scan_object(&data, &filename_str, None, tracker, 0) {
        Ok(mut report) => {
            report.target.path = Some(path.display().to_string());
            report.scan_duration_ms = tracker.elapsed_millis().saturating_sub(start_ms);
            report
        }
        Err(e) => fail(tracker, data.len() as u64, format!("Scan failed: {}", e)),
    }
}

fn run_db(cmd: DbCommand) -> i32 {
    match cmd {
        DbCommand::InitPublicState { root } => match raxosentinel_signatures::rsidb::public_release::local::initialize(&root) {
            Ok(()) => { println!("Public release prototype state initialized"); 0 },
            Err(e) => { eprintln!("Error: cannot initialize public release state: {e}"); 3 }
        },
        DbCommand::MergePrivate {
            root,
            input,
            output,
        } => {
            let inputs: Vec<_> = input.iter().map(String::as_str).collect();
            match raxosentinel_signatures::rsidb::malwarebazaar::private_store::multi::merge(
                &root, &inputs, &output,
            ) {
                Ok(()) => {
                    println!("Private generation published");
                    0
                }
                Err(e) => {
                    eprintln!("Error: private merge failed: {e}");
                    3
                }
            }
        }
        DbCommand::RemovePrivateSource {
            root,
            input,
            output,
            source,
        } => {
            match raxosentinel_signatures::rsidb::malwarebazaar::private_store::multi::remove_source(
                &root, &input, &output, &source,
            ) {
                Ok(()) => {
                    println!("Private generation published");
                    0
                }
                Err(e) => {
                    eprintln!("Error: private source removal failed: {e}");
                    3
                }
            }
        }
        DbCommand::RefreshPrivateSource { root, input, replacement, output, source } => {
            match raxosentinel_signatures::rsidb::malwarebazaar::private_store::multi::refresh_source(&root, &input, &replacement, &output, &source) {
                Ok(()) => { println!("Private generation published"); 0 },
                Err(e) => { eprintln!("Error: private source refresh failed: {e}"); 3 }
            }
        }
        DbCommand::ComparePrivate { root, before, after } => match raxosentinel_signatures::rsidb::malwarebazaar::private_store::multi::history::compare(&root, &before, &after) {
            Ok(report) => { println!("{}", serde_json::to_string_pretty(&report).expect("comparison serialization")); 0 },
            Err(e) => { eprintln!("Error: private generation comparison failed: {e}"); 3 }
        },
        DbCommand::Sources { root, generation } => {
            match raxosentinel_signatures::rsidb::malwarebazaar::private_store::multi::history::inspect(
                &root,
                &generation,
            ) {
                Ok((registry, _)) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&registry).expect("source serialization")
                    );
                    0
                }
                Err(e) => {
                    eprintln!("Error: private database rejected: {e}");
                    3
                }
            }
        }
        DbCommand::Indicator {
            root,
            generation,
            sha256,
        } => {
            if sha256.len() != 64 || !sha256.bytes().all(|c| c.is_ascii_hexdigit()) {
                eprintln!("Error: SHA-256 must be 64 hexadecimal digits");
                return 2;
            }
            match raxosentinel_signatures::rsidb::malwarebazaar::private_store::multi::history::inspect(
                &root,
                &generation,
            ) {
                Ok((_, associations)) => {
                    let found: Vec<_> = associations.indicators
                        .into_iter()
                        .filter(|claim| claim.sha256.eq_ignore_ascii_case(&sha256))
                        .map(|claim| {
                            let mut value = serde_json::to_value(&claim).expect("claim serialization");
                            value["quarantine_reason"] = if claim.quarantined { serde_json::json!("conflicting file sizes") } else { serde_json::Value::Null };
                            value
                        })
                        .collect();
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&found).expect("claim serialization")
                    );
                    0
                }
                Err(e) => {
                    eprintln!("Error: private database rejected: {e}");
                    3
                }
            }
        }
        DbCommand::Verify { path } => {
            let t = std::time::Instant::now();
            match MmapCompactDirIndex::from_file(&path) {
                Ok(idx) => {
                    println!(
                        "OK {} md5={} sha1={} sha256={} names={} verify_ms={:.2}\nprovenance: {}",
                        path.display(),
                        idx.record_count(raxosentinel_signatures::rsidb::HashAlgorithm::Md5),
                        idx.record_count(raxosentinel_signatures::rsidb::HashAlgorithm::Sha1),
                        idx.record_count(raxosentinel_signatures::rsidb::HashAlgorithm::Sha256),
                        idx.name_count(),
                        t.elapsed().as_secs_f64() * 1000.0,
                        idx.provenance()
                    );
                    0
                }
                Err(e) => {
                    eprintln!("INVALID {}: {}", path.display(), e);
                    3
                }
            }
        }
        DbCommand::Keygen {
            out_public,
            out_private,
        } => {
            let (sk, vk) = crypto::generate_keypair();
            if let Err(e) = crypto::save_signing_key_to_file(&sk, &out_private) {
                eprintln!("Failed to save private key: {}", e);
                return 3;
            }
            if let Err(e) = crypto::save_verifying_key_to_file(&vk, &out_public) {
                eprintln!("Failed to save public key: {}", e);
                return 3;
            }
            println!("Generated Ed25519 keypair for release signing:");
            println!("  Public key : {}", out_public.display());
            println!(
                "  Private key: {} (KEEP SECRET, NEVER COMMIT TO GIT)",
                out_private.display()
            );
            0
        }
        DbCommand::Sign {
            manifest,
            key,
            out_sig,
        } => {
            let sk = match crypto::load_signing_key_from_file(&key) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("Failed to load signing key '{}': {}", key.display(), e);
                    return 3;
                }
            };
            let m_bytes = match std::fs::read(&manifest) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Failed to read manifest '{}': {}", manifest.display(), e);
                    return 3;
                }
            };
            let sig = crypto::sign_bytes(&m_bytes, &sk);
            if let Err(e) = crypto::save_signature_to_file(&sig, &out_sig) {
                eprintln!("Failed to save signature '{}': {}", out_sig.display(), e);
                return 3;
            }
            println!(
                "Signed manifest {} -> {}",
                manifest.display(),
                out_sig.display()
            );
            0
        }
        DbCommand::Build {
            sources,
            out,
            manifest_out,
            db_version,
            built_at,
            profile,
            allowed_sources,
            verified_genuine_sources,
            allow_all_sources_dev,
            revocations,
        } => {
            let profile = match profile.as_str() {
                "public" => BuildProfile::Public,
                "internal" => BuildProfile::Internal,
                other => {
                    eprintln!("Unknown profile '{}'", other);
                    return 2;
                }
            };
            let mut pipeline = IngestPipeline::new(profile);
            if allow_all_sources_dev {
                eprintln!("[WARN] Permitting all sources in development testing mode");
                pipeline.authorize_all_for_testing();
            } else {
                for s in &allowed_sources {
                    pipeline.authorize_source(s);
                }
            }
            for s in &verified_genuine_sources {
                pipeline.verify_genuine_source(s);
            }
            for r in &revocations {
                if let Err(e) = pipeline.revoke_hash(r) {
                    eprintln!("Invalid revocation hash '{}': {}", r, e);
                    return 2;
                }
            }

            for src in &sources {
                let res = (|| -> Result<(), String> {
                    let text = std::fs::read_to_string(src).map_err(|e| e.to_string())?;
                    let manifest: SourceManifest =
                        serde_json::from_str(&text).map_err(|e| e.to_string())?;
                    let base = src.parent().unwrap_or(Path::new("."));
                    let path = manifest
                        .resolve_path(base)
                        .map_err(|e| format!("path traversal or access error: {}", e))?;
                    let content = std::fs::read(&path).map_err(|e| e.to_string())?;
                    let r = pipeline
                        .add_source(manifest, &content)
                        .map_err(|e| e.to_string())?;
                    eprintln!(
                        "source {}: accepted={} rejected={} duplicates={} ignored={} [effective_kind={:?}, status={}]",
                        r.source_id,
                        r.accepted,
                        r.rejected,
                        r.duplicates,
                        r.ignored_lines,
                        r.effective_kind,
                        r.authenticity_status
                    );
                    Ok(())
                })();
                if let Err(e) = res {
                    eprintln!("Error ingesting source '{}': {}", src.display(), e);
                    return 3;
                }
            }
            let (bytes, manifest) = match pipeline.build(&db_version, &built_at) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Build failed: {}", e);
                    return 3;
                }
            };
            let json = serde_json::to_string_pretty(&manifest).unwrap_or_default();
            if let Err(e) =
                std::fs::write(&out, &bytes).and_then(|_| std::fs::write(&manifest_out, json))
            {
                eprintln!("Write failed: {}", e);
                return 3;
            }
            println!(
                "built {} sha256={} accepted={} rejected={} duplicates={} genuine={} synthetic={}",
                out.display(),
                manifest.db_sha256,
                manifest.total_accepted,
                manifest.total_rejected,
                manifest.total_duplicates,
                manifest.genuine_records,
                manifest.synthetic_records,
            );
            0
        }
        DbCommand::Install {
            store,
            path,
            manifest,
            sig,
            pubkey,
            sha256: _,
            allow_unsigned,
        } => {
            let pubkey_obj = if let Some(pk_path) = &pubkey {
                match crypto::load_verifying_key_from_file(pk_path) {
                    Ok(k) => Some(k),
                    Err(e) => {
                        eprintln!("Failed to load public key '{}': {}", pk_path.display(), e);
                        return 3;
                    }
                }
            } else {
                None
            };

            if allow_unsigned {
                eprintln!(
                    "[WARN] Installing database without Ed25519 signature verification (--allow-unsigned specified)"
                );
            }

            match DbStore::new(store).install_release(
                &path,
                manifest.as_deref(),
                sig.as_deref(),
                pubkey_obj.as_ref(),
                allow_unsigned,
            ) {
                Ok(r) => {
                    println!("activated {}", r);
                    0
                }
                Err(e) => {
                    eprintln!("Install rejected: {}", e);
                    3
                }
            }
        }
        DbCommand::Rollback { store } => match DbStore::new(store).rollback() {
            Ok(r) => {
                println!("rolled back to {}", r);
                0
            }
            Err(e) => {
                eprintln!("Rollback failed: {}", e);
                3
            }
        },
    }
}

fn print_human_report(report: &ScanReport, memory: Option<&MemoryUsage>) {
    println!("================================================================================");
    println!("                       RAXOSENTINEL MALWARE SCAN REPORT                         ");
    println!("================================================================================");
    println!("Engine Version   : {}", report.engine_version);
    if let Some(ref path) = report.target.path {
        println!("Target Path      : {}", path);
    }
    println!(
        "File Size        : {} bytes ({:.2} KiB)",
        report.target.file_size_bytes,
        report.target.file_size_bytes as f64 / 1024.0
    );
    if !report.target.sha256.is_empty() {
        println!("SHA-256          : {}", report.target.sha256);
    }
    println!("Content Type     : {}", report.target.detected_mime);
    println!("Scan Duration    : {} ms", report.scan_duration_ms);

    if let Some(mem) = memory {
        println!(
            "Memory Usage     : RSS: {:.2} MiB | Peak RSS: {:.2} MiB",
            mem.current_rss_mb(),
            mem.peak_rss_mb()
        );
    }

    println!("--------------------------------------------------------------------------------");
    match report.status {
        ScanStatus::Clean => {
            println!("Overall Status   : [ CLEAN ]");
            println!("Summary          : {}", report.status_description);
            println!();
            println!("{}", report.safety_disclaimer);
        }
        ScanStatus::Infected => {
            println!("Overall Status   : [ DETECTED ]");
            println!("Summary          : {}", report.status_description);
            println!();
            if report.threats.is_empty() {
                println!("Detections are listed in sub-target reports.");
            } else {
                println!("Detected Threats ({}):", report.threats.len());
            }
            for (idx, t) in report.threats.iter().enumerate() {
                println!(
                    "  [{}] {} | Category: {} | Severity: {} | Type: {}",
                    idx + 1,
                    t.name,
                    t.category,
                    t.severity,
                    t.detection_type,
                );
                println!("      Description : {}", t.description);
                println!("      Triggered By: {}", t.matched_by);
                if let Some(ref loc) = t.location {
                    println!("      Location    : {}", loc);
                }
            }
        }
        ScanStatus::Unsupported => {
            println!("Overall Status   : [ UNSCANNED ]");
            println!("Summary          : {}", report.status_description);
            if let Some(ref err) = report.error {
                println!("Details          : {}", err);
            }
        }
        ScanStatus::Failed => {
            println!("Overall Status   : [ ERROR ]");
            println!("Summary          : {}", report.status_description);
            if let Some(ref err) = report.error {
                println!("Error Details    : {}", err);
            }
        }
    }

    if !report.sub_targets.is_empty() {
        println!(
            "--------------------------------------------------------------------------------"
        );
        println!("Extracted sub-targets ({}):", report.sub_targets.len());
        fn print_subtargets(subs: &[ScanReport], depth: usize) {
            let indent = "  ".repeat(depth.min(32));
            for sub in subs {
                let name = sub.target.file_name.as_deref().unwrap_or("unnamed");
                println!(
                    "{}- {} ({} bytes, Type: {}) -> Status: {}",
                    indent, name, sub.target.file_size_bytes, sub.target.detected_mime, sub.status
                );
                for threat in &sub.threats {
                    println!(
                        "{}  Threat: {} [{}] ({})",
                        indent, threat.name, threat.severity, threat.category
                    );
                }
                print_subtargets(&sub.sub_targets, depth + 1);
            }
        }
        print_subtargets(&report.sub_targets, 1);
    }

    println!("================================================================================");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_cli_scan_clean_text_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "Hello world, this is a clean file.").unwrap();

        let db = SignatureDatabase::with_defaults();
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        let report = scan_path(file.path(), &db, &mut tracker);
        assert_eq!(report.status, ScanStatus::Clean);
        assert!(report.threats.is_empty());
    }

    #[test]
    fn test_cli_scan_eicar_file() {
        let mut file = NamedTempFile::new().unwrap();
        write!(
            file,
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        )
        .unwrap();

        let db = SignatureDatabase::with_defaults();
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        let report = scan_path(file.path(), &db, &mut tracker);
        assert_eq!(report.status, ScanStatus::Infected);
        assert!(!report.threats.is_empty());
        assert_eq!(report.threats[0].name, "EICAR-Standard-Antivirus-Test-File");
    }

    #[test]
    fn test_cli_scan_nonexistent_file() {
        let path = Path::new("/nonexistent/file/path/that/does/not/exist");
        let db = SignatureDatabase::with_defaults();
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        let report = scan_path(path, &db, &mut tracker);
        assert_eq!(report.status, ScanStatus::Failed);
    }

    #[test]
    fn test_cli_scan_directory_target() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db = SignatureDatabase::with_defaults();
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        let report = scan_path(temp_dir.path(), &db, &mut tracker);
        assert_eq!(report.status, ScanStatus::Unsupported);
        assert!(report
            .error
            .as_ref()
            .unwrap()
            .contains("not a regular file"));
    }
}
