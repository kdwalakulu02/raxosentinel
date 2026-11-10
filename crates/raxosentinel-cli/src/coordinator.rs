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

use super::hot_reload::DatabaseManager;
use super::print_human_report;
use super::supervised::{
    error_report, execute_worker_on_snapshot, sealed_snapshot_with_budget, SnapshotBudget,
    SupervisedWorkerConfig,
};
use clap::Args;
use raxosentinel_core::{ScanReport, ScanStatus};
use raxosentinel_signatures::rsidb::crypto;
use raxosentinel_signatures::rsidb::malwarebazaar::private_store;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub const MAX_REQUEST_PAYLOAD: usize = 65_536; // 64 KiB
pub const MAX_RESPONSE_PAYLOAD: usize = 2 * 1024 * 1024; // 2 MiB

static RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn handle_signal(_: libc::c_int) {
    RUNNING.store(false, Ordering::SeqCst);
}

#[derive(Args, Debug, Clone)]
pub struct ServeArgs {
    /// Unix domain socket path to bind
    #[arg(long, env = "RAXOSENTINEL_SOCKET")]
    pub socket: PathBuf,

    /// Permitted client user ID (default: current process UID)
    #[arg(long)]
    pub authorized_uid: Option<u32>,

    /// Maximum number of active worker scans running simultaneously (default: 1)
    #[arg(long, default_value_t = 1)]
    pub max_workers: usize,

    /// Maximum number of RSIDB generations kept resident in memory simultaneously (default: 2)
    #[arg(long, default_value_t = 2)]
    pub max_resident_generations: usize,

    /// Maximum number of queued/pending requests while a scan is active (default: 1)
    #[arg(long, default_value_t = 1)]
    pub max_pending: usize,

    /// Maximum total bytes of in-flight sealed snapshots allowed concurrently (default: 200 MiB)
    #[arg(long, default_value_t = 209_715_200u64)]
    pub max_total_snapshot_bytes: u64,

    /// Client connection read timeout in seconds (default: 5s)
    #[arg(long, default_value_t = 5)]
    pub client_timeout_secs: u64,

    /// Worker address-space limit in bytes (default 1 GiB).
    #[arg(long, default_value_t = 1_073_741_824u64)]
    pub worker_memory: u64,

    /// Parent-enforced worker deadline in milliseconds (default 10 seconds).
    #[arg(long, default_value_t = 10_000u64)]
    pub worker_timeout_ms: u64,

    /// Maximum file size limit in bytes (default: 50 MiB).
    #[arg(long, default_value_t = 52_428_800u64)]
    pub max_size: u64,

    /// Maximum scan timeout in seconds (default: 10s)
    #[arg(long)]
    pub timeout: Option<u64>,

    /// Maximum MIME email nesting depth (default: 5).
    #[arg(long, default_value_t = 5)]
    pub max_depth: usize,

    /// Optional external JSON rule pack to pass to workers.
    #[arg(long)]
    pub rules: Option<PathBuf>,

    /// Trusted local YARA-X rule file or directory (repeatable). Rules are compiled
    /// at startup; any error prevents the service from starting.
    #[arg(long = "yara-rules", value_name = "PATH")]
    pub yara_rules: Vec<PathBuf>,

    /// Owner-controlled private storage root.
    #[arg(long, conflicts_with_all = ["db", "db_store", "public_release"])]
    pub private_db_root: Option<PathBuf>,

    /// Immutable private generation to verify before serving (defaults to active pointer).
    #[arg(long, requires = "private_db_root")]
    pub private_generation: Option<String>,

    /// Owner-controlled signed public-release prototype directory.
    #[arg(long, requires_all = ["public_key", "public_approval_key", "public_state"], conflicts_with_all = ["db", "db_store", "private_db_root"])]
    pub public_release: Option<PathBuf>,

    /// Explicitly trusted Ed25519 public key.
    #[arg(long, requires = "public_release")]
    pub public_key: Option<PathBuf>,

    /// Independently trusted reviewer's Ed25519 public key.
    #[arg(long, requires = "public_release")]
    pub public_approval_key: Option<PathBuf>,

    /// Owner-controlled trusted rollback state directory.
    #[arg(long, requires = "public_release")]
    pub public_state: Option<PathBuf>,

    /// Legacy database options are rejected
    #[arg(long, hide = true)]
    pub db: Option<PathBuf>,

    #[arg(long, hide = true)]
    pub db_store: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct ClientArgs {
    /// Unix domain socket path
    #[arg(long, env = "RAXOSENTINEL_SOCKET")]
    pub socket: PathBuf,

    /// Target file path to submit for scanning
    #[arg(value_name = "FILE_PATH")]
    pub target: PathBuf,

    /// Output structured JSON scan results
    #[arg(long)]
    pub json: bool,

    /// Output the complete coordinator response, including database generation
    #[arg(long, conflicts_with = "json")]
    pub json_envelope: bool,

    /// Requested maximum file size in bytes
    #[arg(long)]
    pub max_size: Option<u64>,

    /// Requested scan timeout in seconds
    #[arg(long)]
    pub timeout: Option<u64>,

    /// Requested maximum email MIME depth
    #[arg(long)]
    pub max_depth: Option<usize>,

    #[arg(long, hide = true)]
    pub test_worker_action: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScanRequest {
    pub file_name: Option<String>,
    pub max_size: Option<u64>,
    pub timeout: Option<u64>,
    pub max_depth: Option<usize>,
    pub test_worker_action: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoordinatorVerdict {
    Clean,
    #[serde(rename = "DETECTED")]
    Detected,
    #[serde(rename = "UNSCANNED")]
    Unscanned,
    #[serde(rename = "ERROR")]
    Error,
    #[serde(rename = "BUSY")]
    Busy,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CoordinatorResponse {
    pub status: CoordinatorVerdict,
    pub report: Option<ScanReport>,
    pub error: Option<String>,
    /// Stable reason for recognized timeout errors; absent for other errors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database_generation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub degraded_freshness: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_generation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reload_load_time_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reload_switch_latency_micros: Option<u64>,
}

/// Verify database generation before accepting scan requests.
pub fn verify_startup_database(args: &ServeArgs) -> Result<(), String> {
    if args.db.is_some() || args.db_store.is_some() {
        return Err("Coordinator rejects legacy database options (--db, --db-store)".into());
    }

    if args.private_db_root.is_none() && args.public_release.is_none() {
        return Err("Coordinator requires an explicitly selected, verified private generation or authenticated signed-public release. Silent fallback to built-in rules is prohibited.".into());
    }

    if let Some(ref root) = args.private_db_root {
        let generation = match args.private_generation.as_deref() {
            Some(g) => g.to_string(),
            None => private_store::resolve_generation(root, "current")
                .map_err(|e| format!("Cannot resolve active private generation: {e}"))?,
        };
        match private_store::incomplete(root) {
            Ok(entries) if !entries.is_empty() => {
                return Err(format!(
                    "Incomplete private staging entries require inspection: {}",
                    entries.join(", ")
                ));
            }
            Ok(_) => {}
            Err(e) => {
                return Err(format!("Private database recovery inspection failed: {e}"));
            }
        }
        private_store::load(root, &generation)
            .map_err(|e| format!("Private database verification failed: {e}"))?;
        tracing::info!("Private generation '{}' verified successfully", generation);
    } else if let Some(ref release) = args.public_release {
        let key_path = args
            .public_key
            .as_ref()
            .ok_or("Missing --public-key for public release")?;
        let reviewer_path = args
            .public_approval_key
            .as_ref()
            .ok_or("Missing --public-approval-key for public release")?;
        let state = args
            .public_state
            .as_ref()
            .ok_or("Missing --public-state for public release")?;
        let key = crypto::load_verifying_key_from_file(key_path).map_err(|e| e.to_string())?;
        let reviewer =
            crypto::load_verifying_key_from_file(reviewer_path).map_err(|e| e.to_string())?;
        raxosentinel_signatures::rsidb::public_release::local::load(
            release,
            state,
            key,
            reviewer,
            env!("CARGO_PKG_VERSION"),
        )
        .map_err(|e| format!("Signed public release verification failed: {e}"))?;
        tracing::info!("Signed public release verified successfully");
    }

    Ok(())
}

/// Restrictive owner-controlled socket directory and safe path validation.
pub fn prepare_socket(socket_path: &Path) -> Result<UnixListener, String> {
    let parent = socket_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.exists() {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(parent)
            .map_err(|e| format!("Cannot create socket directory '{}': {e}", parent.display()))?;
    }

    let parent_meta = std::fs::symlink_metadata(parent).map_err(|e| {
        format!(
            "Cannot inspect socket directory '{}': {e}",
            parent.display()
        )
    })?;
    if !parent_meta.is_dir() {
        return Err(format!(
            "Socket directory path '{}' is not a directory",
            parent.display()
        ));
    }
    use std::os::unix::fs::MetadataExt;
    let current_uid = unsafe { libc::geteuid() };
    if parent_meta.uid() != current_uid {
        return Err(format!(
            "Socket directory '{}' is owned by UID {} (expected current UID {}); must be owner-controlled",
            parent.display(),
            parent_meta.uid(),
            current_uid
        ));
    }
    if parent_meta.permissions().mode() & 0o077 != 0 {
        if parent == Path::new(".") {
            return Err(format!(
                "Insecure socket directory permissions on '{}' (must be owner-restricted 0700). Please specify a dedicated socket directory.",
                parent.display()
            ));
        }
        if parent_meta.permissions().mode() & 0o777 != 0o700 {
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            let updated = std::fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
            if updated.permissions().mode() & 0o077 != 0 {
                return Err(format!(
                    "Insecure socket directory permissions on '{}' (must be owner-restricted 0700)",
                    parent.display()
                ));
            }
        }
    }

    if std::fs::symlink_metadata(socket_path).is_ok() {
        let meta = std::fs::symlink_metadata(socket_path)
            .map_err(|e| format!("Cannot inspect existing socket path: {e}"))?;
        let mode = meta.permissions().mode();
        if (mode & libc::S_IFMT) != libc::S_IFSOCK {
            return Err(format!(
                "Existing path '{}' is not a socket; refusing to overwrite unrelated file",
                socket_path.display()
            ));
        }

        use std::os::unix::fs::MetadataExt;
        if meta.uid() != current_uid {
            return Err(format!(
                "Existing socket '{}' is owned by UID {} (expected {}); refusing to remove",
                socket_path.display(),
                meta.uid(),
                current_uid
            ));
        }

        // Check if an existing coordinator is actively running
        match UnixStream::connect(socket_path) {
            Ok(_) => {
                return Err(format!(
                    "Coordinator is already running on socket '{}'",
                    socket_path.display()
                ));
            }
            Err(_) => {
                // Stale socket: safe to remove
                std::fs::remove_file(socket_path).map_err(|e| {
                    format!(
                        "Cannot remove stale socket '{}': {e}",
                        socket_path.display()
                    )
                })?;
            }
        }
    }

    let listener = UnixListener::bind(socket_path)
        .map_err(|e| format!("Cannot bind Unix socket '{}': {e}", socket_path.display()))?;

    // Restrict socket file permissions to owner read/write (0600)
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Cannot set permissions on socket: {e}"))?;

    Ok(listener)
}

/// Safely clean up socket file upon shutdown, confirming it is our socket.
pub fn cleanup_socket(socket_path: &Path) {
    if let Ok(meta) = std::fs::symlink_metadata(socket_path) {
        let mode = meta.permissions().mode();
        let current_uid = unsafe { libc::geteuid() };
        use std::os::unix::fs::MetadataExt;
        if (mode & libc::S_IFMT) == libc::S_IFSOCK && meta.uid() == current_uid {
            let _ = std::fs::remove_file(socket_path);
        }
    }
}

/// Authenticate peer credentials using OS SO_PEERCRED.
pub fn check_peer_creds(stream: &UnixStream, authorized_uid: u32) -> Result<bool, String> {
    let mut ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let res = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if res != 0 || len != std::mem::size_of::<libc::ucred>() as libc::socklen_t {
        return Err(format!(
            "Cannot obtain peer credentials: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(ucred.uid == authorized_uid)
}

/// Send request data and file descriptor over Unix socket via SCM_RIGHTS.
pub fn send_fd_request(
    stream: &UnixStream,
    fd: RawFd,
    request: &ScanRequest,
) -> Result<(), String> {
    let payload =
        serde_json::to_vec(request).map_err(|e| format!("Cannot serialize request: {e}"))?;
    if payload.len() > MAX_REQUEST_PAYLOAD {
        return Err("Request payload exceeds limit".into());
    }

    let len_prefix = (payload.len() as u32).to_be_bytes();
    let mut message = Vec::with_capacity(4 + payload.len());
    message.extend_from_slice(&len_prefix);
    message.extend_from_slice(&payload);

    let mut iov = libc::iovec {
        iov_base: message.as_mut_ptr() as *mut libc::c_void,
        iov_len: message.len(),
    };

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
        if cmsg.is_null() {
            return Err("Cannot construct control message header".into());
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize;
        std::ptr::copy_nonoverlapping(
            &fd as *const RawFd as *const u8,
            libc::CMSG_DATA(cmsg),
            std::mem::size_of::<RawFd>(),
        );
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

/// Receive request data and file descriptor over Unix socket via SCM_RIGHTS,
/// enforcing a total monotonic deadline across the entire receive operation.
pub fn recv_fd_request(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<(ScanRequest, RawFd), String> {
    // Sized for up to 8 FDs to detect extra descriptors
    let cmsg_space =
        unsafe { libc::CMSG_SPACE((8 * std::mem::size_of::<RawFd>()) as u32) as usize };
    let cmsg_words = cmsg_space.div_ceil(std::mem::size_of::<usize>());
    let mut cmsg_buf = vec![0usize; cmsg_words];

    let mut initial_buf = vec![0u8; 4096];
    let mut iov = libc::iovec {
        iov_base: initial_buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: initial_buf.len(),
    };

    let mut msg = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: cmsg_buf.as_mut_ptr() as *mut libc::c_void,
        msg_controllen: cmsg_space,
        msg_flags: 0,
    };

    let remaining = match deadline.checked_duration_since(Instant::now()) {
        Some(d) if !d.is_zero() => d,
        _ => return Err("Client request deadline exceeded".into()),
    };
    stream
        .set_read_timeout(Some(remaining))
        .map_err(|e| format!("Failed to set read timeout: {e}"))?;

    let ret = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, 0) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock
            || err.kind() == std::io::ErrorKind::TimedOut
        {
            return Err("Client request deadline exceeded".into());
        }
        return Err(format!("recvmsg failed: {}", err));
    }
    let bytes_read = ret as usize;
    if bytes_read == 0 {
        return Err("Connection closed by client".into());
    }

    let mut fds = Vec::new();
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let base_len = libc::CMSG_LEN(0) as usize;
                let data_len = (*cmsg).cmsg_len.saturating_sub(base_len);
                let num_fds = data_len / std::mem::size_of::<RawFd>();
                let data_ptr = libc::CMSG_DATA(cmsg) as *const RawFd;
                for i in 0..num_fds {
                    let fd = std::ptr::read_unaligned(data_ptr.add(i));
                    fds.push(fd);
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    // Helper to close all received fds on failure
    let close_all = |fds: &[RawFd]| {
        for &fd in fds {
            unsafe {
                libc::close(fd);
            }
        }
    };

    if (msg.msg_flags & libc::MSG_CTRUNC) != 0 {
        close_all(&fds);
        return Err("Control message truncated: extra file descriptors rejected".into());
    }

    if fds.is_empty() {
        return Err("Missing file descriptor".into());
    }
    if fds.len() > 1 {
        close_all(&fds);
        return Err("Extra file descriptors rejected".into());
    }

    let raw_fd = fds[0];

    // Read remaining bytes if length prefix was incomplete
    let mut total_bytes = initial_buf[..bytes_read].to_vec();
    while total_bytes.len() < 4 {
        let remaining = match deadline.checked_duration_since(Instant::now()) {
            Some(d) if !d.is_zero() => d,
            _ => {
                close_all(&[raw_fd]);
                return Err("Client request deadline exceeded".into());
            }
        };
        let _ = stream.set_read_timeout(Some(remaining));
        let mut chunk = [0u8; 4];
        match stream.read(&mut chunk[..4 - total_bytes.len()]) {
            Ok(0) => {
                close_all(&[raw_fd]);
                return Err("Connection truncated before request length header".into());
            }
            Ok(n) => total_bytes.extend_from_slice(&chunk[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                close_all(&[raw_fd]);
                return Err("Client request deadline exceeded".into());
            }
            Err(e) => {
                close_all(&[raw_fd]);
                return Err(format!("Read failed: {e}"));
            }
        }
    }

    let payload_len = u32::from_be_bytes([
        total_bytes[0],
        total_bytes[1],
        total_bytes[2],
        total_bytes[3],
    ]) as usize;

    if payload_len == 0 || payload_len > MAX_REQUEST_PAYLOAD {
        close_all(&[raw_fd]);
        return Err(format!(
            "Invalid request payload length: {} (limit {})",
            payload_len, MAX_REQUEST_PAYLOAD
        ));
    }

    let mut payload = total_bytes[4..].to_vec();
    while payload.len() < payload_len {
        let remaining = match deadline.checked_duration_since(Instant::now()) {
            Some(d) if !d.is_zero() => d,
            _ => {
                close_all(&[raw_fd]);
                return Err("Client request deadline exceeded".into());
            }
        };
        let _ = stream.set_read_timeout(Some(remaining));
        let needed = payload_len - payload.len();
        let mut chunk = vec![0u8; needed.min(4096)];
        match stream.read(&mut chunk) {
            Ok(0) => {
                close_all(&[raw_fd]);
                return Err("Connection truncated before request payload complete".into());
            }
            Ok(n) => payload.extend_from_slice(&chunk[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                close_all(&[raw_fd]);
                return Err("Client request deadline exceeded".into());
            }
            Err(e) => {
                close_all(&[raw_fd]);
                return Err(format!("Read failed: {e}"));
            }
        }
    }

    let request: ScanRequest = match serde_json::from_slice(&payload[..payload_len]) {
        Ok(req) => req,
        Err(e) => {
            close_all(&[raw_fd]);
            return Err(format!("Malformed request JSON: {e}"));
        }
    };

    Ok((request, raw_fd))
}

/// Send structured framed response to client.
pub fn send_framed_response(
    stream: &mut UnixStream,
    response: &CoordinatorResponse,
) -> Result<(), String> {
    let payload =
        serde_json::to_vec(response).map_err(|e| format!("Cannot serialize response: {e}"))?;
    if payload.len() > MAX_RESPONSE_PAYLOAD {
        return Err("Response payload exceeds limit".into());
    }

    let len_prefix = (payload.len() as u32).to_be_bytes();
    stream
        .write_all(&len_prefix)
        .map_err(|e| format!("Write failed: {e}"))?;
    stream
        .write_all(&payload)
        .map_err(|e| format!("Write failed: {e}"))?;
    stream.flush().map_err(|e| format!("Flush failed: {e}"))?;
    Ok(())
}

/// Receive structured framed response from coordinator.
pub fn recv_framed_response(stream: &mut UnixStream) -> Result<CoordinatorResponse, String> {
    let mut len_prefix = [0u8; 4];
    stream
        .read_exact(&mut len_prefix)
        .map_err(|e| format!("Cannot read response header: {e}"))?;
    let payload_len = u32::from_be_bytes(len_prefix) as usize;
    if payload_len == 0 || payload_len > MAX_RESPONSE_PAYLOAD {
        return Err(format!(
            "Invalid response payload length: {} (limit {})",
            payload_len, MAX_RESPONSE_PAYLOAD
        ));
    }

    let mut payload = vec![0u8; payload_len];
    stream
        .read_exact(&mut payload)
        .map_err(|e| format!("Cannot read response body: {e}"))?;

    let response: CoordinatorResponse =
        serde_json::from_slice(&payload).map_err(|e| format!("Malformed response JSON: {e}"))?;
    Ok(response)
}

pub struct CoordinatorState {
    pub pending_queue: VecDeque<UnixStream>,
    pub max_pending: usize,
    pub active_workers: usize,
    pub max_workers: usize,
    pub in_flight_snapshot_bytes: u64,
    pub max_total_snapshot_bytes: u64,
    pub shutdown: bool,
}

#[derive(Debug)]
pub enum ReservationError {
    ExceedsMaxBudget(String),
    OverCapacity(String),
}

pub struct SnapshotReservation {
    state: Arc<(Mutex<CoordinatorState>, Condvar)>,
    reserved_bytes: u64,
}

impl SnapshotReservation {
    pub fn new(
        state: Arc<(Mutex<CoordinatorState>, Condvar)>,
        requested_bytes: u64,
    ) -> Result<Self, ReservationError> {
        let (lock, _cvar) = &*state;
        let mut guard = lock.lock().unwrap();
        if requested_bytes > guard.max_total_snapshot_bytes {
            return Err(ReservationError::ExceedsMaxBudget(format!(
                "File size ({} bytes) exceeds coordinator snapshot budget ({} bytes)",
                requested_bytes, guard.max_total_snapshot_bytes
            )));
        }
        let needed = match guard.in_flight_snapshot_bytes.checked_add(requested_bytes) {
            Some(n) => n,
            None => {
                return Err(ReservationError::OverCapacity(
                    "Snapshot byte counter overflow".into(),
                ));
            }
        };
        if needed > guard.max_total_snapshot_bytes {
            return Err(ReservationError::OverCapacity(format!(
                "Coordinator busy: snapshot memory limit exceeded (current in-flight: {} bytes, requested: {} bytes, limit: {} bytes)",
                guard.in_flight_snapshot_bytes, requested_bytes, guard.max_total_snapshot_bytes
            )));
        }
        guard.in_flight_snapshot_bytes = needed;
        Ok(Self {
            state: Arc::clone(&state),
            reserved_bytes: requested_bytes,
        })
    }

    #[allow(dead_code)]
    pub fn reserved_bytes(&self) -> u64 {
        self.reserved_bytes
    }
}

impl SnapshotBudget for SnapshotReservation {
    fn ensure_capacity(&mut self, new_total: u64) -> Result<(), String> {
        if new_total > self.reserved_bytes {
            let extra = new_total - self.reserved_bytes;
            let (lock, _cvar) = &*self.state;
            let mut guard = lock.lock().unwrap();
            let new_in_flight = guard
                .in_flight_snapshot_bytes
                .checked_add(extra)
                .ok_or_else(|| "Snapshot byte counter overflow".to_string())?;
            if new_in_flight > guard.max_total_snapshot_bytes {
                return Err(format!(
                    "Snapshot memory budget exceeded: growing file requires {} bytes, exceeding coordinator budget (current in-flight: {} bytes, limit: {} bytes)",
                    new_total, guard.in_flight_snapshot_bytes, guard.max_total_snapshot_bytes
                ));
            }
            guard.in_flight_snapshot_bytes = new_in_flight;
            self.reserved_bytes = new_total;
        }
        Ok(())
    }

    fn finalize(&mut self, final_total: u64) {
        if final_total < self.reserved_bytes {
            let excess = self.reserved_bytes - final_total;
            let (lock, cvar) = &*self.state;
            let mut guard = lock.lock().unwrap();
            if let Some(rem) = guard.in_flight_snapshot_bytes.checked_sub(excess) {
                guard.in_flight_snapshot_bytes = rem;
            } else {
                guard.in_flight_snapshot_bytes = 0;
            }
            self.reserved_bytes = final_total;
            cvar.notify_all();
        }
    }
}

impl Drop for SnapshotReservation {
    fn drop(&mut self) {
        if self.reserved_bytes > 0 {
            let (lock, cvar) = &*self.state;
            let mut guard = lock.lock().unwrap();
            if let Some(rem) = guard
                .in_flight_snapshot_bytes
                .checked_sub(self.reserved_bytes)
            {
                guard.in_flight_snapshot_bytes = rem;
            } else {
                guard.in_flight_snapshot_bytes = 0;
            }
            self.reserved_bytes = 0;
            cvar.notify_all();
        }
    }
}

fn send_busy_response(mut stream: UnixStream, reason: &str) {
    let resp = CoordinatorResponse {
        status: CoordinatorVerdict::Busy,
        report: None,
        error: Some(reason.into()),
        error_code: None,
        database_generation: None,
        degraded_freshness: None,
        pending_generation: None,
        reload_load_time_ms: None,
        reload_switch_latency_micros: None,
    };
    let _ = send_framed_response(&mut stream, &resp);
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut discard = [0u8; 1024];
    let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
    while let Ok(n) = stream.read(&mut discard) {
        if n == 0 {
            break;
        }
    }
}

fn send_unauthorized_response(mut stream: UnixStream, reason: &str) {
    let resp = CoordinatorResponse {
        status: CoordinatorVerdict::Error,
        report: None,
        error: Some(reason.into()),
        error_code: None,
        database_generation: None,
        degraded_freshness: None,
        pending_generation: None,
        reload_load_time_ms: None,
        reload_switch_latency_micros: None,
    };
    let _ = send_framed_response(&mut stream, &resp);
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut discard = [0u8; 1024];
    let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
    while let Ok(n) = stream.read(&mut discard) {
        if n == 0 {
            break;
        }
    }
}

fn handle_client_connection(
    mut stream: UnixStream,
    worker_config: &SupervisedWorkerConfig,
    client_timeout_secs: u64,
    shared_state: &Arc<(Mutex<CoordinatorState>, Condvar)>,
    db_manager: Option<&Arc<DatabaseManager>>,
) {
    let deadline = Instant::now() + Duration::from_secs(client_timeout_secs);
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    // Pin active database handle for the entire duration of this scan
    let pinned_handle = db_manager.map(|dm| dm.pin_active());
    let (
        database_generation,
        degraded_freshness,
        pending_generation,
        reload_load_time_ms,
        reload_switch_latency_micros,
    ) = match (pinned_handle.as_ref(), db_manager) {
        (Some(ph), Some(dm)) => {
            let latest = dm.reload_history().last().cloned();
            (
                Some(ph.generation().to_string()),
                Some(dm.is_degraded()),
                dm.pending_generation(),
                latest.as_ref().map(|m| m.load_time_ms),
                latest.as_ref().map(|m| m.switch_latency_micros),
            )
        }
        _ => (None, None, None, None, None),
    };

    let make_resp = |status: CoordinatorVerdict,
                     report: Option<ScanReport>,
                     error: Option<String>|
     -> CoordinatorResponse {
        let is_timeout = error
            .as_deref()
            .or_else(|| report.as_ref().and_then(|r| r.error.as_deref()))
            .is_some_and(|s| {
                s == "Worker deadline exceeded; worker terminated"
                    || s.starts_with("Scan timeout reached after ")
            });
        CoordinatorResponse {
            status,
            report,
            error,
            error_code: is_timeout.then(|| "TIMEOUT".to_string()),
            database_generation: database_generation.clone(),
            degraded_freshness,
            pending_generation: pending_generation.clone(),
            reload_load_time_ms,
            reload_switch_latency_micros,
        }
    };

    let (request, raw_fd) = match recv_fd_request(&mut stream, deadline) {
        Ok(pair) => pair,
        Err(e) => {
            let resp = make_resp(CoordinatorVerdict::Error, None, Some(e));
            let _ = send_framed_response(&mut stream, &resp);
            return;
        }
    };

    // Validate descriptor: must be a valid regular file
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(raw_fd, stat.as_mut_ptr()) } != 0 {
        unsafe {
            libc::close(raw_fd);
        }
        let resp = make_resp(
            CoordinatorVerdict::Error,
            None,
            Some("Invalid descriptor: fstat failed".into()),
        );
        let _ = send_framed_response(&mut stream, &resp);
        return;
    }
    let stat = unsafe { stat.assume_init() };
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
        unsafe {
            libc::close(raw_fd);
        }
        let resp = make_resp(
            CoordinatorVerdict::Error,
            None,
            Some("Invalid descriptor: not a regular file".into()),
        );
        let _ = send_framed_response(&mut stream, &resp);
        return;
    }

    let file_size = if stat.st_size < 0 {
        0u64
    } else {
        stat.st_size as u64
    };
    let max_size = request
        .max_size
        .unwrap_or(worker_config.max_size.unwrap_or(52_428_800));

    if file_size > max_size {
        unsafe {
            libc::close(raw_fd);
        }
        let target_path = PathBuf::from(request.file_name.unwrap_or_else(|| "target".into()));
        let msg = format!(
            "File size ({} bytes) exceeds maximum allowed size ({} bytes)",
            file_size, max_size
        );
        let report = error_report(&target_path, msg.clone());
        let resp = make_resp(CoordinatorVerdict::Error, Some(report), Some(msg));
        let _ = send_framed_response(&mut stream, &resp);
        return;
    }

    let mut reservation = match SnapshotReservation::new(Arc::clone(shared_state), file_size) {
        Ok(res) => res,
        Err(ReservationError::ExceedsMaxBudget(msg)) => {
            unsafe {
                libc::close(raw_fd);
            }
            let target_path = PathBuf::from(request.file_name.unwrap_or_else(|| "target".into()));
            let report = error_report(&target_path, msg.clone());
            let resp = make_resp(CoordinatorVerdict::Error, Some(report), Some(msg));
            let _ = send_framed_response(&mut stream, &resp);
            return;
        }
        Err(ReservationError::OverCapacity(msg)) => {
            unsafe {
                libc::close(raw_fd);
            }
            let resp = make_resp(CoordinatorVerdict::Busy, None, Some(msg));
            let _ = send_framed_response(&mut stream, &resp);
            return;
        }
    };

    let source = unsafe { File::from_raw_fd(raw_fd) };

    let snapshot = match sealed_snapshot_with_budget(source, max_size, &mut reservation) {
        Ok(snap) => snap,
        Err(e) => {
            let target_path = PathBuf::from(request.file_name.unwrap_or_else(|| "target".into()));
            let report = error_report(&target_path, e.clone());
            let resp = make_resp(CoordinatorVerdict::Error, Some(report), Some(e));
            let _ = send_framed_response(&mut stream, &resp);
            return;
        }
    };

    let target_name = PathBuf::from(request.file_name.unwrap_or_else(|| "target".into()));
    let mut effective_config = worker_config.clone();
    if let Some(ref ph) = pinned_handle {
        effective_config.private_generation = Some(ph.generation().to_string());
    }
    let allow_test = cfg!(debug_assertions);
    if allow_test {
        if let Some(action) = request.test_worker_action {
            effective_config.test_worker_action = Some(action);
        }
    }
    if let Some(ms) = request.max_size {
        effective_config.max_size =
            Some(effective_config.max_size.map(|s| s.min(ms)).unwrap_or(ms));
    }
    if let Some(t) = request.timeout {
        effective_config.timeout = Some(effective_config.timeout.map(|s| s.min(t)).unwrap_or(t));
    }
    if let Some(d) = request.max_depth {
        effective_config.max_depth =
            Some(effective_config.max_depth.map(|s| s.min(d)).unwrap_or(d));
    }

    let scan_result = execute_worker_on_snapshot(snapshot, &target_name, &effective_config);

    let response = match scan_result {
        Ok(report) => {
            let verdict = match report.status {
                ScanStatus::Clean => CoordinatorVerdict::Clean,
                ScanStatus::Infected => CoordinatorVerdict::Detected,
                ScanStatus::Unsupported => CoordinatorVerdict::Unscanned,
                ScanStatus::Failed => CoordinatorVerdict::Error,
            };
            make_resp(verdict, Some(report), None)
        }
        Err(e) => {
            let report = error_report(&target_name, e.clone());
            make_resp(CoordinatorVerdict::Error, Some(report), Some(e))
        }
    };

    let _ = send_framed_response(&mut stream, &response);
}

/// Run persistent coordinator service (`raxosentinel serve`).
pub fn serve(args: ServeArgs) -> i32 {
    if args.max_workers == 0 {
        eprintln!("Coordinator startup error: --max-workers must be at least 1");
        return 3;
    }

    if let Err(e) = verify_startup_database(&args) {
        eprintln!("Coordinator startup error: {e}");
        return 3;
    }
    // Optional YARA-X rules must compile before any request is accepted.
    if let Err(e) = super::attach_yara_rules(
        &args.yara_rules,
        &mut raxosentinel_signatures::SignatureDatabase::new(),
    ) {
        eprintln!("Coordinator startup error: {e}");
        return 3;
    }

    let listener = match prepare_socket(&args.socket) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Coordinator socket setup failed: {e}");
            return 3;
        }
    };

    let authorized_uid = args
        .authorized_uid
        .unwrap_or_else(|| unsafe { libc::geteuid() });

    // Register signal handlers for clean shutdown (SIGINT, SIGTERM)
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = handle_signal as *const () as usize;
    sa.sa_flags = libc::SA_RESETHAND;
    unsafe {
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }

    let worker_config = SupervisedWorkerConfig {
        worker_memory: args.worker_memory,
        worker_timeout_ms: args.worker_timeout_ms,
        max_size: Some(args.max_size),
        timeout: args.timeout,
        max_depth: Some(args.max_depth),
        rules: args.rules.clone(),
        yara_rules: args.yara_rules.clone(),
        private_db_root: args.private_db_root.clone(),
        private_generation: args.private_generation.clone(),
        public_release: args.public_release.clone(),
        public_key: args.public_key.clone(),
        public_approval_key: args.public_approval_key.clone(),
        public_state: args.public_state.clone(),
        test_worker_action: None,
    };

    let shared_state = Arc::new((
        Mutex::new(CoordinatorState {
            pending_queue: VecDeque::new(),
            max_pending: args.max_pending,
            active_workers: 0,
            max_workers: args.max_workers,
            in_flight_snapshot_bytes: 0,
            max_total_snapshot_bytes: args.max_total_snapshot_bytes,
            shutdown: false,
        }),
        Condvar::new(),
    ));

    let db_manager = if let Some(ref root) = args.private_db_root {
        let mgr = match DatabaseManager::new_with_budget(
            root.clone(),
            args.private_generation.clone(),
            args.max_resident_generations,
        ) {
            Ok(m) => Arc::new(m),
            Err(e) => {
                eprintln!("Coordinator database startup error: {e}");
                return 3;
            }
        };
        if let Err(e) = mgr.start_monitor() {
            tracing::warn!("Coordinator monitor setup warning: {e}");
        }
        Some(mgr)
    } else {
        None
    };

    let mut worker_handles = Vec::with_capacity(args.max_workers);
    for _ in 0..args.max_workers {
        let state_clone = Arc::clone(&shared_state);
        let worker_cfg = worker_config.clone();
        let client_timeout = args.client_timeout_secs;
        let db_mgr_clone = db_manager.clone();
        let handle = thread::spawn(move || {
            let (lock, cvar) = &*state_clone;
            loop {
                let stream = {
                    let mut guard = lock.lock().unwrap();
                    while guard.pending_queue.is_empty() && !guard.shutdown {
                        guard = cvar.wait(guard).unwrap();
                    }
                    if guard.pending_queue.is_empty() && guard.shutdown {
                        break;
                    }
                    let stream = guard.pending_queue.pop_front().unwrap();
                    guard.active_workers += 1;
                    stream
                };

                handle_client_connection(
                    stream,
                    &worker_cfg,
                    client_timeout,
                    &state_clone,
                    db_mgr_clone.as_ref(),
                );

                {
                    let mut guard = lock.lock().unwrap();
                    guard.active_workers -= 1;
                    cvar.notify_all();
                }
            }
        });
        worker_handles.push(handle);
    }

    tracing::info!(
        "Coordinator serving on '{}' (authorized UID: {}, max workers: {}, max pending: {}, snapshot limit: {} bytes)",
        args.socket.display(),
        authorized_uid,
        args.max_workers,
        args.max_pending,
        args.max_total_snapshot_bytes
    );
    println!("RAXOSENTINEL_COORDINATOR_READY");
    let _ = std::io::stdout().flush();

    let socket_path = args.socket.clone();

    while RUNNING.load(Ordering::SeqCst) {
        let mut pfd = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let poll_ret = unsafe { libc::poll(&mut pfd, 1, 200) };
        if poll_ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if poll_ret == 0 {
            continue;
        }

        let (stream, _) = match listener.accept() {
            Ok(pair) => pair,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
        };

        // Authenticate peer credentials
        match check_peer_creds(&stream, authorized_uid) {
            Ok(true) => {}
            Ok(false) => {
                send_unauthorized_response(stream, "Unauthorized peer credentials (UID mismatch)");
                continue;
            }
            Err(e) => {
                send_unauthorized_response(stream, &format!("Peer credentials check failed: {e}"));
                continue;
            }
        }

        // Bounded pending admission; reject immediately with BUSY on overload
        let (lock, cvar) = &*shared_state;
        let mut guard = lock.lock().unwrap();
        if guard.shutdown {
            drop(guard);
            send_busy_response(stream, "Coordinator is shutting down");
            continue;
        }
        let total_in_flight = guard.active_workers + guard.pending_queue.len();
        if total_in_flight >= guard.max_workers + guard.max_pending {
            drop(guard);
            send_busy_response(stream, "Coordinator busy: request rejected due to overload");
            continue;
        }

        guard.pending_queue.push_back(stream);
        cvar.notify_one();
    }

    {
        let (lock, cvar) = &*shared_state;
        let mut guard = lock.lock().unwrap();
        guard.shutdown = true;
        cvar.notify_all();
    }

    for handle in worker_handles {
        let _ = handle.join();
    }

    if let Some(ref mgr) = db_manager {
        mgr.stop_monitor();
    }

    cleanup_socket(&socket_path);
    0
}

/// Run client submission to persistent coordinator.
pub fn client(args: ClientArgs) -> i32 {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&args.target)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Cannot open target '{}': {}", args.target.display(), e);
            return 3;
        }
    };

    let meta = match file.metadata() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Cannot stat target '{}': {}", args.target.display(), e);
            return 3;
        }
    };
    if !meta.is_file() {
        eprintln!("Target '{}' is not a regular file", args.target.display());
        return 3;
    }

    let mut stream = match UnixStream::connect(&args.socket) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "Cannot connect to coordinator socket '{}': {}",
                args.socket.display(),
                e
            );
            return 3;
        }
    };

    let request = ScanRequest {
        file_name: args
            .target
            .file_name()
            .map(|s| s.to_string_lossy().into_owned()),
        max_size: args.max_size,
        timeout: args.timeout,
        max_depth: args.max_depth,
        test_worker_action: args
            .test_worker_action
            .or_else(|| std::env::var("RAXOSENTINEL_TEST_WORKER_ACTION").ok()),
    };

    if let Err(e) = send_fd_request(&stream, file.as_raw_fd(), &request) {
        eprintln!("Failed to submit request: {e}");
        return 3;
    }

    let response = match recv_framed_response(&mut stream) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to receive response from coordinator: {e}");
            return 3;
        }
    };

    if args.json_envelope {
        println!("{}", serde_json::to_string(&response).unwrap_or_default());
    } else if args.json {
        if let Some(ref report) = response.report {
            if let Ok(json) = report.to_json_pretty() {
                println!("{json}");
            } else {
                eprintln!("Failed to format report JSON");
            }
        } else {
            let json = serde_json::to_string_pretty(&response).unwrap_or_default();
            println!("{json}");
        }
    } else {
        match response.status {
            CoordinatorVerdict::Busy => {
                eprintln!(
                    "BUSY: {}",
                    response
                        .error
                        .as_deref()
                        .unwrap_or("Coordinator overloaded")
                );
            }
            CoordinatorVerdict::Error => {
                eprintln!(
                    "ERROR: {}",
                    response.error.as_deref().unwrap_or("Scan failed")
                );
                if let Some(ref report) = response.report {
                    print_human_report(report, None);
                }
            }
            _ => {
                if let Some(ref report) = response.report {
                    print_human_report(report, None);
                }
            }
        }
    }

    match response.status {
        CoordinatorVerdict::Clean => 0,
        CoordinatorVerdict::Detected => 1,
        CoordinatorVerdict::Unscanned => 2,
        CoordinatorVerdict::Error | CoordinatorVerdict::Busy => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Seek;

    #[test]
    fn test_snapshot_reservation_accounting_and_lifecycle() {
        let state = Arc::new((
            Mutex::new(CoordinatorState {
                pending_queue: VecDeque::new(),
                max_pending: 2,
                active_workers: 0,
                max_workers: 2,
                in_flight_snapshot_bytes: 0,
                max_total_snapshot_bytes: 10_000,
                shutdown: false,
            }),
            Condvar::new(),
        ));

        // 1. Initial reservation within budget
        let mut res = SnapshotReservation::new(Arc::clone(&state), 4_000).unwrap();
        assert_eq!(res.reserved_bytes(), 4_000);
        assert_eq!(state.0.lock().unwrap().in_flight_snapshot_bytes, 4_000);

        // 2. Incremental capacity growth within budget
        res.ensure_capacity(7_000).unwrap();
        assert_eq!(res.reserved_bytes(), 7_000);
        assert_eq!(state.0.lock().unwrap().in_flight_snapshot_bytes, 7_000);

        // 3. Growth exceeding budget is rejected and does not mutate reservation
        let err = res.ensure_capacity(12_000).unwrap_err();
        assert!(err.contains("Snapshot memory budget exceeded"));
        assert_eq!(res.reserved_bytes(), 7_000);
        assert_eq!(state.0.lock().unwrap().in_flight_snapshot_bytes, 7_000);

        // 4. Finalize downwards to actual size
        res.finalize(5_000);
        assert_eq!(res.reserved_bytes(), 5_000);
        assert_eq!(state.0.lock().unwrap().in_flight_snapshot_bytes, 5_000);

        // 5. Drop releases remaining reservation
        drop(res);
        assert_eq!(state.0.lock().unwrap().in_flight_snapshot_bytes, 0);
    }

    #[test]
    fn test_snapshot_reservation_over_capacity_rejection() {
        let state = Arc::new((
            Mutex::new(CoordinatorState {
                pending_queue: VecDeque::new(),
                max_pending: 2,
                active_workers: 0,
                max_workers: 2,
                in_flight_snapshot_bytes: 8_000,
                max_total_snapshot_bytes: 10_000,
                shutdown: false,
            }),
            Condvar::new(),
        ));

        let res = SnapshotReservation::new(Arc::clone(&state), 3_000);
        match res {
            Err(ReservationError::OverCapacity(msg)) => {
                assert!(msg.contains("snapshot memory limit exceeded"));
            }
            _ => panic!("Expected OverCapacity error"),
        }
        assert_eq!(state.0.lock().unwrap().in_flight_snapshot_bytes, 8_000);
    }

    #[test]
    fn test_sealed_snapshot_with_budget_enforces_limit_during_copy() {
        let mut tmp = tempfile::tempfile().unwrap();
        tmp.write_all(&vec![b'Z'; 150_000]).unwrap();
        tmp.seek(std::io::SeekFrom::Start(0)).unwrap();

        let state = Arc::new((
            Mutex::new(CoordinatorState {
                pending_queue: VecDeque::new(),
                max_pending: 2,
                active_workers: 0,
                max_workers: 2,
                in_flight_snapshot_bytes: 0,
                max_total_snapshot_bytes: 100_000,
                shutdown: false,
            }),
            Condvar::new(),
        ));

        // Start reservation at 50_000 bytes (simulating initial stat of 50KB)
        let mut res = SnapshotReservation::new(Arc::clone(&state), 50_000).unwrap();
        assert_eq!(state.0.lock().unwrap().in_flight_snapshot_bytes, 50_000);

        // Copy 150KB file into sealed snapshot with 100KB budget
        let result = sealed_snapshot_with_budget(tmp, 200_000, &mut res);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Snapshot memory budget exceeded"));

        // Dropping res restores in_flight_snapshot_bytes to 0
        drop(res);
        assert_eq!(state.0.lock().unwrap().in_flight_snapshot_bytes, 0);
    }
}
