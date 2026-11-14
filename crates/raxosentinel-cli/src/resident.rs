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

//! Resident scan workers.
//!
//! A one-shot worker loads the signature database for every scan (0.6–1.6 s for the production
//! database). A resident worker is the same sandboxed process (own process group, `no_new_privs`,
//! `RLIMIT_AS`, Landlock after loading), but it loads the database once and then scans many sealed
//! snapshots passed over a private socketpair. It is replaced after `max_scans` scans, when the
//! active database generation changes, and after any failure (timeout, crash, malformed reply).

use super::coordinator::{recv_fd_request, send_fd_request, ScanRequest};
use super::supervised::{terminate_group, worker_command, SupervisedWorkerConfig};
use raxosentinel_core::{ResourceLimits, ResourceTracker, ScanReport};
use raxosentinel_signatures::SignatureDatabase;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

const MAX_FRAME: usize = 2 * 1024 * 1024;
const WORKER_NAME: &str = "resident-worker";

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WorkerFrame {
    Ready,
    Report { report: Box<ScanReport> },
}

fn write_frame(stream: &mut UnixStream, frame: &WorkerFrame) -> Result<(), String> {
    let payload = serde_json::to_vec(frame).map_err(|e| format!("Cannot serialize frame: {e}"))?;
    if payload.len() > MAX_FRAME {
        return Err("Worker response exceeds limit".into());
    }
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .and_then(|_| stream.write_all(&payload))
        .map_err(|e| format!("Worker write failed: {e}"))
}

fn read_exact_by(stream: &mut UnixStream, buf: &mut [u8], deadline: Instant) -> Result<(), String> {
    let mut filled = 0;
    while filled < buf.len() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or("Worker deadline exceeded; worker terminated")?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|e| format!("Worker response failed: {e}"))?;
        match stream.read(&mut buf[filled..]) {
            Ok(0) => return Err("Worker terminated abnormally: connection closed".into()),
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Err("Worker deadline exceeded; worker terminated".into())
            }
            Err(e) => return Err(format!("Worker response failed: {e}")),
        }
    }
    Ok(())
}

fn read_frame(stream: &mut UnixStream, deadline: Instant) -> Result<WorkerFrame, String> {
    let mut len = [0u8; 4];
    read_exact_by(stream, &mut len, deadline)?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err("Worker response exceeds limit".into());
    }
    let mut payload = vec![0u8; len];
    read_exact_by(stream, &mut payload, deadline)?;
    serde_json::from_slice(&payload).map_err(|_| "Malformed worker response".into())
}

/// Worker side: called after the database is loaded and the filesystem is restricted.
/// fd 0 is the control socket. Returns the process exit code.
pub fn worker_loop(db: &SignatureDatabase, base: &ResourceLimits) -> i32 {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(0, stat.as_mut_ptr()) } != 0
        || unsafe { stat.assume_init() }.st_mode & libc::S_IFMT != libc::S_IFSOCK
    {
        eprintln!("Resident worker control descriptor is not a socket");
        return 3;
    }
    let mut ctl = unsafe { UnixStream::from_raw_fd(0) };
    if write_frame(&mut ctl, &WorkerFrame::Ready).is_err() {
        return 3;
    }
    loop {
        let (request, fd) =
            match recv_fd_request(&mut ctl, Instant::now() + Duration::from_secs(3600)) {
                Ok(pair) => pair,
                Err(e) if e == "Client request deadline exceeded" => continue,
                // The coordinator closed the socket: retire quietly.
                Err(e) if e == "Connection closed by client" => return 0,
                Err(_) => return 3,
            };
        let input = unsafe { File::from_raw_fd(fd) };
        let mut limits = base.clone();
        if let Some(v) = request.max_size {
            limits.max_file_size = v;
        }
        if let Some(v) = request.timeout {
            limits.max_scan_duration_ms = v.saturating_mul(1000);
        }
        if let Some(v) = request.max_depth {
            limits.max_email_depth = v;
        }
        let mut tracker = ResourceTracker::new(limits);
        let path = PathBuf::from(request.file_name.unwrap_or_else(|| "target".into()));
        let report = super::scan_descriptor(&path, db, &mut tracker, input);
        if write_frame(
            &mut ctl,
            &WorkerFrame::Report {
                report: Box::new(report),
            },
        )
        .is_err()
        {
            return 3;
        }
    }
}

struct ResidentWorker {
    child: Child,
    ctl: UnixStream,
    generation: Option<String>,
    scans: u32,
}

impl ResidentWorker {
    fn spawn(config: &SupervisedWorkerConfig, load_timeout: Duration) -> Result<Self, String> {
        let (parent, child_end) =
            UnixStream::pair().map_err(|e| format!("Worker startup failed: {e}"))?;
        let mut command = worker_command(Path::new(WORKER_NAME), config, true)?;
        command
            .stdin(Stdio::from(OwnedFd::from(child_end)))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = command
            .spawn()
            .map_err(|e| format!("Worker startup failed: {e}"))?;
        let mut worker = Self {
            child,
            ctl: parent,
            generation: config.private_generation.clone(),
            scans: 0,
        };
        match read_frame(&mut worker.ctl, Instant::now() + load_timeout) {
            Ok(WorkerFrame::Ready) => Ok(worker),
            Ok(_) => {
                worker.kill();
                Err("Worker startup failed: unexpected frame".into())
            }
            Err(e) => {
                worker.kill();
                Err(format!("Worker startup failed: {e}"))
            }
        }
    }

    fn scan(
        &mut self,
        snapshot: File,
        target_name: &Path,
        config: &SupervisedWorkerConfig,
    ) -> Result<ScanReport, String> {
        let deadline = Instant::now() + Duration::from_millis(config.worker_timeout_ms);
        let request = ScanRequest {
            file_name: Some(target_name.to_string_lossy().into_owned()),
            max_size: config.max_size,
            timeout: config.timeout,
            max_depth: config.max_depth,
            test_worker_action: None,
        };
        let _ = self.ctl.set_write_timeout(Some(Duration::from_secs(5)));
        send_fd_request(&self.ctl, snapshot.as_raw_fd(), &request)
            .map_err(|e| format!("Worker request failed: {e}"))?;
        drop(snapshot);
        match read_frame(&mut self.ctl, deadline)? {
            WorkerFrame::Report { report } => Ok(*report),
            WorkerFrame::Ready => Err("Malformed worker response".into()),
        }
    }

    fn kill(mut self) {
        terminate_group(&mut self.child);
    }
}

/// One resident worker owned by one coordinator scan thread.
pub struct ResidentSlot {
    worker: Option<ResidentWorker>,
    max_scans: u32,
    load_timeout: Duration,
    warm_retry_at: Option<Instant>,
}

const WARM_RETRY_BACKOFF: Duration = Duration::from_secs(30);

impl ResidentSlot {
    pub fn new(max_scans: u32, load_timeout: Duration) -> Self {
        Self {
            worker: None,
            max_scans: max_scans.max(1),
            load_timeout,
            warm_retry_at: None,
        }
    }

    /// Takes the worker if it is still alive and serves `config`'s generation; otherwise kills it.
    fn take_matching(&mut self, config: &SupervisedWorkerConfig) -> Option<ResidentWorker> {
        let mut w = self.worker.take()?;
        if !matches!(w.child.try_wait(), Ok(None)) {
            // Already exited and reaped: its pid may be reused, so never signal it.
            return None;
        }
        if w.generation == config.private_generation {
            Some(w)
        } else {
            w.kill();
            None
        }
    }

    /// Makes sure a worker for `config`'s generation is loaded, off the request path.
    pub fn warm(&mut self, config: &SupervisedWorkerConfig) {
        if let Some(w) = self.take_matching(config) {
            self.worker = Some(w);
            return;
        }
        // After a failed warm-up, idle threads back off; requests still spawn on demand.
        if self.warm_retry_at.is_some_and(|t| Instant::now() < t) {
            return;
        }
        match ResidentWorker::spawn(config, self.load_timeout) {
            Ok(w) => {
                self.worker = Some(w);
                self.warm_retry_at = None;
            }
            Err(e) => {
                tracing::warn!("resident worker warm-up failed: {e}");
                self.warm_retry_at = Some(Instant::now() + WARM_RETRY_BACKOFF);
            }
        }
    }

    pub fn scan(
        &mut self,
        snapshot: File,
        target_name: &Path,
        config: &SupervisedWorkerConfig,
    ) -> Result<ScanReport, String> {
        let mut worker = match self.take_matching(config) {
            Some(w) => w,
            None => ResidentWorker::spawn(config, self.load_timeout)?,
        };
        match worker.scan(snapshot, target_name, config) {
            Ok(report) => {
                worker.scans += 1;
                if worker.scans < self.max_scans {
                    self.worker = Some(worker);
                } else {
                    worker.kill();
                }
                Ok(report)
            }
            Err(e) => {
                // A worker that timed out, crashed or answered badly is never reused.
                worker.kill();
                Err(e)
            }
        }
    }
}

impl Drop for ResidentSlot {
    fn drop(&mut self) {
        if let Some(w) = self.worker.take() {
            w.kill();
        }
    }
}
