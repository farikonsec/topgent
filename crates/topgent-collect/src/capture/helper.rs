//! Reading a capture that another process is holding.
//!
//! # The arrangement
//!
//! `topgent-capture` holds the capability and writes one JSON batch per
//! second to its standard output. This starts it, reads those lines on a
//! thread, and folds them into the same accumulator an in-process capture
//! would fill. Nothing above this layer can tell the two apart, which is the
//! point: the source of the frames is not a policy question.
//!
//! # What is trusted
//!
//! The path, and only the path. The helper is looked for beside the running
//! binary and nowhere else, because a privileged program found by searching
//! `PATH` is a privileged program an agent being watched can arrange to
//! replace. Its output is parsed defensively even so.
//!
//! # Stopping
//!
//! Dropping this kills the child and waits for it. A privileged process that
//! outlives the thing that started it is how a capture becomes something
//! nobody knows is running.

use std::io::BufRead as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use super::flows::{Drained, Flows};
use super::handoff;
use crate::CollectError;

/// What the helper binary is called.
const HELPER: &str = if cfg!(windows) {
    "topgent-capture.exe"
} else {
    "topgent-capture"
};

/// A running helper, and everything read from it so far.
#[derive(Debug)]
pub struct Helper {
    flows: Arc<Mutex<Flows>>,
    ended: Arc<Mutex<Option<String>>>,
    stop: Arc<AtomicBool>,
    child: Option<std::process::Child>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl Helper {
    /// Starts the helper beside this binary, if there is one.
    ///
    /// # Errors
    ///
    /// [`CollectError::Unavailable`] where no helper is installed beside this
    /// binary or it could not be started, and [`CollectError::Denied`] where
    /// it started and reported that it cannot capture. The caller falls back
    /// to an in-process capture rather than treating either as fatal.
    pub fn start() -> Result<Self, CollectError> {
        let path = beside_this_binary().ok_or_else(|| CollectError::Unavailable {
            what: format!("no {HELPER} is installed beside this binary"),
        })?;
        let mut child = std::process::Command::new(&path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .stdin(std::process::Stdio::null())
            .spawn()
            .map_err(|error| CollectError::Unavailable {
                what: format!("{} could not be started: {error}", path.display()),
            })?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| CollectError::Unavailable {
                what: "the capture helper produced no output stream".to_owned(),
            })?;

        let flows = Arc::new(Mutex::new(Flows::new()));
        let ended = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));
        let reader = std::thread::Builder::new()
            .name("topgent-capture-reader".to_owned())
            .spawn({
                let flows = Arc::clone(&flows);
                let ended = Arc::clone(&ended);
                let stop = Arc::clone(&stop);
                move || read(stdout, &flows, &ended, &stop)
            })
            .map_err(|error| CollectError::Unavailable {
                what: format!("the capture reader could not be started: {error}"),
            })?;

        Ok(Self {
            flows,
            ended,
            stop,
            child: Some(child),
            reader: Some(reader),
        })
    }

    /// Takes everything read since the last drain.
    #[must_use]
    pub fn drain(&self) -> Drained {
        self.flows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain()
    }

    /// Why the helper stopped, if it has.
    #[must_use]
    pub fn ended(&self) -> Option<String> {
        self.ended
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(mut child) = self.child.take() {
            drop(child.kill());
            // Waited on, not abandoned. An unwaited child is a zombie, and a
            // zombie of a privileged program is a bad look in a process list.
            drop(child.wait());
        }
        if let Some(reader) = self.reader.take() {
            drop(reader.join());
        }
    }
}

/// Where the helper is, if it is anywhere this build will run it.
///
/// Beside the running binary, and nowhere else. Searching `PATH` for a program
/// that holds a capability would let anything that can write a directory on
/// that path decide what runs with it.
fn beside_this_binary() -> Option<std::path::PathBuf> {
    // The path is not trusted on its own: the file it names is checked below,
    // before anything is run.
    // nosemgrep: rust.lang.security.current-exe.current-exe
    let path = std::env::current_exe().ok()?.parent()?.join(HELPER);
    if !path.is_file() {
        return None;
    }
    safe_to_run(&path).then_some(path)
}

/// Whether a file is safe to hand a privilege to.
///
/// `current_exe` is not evidence of anything by itself: it can be made to name
/// a path its process never came from. So the answer does not rest on it. What
/// rests on it is where to *look*, and the file found there is then checked the
/// same way the sensor binaries are: it must not be writable by anyone other
/// than its owner, and its owner must be either `root` or this account.
///
/// A helper that fails the check is not run, and Topgent captures in-process
/// instead. Refusing to start it is the safe answer; running it would be
/// executing somebody else's program with a capability.
#[cfg(unix)]
#[must_use]
pub fn safe_to_run(path: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    let mode = metadata.permissions().mode();
    let writable_by_others = mode & 0o022 != 0;
    let owner = metadata.uid();
    // A file this account owns is one this account could already have
    // replaced, so owning it is not a weakening of anything.
    !writable_by_others && (owner == 0 || owner == rustix::process::getuid().as_raw())
}

/// Whether every account on this host can execute the file.
///
/// A capability is on the file, not on a session, so a capability-bearing
/// binary that anyone can run is a raw socket anyone can open. Debian ships
/// `dumpcap` as `0750 root:wireshark` for this reason, and Topgent's own
/// archives set `0750` on the helper. A build from source gets Cargo's `0755`,
/// and an operator who granted before this release still has one, so the
/// condition is detected and reported rather than assumed away.
///
/// Group execute is deliberately allowed: it is how the file reaches the one
/// account that should have it. Only the other bit is a finding.
#[cfg(unix)]
#[must_use]
pub fn runnable_by_others(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).is_ok_and(|metadata| metadata.permissions().mode() & 0o001 != 0)
}

/// See the Unix note. Windows grants nothing on a file here.
#[cfg(not(unix))]
#[must_use]
pub const fn runnable_by_others(_path: &std::path::Path) -> bool {
    false
}

/// See the Unix note.
///
/// Windows has no capability to grant on a file, so a helper there carries no
/// privilege the interface does not already have and there is nothing for this
/// check to protect. The driver is the privileged part, and it is the system's.
#[cfg(not(unix))]
#[must_use]
pub fn safe_to_run(_path: &std::path::Path) -> bool {
    true
}

/// Folds the helper's output into the accumulator until it stops.
fn read(
    stdout: std::process::ChildStdout,
    flows: &Mutex<Flows>,
    ended: &Mutex<Option<String>>,
    stop: &AtomicBool,
) {
    let reader = std::io::BufReader::new(stdout);
    for line in reader.lines() {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let Ok(line) = line else {
            break;
        };
        // A line this build cannot read is skipped, not fatal. The helper is
        // Topgent's own binary and it is still not trusted to be the version
        // this build expects.
        let Ok(batch) = serde_json::from_str::<handoff::Batch>(&line) else {
            continue;
        };
        let Some(drained) = handoff::from_wire(&batch) else {
            continue;
        };
        let mut guard = flows.lock().unwrap_or_else(PoisonError::into_inner);
        // Folded, not replaced. The helper drains every second and a sweep
        // takes every few, so several batches wait between reads; replacing
        // would report only the last second of each interval.
        guard.absorb(drained);
    }
    if !stop.load(Ordering::Relaxed) {
        *ended.lock().unwrap_or_else(PoisonError::into_inner) =
            Some("the capture helper stopped producing".to_owned());
    }
}
