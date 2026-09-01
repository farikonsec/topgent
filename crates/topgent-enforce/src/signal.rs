//! Asking the operating system to stop a process, in its own terms.
//!
//! Unix has a ladder of three rungs: ask, wait, force. Windows has two, because
//! it delivers a close request as a window message and a console agent can
//! never receive one. Pretending otherwise would make the first rung a no-op
//! that reports success, so each platform says what it actually did.

#[cfg(unix)]
use nix::sys::signal::{Signal as UnixSignal, kill};
#[cfg(unix)]
use nix::unistd::Pid;
use std::time::Duration;
use topgent_collect::process;
use topgent_facts::UnixMillis;

/// How long a process gets to shut down cleanly before the second signal.
pub const GRACE: Duration = Duration::from_secs(5);

/// How often the grace period is re-checked.
pub(crate) const POLL: Duration = Duration::from_millis(100);

/// Platform-neutral termination intent used by guarded response adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// Ask the process to shut down cleanly.
    Terminate,
    /// Force termination after the grace period.
    Force,
}

/// What a failed `taskkill` actually means for the rung that was attempted.
///
/// Two of its refusals are not failures. A process that has already exited is
/// a completed request, and Windows says so the same way it reports a real
/// refusal. More importantly, asking a console process to close is answered
/// with "this process can only be terminated forcefully": Windows delivers a
/// close request as a window message, and a process with no window can never
/// receive one. That is the rung not applying rather than the rung failing, so
/// treating it as a denial stopped the ladder before it ever reached force,
/// and a stop the operator had approved simply did not happen.
///
/// # Errors
///
/// Returns the system's own words for anything that is a real refusal.
#[cfg(any(windows, test))]
pub fn windows_signal_outcome(signal: Signal, detail: &str) -> Result<(), String> {
    let lowered = detail.to_ascii_lowercase();
    if lowered.contains("not found") || lowered.contains("no running instance") {
        return Ok(());
    }
    if signal == Signal::Terminate
        && (lowered.contains("terminated forcefully") || lowered.contains("with /f option"))
    {
        return Ok(());
    }
    Err(detail.chars().take(512).collect())
}

/// Whether Windows termination can actually be performed on this host.
#[must_use]
pub(crate) fn windows_termination_available() -> bool {
    #[cfg(windows)]
    {
        topgent_collect::tool::TASKKILL.resolve().is_some()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Send a signal to a pid.
///
/// Behind a trait so the guard and identity logic can be tested without any
/// process actually dying.
pub trait Signaller {
    /// Send `signal` to `pid`.
    ///
    /// # Errors
    ///
    /// Returns the system's message when the signal could not be delivered.
    fn send(&self, pid: u32, signal: Signal) -> Result<(), String>;

    /// Whether a process with this pid and start time is running now.
    fn identity(&self, pid: u32) -> Option<UnixMillis>;
}

/// The real one.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemSignaller;

impl Signaller for SystemSignaller {
    #[cfg(unix)]
    fn send(&self, pid: u32, signal: Signal) -> Result<(), String> {
        let pid = i32::try_from(pid).map_err(|_| "pid out of range".to_owned())?;
        let signal = match signal {
            Signal::Terminate => UnixSignal::SIGTERM,
            Signal::Force => UnixSignal::SIGKILL,
        };
        kill(Pid::from_raw(pid), signal).map_err(|e| e.to_string())
    }

    /// Windows has two rungs here, not three, and says so.
    ///
    /// `Terminate` asks a process to close, which Windows delivers as a window
    /// message; a console agent with no window never receives it and simply
    /// keeps running, which the caller sees as the process still being alive
    /// rather than as a success. `Force` ends it outright. Pretending the first
    /// is a graceful shutdown for every process would make the ladder's first
    /// rung a no-op that reports success.
    #[cfg(windows)]
    fn send(&self, pid: u32, signal: Signal) -> Result<(), String> {
        let mut command = topgent_collect::tool::TASKKILL
            .command()
            .map_err(|error| error.to_string())?;
        command.args(["/PID", &pid.to_string()]);
        if signal == Signal::Force {
            command.arg("/F");
        }
        let output = command
            .output()
            .map_err(|error| format!("taskkill unavailable: {error}"))?;
        if output.status.success() {
            return Ok(());
        }
        let mut detail = String::from_utf8_lossy(&output.stderr).into_owned();
        detail.push_str(&String::from_utf8_lossy(&output.stdout));
        windows_signal_outcome(signal, detail.trim())
    }

    fn identity(&self, pid: u32) -> Option<UnixMillis> {
        process::snapshot()
            .into_iter()
            .find(|p| p.pid == pid)
            .map(|p| p.started_at)
    }
}
