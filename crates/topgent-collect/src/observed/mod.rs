//! Actions the kernel recorded, kept for attribution after the actor is gone.
//!
//! The Audit readers used to look each record's pid up in the process table
//! at sweep time. A `cat` that read a credential and exited a millisecond
//! later was not in that table, so the read was real and invisible. This
//! module keeps what each record said (which pid, when, what it did and with
//! what result) and hands the sweep every record it has not handed over
//! before. The report resolves the pid against process history as of the
//! record's own time, which is the only moment the answer is certain.
//!
//! Separate from the readers because it is shared by them: file access, exec
//! and connect records all end up here, in one form, counted once.
//!
//! Syscall events for the behaviour rules travel the same way, beside these:
//! each record once, bounded, with its time in the start-time base.

pub mod changes;
mod held;
mod syscalls;
pub mod tally;
mod watermark;

use std::sync::{Mutex, PoisonError};

use topgent_facts::{Access, UnixMillis};

pub use held::Held;
pub use syscalls::{ObservedSyscall, sensor_delivers, take_syscalls};
#[cfg(target_os = "linux")]
pub(crate) use syscalls::{publish_sensor_calls, publish_syscalls, set_sensor_delivers};
pub use watermark::Watermark;

/// Most actions held between two sweeps.
pub const MAX_HELD: usize = 16_384;
/// How far back the first read of a log reaches. Older records name
/// processes the history cannot have seen.
pub const FIRST_READ_MS: u64 = 60_000;

/// What a connect record's result was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectResult {
    /// The call succeeded.
    Connected,
    /// A non-blocking connect that had not finished (`EINPROGRESS`).
    InProgress,
    /// The call failed, for example refused.
    Failed,
}

impl ConnectResult {
    /// Stable report label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::InProgress => "in_progress",
            Self::Failed => "failed",
        }
    }
}

/// What the process did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionKind {
    /// It opened, changed or executed a file.
    File {
        /// Absolute path.
        path: String,
        /// How.
        access: Access,
    },
    /// It connected, or sent a datagram, to an address.
    Connect {
        /// Address literal.
        host: String,
        /// Port.
        port: u16,
        /// A datagram sent to a named address rather than a connection.
        datagram: bool,
        /// What the call returned.
        result: ConnectResult,
    },
    /// It replaced its program with this one.
    Exec {
        /// The new program's path.
        program: String,
    },
}

/// One kernel record of one action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedAction {
    /// The record's own id, `seconds.millis:serial`. Unique per boot.
    pub record: String,
    /// Executable named by this syscall record, never inferred from a later snapshot.
    pub program: Option<String>,
    /// The process the kernel named.
    pub pid: u32,
    /// When, by the wall clock.
    pub at: UnixMillis,
    /// When, in the base process start times are kept in, which is what the
    /// pid is resolved against.
    pub lineage_at: UnixMillis,
    /// What it did.
    pub kind: ActionKind,
}

impl ObservedAction {
    /// One record, its wall-clock time also stated in the start-time base.
    #[must_use]
    pub fn new(record: &str, pid: u32, at: u64, offset: u64, kind: ActionKind) -> Self {
        Self {
            record: record.to_owned(),
            program: None,
            pid,
            at: UnixMillis(at),
            lineage_at: UnixMillis(to_lineage_base(at, offset)),
            kind,
        }
    }
}

/// The serial number in a record id: `41` in `1700000000.100:41`.
#[must_use]
pub fn serial(record: &str) -> Option<u64> {
    record.split_once(':')?.1.parse().ok()
}

/// A wall-clock time in the base process start times are kept in.
///
/// Start times are the kernel's boot time, published in whole seconds, plus
/// ticks since boot; `offset` is how far the wall clock runs ahead of that.
#[must_use]
pub const fn to_lineage_base(wall: u64, offset: u64) -> u64 {
    wall.saturating_sub(offset)
}

fn held() -> &'static Mutex<Held<ObservedAction>> {
    static HELD: Mutex<Held<ObservedAction>> = Mutex::new(Held::new());
    &HELD
}

/// Which reader's records: each has its own sequence of ids to track.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
pub(crate) enum Stream {
    /// File opens, changes and executes.
    File = 0,
    /// Successful execs.
    Exec = 1,
    /// Connects and addressed sends.
    Connect = 2,
}

/// Hands a reader's actions to the next sweep, each record once.
#[cfg(target_os = "linux")]
pub(crate) fn publish(stream: Stream, actions: Vec<ObservedAction>, now: u64) {
    static MARKS: Mutex<[Watermark; 3]> =
        Mutex::new([Watermark::new(), Watermark::new(), Watermark::new()]);
    let fresh = {
        let mut marks = MARKS.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(mark) = marks.get_mut(stream as usize) else {
            return;
        };
        mark.fresh(actions, now, |action| (serial(&action.record), action.at.0))
    };
    held()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(fresh);
}

/// How far the wall clock runs ahead of the base process start times are
/// kept in: boot time in whole seconds plus time since boot.
#[cfg(target_os = "linux")]
pub(crate) fn lineage_offset() -> u64 {
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| u64::try_from(since.as_millis()).unwrap_or(0));
    let since_boot = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let since_boot_ms = u64::try_from(since_boot.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1_000)
        .saturating_add(u64::try_from(since_boot.tv_nsec).unwrap_or(0) / 1_000_000);
    let base = crate::process::boot_seconds()
        .unwrap_or(0)
        .saturating_mul(1_000)
        .saturating_add(since_boot_ms);
    wall.saturating_sub(base)
}

/// Now, in the base process start times are kept in, which is the base the
/// running totals are kept in.
#[must_use]
pub fn tally_now() -> u64 {
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| u64::try_from(since.as_millis()).unwrap_or(0));
    #[cfg(target_os = "linux")]
    {
        to_lineage_base(wall, lineage_offset())
    }
    #[cfg(not(target_os = "linux"))]
    {
        wall
    }
}

/// Measured queue losses since the last sweep; upstream loss is not included.
#[must_use]
pub fn take_loss() -> u64 {
    std::mem::take(
        &mut held()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .overflowed,
    )
}

/// Everything recorded since the last call.
#[must_use]
pub fn take() -> Vec<ObservedAction> {
    held().lock().unwrap_or_else(PoisonError::into_inner).take()
}

#[cfg(test)]
mod tests {
    use super::to_lineage_base;

    #[test]
    fn a_wall_time_moves_into_the_start_time_base() {
        assert_eq!(to_lineage_base(10_500, 420), 10_080);
        assert_eq!(to_lineage_base(100, 420), 0, "never below zero");
    }
}
