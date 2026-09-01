//! What a fact is about.
//!
//! A process subject carries its start time, not just its pid. The kernel
//! reuses pids, and a fact identified by pid alone can be read as being about a
//! process that did not exist when it was recorded.

use crate::scalar::UnixMillis;

/// What a fact is about.
///
/// The subject is the join key of the whole system: two facts about the same
/// subject describe the same thing, and nothing else merges them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Subject {
    /// One running process.
    ///
    /// Identified by pid **and** start time, because pids are reused. Two
    /// processes with the same pid and different start times are different
    /// subjects, which is what stops a recycled pid inheriting the previous
    /// occupant's findings.
    Process {
        /// Process id.
        pid: u32,
        /// Process start time, as reported by the OS.
        started_at: UnixMillis,
    },
    /// One filesystem path.
    Resource {
        /// Path as the collector saw it, not canonicalised here.
        path: String,
    },
    /// One network destination.
    Endpoint {
        /// Hostname or address literal.
        host: String,
        /// Port.
        port: u16,
    },
}

impl Subject {
    /// The process id, when this subject is a process.
    #[must_use]
    pub const fn pid(&self) -> Option<u32> {
        match self {
            Self::Process { pid, .. } => Some(*pid),
            _ => None,
        }
    }
}
