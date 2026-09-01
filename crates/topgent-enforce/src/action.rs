//! What Topgent is willing to do, and what it says when it will not.
//!
//! An action names the exact run it was authorised against, so the identity can
//! be rechecked immediately before anything happens. A refusal is not a
//! failure: most of them are the guard working, and each says why in words an
//! operator can act on rather than an error code they have to look up.

use std::fmt;
use topgent_facts::{Fact, UnixMillis};

/// A change Topgent is willing to make.
///
/// Exhaustive on purpose. If it is not in this enum, Topgent cannot do it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Stop one process: `SIGTERM`, a grace period, then `SIGKILL` if needed.
    Kill {
        /// Process id.
        pid: u32,
        /// The start time this action was authorised against.
        ///
        /// Re-checked immediately before the signal. A mismatch is refused.
        started_at: UnixMillis,
    },
    /// Stop an agent root and every currently attributable descendant,
    /// deepest descendants first, with exact identity checks throughout.
    KillTree {
        /// Root process id.
        pid: u32,
        /// Root start time this action was authorised against.
        started_at: UnixMillis,
    },
}

impl Action {
    /// Short machine-readable name, written into the fact.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Kill { .. } => "kill",
            Self::KillTree { .. } => "kill_tree",
        }
    }

    /// The pid this action targets.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        match self {
            Self::Kill { pid, .. } | Self::KillTree { pid, .. } => *pid,
        }
    }

    /// The identity this action was authorised against.
    #[must_use]
    pub const fn started_at(&self) -> UnixMillis {
        match self {
            Self::Kill { started_at, .. } | Self::KillTree { started_at, .. } => *started_at,
        }
    }
}

/// Why an action was refused or failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The process is gone. Nothing to do, and not an error worth alarming about.
    NotRunning,
    /// A process with this pid exists but is not the one that was authorised.
    ///
    /// The pid was reused between the decision and the signal.
    IdentityChanged {
        /// The start time the action carried.
        expected: UnixMillis,
        /// The start time the process on that pid actually has.
        found: UnixMillis,
    },
    /// Topgent will not signal this process.
    Protected {
        /// Why not, in words a user can act on.
        why: &'static str,
    },
    /// The operating system refused the signal.
    Denied {
        /// What it said.
        detail: String,
    },
    /// A tree response signalled some members before a later signal failed.
    Partial {
        /// Number of members already signalled.
        signalled: usize,
        /// Sanitized operating-system refusal for the next member.
        detail: String,
    },
    /// The process survived both signals.
    Survived,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRunning => write!(f, "already gone"),
            Self::IdentityChanged { expected, found } => write!(
                f,
                "pid reused: authorised against start {}, found {}",
                expected.0, found.0
            ),
            Self::Protected { why } => write!(f, "refused: {why}"),
            Self::Denied { detail } => write!(f, "denied by the system: {detail}"),
            Self::Partial { signalled, detail } => write!(
                f,
                "partial process-tree response after {signalled} signal(s): {detail}"
            ),
            Self::Survived => write!(f, "still running after forced termination"),
        }
    }
}

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// It shut down on `SIGTERM` within the grace period.
    StoppedGracefully,
    /// It needed `SIGKILL`.
    Killed,
    /// The root and all descendants stopped during the graceful window.
    TreeStoppedGracefully,
    /// At least one member of the process tree required `SIGKILL`.
    TreeKilled,
    /// The exact runtime container was stopped through its authenticated local API.
    ContainerStopped,
}

impl Outcome {
    /// Display label, in the words the platform actually uses.
    ///
    /// Windows has no signals. Reporting "killed with SIGKILL" on a host where
    /// nothing of the sort happened tells the reader something untrue about
    /// how their machine works, and sends anyone checking the evidence looking
    /// for a signal that was never sent.
    #[must_use]
    pub const fn label(self) -> &'static str {
        #[cfg(windows)]
        {
            match self {
                Self::StoppedGracefully => "closed on request",
                Self::Killed => "terminated forcefully",
                Self::TreeStoppedGracefully => "process tree closed on request",
                Self::TreeKilled => "process tree stopped; forced termination was required",
                Self::ContainerStopped => "container stopped",
            }
        }
        #[cfg(not(windows))]
        {
            match self {
                Self::StoppedGracefully => "stopped on SIGTERM",
                Self::Killed => "killed with SIGKILL",
                Self::TreeStoppedGracefully => "process tree stopped on SIGTERM",
                Self::TreeKilled => "process tree stopped; SIGKILL was required",
                Self::ContainerStopped => "container stopped",
            }
        }
    }
}

/// The result of an action, and the fact that records it.
#[derive(Debug, Clone)]
pub struct Executed {
    /// What happened.
    pub result: Result<Outcome, Refusal>,
    /// The fact written for it, when a subject could be formed.
    pub fact: Option<Fact>,
}
