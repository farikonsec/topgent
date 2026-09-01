//! What a connection or a lookup did.
//!
//! Byte counters are optional and absent by default, because most platforms do
//! not count. A zero here means the kernel counted zero; absence means it does
//! not count at all, and the two must never render the same.

/// Operating-system decision observed for a connection attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionOutcome {
    /// The operating system permitted the attempt; handshake completion is not implied.
    Allowed,
    /// The operating system blocked the attempt before completion.
    Blocked,
}

impl ConnectionOutcome {
    /// Stable report and journal label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Blocked => "blocked",
        }
    }
}

/// Traffic the kernel has accounted to one connection.
///
/// Cumulative for the life of the connection, in the operating system's own
/// terms. Sent and received are kept apart because a connection that mostly
/// receives and one that mostly sends are different behaviours, and adding them
/// together loses the distinction that matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteCounters {
    /// Bytes this host has sent on the connection.
    pub sent: u64,
    /// Bytes this host has received on the connection.
    pub received: u64,
}

/// What the resolver said about a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsOutcome {
    /// The resolver returned records.
    Answered,
    /// The resolver answered that the name has no such records, or no name.
    NotFound,
    /// The lookup did not complete.
    Failed,
}

impl DnsOutcome {
    /// Stable report and journal label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Answered => "answered",
            Self::NotFound => "not_found",
            Self::Failed => "failed",
        }
    }
}
