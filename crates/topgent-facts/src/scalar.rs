//! The small vocabulary every claim is built from.
//!
//! `Tri` exists because a sensor has three answers, not two: yes, no, and
//! nothing was established. Collapsing the third into `false` is what turns an
//! unavailable sensor into a clean bill of health.

/// Milliseconds since the Unix epoch.
///
/// A plain integer rather than a clock type: this crate never asks what time it
/// is, which is what lets the core replay a recorded fact stream and get the
/// same answer every time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixMillis(pub u64);

/// How much weight a probe's output deserves.
///
/// Displayed to the user on every row. Topgent never presents an inference as an
/// observation, so a collector that guessed says so here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    /// Inferred from indirect signal, such as a process talking to a model endpoint.
    Possible,
    /// Strong signal from one authority, such as a config file naming the agent.
    Likely,
    /// Read directly from the operating system.
    Certain,
}

impl Confidence {
    /// Weight in the range `0.0..=1.0`, used when a factor's points are scaled.
    #[must_use]
    pub const fn weight(self) -> f32 {
        match self {
            Self::Possible => 0.4,
            Self::Likely => 0.7,
            Self::Certain => 1.0,
        }
    }

    /// Short label for display.
    ///
    /// Standard evidence wording rather than everyday adjectives, so the same
    /// three words mean the same thing in the UI, the CLI and the event log.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Possible => "Possible",
            Self::Likely => "Probable",
            Self::Certain => "Confirmed",
        }
    }
}

/// A three-valued answer.
///
/// Deliberately not `bool`. "We have not looked" and "we looked and it is not so"
/// are different answers, and collapsing them is how a security tool starts
/// claiming things it does not know.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tri {
    /// Established as true.
    Yes,
    /// Established as false.
    No,
    /// Not established either way.
    Unknown,
}

impl Tri {
    /// True only for [`Tri::Yes`]. `Unknown` is never treated as permission.
    #[must_use]
    pub const fn is_yes(self) -> bool {
        matches!(self, Self::Yes)
    }

    /// Combine two answers, where any `Yes` wins and `Unknown` yields to a decision.
    ///
    /// Used when several collectors speak about the same resource.
    #[must_use]
    pub const fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::Yes, _) | (_, Self::Yes) => Self::Yes,
            (Self::No, _) | (_, Self::No) => Self::No,
            (Self::Unknown, Self::Unknown) => Self::Unknown,
        }
    }

    /// Display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::No => "no",
            Self::Unknown => "unknown",
        }
    }
}

/// The kind of access a claim is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Access {
    /// Read only.
    Read,
    /// Write only.
    Write,
    /// Both read and write.
    ReadWrite,
    /// Execute.
    Execute,
}

impl Access {
    /// Whether this access can change the resource.
    #[must_use]
    pub const fn is_mutating(self) -> bool {
        matches!(self, Self::Write | Self::ReadWrite | Self::Execute)
    }

    /// Display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::ReadWrite => "read, write",
            Self::Execute => "execute",
        }
    }
}

/// Which side of a connection was initiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// The process connected outwards.
    Outbound,
    /// The process is listening.
    Listening,
}

/// Which protocol a socket carries.
///
/// Recorded because the answer changes what the evidence can say. A TCP socket
/// names its peer; a bound UDP socket has no peer to name; and on macOS an ICMP
/// socket exposes neither. Collapsing the three into "a socket" is how a ping
/// to a host on the other side of the world produced no evidence at all while
/// the collector reported itself healthy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Protocol {
    /// A stream. The peer is always named.
    #[default]
    Tcp,
    /// A datagram socket. The peer is named only when it is connected.
    Udp,
    /// Raw ICMP. A process holding one can reach any host on the network, and
    /// on macOS the destination is not observable from a socket listing.
    Icmp,
    /// Something the platform named and this build does not model.
    Other,
}

impl Protocol {
    /// The word used in facts, reports, and the interface.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Other => "other",
        }
    }

    /// Read a platform's own word for it.
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "tcp" | "tcp4" | "tcp6" => Self::Tcp,
            "udp" | "udp4" | "udp6" => Self::Udp,
            "icmp" | "icmpv6" | "icmp6" => Self::Icmp,
            _ => Self::Other,
        }
    }

    /// Whether a peer address can exist for this protocol on this platform.
    ///
    /// `false` means an absent peer is a property of the platform, not a
    /// missed observation, and the interface must say so rather than showing
    /// a blank.
    #[must_use]
    pub const fn peer_observable(self) -> bool {
        !matches!(self, Self::Icmp)
    }
}
