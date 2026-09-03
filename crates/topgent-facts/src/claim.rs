//! Everything a collector is allowed to assert.
//!
//! A closed vocabulary, deliberately. A collector cannot invent a new kind of
//! finding without a change here, which is a change with review attached — the
//! alternative is a free-text field, and a free-text field is how a monitor
//! ends up asserting things nobody can verify.

use crate::network::ByteCounters;
use crate::network::ConnectionOutcome;
use crate::network::DnsOutcome;
use crate::scalar::Access;
use crate::scalar::Direction;
use crate::scalar::MatchBasis;
use crate::scalar::Protocol;
use crate::scalar::Reachability;
use crate::scalar::UnixMillis;

/// What is asserted about a subject.
///
/// One variant per thing a collector can honestly report. Adding a variant is
/// how Topgent learns to see something new; nothing else in the pipeline changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    /// A process exists, with this executable and owner.
    ProcessSeen {
        /// Absolute path to the executable, or the process name when the
        /// operating system would not give a path.
        exe: String,
        /// Whether `exe` is the executable path the operating system reported.
        ///
        /// False means the path was refused and only the process name is
        /// known, which is a sensor limit rather than an absent executable.
        /// Recognition depends on the path, so the distinction is the
        /// difference between "not an agent" and "cannot tell".
        exe_path_known: bool,
        /// Numeric user id the process runs as; zero means the platform did
        /// not provide a Unix-compatible numeric owner identity.
        uid: u32,
        /// Resolved user name.
        user: String,
    },
    /// A process was spawned by another process.
    ProcessParent {
        /// Parent process id.
        parent_pid: u32,
    },
    /// A descendant process currently running beneath the agent.
    ///
    /// Only the executable name is retained. Command arguments can contain
    /// secrets and do not belong in Topgent's fact stream.
    ChildProcessSeen {
        /// Child process id.
        pid: u32,
        /// Short executable name from the process table.
        name: String,
        /// Number of parent edges between the agent and this descendant.
        depth: u16,
    },
    /// The subject holds a socket to this endpoint.
    SocketOpen {
        /// Which protocol this socket carries.
        ///
        /// A bound UDP socket has no peer, and on macOS an ICMP socket exposes
        /// none. The protocol is what tells a host nobody could observe apart
        /// from a host the collector failed to read, and dropping every
        /// non-TCP row is how a ping across the world produced no evidence
        /// while the collector called itself healthy.
        protocol: Protocol,
        /// Peer host, or the bind address when listening. `*` where the
        /// platform states no address at all.
        host: String,
        /// Peer port.
        port: u16,
        /// Which way the connection goes.
        direction: Direction,
        /// When the operating system recorded this connection being created.
        ///
        /// `None` where the platform does not keep one. A socket snapshot says
        /// a connection exists now; it does not say how long it has existed,
        /// and the difference between two snapshots is an inference, not an
        /// observation. Only a timestamp the kernel itself recorded belongs
        /// here, so this is never filled in by subtraction or defaulted to
        /// zero.
        opened_at: Option<UnixMillis>,
        /// Bytes the kernel has accounted to this connection, when it keeps a
        /// counter.
        ///
        /// `None` where the platform's socket listing carries none. A snapshot
        /// collector counts sweeps, not traffic, and the number of times an
        /// endpoint was visible has never been a volume; only a counter the
        /// kernel itself maintains belongs here.
        bytes: Option<ByteCounters>,
        /// How the socket was tied to the process this fact is about.
        ///
        /// A tool that lists a process's open sockets names an owner without
        /// saying how it matched, which is [`MatchBasis::Unreported`] and not a
        /// defect. A backend that searched a socket table can say whether the
        /// whole tuple matched or whether a key had to be relaxed, and those
        /// are different findings that used to render identically.
        basis: MatchBasis,
    },
    /// A previously connected socket was closed, with kernel-timestamp duration.
    SocketClosed {
        /// Peer host recovered from the matching connect event.
        host: String,
        /// Peer port recovered from the matching connect event.
        port: u16,
        /// Which way the connection was initiated.
        direction: Direction,
        /// Elapsed milliseconds between matching connect and close syscalls.
        duration_ms: u64,
    },
    /// The operating system allowed or blocked a connection attempt.
    ///
    /// An allowed attempt does not prove a completed handshake or an open socket.
    ConnectionAttempt {
        /// Destination address literal.
        host: String,
        /// Destination port.
        port: u16,
        /// Which way the attempt was initiated.
        direction: Direction,
        /// Operating-system filtering decision.
        outcome: ConnectionOutcome,
    },
    /// The subject asked the resolver to look up a name.
    ///
    /// Only emitted where the operating system names the process that asked.
    /// A resolver contact whose requester the platform does not identify is
    /// left unattributed rather than pinned on whichever process looks likely:
    /// on Windows the service that writes these records is itself the resolver
    /// cache, so the record's own process id is never the client's.
    DnsQueryObserved {
        /// The name as the operating system recorded it.
        name: String,
        /// Numeric DNS record type the resolver was asked for.
        query_type: u16,
        /// What the resolver said.
        outcome: DnsOutcome,
    },
    /// The subject touched a path.
    FileTouched {
        /// The path.
        path: String,
        /// How it was touched.
        access: Access,
    },
    /// The subject's own configuration grants or denies a path.
    ///
    /// This is the **declared** column: what the agent says it may do.
    PermissionDeclared {
        /// The path or glob the config names.
        path: String,
        /// The access the config names.
        access: Access,
        /// Whether the config grants it.
        granted: bool,
    },
    /// The subject could reach a path, whether or not it ever has.
    ///
    /// This is the **reachable** column: computed from the process user and the
    /// filesystem, never from the agent's claims about itself.
    ResourceReachable {
        /// The path.
        path: String,
        /// The access that would succeed.
        access: Access,
        /// Whether the path holds a credential.
        sensitive: bool,
        /// What the probe actually established.
        ///
        /// A stat that succeeded and a kernel that said "this account may read
        /// it" are not the same finding, and the reachable column used to
        /// present them as one.
        evidence: Reachability,
    },
    /// The subject belongs to a known agent family.
    AgentFamily {
        /// Family name, such as `claude-code`.
        family: String,
    },
    /// A known agent extension is active inside this editor host process.
    EditorExtensionActive {
        /// Family name, such as `cline`.
        family: String,
        /// Exact extension publisher and package identifier.
        extension_id: String,
    },
    /// The subject talks to this model.
    ModelInUse {
        /// Provider, such as `anthropic` or `local`.
        provider: String,
        /// Model identifier as reported.
        model: String,
    },
    /// The subject declares a connector it may call.
    ConnectorDeclared {
        /// Connector name.
        name: String,
        /// Access the connector grants.
        access: Access,
    },
    /// The subject can invoke another agent.
    ///
    /// The second hop. This is the edge nothing else draws.
    InvokesAgent {
        /// Process id of the agent it can invoke.
        target_pid: u32,
        /// How, such as `mcp`, `child-process` or `localhost`.
        via: String,
    },
    /// A collector could not evaluate this subject, and says so.
    ///
    /// The claim exists because silence is ambiguous. A reach collector that
    /// skips an agent owned by another account is doing the right thing, but a
    /// report where that skip is indistinguishable from "nothing was found"
    /// presents an unexamined agent as a clean one. Stating the skip is what
    /// lets everything downstream tell a zero from an absence.
    SubjectNotEvaluated {
        /// Why, in the words a report should use.
        reason: String,
    },
    /// Topgent itself did something.
    ///
    /// Enforcement writes this, so an action taken and an action observed are the
    /// same shape in the log.
    ActionTaken {
        /// What was done, such as `kill`.
        action: String,
        /// Whether it succeeded.
        succeeded: bool,
    },
}

impl Claim {
    /// Stable machine-readable name, used in logs and tests.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::ProcessSeen { .. } => "process_seen",
            Self::ProcessParent { .. } => "process_parent",
            Self::ChildProcessSeen { .. } => "child_process_seen",
            Self::SocketOpen { .. } => "socket_open",
            Self::SocketClosed { .. } => "socket_closed",
            Self::ConnectionAttempt { .. } => "connection_attempt",
            Self::DnsQueryObserved { .. } => "dns_query_observed",
            Self::FileTouched { .. } => "file_touched",
            Self::PermissionDeclared { .. } => "permission_declared",
            Self::ResourceReachable { .. } => "resource_reachable",
            Self::AgentFamily { .. } => "agent_family",
            Self::EditorExtensionActive { .. } => "editor_extension_active",
            Self::ModelInUse { .. } => "model_in_use",
            Self::ConnectorDeclared { .. } => "connector_declared",
            Self::InvokesAgent { .. } => "invokes_agent",
            Self::SubjectNotEvaluated { .. } => "subject_not_evaluated",
            Self::ActionTaken { .. } => "action_taken",
        }
    }
}
