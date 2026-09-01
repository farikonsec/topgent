//! The timeline vocabulary.
//!
//! Every event carries how it was linked to the agent, because the difference
//! between "this process spawned it" and "this happened while the agent was
//! running" is the difference between evidence and coincidence, and only one of
//! them belongs in an incident write-up.

use topgent_facts::Confidence;
use topgent_facts::Direction;

/// One kind of activity shown in an agent timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ActivityKind {
    /// The agent process started.
    Started,
    /// It spawned a descendant process.
    Process,
    /// A path was opened or modified.
    File,
    /// A network socket was observed.
    Network,
    /// A model was selected or observed.
    Model,
    /// A connector was declared.
    Connector,
    /// Another agent can be invoked.
    Agent,
    /// Topgent took an enforcement action.
    Action,
}

impl ActivityKind {
    /// Stable report label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Process => "process",
            Self::File => "file",
            Self::Network => "network",
            Self::Model => "model",
            Self::Connector => "connector",
            Self::Agent => "agent",
            Self::Action => "action",
        }
    }
}

/// How strongly two timeline events are connected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkCertainty {
    /// The fact itself names the relationship, such as parent to child.
    Direct,
    /// The event is attributed to the same agent by collector evidence.
    Attributed,
    /// Events share an agent and time window, but causation is not established.
    Correlated,
}

impl LinkCertainty {
    /// Stable report label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Attributed => "attributed",
            Self::Correlated => "correlated",
        }
    }
}

/// Whether network activity is a snapshot observation or an exact close event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NetworkActivityPhase {
    /// An endpoint was observed; this does not prove a connection opened.
    Observed,
    /// The operating system permitted an attempt; completion is not implied.
    Allowed,
    /// The operating system blocked an attempt.
    Blocked,
    /// A successful close was correlated to an earlier successful connect.
    Closed,
}

impl NetworkActivityPhase {
    /// Stable report and journal label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Allowed => "allowed",
            Self::Blocked => "blocked",
            Self::Closed => "closed",
        }
    }
}

/// Structured metadata for one network activity event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityNetwork {
    /// Normalized host or address.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// Outbound or listening direction.
    pub direction: Direction,
    /// Evidence phase.
    pub phase: NetworkActivityPhase,
    /// Exact connect-to-close duration when the collector supplied it.
    pub duration_ms: Option<u64>,
}

impl PartialOrd for ActivityNetwork {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ActivityNetwork {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let direction = |value| match value {
            Direction::Outbound => 0_u8,
            Direction::Listening => 1_u8,
        };
        (
            &self.host,
            self.port,
            direction(self.direction),
            self.phase,
            self.duration_ms,
        )
            .cmp(&(
                &other.host,
                other.port,
                direction(other.direction),
                other.phase,
                other.duration_ms,
            ))
    }
}

/// One immutable event in the current activity projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityEvent {
    /// Deterministic identifier within an agent run.
    pub id: String,
    /// Durable monotonic order within one exact agent run.
    pub sequence: u64,
    /// Explicit direct parent event when collector evidence establishes one.
    pub parent_id: Option<String>,
    /// Running agent instance.
    pub agent_pid: u32,
    /// Agent process start time, preventing PID-reuse attribution.
    pub agent_started_at: u64,
    /// Process responsible when known.
    pub actor_pid: u32,
    /// Observation time in Unix milliseconds.
    pub at: u64,
    /// Event category.
    pub kind: ActivityKind,
    /// Short explanation.
    pub title: String,
    /// Metadata-only detail.
    pub detail: String,
    /// Evidence strength.
    pub confidence: Confidence,
    /// Collector name.
    pub collector: String,
    /// Probe description.
    pub probe: String,
    /// Structured network metadata when this is a network event.
    pub network: Option<ActivityNetwork>,
}

/// One relationship rendered between timeline events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityLink {
    /// Earlier/source event.
    pub from: String,
    /// Later/target event.
    pub to: String,
    /// Human-readable relationship.
    pub relation: &'static str,
    /// Whether the relationship is direct, attributed, or correlated.
    pub certainty: LinkCertainty,
}

/// A security-relevant sequence composed from timeline events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityPath {
    /// Stable path identifier.
    pub id: String,
    /// Running agent instance.
    pub agent_pid: u32,
    /// Agent process start time, preventing PID-reuse attribution.
    pub agent_started_at: u64,
    /// Path explanation.
    pub title: String,
    /// Why the events were connected.
    pub explanation: String,
    /// Event identifiers in display order.
    pub events: Vec<String>,
    /// Strength of the weakest link.
    pub certainty: LinkCertainty,
}

/// Timeline events, their links, and conservative attack-path correlations.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Activity {
    /// Events in timestamp/identity order.
    pub events: Vec<ActivityEvent>,
    /// Event relationships.
    pub links: Vec<ActivityLink>,
    /// Security-relevant event sequences.
    pub paths: Vec<ActivityPath>,
}
