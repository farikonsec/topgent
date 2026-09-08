//! When a risk factor fires, expressed as data rather than as Rust.
//!
//! Every factor's firing decision used to be an `if` in the scorer. That made
//! three things impossible: an operator could not tune a factor without a
//! rebuild, two catalogues could not be compared to say what a policy change
//! would do, and nothing could report that a factor is unreachable on this
//! platform because nothing could read the condition.
//!
//! # What this deliberately is not
//!
//! It is not an expression language. There is no parser, no precedence, no
//! escaping and no string syntax. A condition is a small typed tree that the
//! JSON schema validates on the way in, which means a malformed condition is
//! a load error with a location rather than a runtime surprise. The set of
//! operators is closed and every one of them terminates.
//!
//! It also cannot introduce a finding. A condition decides whether a
//! [`crate::catalogue::FactorEntry`] that the binary already knows about
//! fires. A data file that could mint a new kind of finding would be a data
//! file that could talk the scorer into a verdict, so the vocabulary of codes
//! stays a Rust enum and this decides only their gating.
//!
//! # What stays in Rust
//!
//! The sentence a factor prints, and the iteration where one factor is emitted
//! per matching resource. Those need the matching values, not just the
//! decision, and a language that could project values would be the expression
//! language this is not. The split is: data says *whether*, Rust says *what it
//! says*.

use serde::Deserialize;

use crate::Thresholds;

/// One named, typed value a condition may read from an agent.
///
/// The list is closed. A condition naming anything else fails to parse, which
/// is why a typo in a catalogue is a load error rather than a factor that
/// silently never fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Signal {
    /// The agent's own configuration grants it execute.
    CanExecute,
    /// A declared write grant contains a recursive glob.
    CanWriteBroadly,
    /// The agent declared a sandbox.
    IsSandboxed,
    /// Whether the executable path is the one the operating system reported.
    ExePathKnown,
    /// Whether a family was recognised.
    FamilyKnown,
    /// Distinct outbound destinations.
    OutboundCount,
    /// Distinct remote hosts.
    DistinctHosts,
    /// Most ports seen to any single host.
    MaxPortsToOneHost,
    /// Credentials in reach that nothing has touched.
    LatentSecretCount,
    /// Resources touched beyond what was declared.
    DriftCount,
    /// Other agents this one can invoke.
    InvokesCount,
    /// Descendant processes.
    ChildrenCount,
    /// Declared connectors.
    ConnectorCount,
    /// Network endpoints of any kind.
    EndpointCount,
    /// Resources of any kind.
    ResourceCount,
    /// Reasons a collector gave for not examining this agent.
    UnevaluatedCount,
    /// Facts that produced this agent.
    FactCount,
}

impl Signal {
    /// The wire name, which is what a catalogue writes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CanExecute => "can_execute",
            Self::CanWriteBroadly => "can_write_broadly",
            Self::IsSandboxed => "is_sandboxed",
            Self::ExePathKnown => "exe_path_known",
            Self::FamilyKnown => "family_known",
            Self::OutboundCount => "outbound_count",
            Self::DistinctHosts => "distinct_hosts",
            Self::MaxPortsToOneHost => "max_ports_to_one_host",
            Self::LatentSecretCount => "latent_secret_count",
            Self::DriftCount => "drift_count",
            Self::InvokesCount => "invokes_count",
            Self::ChildrenCount => "children_count",
            Self::ConnectorCount => "connector_count",
            Self::EndpointCount => "endpoint_count",
            Self::ResourceCount => "resource_count",
            Self::UnevaluatedCount => "unevaluated_count",
            Self::FactCount => "fact_count",
        }
    }

    /// Whether this signal is a yes-or-no rather than a count.
    ///
    /// A count compared with `is`, or a flag compared with `at_least`, is a
    /// mistake in the catalogue and is reported as one.
    #[must_use]
    pub const fn is_flag(self) -> bool {
        matches!(
            self,
            Self::CanExecute
                | Self::CanWriteBroadly
                | Self::IsSandboxed
                | Self::ExePathKnown
                | Self::FamilyKnown
        )
    }

    /// Every signal, for validation and for the schema.
    #[must_use]
    pub const fn all() -> [Self; 17] {
        [
            Self::CanExecute,
            Self::CanWriteBroadly,
            Self::IsSandboxed,
            Self::ExePathKnown,
            Self::FamilyKnown,
            Self::OutboundCount,
            Self::DistinctHosts,
            Self::MaxPortsToOneHost,
            Self::LatentSecretCount,
            Self::DriftCount,
            Self::InvokesCount,
            Self::ChildrenCount,
            Self::ConnectorCount,
            Self::EndpointCount,
            Self::ResourceCount,
            Self::UnevaluatedCount,
            Self::FactCount,
        ]
    }
}

/// The values one agent presents to every condition.
///
/// Filled by the scorer, which is the only thing that knows how to compute
/// them. Keeping the struct here rather than in the scorer means the vocabulary
/// and the evaluator cannot drift apart: a signal added to the enum will not
/// compile until it has a value.
// Five of these are flags because five of the signals are yes-or-no questions
// about an agent. Packing them into a bitfield would make the struct shorter
// and every use site harder to read.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Signals {
    /// See [`Signal::CanExecute`].
    pub can_execute: bool,
    /// See [`Signal::CanWriteBroadly`].
    pub can_write_broadly: bool,
    /// See [`Signal::IsSandboxed`].
    pub is_sandboxed: bool,
    /// See [`Signal::ExePathKnown`].
    pub exe_path_known: bool,
    /// See [`Signal::FamilyKnown`].
    pub family_known: bool,
    /// See [`Signal::OutboundCount`].
    pub outbound_count: u32,
    /// See [`Signal::DistinctHosts`].
    pub distinct_hosts: u32,
    /// See [`Signal::MaxPortsToOneHost`].
    pub max_ports_to_one_host: u32,
    /// See [`Signal::LatentSecretCount`].
    pub latent_secret_count: u32,
    /// See [`Signal::DriftCount`].
    pub drift_count: u32,
    /// See [`Signal::InvokesCount`].
    pub invokes_count: u32,
    /// See [`Signal::ChildrenCount`].
    pub children_count: u32,
    /// See [`Signal::ConnectorCount`].
    pub connector_count: u32,
    /// See [`Signal::EndpointCount`].
    pub endpoint_count: u32,
    /// See [`Signal::ResourceCount`].
    pub resource_count: u32,
    /// See [`Signal::UnevaluatedCount`].
    pub unevaluated_count: u32,
    /// See [`Signal::FactCount`].
    pub fact_count: u32,
}

impl Signals {
    /// The value of one signal, as a count. A flag is zero or one.
    #[must_use]
    pub const fn count(&self, signal: Signal) -> u32 {
        match signal {
            Signal::CanExecute => self.can_execute as u32,
            Signal::CanWriteBroadly => self.can_write_broadly as u32,
            Signal::IsSandboxed => self.is_sandboxed as u32,
            Signal::ExePathKnown => self.exe_path_known as u32,
            Signal::FamilyKnown => self.family_known as u32,
            Signal::OutboundCount => self.outbound_count,
            Signal::DistinctHosts => self.distinct_hosts,
            Signal::MaxPortsToOneHost => self.max_ports_to_one_host,
            Signal::LatentSecretCount => self.latent_secret_count,
            Signal::DriftCount => self.drift_count,
            Signal::InvokesCount => self.invokes_count,
            Signal::ChildrenCount => self.children_count,
            Signal::ConnectorCount => self.connector_count,
            Signal::EndpointCount => self.endpoint_count,
            Signal::ResourceCount => self.resource_count,
            Signal::UnevaluatedCount => self.unevaluated_count,
            Signal::FactCount => self.fact_count,
        }
    }
}

/// A number a condition compares against.
///
/// A literal pins the number in the catalogue. A threshold reference reads it
/// from the operator's policy, so `network_spread` stays one tunable value
/// rather than being copied into every condition that needs it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum Amount {
    /// A number written in the catalogue.
    Literal(u32),
    /// A named threshold from the policy in force.
    Named(ThresholdRef),
}

/// One named threshold.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdRef {
    /// Which threshold, by name.
    pub threshold: ThresholdName,
}

/// The thresholds a condition may read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdName {
    /// Distinct destinations before outbound reads as unrestricted.
    NetworkSpread,
    /// Distinct hosts before a pattern reads as scanning a network.
    ReconHosts,
    /// Ports to one host before it reads as scanning a host.
    ReconPorts,
    /// Descendants before process creation reads as a burst.
    ProcessChildren,
}

impl ThresholdName {
    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NetworkSpread => "network_spread",
            Self::ReconHosts => "recon_hosts",
            Self::ReconPorts => "recon_ports",
            Self::ProcessChildren => "process_children",
        }
    }

    /// The value in force.
    #[must_use]
    pub fn of(self, thresholds: &Thresholds) -> u32 {
        let value = match self {
            Self::NetworkSpread => thresholds.network_spread,
            Self::ReconHosts => thresholds.recon_hosts,
            Self::ReconPorts => thresholds.recon_ports,
            Self::ProcessChildren => thresholds.process_children,
        };
        u32::try_from(value).unwrap_or(u32::MAX)
    }
}

impl Amount {
    /// The number, resolved against the policy in force.
    #[must_use]
    pub fn resolve(&self, thresholds: &Thresholds) -> u32 {
        match self {
            Self::Literal(value) => *value,
            Self::Named(named) => named.threshold.of(thresholds),
        }
    }
}

/// When a factor fires.
///
/// Named `Firing` rather than `Condition` because [`crate::Condition`] already
/// means something else: when a watchlist rule applies. Six operators, all total. Nothing here can loop, allocate unboundedly, read
/// the filesystem, or call out.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Firing {
    /// Every branch holds. An empty list is true.
    All(Vec<Firing>),
    /// Some branch holds. An empty list is false.
    Any(Vec<Firing>),
    /// The branch does not hold.
    Not(Box<Firing>),
    /// A flag signal is set.
    Is(Signal),
    /// A count signal is at or above an amount.
    AtLeast(Signal, Amount),
    /// A count signal is strictly below an amount.
    Below(Signal, Amount),
}

impl Firing {
    /// Whether this condition holds for one agent under one policy.
    #[must_use]
    pub fn holds(&self, signals: &Signals, thresholds: &Thresholds) -> bool {
        match self {
            Self::All(branches) => branches
                .iter()
                .all(|branch| branch.holds(signals, thresholds)),
            Self::Any(branches) => branches
                .iter()
                .any(|branch| branch.holds(signals, thresholds)),
            Self::Not(inner) => !inner.holds(signals, thresholds),
            Self::Is(signal) => signals.count(*signal) > 0,
            Self::AtLeast(signal, amount) => signals.count(*signal) >= amount.resolve(thresholds),
            Self::Below(signal, amount) => signals.count(*signal) < amount.resolve(thresholds),
        }
    }

    /// Every signal this condition reads, for validation and for explaining it.
    #[must_use]
    pub fn signals(&self) -> Vec<Signal> {
        let mut out = Vec::new();
        self.collect_signals(&mut out);
        out.sort_unstable();
        out.dedup();
        out
    }

    fn collect_signals(&self, into: &mut Vec<Signal>) {
        match self {
            Self::All(branches) | Self::Any(branches) => {
                for branch in branches {
                    branch.collect_signals(into);
                }
            }
            Self::Not(inner) => inner.collect_signals(into),
            Self::Is(signal) | Self::AtLeast(signal, _) | Self::Below(signal, _) => {
                into.push(*signal);
            }
        }
    }

    /// How deep the tree goes, so a pathological catalogue can be refused.
    #[must_use]
    pub fn depth(&self) -> usize {
        match self {
            Self::All(branches) | Self::Any(branches) => {
                1 + branches.iter().map(Self::depth).max().unwrap_or(0)
            }
            Self::Not(inner) => 1 + inner.depth(),
            Self::Is(_) | Self::AtLeast(..) | Self::Below(..) => 1,
        }
    }

    /// Whether the condition can ever hold.
    ///
    /// Detects the two shapes that are always false: an `any` with no branches,
    /// and a flag compared with `at_least` against an amount above one. Both
    /// are catalogue mistakes that would otherwise present as a factor that
    /// simply never fires, which is indistinguishable from a quiet host.
    #[must_use]
    pub fn is_satisfiable(&self, thresholds: &Thresholds) -> bool {
        match self {
            Self::Any(branches) => {
                !branches.is_empty()
                    && branches
                        .iter()
                        .any(|branch| branch.is_satisfiable(thresholds))
            }
            Self::All(branches) => branches
                .iter()
                .all(|branch| branch.is_satisfiable(thresholds)),
            // A negation is satisfiable whatever it wraps, and a flag test is
            // satisfiable by definition. Kept apart because they are different
            // arguments that happen to reach the same answer.
            Self::Not(_) | Self::Is(_) => true,
            Self::AtLeast(signal, amount) => !signal.is_flag() || amount.resolve(thresholds) <= 1,
            Self::Below(signal, amount) => {
                let bound = amount.resolve(thresholds);
                bound > 0 && (!signal.is_flag() || bound <= 2)
            }
        }
    }
}
