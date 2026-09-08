//! The pure core.
//!
//! Two things live here and nothing else: the [`fold`](graph::fold) from a fact
//! stream to an agent graph, and the [`assess`](risk::assess) from an agent to a
//! score built out of named factors.
//!
//! Both are pure functions of their input. No clock, no filesystem, no sockets,
//! no ambient state. Four things follow from that, and they are why the boundary
//! is drawn here:
//!
//! - The timeline is not a feature. The fact log already is one.
//! - Tests are recorded fact streams replayed, not mocks of an operating system.
//! - The core can be fuzzed with synthetic streams on any machine.
//! - Two installs given the same facts always agree.
//!
//! Collectors are untrusted and live outside this crate. They may crash, lie or
//! flood; the worst they can do here is produce a fact that lands in
//! [`AgentGraph::rejected`](graph::AgentGraph::rejected).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod activity;
pub mod graph;
pub mod inventory;
pub mod network;
pub mod risk;

pub use graph::{
    Agent, AgentEdge, AgentGraph, AgentId, Connector, Endpoint, IdentityKind, RejectReason,
    Rejected, ResourceAccess, Sighting, fold, fold_with_home, resource_key,
};
pub use inventory::{
    Asset, AssetId, AssetKind, Inventory, Relationship, agent_asset_id, build as build_inventory,
    build_with_installed as build_inventory_with_installed, extension_asset_id,
};
pub use risk::{
    Factor, FactorCode, Grade, Remediation, Risk, apply_exceptions, assess, assess_with, items_of,
    matched_watchlist_rules, remediations, signals_for,
};

/// Fold a fact stream and score every agent in it.
///
/// The one call the rest of the system makes.
#[must_use]
pub fn analyse(facts: &[topgent_facts::Fact]) -> Vec<(Agent, Risk)> {
    analyse_with(facts, &topgent_policy::Policy::default())
}

/// Fold a fact stream and score every agent against a policy.
#[must_use]
pub fn analyse_with(
    facts: &[topgent_facts::Fact],
    policy: &topgent_policy::Policy,
) -> Vec<(Agent, Risk)> {
    analyse_at(facts, policy, std::env::var("HOME").ok().as_deref())
}

/// Fold and score, with the home directory supplied rather than read.
///
/// The one impure edge of the fold is which directory `~` stands for, and a
/// replay must not take it from the machine doing the replaying. A bundle
/// collected under `/Users/someone` and replayed under `/home/other` produced
/// a different resource set, a different factor count and a different grade,
/// because paths that had folded to `~/...` on one machine stayed absolute on
/// the other. Passing `None` keeps every path literal, which is what makes two
/// replays of one bundle agree wherever they run.
#[must_use]
pub fn analyse_at(
    facts: &[topgent_facts::Fact],
    policy: &topgent_policy::Policy,
    home: Option<&str>,
) -> Vec<(Agent, Risk)> {
    fold_with_home(facts, home)
        .agents
        .into_iter()
        .map(|a| {
            let r = assess_with(&a, policy);
            (a, r)
        })
        .collect()
}
pub use activity::{
    ACTIVITY_RETENTION_MS, Activity, ActivityEvent, ActivityKind, ActivityLink, ActivityNetwork,
    ActivityPath, LIFECYCLE_PERIODIC_MAX_INTERVAL_MS, LIFECYCLE_PERIODIC_MAX_JITTER_PERCENT,
    LIFECYCLE_PERIODIC_MIN_EVENTS, LIFECYCLE_PERIODIC_MIN_INTERVAL_MS, LinkCertainty,
    MAX_ACTIVITY_EVENTS, NetworkActivityPhase, build as build_activity, merge_activity_history,
};
pub use network::{
    MAX_NETWORK_RECORDS, MAX_NETWORK_SAMPLES, NETWORK_BASELINE_EXPIRY_MS,
    NETWORK_BASELINE_WARMUP_SAMPLES, NETWORK_HISTORY_RETENTION_MS, NetworkBaseline,
    NetworkBaselineState, NetworkRecord, NetworkVerdict, build_network_baselines,
    is_metadata_service, merge_network_history,
};
