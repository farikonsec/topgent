//! Portable, metadata-only network history aggregation.
//!
//! Snapshot collectors observe open sockets, not connection lifecycles. The
//! counter here is therefore deliberately named `observations`: it must never
//! be presented as bytes, requests, or completed connections.

use crate::Agent;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use topgent_facts::Direction;
use topgent_facts::Protocol;

/// Default bound for persisted endpoint records.
pub const MAX_NETWORK_RECORDS: usize = 2_048;
/// Maximum retained sweep timestamps per endpoint record.
pub const MAX_NETWORK_SAMPLES: usize = 64;
/// Distinct snapshot samples required before a baseline is frozen.
pub const NETWORK_BASELINE_WARMUP_SAMPLES: usize = 5;
/// Inactivity after which a retained baseline is expired.
pub const NETWORK_BASELINE_EXPIRY_MS: u64 = 24 * 60 * 60 * 1_000;
/// Historical endpoint retention window: seven days since last observation.
pub const NETWORK_HISTORY_RETENTION_MS: u64 = 7 * 24 * 60 * 60 * 1_000;

/// Lifecycle state for one agent-instance network baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkBaselineState {
    /// Fewer than the required distinct sweep samples have been observed.
    Collecting,
    /// Warm-up completed and the initial host/port set is frozen.
    Ready,
    /// The retained agent instance has not been observed within the expiry window.
    Expired,
}

impl NetworkBaselineState {
    /// Stable report label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Ready => "ready",
            Self::Expired => "expired",
        }
    }
}

/// Derived, persistent network baseline for one exact agent process instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkBaseline {
    /// Agent process ID.
    pub agent_pid: u32,
    /// Agent process start time, preventing PID-reuse inheritance.
    pub agent_started_at: u64,
    /// First retained observation for this instance.
    pub started_at: u64,
    /// Fifth distinct sample timestamp, when the baseline froze.
    pub ready_at: Option<u64>,
    /// Most recent retained endpoint observation.
    pub last_observed_at: u64,
    /// Current lifecycle state.
    pub state: NetworkBaselineState,
    /// Number of distinct retained sweep timestamps across this agent instance.
    pub retained_samples: usize,
    /// Hosts first seen no later than the warm-up cutoff.
    pub known_hosts: BTreeSet<String>,
    /// Ports first seen no later than the warm-up cutoff.
    pub known_ports: BTreeSet<u16>,
}

/// Deterministic metadata verdict for one endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NetworkVerdict {
    /// No higher-priority metadata rule matched.
    Observed,
    /// A listener is exposed beyond loopback.
    ExposedListener,
    /// A raw IP is used with a commonly suspicious port.
    SuspiciousEndpoint,
    /// An outbound peer is in a private address range.
    PrivatePeer,
    /// An outbound request targets a cloud instance metadata endpoint.
    MetadataService,
}

impl NetworkVerdict {
    /// Stable report label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::ExposedListener => "exposed_listener",
            Self::SuspiciousEndpoint => "suspicious_endpoint",
            Self::PrivatePeer => "private_peer",
            Self::MetadataService => "metadata_service",
        }
    }
}

/// One bounded aggregate for a running agent instance and endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRecord {
    /// Agent process ID.
    pub agent_pid: u32,
    /// Agent process start time, protecting history from PID reuse.
    pub agent_started_at: u64,
    /// Agent family at observation time.
    pub agent_family: String,
    /// Which protocol carries it. Part of the identity: a datagram and a
    /// stream to the same host and port are two different things.
    pub protocol: Protocol,
    /// Hostname or address exactly as normalized by the graph. `*` where the
    /// platform stated none.
    pub host: String,
    /// Peer or listening port.
    pub port: u16,
    /// Connection direction.
    pub direction: Direction,
    /// First sweep that observed this tuple.
    pub first_seen: u64,
    /// Most recent sweep that observed this tuple.
    pub last_seen: u64,
    /// Number of sweeps in which the tuple was observed.
    pub observations: u64,
    /// Bounded timestamps for recent sweeps where this tuple was visible.
    pub sample_times: Vec<u64>,
    /// Whether the tuple was present in the most recent socket snapshot.
    pub currently_observed: bool,
    /// Most recent sweep where snapshot visibility entered or exited.
    pub last_visibility_change: u64,
    /// Number of observed visibility edges, including the initial appearance.
    pub visibility_changes: u64,
    /// Highest-priority deterministic metadata verdict.
    pub verdict: NetworkVerdict,
}

fn direction_rank(direction: Direction) -> u8 {
    match direction {
        Direction::Outbound => 0,
        Direction::Listening => 1,
    }
}

fn is_loopback(host: &str) -> bool {
    host == "localhost"
        || host == "*"
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn is_private(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok_and(|address| match address {
        IpAddr::V4(address) => address.is_private(),
        IpAddr::V6(address) => (address.segments()[0] & 0xfe00) == 0xfc00,
    })
}

/// Whether a host label is a well-known cloud instance metadata endpoint.
///
/// The addresses themselves live in the detection signals file, so the verdict
/// here and the factor that explains it cannot disagree about which hosts
/// count. A build that cannot read its signals answers no, matching every
/// other signal-backed predicate: a missing list makes Topgent quieter, and
/// `doctor` reports the failure rather than the scorer inventing a default.
#[must_use]
pub fn is_metadata_service(host: &str) -> bool {
    topgent_policy::signals::builtin().is_ok_and(|signals| signals.is_metadata_host(host))
}

/// Whether a raw address on this port is worth a suspicious-endpoint verdict.
fn is_suspicious_port(port: u16) -> bool {
    topgent_policy::signals::builtin().is_ok_and(|signals| signals.is_suspicious_port(port))
}

fn verdict(protocol: Protocol, host: &str, port: u16, direction: Direction) -> NetworkVerdict {
    // A socket whose peer the platform never states is not a listener, exposed
    // or otherwise. A raw ICMP socket has no port to listen on, and calling it
    // `Opened a listener on *:0` is a finding about a thing that did not
    // happen. The socket is still worth recording; it is not worth scoring as
    // something else.
    if !protocol.peer_observable() || host == "*" && port == 0 {
        return NetworkVerdict::Observed;
    }
    match direction {
        Direction::Listening if !is_loopback(host) => NetworkVerdict::ExposedListener,
        Direction::Outbound if is_metadata_service(host) => NetworkVerdict::MetadataService,
        Direction::Outbound if host.parse::<IpAddr>().is_ok() && is_suspicious_port(port) => {
            NetworkVerdict::SuspiciousEndpoint
        }
        Direction::Outbound if is_private(host) && !is_loopback(host) => {
            NetworkVerdict::PrivatePeer
        }
        Direction::Outbound | Direction::Listening => NetworkVerdict::Observed,
    }
}

type Key = (u32, u64, Protocol, String, u16, u8);

fn key(record: &NetworkRecord) -> Key {
    (
        record.agent_pid,
        record.agent_started_at,
        record.protocol,
        record.host.clone(),
        record.port,
        direction_rank(record.direction),
    )
}

/// Merge one socket snapshot into bounded history.
///
/// Existing records for inactive agent instances remain until the global bound
/// evicts the least recently seen entry. Duplicate endpoints inside a sweep are
/// already folded by the graph and increment only once.
#[must_use]
pub fn merge_network_history(
    previous: &[NetworkRecord],
    agents: &[Agent],
    observed_at: u64,
    limit: usize,
) -> Vec<NetworkRecord> {
    let mut records: BTreeMap<Key, NetworkRecord> = previous
        .iter()
        .filter(|record| {
            record.last_seen <= observed_at
                && observed_at.saturating_sub(record.last_seen) <= NETWORK_HISTORY_RETENTION_MS
        })
        .cloned()
        .map(|record| (key(&record), record))
        .collect();
    let observed_keys = agents
        .iter()
        .flat_map(|agent| {
            agent.endpoints.iter().map(move |endpoint| {
                (
                    agent.id.pid,
                    agent.id.started_at.0,
                    endpoint.protocol,
                    endpoint.host.clone(),
                    endpoint.port,
                    direction_rank(endpoint.direction),
                )
            })
        })
        .collect::<BTreeSet<_>>();
    for (record_key, record) in &mut records {
        if record.currently_observed && !observed_keys.contains(record_key) {
            record.currently_observed = false;
            record.last_visibility_change = observed_at;
            record.visibility_changes = record.visibility_changes.saturating_add(1);
        }
    }
    for agent in agents {
        for endpoint in &agent.endpoints {
            let candidate = NetworkRecord {
                agent_pid: agent.id.pid,
                agent_started_at: agent.id.started_at.0,
                agent_family: agent
                    .family
                    .clone()
                    .unwrap_or_else(|| "unclassified".to_owned()),
                protocol: endpoint.protocol,
                host: endpoint.host.clone(),
                port: endpoint.port,
                direction: endpoint.direction,
                first_seen: observed_at,
                last_seen: observed_at,
                observations: 1,
                sample_times: vec![observed_at],
                currently_observed: true,
                last_visibility_change: observed_at,
                visibility_changes: 1,
                verdict: verdict(
                    endpoint.protocol,
                    &endpoint.host,
                    endpoint.port,
                    endpoint.direction,
                ),
            };
            records
                .entry(key(&candidate))
                .and_modify(|record| {
                    record.last_seen = record.last_seen.max(observed_at);
                    record.first_seen = record.first_seen.min(observed_at);
                    record.observations = record.observations.saturating_add(1);
                    if record.sample_times.last().copied() != Some(observed_at) {
                        record.sample_times.push(observed_at);
                        if record.sample_times.len() > MAX_NETWORK_SAMPLES {
                            record
                                .sample_times
                                .drain(..record.sample_times.len() - MAX_NETWORK_SAMPLES);
                        }
                    }
                    if !record.currently_observed {
                        record.currently_observed = true;
                        record.last_visibility_change = observed_at;
                        record.visibility_changes = record.visibility_changes.saturating_add(1);
                    }
                    record.agent_family.clone_from(&candidate.agent_family);
                    record.verdict = candidate.verdict;
                })
                .or_insert(candidate);
        }
    }
    let mut records = records.into_values().collect::<Vec<_>>();
    records.sort_by(|left, right| {
        right
            .last_seen
            .cmp(&left.last_seen)
            .then_with(|| key(left).cmp(&key(right)))
    });
    records.truncate(limit);
    records
}

/// Derive PID-reuse-safe baselines from bounded persisted endpoint history.
///
/// Warm-up freezes after five distinct sweep timestamps. Endpoints first seen
/// later remain visible but do not silently teach themselves into the baseline.
#[must_use]
pub fn build_network_baselines(records: &[NetworkRecord], now: u64) -> Vec<NetworkBaseline> {
    let mut grouped = BTreeMap::<(u32, u64), Vec<&NetworkRecord>>::new();
    for record in records {
        grouped
            .entry((record.agent_pid, record.agent_started_at))
            .or_default()
            .push(record);
    }
    grouped
        .into_iter()
        .map(|((agent_pid, agent_started_at), records)| {
            let samples = records
                .iter()
                .flat_map(|record| record.sample_times.iter().copied())
                .collect::<BTreeSet<_>>();
            let ready_at = samples
                .iter()
                .nth(NETWORK_BASELINE_WARMUP_SAMPLES - 1)
                .copied();
            let started_at = records
                .iter()
                .map(|record| record.first_seen)
                .min()
                .unwrap_or(0);
            let last_observed_at = records
                .iter()
                .map(|record| record.last_seen)
                .max()
                .unwrap_or(0);
            let state = if now.saturating_sub(last_observed_at) > NETWORK_BASELINE_EXPIRY_MS {
                NetworkBaselineState::Expired
            } else if ready_at.is_some() {
                NetworkBaselineState::Ready
            } else {
                NetworkBaselineState::Collecting
            };
            NetworkBaseline {
                agent_pid,
                agent_started_at,
                started_at,
                ready_at,
                last_observed_at,
                state,
                retained_samples: samples.len(),
                known_hosts: records
                    .iter()
                    .filter(|record| ready_at.is_none_or(|cutoff| record.first_seen <= cutoff))
                    .map(|record| record.host.clone())
                    .collect(),
                known_ports: records
                    .iter()
                    .filter(|record| ready_at.is_none_or(|cutoff| record.first_seen <= cutoff))
                    .map(|record| record.port)
                    .collect(),
            }
        })
        .collect()
}

#[cfg(test)]
mod verdict_tests {
    use super::{Direction, NetworkVerdict, Protocol, verdict};

    /// A raw ICMP socket has no port to listen on. Scoring it as an exposed
    /// listener is a finding about a thing that did not happen, and it appeared
    /// the moment the collector stopped dropping non-TCP rows.
    #[test]
    fn an_icmp_socket_is_not_an_exposed_listener() {
        assert_eq!(
            verdict(Protocol::Icmp, "*", 0, Direction::Listening),
            NetworkVerdict::Observed
        );
    }

    /// And the rule that matters still fires for a real one.
    #[test]
    fn a_real_tcp_listener_off_loopback_is_still_exposed() {
        assert_eq!(
            verdict(Protocol::Tcp, "0.0.0.0", 8080, Direction::Listening),
            NetworkVerdict::ExposedListener
        );
        assert_eq!(
            verdict(Protocol::Tcp, "127.0.0.1", 8080, Direction::Listening),
            NetworkVerdict::Observed
        );
    }
}
