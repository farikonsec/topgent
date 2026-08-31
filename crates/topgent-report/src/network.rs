//! Retained network metadata, as the interface reads it.
//!
//! A row here spans a history of connections rather than one, so what it can
//! honestly say is bounded: which endpoint, how often it was visible, what the
//! detectors made of the pattern, and where the kernel counted traffic. Number
//! of sweeps an endpoint appeared in is never presented as volume.

use serde_json::{Value, json};
use topgent_core::{Agent, NetworkBaseline, NetworkBaselineState};
use topgent_policy::Policy;

pub(crate) fn network_alert(
    record: topgent_core::NetworkVerdict,
    policy: &Policy,
) -> (&'static str, u32) {
    match record {
        topgent_core::NetworkVerdict::Observed => ("none", 0),
        topgent_core::NetworkVerdict::PrivatePeer => ("high", policy.weights.private_peer),
        topgent_core::NetworkVerdict::ExposedListener => {
            ("critical", policy.weights.exposed_listener)
        }
        topgent_core::NetworkVerdict::SuspiciousEndpoint => {
            ("critical", policy.weights.suspicious_endpoint)
        }
        topgent_core::NetworkVerdict::MetadataService => {
            ("critical", policy.weights.metadata_service)
        }
    }
}

fn record_baseline_json(
    baseline: Option<&NetworkBaseline>,
    outside_baseline: bool,
) -> Option<Value> {
    baseline.map(|baseline| {
        json!({
            "state": baseline.state.as_str(),
            "started_at": baseline.started_at,
            "ready_at": baseline.ready_at,
            "last_observed_at": baseline.last_observed_at,
            "retained_samples": baseline.retained_samples,
            "warmup_samples": topgent_core::NETWORK_BASELINE_WARMUP_SAMPLES,
            "expiry_ms": topgent_core::NETWORK_BASELINE_EXPIRY_MS,
            "known_host_count": baseline.known_hosts.len(),
            "known_port_count": baseline.known_ports.len(),
            "outside_baseline": outside_baseline,
            "reset_identity": "pid_and_process_start_time",
        })
    })
}

pub(crate) fn network_json(
    records: &[topgent_core::NetworkRecord],
    baselines: &[NetworkBaseline],
    agents: &[Agent],
    generated_at: u64,
    policy: &Policy,
) -> Vec<Value> {
    records
        .iter()
        .map(|record| {
            let extensions = agents
                .iter()
                .find(|agent| {
                    agent.id.pid == record.agent_pid
                        && agent.id.started_at.0 == record.agent_started_at
                })
                .map(|agent| {
                    agent
                        .extensions
                        .iter()
                        .map(|extension| extension.family.clone())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let raw_ip = record.host.parse::<std::net::IpAddr>().is_ok();
            // Whether this platform could have named a peer at all. `false`
            // means an absent host is the platform's limit and not a missed
            // observation, which is the difference an operator has to see.
            let peer_observable = record.protocol.peer_observable() && record.host != "*";
            let (alert_level, risk_points) = network_alert(record.verdict, policy);
            let baseline = baselines.iter().find(|baseline| {
                baseline.agent_pid == record.agent_pid
                    && baseline.agent_started_at == record.agent_started_at
            });
            let mut patterns = Vec::new();
            if record.first_seen == generated_at {
                patterns.push("new_destination");
            }
            if raw_ip {
                patterns.push("raw_ip_endpoint");
            }
            if record.direction == topgent_facts::Direction::Outbound
                && !matches!(record.port, 22 | 53 | 80 | 123 | 443)
            {
                patterns.push("nonstandard_port");
            }
            let recent_samples = record
                .sample_times
                .iter()
                .filter(|sample| **sample >= generated_at.saturating_sub(60_000))
                .count();
            if recent_samples >= 5 {
                patterns.push("repeated_snapshot_visibility");
            }
            let outside_baseline = baseline.is_some_and(|baseline| {
                baseline.state == NetworkBaselineState::Ready
                    && (!baseline.known_hosts.contains(&record.host)
                        || !baseline.known_ports.contains(&record.port))
            });
            if outside_baseline {
                patterns.push("outside_baseline");
            }
            json!({
                "agent_pid": record.agent_pid,
                "agent_started_at": record.agent_started_at,
                "agent_family": record.agent_family,
                "active_agent_extensions": extensions,
                "attribution_scope": if extensions.is_empty() { "process" } else { "shared_host" },
                "protocol": record.protocol.as_str(),
                "peer_observable": peer_observable,
                "host": record.host,
                "port": record.port,
                "direction": match record.direction { topgent_facts::Direction::Outbound => "outbound", topgent_facts::Direction::Listening => "listening" },
                "first_seen": record.first_seen,
                "last_seen": record.last_seen,
                "observations": record.observations,
                "time_series": {
                    "detector_version": "1",
                    "evidence": "socket_snapshot_visibility",
                    "retained_samples": record.sample_times.len(),
                    "max_samples": topgent_core::MAX_NETWORK_SAMPLES,
                    "retention_ms": topgent_core::NETWORK_HISTORY_RETENTION_MS,
                    "window_start": record.sample_times.first(),
                    "window_end": record.sample_times.last(),
                    "warmup": if record.sample_times.len() < 5 { "collecting" } else { "ready" },
                    "patterns": patterns,
                    "thresholds": { "repeated_visibility_samples": 5, "window_ms": 60_000 },
                },
                "baseline": record_baseline_json(baseline, outside_baseline),
                "currently_observed": record.currently_observed,
                "last_visibility_change": record.last_visibility_change,
                "visibility_changes": record.visibility_changes,
                "lifecycle_evidence": "socket_snapshot_visibility",
                "verdict": record.verdict.as_str(),
                "alert_level": alert_level,
                "risk_points": risk_points,
                "first_seen_this_sweep": record.first_seen == generated_at,
                "dns_name": if raw_ip { Value::Null } else { Value::String(record.host.clone()) },
                "bytes": Value::Null,
                "duration_ms": Value::Null,
            })
        })
        .collect()
}

pub(crate) fn baseline_json(baselines: &[NetworkBaseline]) -> Vec<Value> {
    baselines
        .iter()
        .map(|baseline| {
            json!({
                "agent_pid": baseline.agent_pid,
                "agent_started_at": baseline.agent_started_at,
                "state": baseline.state.as_str(),
                "started_at": baseline.started_at,
                "ready_at": baseline.ready_at,
                "last_observed_at": baseline.last_observed_at,
                "retained_samples": baseline.retained_samples,
                "warmup_samples": topgent_core::NETWORK_BASELINE_WARMUP_SAMPLES,
                "expiry_ms": topgent_core::NETWORK_BASELINE_EXPIRY_MS,
                "known_hosts": baseline.known_hosts,
                "known_ports": baseline.known_ports,
                "reset_identity": "pid_and_process_start_time",
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::network_alert;
    use topgent_core::NetworkVerdict;
    use topgent_policy::Policy;

    #[test]
    fn network_alerts_expose_policy_risk_without_overstating_observed_traffic() {
        let policy = Policy::default();
        assert_eq!(
            network_alert(NetworkVerdict::Observed, &policy),
            ("none", 0)
        );
        assert_eq!(
            network_alert(NetworkVerdict::PrivatePeer, &policy),
            ("high", policy.weights.private_peer)
        );
        assert_eq!(
            network_alert(NetworkVerdict::MetadataService, &policy),
            ("critical", policy.weights.metadata_service)
        );
    }
}
