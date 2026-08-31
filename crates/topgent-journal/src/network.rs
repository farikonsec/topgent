//! Retained network metadata, bounded and expiring.
//!
//! Endpoints are kept long enough to tell a first sighting from a familiar one,
//! and no longer. Nothing here is traffic content: a record says an agent held
//! a socket to somewhere, how often it was visible, and what the kernel counted
//! where it counts.

use serde_json::{Value, json};
use topgent_core::{MAX_NETWORK_SAMPLES, NetworkRecord, NetworkVerdict};
use topgent_facts::Direction;

pub(crate) fn network_record_json(record: &NetworkRecord) -> Value {
    json!({
        "agent_pid": record.agent_pid,
        "agent_started_at": record.agent_started_at,
        "agent_family": record.agent_family,
        "protocol": record.protocol.as_str(),
        "host": record.host,
        "port": record.port,
        "direction": match record.direction { Direction::Outbound => "outbound", Direction::Listening => "listening" },
        "first_seen": record.first_seen,
        "last_seen": record.last_seen,
        "observations": record.observations,
        "sample_times": record.sample_times,
        "currently_observed": record.currently_observed,
        "last_visibility_change": record.last_visibility_change,
        "visibility_changes": record.visibility_changes,
        "verdict": record.verdict.as_str(),
    })
}

pub(crate) fn network_record_from_json(value: &Value) -> Option<NetworkRecord> {
    let direction = match value.get("direction")?.as_str()? {
        "outbound" => Direction::Outbound,
        "listening" => Direction::Listening,
        _ => return None,
    };
    let verdict = match value.get("verdict")?.as_str()? {
        "observed" => NetworkVerdict::Observed,
        "exposed_listener" => NetworkVerdict::ExposedListener,
        "suspicious_endpoint" => NetworkVerdict::SuspiciousEndpoint,
        "private_peer" => NetworkVerdict::PrivatePeer,
        "metadata_service" => NetworkVerdict::MetadataService,
        _ => return None,
    };
    let first_seen = value.get("first_seen")?.as_u64()?;
    let last_seen = value.get("last_seen")?.as_u64()?;
    let mut sample_times = value
        .get("sample_times")
        .and_then(Value::as_array)
        .map_or_else(
            || vec![last_seen],
            |samples| {
                samples
                    .iter()
                    .filter_map(Value::as_u64)
                    .filter(|sample| *sample >= first_seen && *sample <= last_seen)
                    .collect::<Vec<_>>()
            },
        );
    sample_times.sort_unstable();
    sample_times.dedup();
    if sample_times.len() > MAX_NETWORK_SAMPLES {
        sample_times.drain(..sample_times.len() - MAX_NETWORK_SAMPLES);
    }
    Some(NetworkRecord {
        protocol: value
            .get("protocol")
            .and_then(serde_json::Value::as_str)
            .map_or(topgent_facts::Protocol::Tcp, topgent_facts::Protocol::parse),
        agent_pid: u32::try_from(value.get("agent_pid")?.as_u64()?).ok()?,
        agent_started_at: value.get("agent_started_at")?.as_u64()?,
        agent_family: value.get("agent_family")?.as_str()?.to_owned(),
        host: value.get("host")?.as_str()?.to_owned(),
        port: u16::try_from(value.get("port")?.as_u64()?).ok()?,
        direction,
        first_seen,
        last_seen,
        observations: value.get("observations")?.as_u64()?,
        sample_times,
        currently_observed: value
            .get("currently_observed")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        last_visibility_change: value
            .get("last_visibility_change")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| value.get("last_seen").and_then(Value::as_u64).unwrap_or(0)),
        visibility_changes: value
            .get("visibility_changes")
            .and_then(Value::as_u64)
            .unwrap_or(1),
        verdict,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{network_record_from_json, network_record_json};
    use crate::activity_history::activity_from_json;
    use crate::journal::Journal;
    use crate::test_support::test_dir;
    use serde_json::{Value, json};
    use topgent_core::{MAX_NETWORK_SAMPLES, NetworkActivityPhase, NetworkRecord, NetworkVerdict};
    use topgent_facts::Direction;

    #[test]
    fn network_history_records_round_trip_without_payload_fields() {
        let record = NetworkRecord {
            protocol: topgent_facts::Protocol::Tcp,
            agent_pid: 42,
            agent_started_at: 1_000,
            agent_family: "codex-cli".to_owned(),
            host: "api.openai.com".to_owned(),
            port: 443,
            direction: Direction::Outbound,
            first_seen: 2_000,
            last_seen: 3_000,
            observations: 4,
            sample_times: vec![2_000, 2_500, 3_000],
            currently_observed: true,
            last_visibility_change: 2_000,
            visibility_changes: 1,
            verdict: NetworkVerdict::Observed,
        };
        assert_eq!(
            network_record_from_json(&network_record_json(&record)),
            Some(record)
        );
    }

    #[test]
    fn baseline_reset_removes_only_the_exact_process_identity() -> std::io::Result<()> {
        let dir = test_dir("baseline-reset");
        let journal = Journal::at(&dir);
        let record = |pid, started_at, host: &str| NetworkRecord {
            protocol: topgent_facts::Protocol::Tcp,
            agent_pid: pid,
            agent_started_at: started_at,
            agent_family: "codex-cli".to_owned(),
            host: host.to_owned(),
            port: 443,
            direction: Direction::Outbound,
            first_seen: 2_000,
            last_seen: 3_000,
            observations: 2,
            sample_times: vec![2_000, 3_000],
            currently_observed: false,
            last_visibility_change: 3_000,
            visibility_changes: 2,
            verdict: NetworkVerdict::Observed,
        };
        journal.save_network_history(&[
            record(42, 1_000, "old.example"),
            record(42, 2_000, "current.example"),
            record(43, 2_000, "other.example"),
        ])?;

        assert_eq!(journal.reset_network_baseline(42, 2_000)?, 1);
        assert_eq!(
            journal
                .network_history()?
                .iter()
                .map(|entry| (entry.agent_pid, entry.agent_started_at, entry.host.as_str()))
                .collect::<Vec<_>>(),
            [(42, 1_000, "old.example"), (43, 2_000, "other.example")]
        );
        assert_eq!(journal.reset_network_baseline(42, 9_999)?, 0);
        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn malformed_or_future_network_records_are_skipped() {
        assert_eq!(
            network_record_from_json(&json!({"host": "missing fields"})),
            None
        );
        assert_eq!(
            network_record_from_json(&json!({
                "agent_pid": 42, "agent_started_at": 1, "agent_family": "codex",
                "host": "example.com", "port": 443, "direction": "sideways",
                "first_seen": 1, "last_seen": 2, "observations": 1, "verdict": "future"
            })),
            None
        );
    }

    #[test]
    fn malformed_structured_network_metadata_rejects_only_its_event() {
        let value = json!({"events":[{
            "id":"activity:42:bad-network", "agent_pid":42, "agent_started_at":1000,
            "actor_pid":42, "at":2000, "kind":"network", "title":"bad",
            "detail":"metadata", "confidence":"Confirmed", "collector":"test",
            "probe":"fixture", "network":{"host":"example.com", "port":443,
            "direction":"outbound", "phase":"closed", "duration_ms":null}
        }], "links":[], "paths":[]});
        assert!(activity_from_json(&value).events.is_empty());
    }

    #[test]
    fn connection_attempt_phases_round_trip_without_inventing_duration() {
        for phase in ["allowed", "blocked"] {
            let value = json!({"events":[{
                "id":format!("activity:42:{phase}"), "agent_pid":42,
                "agent_started_at":1000, "actor_pid":42, "at":2000,
                "kind":"network", "title":"attempt", "detail":"metadata",
                "confidence":"Confirmed", "collector":"network_events",
                "probe":"fixture", "network":{"host":"192.0.2.10","port":443,
                "direction":"outbound", "phase":phase, "duration_ms":null}
            }], "links":[], "paths":[]});
            let parsed = activity_from_json(&value);
            assert_eq!(
                parsed
                    .events
                    .first()
                    .and_then(|event| event.network.as_ref()),
                Some(&topgent_core::ActivityNetwork {
                    host: "192.0.2.10".to_owned(),
                    port: 443,
                    direction: topgent_facts::Direction::Outbound,
                    phase: if phase == "allowed" {
                        NetworkActivityPhase::Allowed
                    } else {
                        NetworkActivityPhase::Blocked
                    },
                    duration_ms: None,
                })
            );
        }
    }

    #[test]
    fn persisted_sample_times_are_normalized_bounded_and_backward_compatible() {
        let base = json!({
            "agent_pid": 42, "agent_started_at": 1, "agent_family": "codex",
            "host": "example.com", "port": 443, "direction": "outbound",
            "first_seen": 100, "last_seen": 300, "observations": 1,
            "verdict": "observed"
        });
        assert!(
            network_record_from_json(&base)
                .is_some_and(|record| { record.sample_times == vec![300] })
        );

        let mut oversized = base;
        if let Some(object) = oversized.as_object_mut() {
            object.insert(
                "sample_times".to_owned(),
                Value::Array(
                    (0..500)
                        .map(|sample| json!(sample))
                        .chain([json!("bad"), json!(250), json!(250)])
                        .collect(),
                ),
            );
        }
        assert!(network_record_from_json(&oversized).is_some_and(|record| {
            record.sample_times.len() == MAX_NETWORK_SAMPLES
                && record.sample_times.first().copied() == Some(237)
                && record.sample_times.last().copied() == Some(300)
        }));
    }
}
