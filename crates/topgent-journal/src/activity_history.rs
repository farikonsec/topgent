//! Persisting the causal timeline across sweeps.
//!
//! An activity event keeps its place in the order it was first given: replay
//! preserves an existing sequence rather than renumbering it, and a late
//! observation with a backwards clock cannot reorder what came before. A parent
//! reference that does not resolve inside the same exact agent run is cleared
//! rather than followed.

use crate::text::sanitize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use topgent_core::{
    Activity, ActivityEvent, ActivityKind, ActivityLink, ActivityNetwork, ActivityPath,
    LinkCertainty, MAX_ACTIVITY_EVENTS, NetworkActivityPhase,
};
use topgent_facts::{Confidence, Direction};

fn activity_kind(value: &str) -> Option<ActivityKind> {
    Some(match value {
        "started" => ActivityKind::Started,
        "process" => ActivityKind::Process,
        "file" => ActivityKind::File,
        "network" => ActivityKind::Network,
        "model" => ActivityKind::Model,
        "connector" => ActivityKind::Connector,
        "agent" => ActivityKind::Agent,
        "action" => ActivityKind::Action,
        _ => return None,
    })
}

fn confidence(value: &str) -> Option<Confidence> {
    Some(match value {
        "Possible" => Confidence::Possible,
        "Probable" => Confidence::Likely,
        "Confirmed" => Confidence::Certain,
        _ => return None,
    })
}

fn certainty(value: &str) -> Option<LinkCertainty> {
    Some(match value {
        "direct" => LinkCertainty::Direct,
        "attributed" => LinkCertainty::Attributed,
        "correlated" => LinkCertainty::Correlated,
        _ => return None,
    })
}

fn network_phase(value: &str) -> Option<NetworkActivityPhase> {
    Some(match value {
        "observed" => NetworkActivityPhase::Observed,
        "allowed" => NetworkActivityPhase::Allowed,
        "blocked" => NetworkActivityPhase::Blocked,
        "closed" => NetworkActivityPhase::Closed,
        _ => return None,
    })
}

fn activity_network(value: Option<&Value>) -> Option<ActivityNetwork> {
    let value = value?;
    let direction = match value.get("direction")?.as_str()? {
        "outbound" => Direction::Outbound,
        "listening" => Direction::Listening,
        _ => return None,
    };
    let host = sanitize(value.get("host")?.as_str()?, 255);
    if host.is_empty() {
        return None;
    }
    let phase = network_phase(value.get("phase")?.as_str()?)?;
    let duration_ms = value.get("duration_ms").and_then(Value::as_u64);
    if (phase == NetworkActivityPhase::Closed) != duration_ms.is_some() {
        return None;
    }
    Some(ActivityNetwork {
        host,
        port: u16::try_from(value.get("port")?.as_u64()?).ok()?,
        direction,
        phase,
        duration_ms,
    })
}

fn relation(value: &str) -> Option<&'static str> {
    Some(match value {
        "spawned" => "spawned",
        "accessed" => "accessed",
        "opened socket" => "opened socket",
        "observed socket" => "observed socket",
        "closed socket" => "closed socket",
        "selected model" => "selected model",
        "declared" => "declared",
        "can invoke" => "can invoke",
        "acted on" => "acted on",
        _ => return None,
    })
}

pub(crate) fn activity_id(value: &Value) -> Option<String> {
    let value = value.as_str()?;
    if value.is_empty()
        || value.len() > 512
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_' | b'.'))
    {
        return None;
    }
    Some(value.to_owned())
}

pub(crate) fn activity_json(activity: &Activity) -> Value {
    json!({
        "events": activity.events.iter().take(MAX_ACTIVITY_EVENTS).map(|event| json!({
            "id": event.id, "sequence": event.sequence, "parent_id": event.parent_id,
            "agent_pid": event.agent_pid,
            "agent_started_at": event.agent_started_at, "actor_pid": event.actor_pid,
            "at": event.at, "kind": event.kind.as_str(), "title": event.title,
            "detail": event.detail, "confidence": event.confidence.label(),
            "collector": event.collector, "probe": event.probe,
            "network": event.network.as_ref().map(|network| json!({
                "host": network.host, "port": network.port,
                "direction": match network.direction { Direction::Outbound => "outbound", Direction::Listening => "listening" },
                "phase": network.phase.as_str(), "duration_ms": network.duration_ms,
            })),
        })).collect::<Vec<_>>(),
        "links": activity.links.iter().map(|link| json!({
            "from": link.from, "to": link.to, "relation": link.relation,
            "certainty": link.certainty.as_str(),
        })).collect::<Vec<_>>(),
        "paths": activity.paths.iter().map(|path| json!({
            "id": path.id, "agent_pid": path.agent_pid,
            "agent_started_at": path.agent_started_at, "title": path.title,
            "explanation": path.explanation, "events": path.events,
            "certainty": path.certainty.as_str(),
        })).collect::<Vec<_>>(),
    })
}

fn validate_activity_parents(events: &mut [ActivityEvent]) {
    let identities = events
        .iter()
        .map(|event| {
            (
                event.id.clone(),
                (event.agent_pid, event.agent_started_at, event.sequence),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for event in events {
        if event.parent_id.as_ref().is_some_and(|parent| {
            !identities.get(parent).is_some_and(|identity| {
                identity.0 == event.agent_pid
                    && identity.1 == event.agent_started_at
                    && identity.2 < event.sequence
            })
        }) {
            event.parent_id = None;
        }
    }
}

pub(crate) fn activity_from_json(value: &Value) -> Activity {
    let mut events = value
        .get("events")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_ACTIVITY_EVENTS)
        .filter_map(|event| {
            Some(ActivityEvent {
                id: activity_id(event.get("id")?)?,
                sequence: event.get("sequence").and_then(Value::as_u64).unwrap_or(0),
                parent_id: match event.get("parent_id") {
                    None | Some(Value::Null) => None,
                    Some(parent) => Some(activity_id(parent)?),
                },
                agent_pid: u32::try_from(event.get("agent_pid")?.as_u64()?).ok()?,
                agent_started_at: event.get("agent_started_at")?.as_u64()?,
                actor_pid: u32::try_from(event.get("actor_pid")?.as_u64()?).ok()?,
                at: event.get("at")?.as_u64()?,
                kind: activity_kind(event.get("kind")?.as_str()?)?,
                title: sanitize(event.get("title")?.as_str()?, 240),
                detail: sanitize(event.get("detail")?.as_str()?, 512),
                confidence: confidence(event.get("confidence")?.as_str()?)?,
                collector: sanitize(event.get("collector")?.as_str()?, 96),
                probe: sanitize(event.get("probe")?.as_str()?, 240),
                network: match event.get("network") {
                    None | Some(Value::Null) => None,
                    Some(value) => Some(activity_network(Some(value))?),
                },
            })
        })
        .collect::<Vec<_>>();
    validate_activity_parents(&mut events);
    let ids = events
        .iter()
        .map(|event| event.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let links = value
        .get("links")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_ACTIVITY_EVENTS)
        .filter_map(|link| {
            Some(ActivityLink {
                from: activity_id(link.get("from")?)?,
                to: activity_id(link.get("to")?)?,
                relation: relation(link.get("relation")?.as_str()?)?,
                certainty: certainty(link.get("certainty")?.as_str()?)?,
            })
        })
        .filter(|link| ids.contains(link.from.as_str()) && ids.contains(link.to.as_str()))
        .collect();
    let paths = value
        .get("paths")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_ACTIVITY_EVENTS)
        .filter_map(|path| {
            Some(ActivityPath {
                id: activity_id(path.get("id")?)?,
                agent_pid: u32::try_from(path.get("agent_pid")?.as_u64()?).ok()?,
                agent_started_at: path.get("agent_started_at")?.as_u64()?,
                title: sanitize(path.get("title")?.as_str()?, 240),
                explanation: sanitize(path.get("explanation")?.as_str()?, 512),
                events: path
                    .get("events")?
                    .as_array()?
                    .iter()
                    .filter_map(activity_id)
                    .collect(),
                certainty: certainty(path.get("certainty")?.as_str()?)?,
            })
        })
        .filter(|path| {
            !path.events.is_empty() && path.events.iter().all(|event| ids.contains(event.as_str()))
        })
        .collect();
    Activity {
        events,
        links,
        paths,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{activity_from_json, activity_id, activity_json};
    use crate::journal::Journal;
    use serde_json::{Value, json};
    use topgent_core::{build_activity, fold};
    use topgent_facts::{Direction, UnixMillis};

    #[test]
    fn activity_history_round_trips_exact_identity_and_rejects_dangling_members()
    -> Result<(), String> {
        use topgent_facts::{Claim, Confidence, Fact, Provenance, SCHEMA_VERSION, Subject};
        let fact = |claim, at| {
            Fact::new(
                SCHEMA_VERSION,
                Subject::Process {
                    pid: 42,
                    started_at: UnixMillis(1_000),
                },
                claim,
                Provenance {
                    collector: "test".to_owned(),
                    probe: "fixture".to_owned(),
                    confidence: Confidence::Certain,
                    observed_at: UnixMillis(at),
                },
            )
            .map_err(|error| error.to_string())
        };
        let facts = vec![
            fact(
                Claim::ProcessSeen {
                    exe_path_known: true,
                    exe: "/opt/codex".to_owned(),
                    uid: 501,
                    user: "testuser".to_owned(),
                },
                2_000,
            )?,
            fact(
                Claim::AgentFamily {
                    family: "codex-cli".to_owned(),
                },
                2_001,
            )?,
            fact(
                Claim::SocketOpen {
                    protocol: topgent_facts::Protocol::Tcp,
                    bytes: None,
                    opened_at: None,
                    host: "203.0.113.10".to_owned(),
                    port: 443,
                    direction: Direction::Outbound,
                },
                2_002,
            )?,
        ];
        let activity = build_activity(&facts, &fold(&facts).agents);
        let mut value = activity_json(&activity);
        value
            .get_mut("links")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "serialized activity omitted links".to_owned())?
            .push(json!({
            "from":"missing", "to":"also-missing", "relation":"spawned", "certainty":"direct"
            }));
        assert_eq!(activity_from_json(&value), activity);
        let mut forged_parent = activity_json(&activity);
        let events = forged_parent
            .get_mut("events")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "serialized activity omitted events".to_owned())?;
        if let Some(event) = events.iter_mut().find(|event| {
            event
                .get("sequence")
                .and_then(Value::as_u64)
                .is_some_and(|sequence| sequence > 0)
        }) {
            let own_id = event
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| "event omitted id".to_owned())?
                .to_owned();
            event["parent_id"] = json!(own_id);
        }
        assert!(
            activity_from_json(&forged_parent)
                .events
                .iter()
                .filter(|event| event.sequence > 0)
                .all(|event| event.parent_id.is_none()),
            "self/future parent references fail closed"
        );
        assert!(value.to_string().contains("agent_started_at"));
        assert!(!value.to_string().contains("prompt"));
        Ok(())
    }

    #[test]
    fn activity_history_file_is_atomic_and_malformed_input_fails_closed() -> std::io::Result<()> {
        // nosemgrep: rust.lang.security.temp-dir.temp-dir - test fixture, per-process name, not a trust boundary
        let dir = std::env::temp_dir().join(format!("topgent-activity-{}", std::process::id()));
        let journal = Journal::at(&dir);
        journal.save_activity_history(&topgent_core::Activity::default())?;
        assert_eq!(
            journal.activity_history()?,
            topgent_core::Activity::default()
        );
        std::fs::write(dir.join("activity-history.json"), "not json")?;
        assert_eq!(
            journal.activity_history()?,
            topgent_core::Activity::default()
        );
        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn activity_identifiers_are_bounded_and_reject_control_or_reference_syntax() {
        assert_eq!(
            activity_id(&json!("activity:42:1000")),
            Some("activity:42:1000".to_owned())
        );
        assert_eq!(activity_id(&json!("activity\n42")), None);
        assert_eq!(activity_id(&json!("../../event")), None);
        assert_eq!(activity_id(&json!("x".repeat(513))), None);
    }
}
