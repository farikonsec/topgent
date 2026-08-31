//! The causal timeline, as the interface reads it.
//!
//! Each event says which agent run it belongs to, which process actually did
//! it, and how confident the collector was. Where the two differ the timeline
//! keeps both, because "the agent's descendant did this" and "the agent did
//! this" are not the same claim.

use serde_json::{Value, json};
use topgent_core::Agent;

pub(crate) fn activity_json(activity: &topgent_core::Activity, agents: &[Agent]) -> Value {
    let scope = |pid: u32, started_at: u64| {
        if agents.iter().any(|agent| {
            agent.id.pid == pid
                && agent.id.started_at.0 == started_at
                && !agent.extensions.is_empty()
        }) {
            "shared_host"
        } else {
            "process"
        }
    };
    json!({
        "events": activity.events.iter().map(|event| json!({
            "id": event.id,
            "sequence": event.sequence,
            "parent_id": event.parent_id,
            "agent_pid": event.agent_pid,
            "agent_started_at": event.agent_started_at,
            "actor_pid": event.actor_pid,
            "at": event.at,
            "kind": event.kind.as_str(),
            "title": event.title,
            "detail": event.detail,
            "confidence": event.confidence.label(),
            "collector": event.collector,
            "probe": event.probe,
            "network": event.network.as_ref().map(|network| json!({
                "host": network.host,
                "port": network.port,
                "direction": match network.direction { topgent_facts::Direction::Outbound => "outbound", topgent_facts::Direction::Listening => "listening" },
                "phase": network.phase.as_str(),
                "duration_ms": network.duration_ms,
            })),
            "attribution_scope": scope(event.agent_pid, event.agent_started_at),
        })).collect::<Vec<_>>(),
        "links": activity.links.iter().map(|link| json!({
            "from": link.from,
            "to": link.to,
            "relation": link.relation,
            "certainty": link.certainty.as_str(),
        })).collect::<Vec<_>>(),
        "paths": activity.paths.iter().map(|path| json!({
            "id": path.id,
            "agent_pid": path.agent_pid,
            "agent_started_at": path.agent_started_at,
            "title": path.title,
            "explanation": path.explanation,
            "events": path.events,
            "certainty": path.certainty.as_str(),
            "attribution_scope": scope(path.agent_pid, path.agent_started_at),
        })).collect::<Vec<_>>(),
        "detectors": [{
            "id": "periodic_completed_connections",
            "version": "1",
            "evidence": "exact_connect_close_lifecycle",
            "min_events": topgent_core::LIFECYCLE_PERIODIC_MIN_EVENTS,
            "min_interval_ms": topgent_core::LIFECYCLE_PERIODIC_MIN_INTERVAL_MS,
            "max_interval_ms": topgent_core::LIFECYCLE_PERIODIC_MAX_INTERVAL_MS,
            "max_jitter_percent": topgent_core::LIFECYCLE_PERIODIC_MAX_JITTER_PERCENT,
            "risk_points": 0,
            "interpretation": "periodic metadata; not proof of beaconing, intent, payload, or data transfer",
        }],
    })
}
