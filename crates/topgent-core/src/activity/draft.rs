//! One fact becomes at most one candidate event.
//!
//! A draft is given an identity derived from what the event *is* rather than
//! when it was seen, so the same observation arriving twice is the same event
//! and a retained timeline can be merged with a fresh one without duplicates.

use super::model::ActivityKind;
use super::model::ActivityNetwork;
use super::model::NetworkActivityPhase;
use topgent_facts::Claim;
use topgent_facts::Confidence;
use topgent_facts::Direction;
use topgent_facts::Fact;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Draft {
    pub(super) agent_pid: u32,
    pub(super) agent_started_at: u64,
    pub(super) actor_pid: u32,
    pub(super) at: u64,
    pub(super) kind: ActivityKind,
    pub(super) title: String,
    pub(super) detail: String,
    pub(super) confidence: Confidence,
    pub(super) collector: String,
    pub(super) probe: String,
    pub(super) relation: &'static str,
    pub(super) certainty_rank: u8,
    pub(super) network: Option<ActivityNetwork>,
}

#[allow(clippy::too_many_lines)]
pub(super) fn fact_draft(
    fact: &Fact,
    agent_pid: u32,
    agent_started_at: u64,
    actor_pid: u32,
) -> Option<Draft> {
    let provenance = fact.provenance();
    let common = |actor_pid, kind, title, detail, relation, certainty_rank| Draft {
        agent_pid,
        agent_started_at,
        actor_pid,
        at: provenance.observed_at.0,
        kind,
        title,
        detail,
        confidence: provenance.confidence,
        collector: provenance.collector.clone(),
        probe: provenance.probe.clone(),
        relation,
        certainty_rank,
        network: None,
    };
    match fact.claim() {
        Claim::ChildProcessSeen { pid, name, depth } => Some(common(
            *pid,
            ActivityKind::Process,
            format!("Spawned {name}"),
            format!("pid {pid} · depth {depth}"),
            "spawned",
            0,
        )),
        Claim::FileTouched { path, access } => Some(common(
            actor_pid,
            ActivityKind::File,
            format!("{} {path}", access.label()),
            path.clone(),
            "accessed",
            1,
        )),
        Claim::SocketOpen {
            protocol,
            host,
            port,
            opened_at: _,
            bytes: _,
            direction,
        } => {
            // A socket whose peer the platform does not expose is described as
            // what it is. `Observed endpoint *:0` would read as a bug; "holds a
            // raw icmp socket, destination not observable here" is the truth
            // and is the more alarming of the two.
            let named = protocol.peer_observable() && host != "*";
            let where_to = if named {
                format!("{host}:{port}")
            } else {
                format!(
                    "{} · destination not observable on this platform",
                    protocol.as_str()
                )
            };
            let mut draft = common(
                actor_pid,
                ActivityKind::Network,
                match direction {
                    Direction::Outbound => format!("Observed endpoint {where_to}"),
                    Direction::Listening => format!("Observed listener {where_to}"),
                },
                format!(
                    "{} · {} · {where_to}",
                    match direction {
                        Direction::Outbound => "outbound",
                        Direction::Listening => "listening",
                    },
                    protocol.as_str()
                ),
                "observed socket",
                1,
            );
            draft.network = Some(ActivityNetwork {
                host: host.clone(),
                port: *port,
                direction: *direction,
                phase: NetworkActivityPhase::Observed,
                duration_ms: None,
            });
            Some(draft)
        }
        Claim::SocketClosed { .. } => {
            closed_socket_draft(fact, agent_pid, agent_started_at, actor_pid)
        }
        Claim::ConnectionAttempt {
            host,
            port,
            direction,
            outcome,
        } => {
            let outcome_label = outcome.as_str();
            let mut draft = common(
                actor_pid,
                ActivityKind::Network,
                format!("Connection attempt {outcome_label}: {host}:{port}"),
                format!("outbound · {host}:{port} · {outcome_label}"),
                "attempted connection",
                1,
            );
            draft.network = Some(ActivityNetwork {
                host: host.clone(),
                port: *port,
                direction: *direction,
                phase: match outcome {
                    topgent_facts::ConnectionOutcome::Allowed => NetworkActivityPhase::Allowed,
                    topgent_facts::ConnectionOutcome::Blocked => NetworkActivityPhase::Blocked,
                },
                duration_ms: None,
            });
            Some(draft)
        }
        Claim::DnsQueryObserved {
            name,
            query_type,
            outcome,
        } => {
            let outcome_label = outcome.as_str().replace('_', " ");
            Some(common(
                actor_pid,
                ActivityKind::Network,
                format!("Name lookup {outcome_label}: {name}"),
                // A lookup is a question the agent asked. It is not a
                // connection, and it must never be rendered as one: a name
                // resolved is not a name reached.
                format!("dns · {name} · type {query_type} · {outcome_label}"),
                "resolver record naming the requesting process",
                1,
            ))
        }
        Claim::ModelInUse { provider, model } => Some(common(
            agent_pid,
            ActivityKind::Model,
            format!("Using {provider}/{model}"),
            format!("{provider}/{model}"),
            "selected model",
            1,
        )),
        Claim::ConnectorDeclared { name, access } => Some(common(
            agent_pid,
            ActivityKind::Connector,
            format!("Declared connector {name}"),
            access.label().to_owned(),
            "declared",
            1,
        )),
        Claim::InvokesAgent { target_pid, via } => Some(common(
            agent_pid,
            ActivityKind::Agent,
            format!("Can invoke agent pid {target_pid}"),
            via.clone(),
            "can invoke",
            0,
        )),
        Claim::ActionTaken { action, succeeded } => Some(common(
            agent_pid,
            ActivityKind::Action,
            format!("Topgent {action}"),
            if *succeeded { "succeeded" } else { "failed" }.to_owned(),
            "acted on",
            0,
        )),
        _ => None,
    }
}

pub(super) fn closed_socket_draft(
    fact: &Fact,
    agent_pid: u32,
    agent_started_at: u64,
    actor_pid: u32,
) -> Option<Draft> {
    let Claim::SocketClosed {
        host,
        port,
        direction,
        duration_ms,
    } = fact.claim()
    else {
        return None;
    };
    let provenance = fact.provenance();
    Some(Draft {
        agent_pid,
        agent_started_at,
        actor_pid,
        at: provenance.observed_at.0,
        kind: ActivityKind::Network,
        title: format!("Closed connection to {host}:{port}"),
        detail: format!(
            "{} · {host}:{port} · duration {duration_ms} ms",
            match direction {
                Direction::Outbound => "outbound",
                Direction::Listening => "listening",
            }
        ),
        confidence: provenance.confidence,
        collector: provenance.collector.clone(),
        probe: provenance.probe.clone(),
        relation: "closed socket",
        certainty_rank: 1,
        network: Some(ActivityNetwork {
            host: host.clone(),
            port: *port,
            direction: *direction,
            phase: NetworkActivityPhase::Closed,
            duration_ms: Some(*duration_ms),
        }),
    })
}

pub(super) fn identity_digest(draft: &Draft) -> u64 {
    // FNV-1a is used only to keep report identifiers compact and deterministic;
    // it is not a security boundary or an integrity check.
    let mut digest = 0xcbf2_9ce4_8422_2325_u64;
    for value in [
        draft.title.as_str(),
        draft.detail.as_str(),
        draft.collector.as_str(),
        draft.probe.as_str(),
    ] {
        for byte in value.bytes().chain(std::iter::once(0)) {
            digest ^= u64::from(byte);
            digest = digest.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    digest
}

pub(super) fn event_id(draft: &Draft) -> String {
    format!(
        "activity:{}:{}:{}:{}:{}:{:016x}",
        draft.agent_pid,
        draft.agent_started_at,
        draft.at,
        draft.kind.as_str(),
        draft.actor_pid,
        identity_digest(draft)
    )
}
