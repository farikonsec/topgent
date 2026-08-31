//! The two correlations Topgent is willing to draw.
//!
//! Both are deliberately narrow. Sensitive-path correlation joins events only
//! through a resource the agent can actually reach, and lifecycle periodicity
//! requires enough evenly spaced repetitions that coincidence is implausible.
//! The thresholds are here rather than inline because they are the argument:
//! anyone who thinks Topgent cries wolf should be able to find and change them.

use super::model::ActivityEvent;
use super::model::ActivityKind;
use super::model::ActivityPath;
use super::model::LinkCertainty;
use super::model::NetworkActivityPhase;
use crate::Agent;
use std::collections::{BTreeMap, BTreeSet};
use topgent_facts::Direction;

/// Completed lifecycle events required before periodicity is reported.
pub const LIFECYCLE_PERIODIC_MIN_EVENTS: usize = 5;

/// Maximum interval deviation from the median, as a percentage.
pub const LIFECYCLE_PERIODIC_MAX_JITTER_PERCENT: u64 = 20;

/// Smallest accepted period, excluding tight retry/burst behavior.
pub const LIFECYCLE_PERIODIC_MIN_INTERVAL_MS: u64 = 1_000;

/// Largest accepted period within the retained event window.
pub const LIFECYCLE_PERIODIC_MAX_INTERVAL_MS: u64 = 60 * 60 * 1_000;

pub(super) fn sensitive_paths(agent: &Agent) -> BTreeSet<&str> {
    agent
        .resources
        .iter()
        .filter(|resource| resource.sensitive)
        .map(|resource| resource.path.as_str())
        .collect()
}

pub(super) fn correlated_paths(events: &[ActivityEvent], agents: &[Agent]) -> Vec<ActivityPath> {
    let by_identity: BTreeMap<(u32, u64), &Agent> = agents
        .iter()
        .map(|agent| ((agent.id.pid, agent.id.started_at.0), agent))
        .collect();
    let mut paths = Vec::new();
    for ((pid, started_at), agent) in by_identity {
        let sensitive = sensitive_paths(agent);
        let read = events.iter().find(|event| {
            event.agent_pid == pid
                && event.agent_started_at == started_at
                && event.kind == ActivityKind::File
                && sensitive.contains(event.detail.as_str())
        });
        let outbound = events.iter().find(|event| {
            event.agent_pid == pid
                && event.agent_started_at == started_at
                && event.kind == ActivityKind::Network
                && event.detail.starts_with("outbound ·")
        });
        if let (Some(read), Some(outbound)) = (read, outbound) {
            paths.push(ActivityPath {
                id: format!("path:{pid}:{started_at}:sensitive-to-network"),
                agent_pid: pid,
                agent_started_at: started_at,
                title: "Sensitive access and outbound network observed".to_owned(),
                explanation: "Both events were observed for this agent run. Their shared identity and scan window are a correlation; metadata does not prove event order, causation, or what data crossed the connection.".to_owned(),
                events: vec![read.id.clone(), outbound.id.clone()],
                certainty: LinkCertainty::Correlated,
            });
        }
    }
    paths
}

pub(super) fn endpoint_digest(host: &str, port: u16) -> u64 {
    let mut digest = 0xcbf2_9ce4_8422_2325_u64;
    for byte in host
        .bytes()
        .chain(port.to_be_bytes())
        .chain(std::iter::once(0))
    {
        digest ^= u64::from(byte);
        digest = digest.wrapping_mul(0x0000_0100_0000_01b3);
    }
    digest
}

pub(super) fn lifecycle_periodicity_paths(events: &[ActivityEvent]) -> Vec<ActivityPath> {
    let mut grouped = BTreeMap::<(u32, u64, String, u16, u8), Vec<&ActivityEvent>>::new();
    for event in events {
        let Some(network) = event.network.as_ref() else {
            continue;
        };
        if network.phase != NetworkActivityPhase::Closed || network.direction != Direction::Outbound
        {
            continue;
        }
        grouped
            .entry((
                event.agent_pid,
                event.agent_started_at,
                network.host.clone(),
                network.port,
                0,
            ))
            .or_default()
            .push(event);
    }
    let mut paths = Vec::new();
    for ((pid, started_at, host, port, _), mut lifecycle) in grouped {
        lifecycle
            .sort_by(|left, right| left.at.cmp(&right.at).then_with(|| left.id.cmp(&right.id)));
        lifecycle.dedup_by(|left, right| left.at == right.at);
        if lifecycle.len() < LIFECYCLE_PERIODIC_MIN_EVENTS {
            continue;
        }
        let mut intervals = lifecycle
            .windows(2)
            .filter_map(|pair| {
                pair.first()
                    .zip(pair.get(1))
                    .map(|(first, second)| second.at.saturating_sub(first.at))
            })
            .collect::<Vec<_>>();
        intervals.sort_unstable();
        let Some(median) = intervals.get(intervals.len() / 2).copied() else {
            continue;
        };
        if !(LIFECYCLE_PERIODIC_MIN_INTERVAL_MS..=LIFECYCLE_PERIODIC_MAX_INTERVAL_MS)
            .contains(&median)
            || intervals.iter().any(|interval| {
                interval.abs_diff(median).saturating_mul(100)
                    > median.saturating_mul(LIFECYCLE_PERIODIC_MAX_JITTER_PERCENT)
            })
        {
            continue;
        }
        let keep_from = lifecycle.len().saturating_sub(8);
        paths.push(ActivityPath {
            id: format!(
                "path:{pid}:{started_at}:periodic-lifecycle:{:016x}",
                endpoint_digest(&host, port)
            ),
            agent_pid: pid,
            agent_started_at: started_at,
            title: format!("Regular completed connections observed to {host}:{port}"),
            explanation: format!(
                "At least {LIFECYCLE_PERIODIC_MIN_EVENTS} exact connect/close lifecycles have a median interval of {median} ms with no interval beyond {LIFECYCLE_PERIODIC_MAX_JITTER_PERCENT}% jitter. This is periodic metadata, not proof of beaconing, intent, payload, or data transfer."
            ),
            events: lifecycle
                .iter()
                .skip(keep_from)
                .map(|event| event.id.clone())
                .collect(),
            certainty: LinkCertainty::Correlated,
        });
    }
    paths
}
