//! Assembling a timeline, and merging it with what was already retained.
//!
//! Bounded on both axes: a fixed ceiling on events kept and a retention window
//! past which they are dropped. An unbounded timeline is a memory leak that
//! only shows up on the machines that have been running longest, which are the
//! ones whose history matters most.

use super::draft::event_id;
use super::draft::fact_draft;
use super::model::Activity;
use super::model::ActivityEvent;
use super::model::ActivityKind;
use super::model::ActivityLink;
use super::model::LinkCertainty;
use super::paths::correlated_paths;
use super::paths::lifecycle_periodicity_paths;
use crate::Agent;
use std::collections::{BTreeMap, BTreeSet};
use topgent_facts::Claim;
use topgent_facts::Fact;
use topgent_facts::Subject;

/// Maximum metadata-only activity events retained between scans.
pub const MAX_ACTIVITY_EVENTS: usize = 4_096;

/// Historical activity retention window: seven days.
pub const ACTIVITY_RETENTION_MS: u64 = 7 * 24 * 60 * 60 * 1_000;

/// Build activity for recognized agents from the immutable fact stream.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn build(facts: &[Fact], agents: &[Agent]) -> Activity {
    let subjects: BTreeSet<(u32, u64)> = agents
        .iter()
        .filter(|agent| agent.family.is_some() || !agent.extensions.is_empty())
        .map(|agent| (agent.id.pid, agent.id.started_at.0))
        .collect();
    // ChildProcessSeen intentionally carries only a PID. Resolve that PID back
    // to exactly one current ProcessSeen identity before admitting any native
    // child facts. This prevents a recycled or ambiguously shared PID from
    // inheriting an agent's activity.
    let mut live_starts = BTreeMap::<u32, BTreeSet<u64>>::new();
    for fact in facts {
        if matches!(fact.claim(), Claim::ProcessSeen { .. })
            && let Subject::Process { pid, started_at } = fact.subject()
        {
            live_starts.entry(*pid).or_default().insert(started_at.0);
        }
    }
    let mut child_owner = BTreeMap::<(u32, u64), Option<(u32, u64)>>::new();
    for agent in agents
        .iter()
        .filter(|agent| agent.family.is_some() || !agent.extensions.is_empty())
    {
        let owner = (agent.id.pid, agent.id.started_at.0);
        for child in &agent.children {
            let Some(starts) = live_starts.get(&child.pid) else {
                continue;
            };
            let mut starts = starts.iter();
            let Some(started_at) = starts.next().copied() else {
                continue;
            };
            if starts.next().is_some() {
                continue;
            }
            child_owner
                .entry((child.pid, started_at))
                .and_modify(|existing| {
                    if *existing != Some(owner) {
                        *existing = None;
                    }
                })
                .or_insert(Some(owner));
        }
    }
    let mut drafts = Vec::new();
    for fact in facts {
        let Subject::Process { pid, started_at } = fact.subject() else {
            continue;
        };
        let identity = (*pid, started_at.0);
        let owner = if subjects.contains(&identity) {
            Some(identity)
        } else {
            child_owner.get(&identity).copied().flatten()
        };
        let Some((agent_pid, agent_started_at)) = owner else {
            continue;
        };
        if let Some(draft) = fact_draft(fact, agent_pid, agent_started_at, identity.0) {
            drafts.push(draft);
        }
    }
    drafts.sort();
    drafts.dedup();

    let mut events = Vec::new();
    let mut links = Vec::new();
    for agent in agents
        .iter()
        .filter(|agent| agent.family.is_some() || !agent.extensions.is_empty())
    {
        let root_id = format!(
            "activity:{}:{}:started:0",
            agent.id.pid, agent.id.started_at.0
        );
        events.push(ActivityEvent {
            id: root_id,
            sequence: 0,
            parent_id: None,
            agent_pid: agent.id.pid,
            agent_started_at: agent.id.started_at.0,
            actor_pid: agent.id.pid,
            at: agent.id.started_at.0,
            kind: ActivityKind::Started,
            title: format!("{} started", agent.family.as_deref().unwrap_or("agent")),
            detail: format!("pid {}", agent.id.pid),
            confidence: agent.discovery_confidence,
            collector: "process".to_owned(),
            probe: "process table".to_owned(),
            network: None,
        });
    }
    let process_event_ids = drafts
        .iter()
        .filter(|draft| draft.kind == ActivityKind::Process)
        .map(|draft| {
            (
                (draft.agent_pid, draft.agent_started_at, draft.actor_pid),
                event_id(draft),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut next_sequence = BTreeMap::<(u32, u64), u64>::new();
    for draft in &drafts {
        let id = event_id(draft);
        let root = events
            .iter()
            .find(|event| event.agent_pid == draft.agent_pid && event.kind == ActivityKind::Started)
            .filter(|event| event.agent_started_at == draft.agent_started_at)
            .map(|event| event.id.clone());
        let direct_actor_parent = (draft.kind != ActivityKind::Process
            && draft.actor_pid != draft.agent_pid)
            .then(|| {
                process_event_ids
                    .get(&(draft.agent_pid, draft.agent_started_at, draft.actor_pid))
                    .cloned()
            })
            .flatten();
        let link_parent = direct_actor_parent.as_ref().or(root.as_ref());
        if let Some(parent_id) = link_parent {
            links.push(ActivityLink {
                from: parent_id.clone(),
                to: id.clone(),
                relation: draft.relation,
                certainty: if draft.certainty_rank == 0 || direct_actor_parent.is_some() {
                    LinkCertainty::Direct
                } else {
                    LinkCertainty::Attributed
                },
            });
        }
        events.push(ActivityEvent {
            id,
            sequence: {
                let sequence = next_sequence
                    .entry((draft.agent_pid, draft.agent_started_at))
                    .or_insert(1);
                let assigned = *sequence;
                *sequence = sequence.saturating_add(1);
                assigned
            },
            parent_id: if let Some(parent) = direct_actor_parent {
                Some(parent)
            } else if draft.certainty_rank == 0 {
                root
            } else {
                None
            },
            agent_pid: draft.agent_pid,
            agent_started_at: draft.agent_started_at,
            actor_pid: draft.actor_pid,
            at: draft.at,
            kind: draft.kind,
            title: draft.title.clone(),
            detail: draft.detail.clone(),
            confidence: draft.confidence,
            collector: draft.collector.clone(),
            probe: draft.probe.clone(),
            network: draft.network.clone(),
        });
    }
    events.sort_by(|left, right| left.at.cmp(&right.at).then_with(|| left.id.cmp(&right.id)));
    let paths = correlated_paths(&events, agents);
    Activity {
        events,
        links,
        paths,
    }
}

pub(super) fn assign_durable_sequences(
    events: &mut [ActivityEvent],
    previous_ids: &BTreeSet<&str>,
) {
    let mut next_sequence = BTreeMap::<(u32, u64), u64>::new();
    for event in events.iter() {
        if previous_ids.contains(event.id.as_str()) {
            next_sequence
                .entry((event.agent_pid, event.agent_started_at))
                .and_modify(|next| *next = (*next).max(event.sequence.saturating_add(1)))
                .or_insert(event.sequence.saturating_add(1));
        }
    }
    events.sort_by(|left, right| left.at.cmp(&right.at).then_with(|| left.id.cmp(&right.id)));
    let mut used = BTreeMap::<(u32, u64), BTreeSet<u64>>::new();
    for event in events {
        let identity = (event.agent_pid, event.agent_started_at);
        if event.kind == ActivityKind::Started {
            event.sequence = 0;
            used.entry(identity).or_default().insert(0);
            continue;
        }
        let valid_existing = previous_ids.contains(event.id.as_str())
            && event.sequence > 0
            && used.entry(identity).or_default().insert(event.sequence);
        if !valid_existing {
            let next = next_sequence.entry(identity).or_insert(1);
            event.sequence = *next;
            *next = next.saturating_add(1);
        }
    }
}

/// Merge a current activity projection with bounded prior metadata.
///
/// Current observations are always preferred. Historical observations outside
/// the retention window are discarded, then the oldest non-root events are
/// removed to satisfy `limit`. Links and paths with missing event references
/// are dropped so replay cannot manufacture dangling relationships.
#[must_use]
pub fn merge_activity_history(
    previous: &Activity,
    current: &Activity,
    now: u64,
    limit: usize,
) -> Activity {
    let current_ids = current
        .events
        .iter()
        .map(|event| event.id.as_str())
        .collect::<BTreeSet<_>>();
    let cutoff = now.saturating_sub(ACTIVITY_RETENTION_MS);
    let previous_ids = previous
        .events
        .iter()
        .map(|event| event.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut by_id = BTreeMap::new();
    for event in &previous.events {
        if event.at >= cutoff && event.at <= now {
            by_id.insert(event.id.clone(), event.clone());
        }
    }
    for event in &current.events {
        let mut preferred = event.clone();
        if let Some(persisted) = by_id.get(&event.id) {
            preferred.sequence = persisted.sequence;
        }
        if current_ids.contains(event.id.as_str()) {
            by_id.insert(event.id.clone(), preferred);
        }
    }
    let mut events = by_id.into_values().collect::<Vec<_>>();
    assign_durable_sequences(&mut events, &previous_ids);
    events.sort_by(|left, right| left.at.cmp(&right.at).then_with(|| left.id.cmp(&right.id)));
    while events.len() > limit {
        let removable = events
            .iter()
            .position(|event| {
                !current_ids.contains(event.id.as_str()) && event.kind != ActivityKind::Started
            })
            .or_else(|| {
                events
                    .iter()
                    .position(|event| event.kind != ActivityKind::Started)
            })
            .or(Some(0));
        let Some(index) = removable else { break };
        events.remove(index);
    }

    let retained = events
        .iter()
        .map(|event| event.id.clone())
        .collect::<BTreeSet<_>>();
    for event in &mut events {
        if event
            .parent_id
            .as_ref()
            .is_some_and(|parent| !retained.contains(parent.as_str()))
        {
            event.parent_id = None;
        }
    }
    let mut links = previous
        .links
        .iter()
        .chain(&current.links)
        .cloned()
        .collect::<Vec<_>>();
    links.sort_by(|left, right| (&left.from, &left.to).cmp(&(&right.from, &right.to)));
    links.dedup_by(|left, right| left.from == right.from && left.to == right.to);
    links.retain(|link| {
        retained.contains(link.from.as_str()) && retained.contains(link.to.as_str())
    });

    let mut paths = previous
        .paths
        .iter()
        .chain(&current.paths)
        .cloned()
        .collect::<Vec<_>>();
    paths.sort_by(|left, right| left.id.cmp(&right.id));
    paths.dedup_by(|left, right| left.id == right.id);
    paths.retain(|path| {
        path.events
            .iter()
            .all(|event| retained.contains(event.as_str()))
    });
    for derived in lifecycle_periodicity_paths(&events) {
        if let Some(existing) = paths.iter_mut().find(|path| path.id == derived.id) {
            *existing = derived;
        } else {
            paths.push(derived);
        }
    }
    paths.sort_by(|left, right| left.id.cmp(&right.id));
    Activity {
        events,
        links,
        paths,
    }
}
