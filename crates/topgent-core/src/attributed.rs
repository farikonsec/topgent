//! What a process did, pinned on it and on its agent as of the moment it did it.
//!
//! A kernel record names a pid and a time. By the next sweep that pid may
//! belong to nobody, or to somebody else. The only answer that holds is the
//! one the process history gives for that exact moment: which run of that pid
//! was alive then, and which agent it descended from. An action whose actor
//! the history cannot place is not attributed at all. A near guess would put
//! one process's action on another, which is the one thing this must not do.
//!
//! Separate from [`crate::lineage`] because lineage answers "who was this
//! process"; this answers "whose action was this".

use topgent_facts::UnixMillis;

use crate::lineage::{Lineage, ProcessKey};

/// Where an action lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribution {
    /// The process that acted, as of the action.
    pub actor: ProcessKey,
    /// The agent it descends from, or is.
    pub agent: ProcessKey,
    /// Pids from the agent's child down to the actor. Empty when the agent
    /// acted itself.
    pub chain: Vec<u32>,
}

/// How far before a process's recorded start a record may be stamped and
/// still be its. Audit stamps records with the kernel's coarse clock, which
/// runs up to one scheduler tick (4 ms at 250 Hz) behind the precise time the
/// process connector gives a start.
pub const CLOCK_SLACK_MS: u64 = 10;

/// The run of `pid` that made a record stamped `at`, or none when it cannot
/// be told.
///
/// A record stamped just before a run's start belongs to that run only if no
/// other run of the pid could have made it: one that ended within the slack
/// makes the record ambiguous, and an ambiguous record is nobody's.
#[must_use]
pub fn actor_at(lineage: &Lineage, pid: u32, at: UnixMillis) -> Option<ProcessKey> {
    if let Some(actor) = lineage.resolve(pid, at) {
        return Some(actor);
    }
    // The run that started within the slack after the stamp. Found by its
    // start, not by who held the pid at the end of the slack: a process that
    // lived three milliseconds is gone by then.
    let mut starting = lineage.records().filter(|record| {
        record.key.pid == pid
            && record.key.started_at > at
            && record.key.started_at.0 <= at.0.saturating_add(CLOCK_SLACK_MS)
    });
    let later = starting.next()?.key;
    if starting.next().is_some() {
        return None;
    }
    let rival = lineage.records().any(|record| {
        record.key.pid == pid
            && record.key != later
            && record.key.started_at <= at
            && record
                .exited_at
                .or(record.gone_after)
                .is_none_or(|ended| ended.0.saturating_add(CLOCK_SLACK_MS) >= at.0)
    });
    (!rival).then_some(later)
}

/// Places an action by `pid` at `at` on its actor and agent, or nowhere.
#[must_use]
pub fn attribute(
    lineage: &Lineage,
    agents: &[ProcessKey],
    pid: u32,
    at: UnixMillis,
) -> Option<Attribution> {
    let actor = actor_at(lineage, pid, at)?;
    if agents.contains(&actor) {
        return Some(Attribution {
            actor,
            agent: actor,
            chain: Vec::new(),
        });
    }
    let ancestry = lineage.ancestry(actor);
    let nearest = ancestry.iter().position(|key| agents.contains(key))?;
    let agent = *ancestry.get(nearest)?;
    let mut chain: Vec<u32> = ancestry
        .iter()
        .take(nearest)
        .rev()
        .map(|key| key.pid)
        .collect();
    chain.push(actor.pid);
    Some(Attribution {
        actor,
        agent,
        chain,
    })
}
