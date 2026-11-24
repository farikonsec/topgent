//! Agents this session has seen, including the ones no longer running.
//!
//! A monitor that forgets an agent the sweep after it exits shows the lab's
//! busiest minute as empty a minute later. A capture tool keeps every packet
//! of its capture, and an antivirus keeps its detections after the process
//! is gone; this keeps every agent seen since the process began sweeping,
//! each with when it was first and last seen. An agent that is not in the
//! current sweep is reported as ended, with its last known row: what it was
//! when it was last seen, not what it might have become.
//!
//! Held in memory, by the process that sweeps (the desktop application, or
//! the viewer's `--follow`): one session is one process, and a saved session
//! keeps them through the report it saves.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use serde_json::Value;

/// Most ended agents kept. Past it the oldest-ended go first, counted.
pub const MAX_ENDED_AGENTS: usize = 256;

#[derive(Debug)]
struct Run {
    first_seen: u64,
    last_seen: u64,
    row: Value,
}

#[derive(Debug, Default)]
struct History {
    seen: HashMap<(u64, u64), Run>,
    evicted: u64,
}

static HISTORY: Mutex<Option<History>> = Mutex::new(None);

/// What one sweep adds: the agents that ended before it, and how many older
/// ones were let go to stay within [`MAX_ENDED_AGENTS`].
#[derive(Debug, Default)]
pub struct Ended {
    /// Ended agents, most recently seen first, each its last known row with
    /// `first_seen`, `last_seen` and `live: false`.
    pub agents: Vec<Value>,
    /// Ended agents dropped from the session so far.
    pub evicted: u64,
}

/// A run of an agent: its pid and when it started.
fn key(row: &Value) -> Option<(u64, u64)> {
    Some((row.get("pid")?.as_u64()?, row.get("started_at")?.as_u64()?))
}

/// Records this sweep's agents, stamps each with when it was first seen,
/// and returns the ones seen before but not now.
pub fn track(live: &mut [Value], at: u64) -> Ended {
    let mut guard = HISTORY.lock().unwrap_or_else(PoisonError::into_inner);
    let history = guard.get_or_insert_with(History::default);
    track_in(history, live, at)
}

fn track_in(history: &mut History, live: &mut [Value], at: u64) -> Ended {
    let mut now = Vec::new();
    for row in live.iter_mut() {
        let Some(k) = key(row) else { continue };
        now.push(k);
        let entry = history.seen.entry(k).or_insert_with(|| Run {
            first_seen: at,
            last_seen: at,
            row: Value::Null,
        });
        entry.last_seen = at;
        entry.row = row.clone();
        if let Some(fields) = row.as_object_mut() {
            fields.insert("first_seen".to_owned(), entry.first_seen.into());
            fields.insert("live".to_owned(), true.into());
        }
    }
    let mut ended: Vec<(&(u64, u64), &Run)> = history
        .seen
        .iter()
        .filter(|(k, _)| !now.contains(k))
        .collect();
    ended.sort_by_key(|(_, seen)| std::cmp::Reverse(seen.last_seen));
    let over: Vec<(u64, u64)> = ended
        .iter()
        .skip(MAX_ENDED_AGENTS)
        .map(|(k, _)| **k)
        .collect();
    let agents = ended
        .iter()
        .take(MAX_ENDED_AGENTS)
        .map(|(_, seen)| {
            let mut row = seen.row.clone();
            if let Some(fields) = row.as_object_mut() {
                fields.insert("first_seen".to_owned(), seen.first_seen.into());
                fields.insert("last_seen".to_owned(), seen.last_seen.into());
                fields.insert("live".to_owned(), false.into());
            }
            row
        })
        .collect();
    for k in &over {
        history.seen.remove(k);
    }
    history.evicted = history
        .evicted
        .saturating_add(u64::try_from(over.len()).unwrap_or(u64::MAX));
    Ended {
        agents,
        evicted: history.evicted,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]

    use serde_json::json;

    use super::{History, MAX_ENDED_AGENTS, track_in};

    fn agent(pid: u64, started: u64) -> serde_json::Value {
        json!({"pid": pid, "started_at": started, "family": "opencode"})
    }

    #[test]
    fn an_agent_that_exits_stays_as_ended_with_when_it_was_seen() {
        let mut history = History::default();
        let mut first = vec![agent(7, 100), agent(8, 100)];
        assert!(track_in(&mut history, &mut first, 1_000).agents.is_empty());
        assert_eq!(first[0]["first_seen"], 1_000);
        let mut second = vec![agent(7, 100)];
        let ended = track_in(&mut history, &mut second, 2_000);
        assert_eq!(ended.agents.len(), 1);
        let gone = &ended.agents[0];
        assert_eq!(
            (gone["pid"].as_u64(), gone["live"].as_bool()),
            (Some(8), Some(false))
        );
        assert_eq!(
            (gone["first_seen"].as_u64(), gone["last_seen"].as_u64()),
            (Some(1_000), Some(1_000))
        );
        assert_eq!(
            second[0]["first_seen"], 1_000,
            "still running: first seen kept"
        );
        assert_eq!(second[0]["live"], true);
    }

    #[test]
    fn a_reused_pid_is_a_different_run() {
        let mut history = History::default();
        track_in(&mut history, &mut [agent(7, 100)], 1_000);
        let ended = track_in(&mut history, &mut [agent(7, 900)], 2_000);
        assert_eq!(ended.agents.len(), 1, "the first run of pid 7 ended");
        assert_eq!(ended.agents[0]["started_at"], 100);
    }

    #[test]
    fn past_the_bound_the_oldest_ended_are_counted_and_let_go() {
        let mut history = History::default();
        for n in 0..(MAX_ENDED_AGENTS as u64 + 5) {
            track_in(&mut history, &mut [agent(n, 1)], n);
        }
        let ended = track_in(&mut history, &mut [], 10_000);
        assert_eq!(ended.agents.len(), MAX_ENDED_AGENTS);
        assert_eq!(ended.evicted, 5);
        assert_eq!(
            ended.agents[0]["pid"],
            MAX_ENDED_AGENTS as u64 + 4,
            "most recent first"
        );
    }
}
