//! Findings: a rule that fired, on whom, kept across sweeps.
//!
//! A finding row holds the rule, the record, the acting process's pid, name
//! and start-base time, and a short target (a path, an address, a program).
//! Never arguments. Which agent it belongs to is resolved again on every
//! sweep against process history, so a finding recorded before its actor's
//! fork event arrived is placed once that event does, and one whose actor
//! belongs to no agent is reported as a host finding. Once placed, a finding
//! keeps its agent after that agent exits: the ancestry of a run that has
//! already happened cannot change, and a finding that lost its agent the
//! moment the agent finished would blame the host for what the agent did.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use topgent_core::lineage::{Lineage, ProcessKey};
use topgent_facts::UnixMillis;

/// Most findings kept.
pub(crate) const MAX_FINDINGS: usize = 1_024;

fn text<'a>(row: &'a Value, field: &str) -> Option<&'a str> {
    row.get(field)?.as_str()
}

fn number(row: &Value, field: &str) -> Option<u64> {
    row.get(field)?.as_u64()
}

/// One row per rule, acting process and target; repeats are counted.
fn identity(row: &Value) -> Option<String> {
    Some(format!(
        "{}\u{1f}{}\u{1f}{}",
        text(row, "rule")?,
        number(row, "actor_pid")?,
        text(row, "target").unwrap_or("")
    ))
}

/// Adds `new` rows to the saved `history`, bounded, and places each on its
/// agent as of now.
pub(crate) fn project(
    history: &Value,
    new: Vec<Value>,
    lineage: &Lineage,
    agents: &[ProcessKey],
    boot: &str,
) -> Value {
    let same_boot = history.get("boot").and_then(Value::as_str) == Some(boot);
    let mut evicted = if same_boot {
        number(history, "evicted").unwrap_or(0)
    } else {
        0
    };
    let mut rows: BTreeMap<String, Value> = BTreeMap::new();
    let saved = history
        .get("rows")
        .and_then(Value::as_array)
        .filter(|_| same_boot)
        .into_iter()
        .flatten()
        .take(MAX_FINDINGS)
        .cloned();
    for row in saved.chain(new) {
        let Some(id) = identity(&row) else { continue };
        let at = row.get("at").cloned().unwrap_or(Value::Null);
        if let Some(known) = rows.get_mut(&id) {
            // A native temporal rule is derived again from retained action
            // history on every sweep. The same pair of records is the same
            // finding, not another occurrence. Kernel-event findings arrive
            // once from their watermark, but this also makes replay safe.
            if text(known, "record").is_some() && text(known, "record") == text(&row, "record") {
                continue;
            }
            let count = number(known, "count").unwrap_or(1) + number(&row, "count").unwrap_or(1);
            let later = number(&row, "at") > number(known, "last_at");
            if let Some(object) = known.as_object_mut() {
                object.insert("count".into(), json!(count));
                if later {
                    object.insert("last_at".into(), at);
                }
            }
        } else {
            let mut row = row;
            if let Some(object) = row.as_object_mut() {
                object.entry("last_at").or_insert(at);
            }
            rows.insert(id, row);
        }
    }
    let mut rows: Vec<Value> = rows.into_values().collect();
    // Newest first; the oldest go when the bound is reached.
    rows.sort_by_key(|row| std::cmp::Reverse(number(row, "last_at").unwrap_or(0)));
    if rows.len() > MAX_FINDINGS {
        evicted += (rows.len() - MAX_FINDINGS) as u64;
        rows.truncate(MAX_FINDINGS);
    }
    for row in &mut rows {
        place(row, lineage, agents);
    }
    json!({"boot": boot, "evicted": evicted, "rows": rows})
}

/// The agent, the chain and the actor's run, as of now, or as placed before
/// when history can no longer place it (its agent has exited).
fn place(row: &mut Value, lineage: &Lineage, agents: &[ProcessKey]) {
    let found = u32::try_from(number(row, "actor_pid").unwrap_or(0))
        .ok()
        .zip(number(row, "lineage_at"))
        .and_then(|(pid, at)| {
            topgent_core::attributed::attribute(lineage, agents, pid, UnixMillis(at))
        });
    let Some(object) = row.as_object_mut() else {
        return;
    };
    let Some(found) = found else {
        // Not placeable now. A placement made earlier stands: `attribute`
        // never guesses, so what it placed was so, and stays so.
        return;
    };
    for key in [
        "agent_pid",
        "agent_started_at",
        "agent_name",
        "actor_started_at",
        "chain",
    ] {
        object.remove(key);
    }
    object.insert("agent_pid".into(), json!(found.agent.pid));
    object.insert("agent_started_at".into(), json!(found.agent.started_at.0));
    // Named as history knew it, so a reader can still name the agent once
    // it has exited and left the list of running agents.
    if let Some(name) = lineage.get(found.agent).map(|agent| agent.name.clone()) {
        object.insert("agent_name".into(), json!(name));
    }
    object.insert("actor_started_at".into(), json!(found.actor.started_at.0));
    object.insert("chain".into(), json!(found.chain));
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::expect_used)]

    use super::{MAX_FINDINGS, number, project};
    use serde_json::{Value, json};
    use topgent_core::lineage::{Lineage, Observation, ProcessKey};
    use topgent_facts::UnixMillis;

    fn key(pid: u32, at: u64) -> ProcessKey {
        ProcessKey {
            pid,
            started_at: UnixMillis(at),
        }
    }

    fn lineage() -> Lineage {
        let mut l = Lineage::new(64);
        for (pid, start, parent) in [(10, 100, None), (11, 200, Some(10))] {
            l.observe(Observation {
                key: key(pid, start),
                parent_pid: parent,
                name: "p".into(),
                exe: None,
                pid_namespace: None,
                at: UnixMillis(start),
                from_event: true,
            });
        }
        l
    }

    fn row(rule: &str, pid: u32, at: u64, target: &str) -> Value {
        json!({"rule": rule, "record": format!("0:{at}"), "actor_pid": pid,
            "lineage_at": at, "at": at, "target": target})
    }

    #[test]
    fn a_descendants_finding_is_placed_on_its_agent_and_a_strangers_is_not() {
        let out = project(
            &json!({}),
            vec![
                row("R", 11, 250, "/etc/shadow"),
                row("R", 99, 250, "/etc/shadow"),
            ],
            &lineage(),
            &[key(10, 100)],
            "boot",
        );
        let rows = out["rows"].as_array().expect("rows");
        let child = rows.iter().find(|r| r["actor_pid"] == 11).expect("child");
        assert_eq!(child["agent_pid"], 10);
        assert_eq!(child["chain"], json!([11]));
        let stranger = rows
            .iter()
            .find(|r| r["actor_pid"] == 99)
            .expect("stranger");
        assert!(stranger.get("agent_pid").is_none(), "a host finding");
    }

    /// An agent that has exited is no longer a running agent, but what its
    /// children did is still its doing.
    #[test]
    fn a_finding_keeps_its_agent_after_the_agent_exits() {
        let running = project(
            &json!({}),
            vec![row("R", 11, 250, "/etc/shadow")],
            &lineage(),
            &[key(10, 100)],
            "boot",
        );
        assert_eq!(running["rows"][0]["agent_pid"], 10);
        assert_eq!(running["rows"][0]["agent_name"], "p");
        // Next sweep: the agent is gone from the running list, and its
        // history has been evicted too.
        let after = project(&running, Vec::new(), &Lineage::new(64), &[], "boot");
        let row = &after["rows"][0];
        assert_eq!(row["agent_pid"], 10);
        assert_eq!(row["agent_name"], "p");
        assert_eq!(row["chain"], json!([11]));
    }

    #[test]
    fn a_repeat_is_counted_not_listed_and_history_is_bounded() {
        let first = project(
            &json!({}),
            vec![row("R", 11, 250, "/x")],
            &lineage(),
            &[],
            "b",
        );
        let second = project(&first, vec![row("R", 11, 260, "/x")], &lineage(), &[], "b");
        assert_eq!(second["rows"].as_array().map(Vec::len), Some(1));
        assert_eq!(second["rows"][0]["count"], 2);
        assert_eq!(second["rows"][0]["last_at"], 260);
        let many = (0..MAX_FINDINGS + 5)
            .map(|n| row("R", 11, n as u64, &format!("/f{n}")))
            .collect();
        let bounded = project(&json!({}), many, &lineage(), &[], "b");
        assert_eq!(bounded["rows"].as_array().map(Vec::len), Some(MAX_FINDINGS));
        assert_eq!(bounded["evicted"], 5);
    }

    #[test]
    fn another_boot_starts_empty() {
        let first = project(
            &json!({}),
            vec![row("R", 11, 250, "/x")],
            &lineage(),
            &[],
            "old",
        );
        let next = project(&first, Vec::new(), &lineage(), &[], "new");
        assert_eq!(next["rows"].as_array().map(Vec::len), Some(0));
    }

    #[test]
    fn replaying_the_same_source_record_does_not_inflate_its_count() {
        let first = project(
            &json!({}),
            vec![row("R", 11, 250, "/x")],
            &lineage(),
            &[],
            "b",
        );
        let second = project(&first, vec![row("R", 11, 250, "/x")], &lineage(), &[], "b");
        assert_eq!(number(&second["rows"][0], "count").unwrap_or(1), 1);
    }
}
