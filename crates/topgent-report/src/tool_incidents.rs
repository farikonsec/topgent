//! An agent ran an offensive tool: an incident that outlives the tool.
//!
//! `OFFENSIVE_TOOL` is a risk factor, and a factor describes what is running
//! now. A port scan that lasts five seconds raised its agent to Critical for
//! five seconds and then left no trace but a line in the event log, so a
//! person who looked a minute later saw a calm agent. This builds an incident
//! from the retained process history instead, which keeps the tool's run after
//! it exits, so the card stays as long as the history does.
//!
//! The history places each process on the nearest agent above it, so a scan
//! run by Claude Code under Claude Desktop is one incident on Claude Code, not
//! two.
//!
//! Derived again on every sweep, like the behaviour-rule incidents: it needs
//! no state of its own.

use std::collections::BTreeMap;

use serde_json::{Value, json};

/// Most runs listed as evidence on one card.
const MAX_EVIDENCE: usize = 20;

/// A family's product name, from the agent catalogue.
pub(crate) fn product_name(family: &str) -> String {
    topgent_collect::signatures::builtin()
        .ok()
        .and_then(|c| c.families.iter().find(|f| f.id == family))
        .map_or_else(|| family.to_owned(), |f| f.name.clone())
}

fn number(row: &Value, field: &str) -> Option<u64> {
    row.get(field).and_then(Value::as_u64)
}

fn text<'a>(row: &'a Value, field: &str) -> &'a str {
    row.get(field).and_then(Value::as_str).unwrap_or("")
}

/// The tool a process is, by its lowercased name, when the signal list names it.
fn tool(row: &Value, is_tool: &dyn Fn(&str) -> bool) -> Option<String> {
    let name = text(row, "name").to_ascii_lowercase();
    let program = text(row, "program").to_ascii_lowercase();
    let program = program.rsplit('/').next().unwrap_or("").to_owned();
    [name, program]
        .into_iter()
        .find(|candidate| !candidate.is_empty() && is_tool(candidate))
}

/// One incident per agent run that started an offensive tool.
///
/// `processes` are the report's `process_history` rows; `agent_name` names a
/// run for the headline.
pub(crate) fn derive(
    processes: &[Value],
    is_tool: &dyn Fn(&str) -> bool,
    agent: &dyn Fn(u32, u64) -> (String, Option<String>),
) -> Vec<Value> {
    // The history lists a process once under every agent above it: a scan run
    // by Claude Code inside Claude Desktop appears under both. Each process is
    // kept only under its nearest agent, the one with the smallest depth.
    let mut nearest: BTreeMap<(u64, u64), &Value> = BTreeMap::new();
    for row in processes {
        let (Some(pid), Some(at)) = (
            number(row, "pid"),
            number(row, "started_at").or_else(|| number(row, "first_seen")),
        ) else {
            continue;
        };
        let depth = number(row, "depth").unwrap_or(u64::MAX);
        let slot = nearest.entry((pid, at)).or_insert(row);
        if depth < number(slot, "depth").unwrap_or(u64::MAX) {
            *slot = row;
        }
    }
    let mut groups: BTreeMap<(u32, u64), Vec<(&Value, String)>> = BTreeMap::new();
    for row in nearest.into_values() {
        let (Some(pid), Some(started)) = (
            number(row, "agent_pid").and_then(|p| u32::try_from(p).ok()),
            number(row, "agent_started_at"),
        ) else {
            continue;
        };
        let Some(tool) = tool(row, is_tool) else {
            continue;
        };
        groups.entry((pid, started)).or_default().push((row, tool));
    }
    let mut out: Vec<Value> = groups
        .into_iter()
        .map(|((pid, started), mut runs)| {
            runs.sort_by_key(|(r, _)| {
                number(r, "started_at")
                    .or_else(|| number(r, "first_seen"))
                    .unwrap_or(0)
            });
            card(pid, started, &runs, agent(pid, started))
        })
        .collect();
    out.sort_by_key(|r| std::cmp::Reverse(number(r, "first_seen").unwrap_or(0)));
    out
}

fn card(
    pid: u32,
    started: u64,
    runs: &[(&Value, String)],
    (name, family): (String, Option<String>),
) -> Value {
    let at = |r: &Value| {
        number(r, "started_at")
            .or_else(|| number(r, "first_seen"))
            .unwrap_or(0)
    };
    let first_at = runs.iter().map(|(r, _)| at(r)).min().unwrap_or(0);
    let last_at = runs
        .iter()
        .map(|(r, _)| {
            number(r, "gone_after")
                .or_else(|| number(r, "last_seen"))
                .unwrap_or_else(|| at(r))
        })
        .max()
        .unwrap_or(first_at);
    let mut tools: Vec<&str> = runs.iter().map(|(_, t)| t.as_str()).collect();
    tools.sort_unstable();
    tools.dedup();
    let times = runs.len();
    let headline = format!(
        "{name} ran {}{}",
        tools.join(", "),
        if times > 1 {
            format!(" ({times} times)")
        } else {
            String::new()
        }
    );
    let evidence: Vec<Value> = runs
        .iter()
        .take(MAX_EVIDENCE)
        .map(|(r, tool)| {
            json!({
                "rule": "Offensive tool",
                "summary": tool,
                "target": text(r, "exe"),
                "actor_pid": number(r, "pid"),
                "actor_name": text(r, "name"),
                "at": at(r),
                "count": 1,
                "source": "process history",
                "container": "",
            })
        })
        .collect();
    json!({
        "id": format!("offensive_tool:{pid}:{started}"),
        "rule": "offensive_tool",
        "kind": "offensive_tool",
        "name": "Offensive Tool",
        "severity": "high",
        "headline": headline,
        "why": [
            "Scanners and password crackers probe or attack other hosts.",
        ],
        "actions": [
            {"label": "Confirm a user requested it."},
            {"label": "If not, stop the agent and check its targets."},
        ],
        "tools": tools,
        "process_pid": runs.last().and_then(|(r, _)| number(r, "pid")),
        "agent": {
            "pid": pid,
            "started_at": started,
            "name": name,
            "recognised": family.is_some(),
            "family": family,
        },
        "numbers": {
            "findings": times,
            "rules": tools.len(),
            "duration_ms": last_at.saturating_sub(first_at),
            "duration": crate::incidents::duration(last_at.saturating_sub(first_at)),
        },
        "evidence": {"findings": evidence},
        "first_at": first_at,
        "last_at": last_at,
        "first_seen": first_at,
        "last_seen": last_at,
        "limits": [
            "Arguments and targets are not recorded.",
            "Without a kernel process feed, a tool that exits between sweeps is missed.",
        ],
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn process(name: &str, pid: u32, agent: Option<(u32, u64)>, started: u64) -> Value {
        let mut row = json!({"name": name, "program": name, "exe": format!("/usr/local/bin/{name}"), "pid": pid,
            "started_at": started, "state": "gone", "gone_after": started + 5_000});
        if let Some((p, s)) = agent {
            row["agent_pid"] = json!(p);
            row["agent_started_at"] = json!(s);
        }
        row
    }

    fn named(_: u32, _: u64) -> (String, Option<String>) {
        ("Claude Code".to_owned(), Some("claude-code".to_owned()))
    }

    const TOOLS: &dyn Fn(&str) -> bool = &|name| matches!(name, "nmap" | "hydra");

    #[test]
    fn a_tool_that_exited_still_opens_an_incident_on_its_agent() {
        let rows = vec![
            process("nmap", 93705, Some((93984, 1)), 1_000),
            process("zsh", 93700, Some((93984, 1)), 900),
            process("nmap", 5, None, 1_000),
        ];
        let out = derive(&rows, TOOLS, &named);
        assert_eq!(out.len(), 1, "only a tool on an agent run is an incident");
        assert_eq!(out[0]["kind"], "offensive_tool");
        assert_eq!(out[0]["agent"]["pid"], 93984);
        assert_eq!(out[0]["headline"], "Claude Code ran nmap");
        assert_eq!(out[0]["evidence"]["findings"][0]["actor_pid"], 93705);
        assert_eq!(out[0]["numbers"]["duration_ms"], 5_000);
    }

    #[test]
    fn a_tool_under_nested_agents_is_one_incident_on_the_nearest() {
        let mut inner = process("nmap", 15078, Some((93984, 1)), 1_000);
        inner["depth"] = json!(2);
        let mut outer = process("nmap", 15078, Some((28673, 1)), 1_000);
        outer["depth"] = json!(4);
        let out = derive(&[outer, inner], TOOLS, &named);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["agent"]["pid"], 93984);
    }

    #[test]
    fn several_runs_of_several_tools_are_one_card_per_agent_run() {
        let rows = vec![
            process("nmap", 1, Some((10, 1)), 1_000),
            process("hydra", 2, Some((10, 1)), 2_000),
            process("nmap", 3, Some((10, 1)), 3_000),
            process("nmap", 4, Some((20, 1)), 4_000),
        ];
        let out = derive(&rows, TOOLS, &named);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["agent"]["pid"], 20, "newest first");
        assert_eq!(out[1]["headline"], "Claude Code ran hydra, nmap (3 times)");
    }
}
