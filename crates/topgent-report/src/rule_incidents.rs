//! Named incidents built from behaviour-rule findings.
//!
//! The behaviour rules already say *what* matched; a person still has to read
//! a rule name, a priority and a syscall target and decide whether it matters.
//! This turns the findings that belong to one agent run into one card per kind
//! of behaviour (sandbox escape, remote control, persistence and so on), in the
//! same shape as the workspace-exfiltration card, so every interface renders it
//! without new code paths beyond the evidence list.
//!
//! Derived again on every sweep from the retained findings, so it needs no
//! history of its own: a finding kept across sweeps keeps its card, and a run
//! whose findings are evicted loses it with them.
//!
//! Only findings placed on an agent run become incidents. A finding on a
//! process no agent started stays a behaviour finding: incidents are about what
//! agents did.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde_json::{Value, json};

const DATA: &str = include_str!("../data/rule-incidents.json");

/// Most findings listed as evidence on one card.
const MAX_EVIDENCE: usize = 20;

/// One kind of incident and the rules that feed it.
#[derive(Debug)]
pub(crate) struct Kind {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) severity: String,
    verb: String,
    pub(crate) rules: Vec<String>,
    why: Vec<String>,
    actions: Vec<String>,
}

#[derive(Debug)]
struct Catalogue {
    kinds: Vec<Kind>,
    limits: Vec<String>,
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn catalogue() -> &'static Catalogue {
    static CATALOGUE: OnceLock<Catalogue> = OnceLock::new();
    CATALOGUE.get_or_init(|| {
        // Shipped with the binary and checked by a test; a parse failure here
        // is a build defect, so it yields no kinds rather than a panic.
        let data: Value = serde_json::from_str(DATA).unwrap_or(Value::Null);
        let text = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
        let kinds = data
            .get("incidents")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|k| Kind {
                id: text(k, "id"),
                name: text(k, "name"),
                severity: text(k, "severity"),
                verb: text(k, "verb"),
                rules: strings(k.get("rules")),
                why: strings(k.get("why")),
                actions: strings(k.get("actions")),
            })
            .collect();
        Catalogue {
            kinds,
            limits: strings(data.get("limits")),
        }
    })
}

/// The named incidents and the rules behind each, with whether each rule can
/// fire on this host, taken from the behaviour catalogue's own coverage.
pub(crate) fn kinds_json(catalogue: &Value) -> Value {
    let live = |rule: &str| {
        catalogue
            .get("coverage")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find(|c| c.get("rule").and_then(Value::as_str) == Some(rule))
            .and_then(|c| c.get("live").and_then(Value::as_bool))
            .unwrap_or(false)
    };
    json!(kinds()
        .iter()
        .map(|k| json!({
            "id": k.id,
            "name": k.name,
            "severity": k.severity,
            "rules": k.rules.iter().map(|r| json!({"rule": r, "live": live(r)})).collect::<Vec<_>>(),
        }))
        .collect::<Vec<_>>())
}

fn kinds() -> &'static [Kind] {
    &catalogue().kinds
}

fn kind_of(rule: &str) -> Option<&'static Kind> {
    catalogue()
        .kinds
        .iter()
        .find(|k| k.rules.iter().any(|r| r == rule))
}

fn text<'a>(row: &'a Value, field: &str) -> &'a str {
    row.get(field).and_then(Value::as_str).unwrap_or("")
}

fn number(row: &Value, field: &str) -> Option<u64> {
    row.get(field).and_then(Value::as_u64)
}

/// One incident per kind per agent run, from the retained findings.
///
/// `family_of` names the agent family for a run, when the run is a recognised
/// agent still known to this sweep.
pub(crate) fn derive(
    findings: &[Value],
    family_of: &dyn Fn(u32, u64) -> Option<String>,
) -> Vec<Value> {
    let mut groups: BTreeMap<(String, u32, u64), Vec<&Value>> = BTreeMap::new();
    for row in findings {
        let (Some(pid), Some(started)) = (
            number(row, "agent_pid").and_then(|p| u32::try_from(p).ok()),
            number(row, "agent_started_at"),
        ) else {
            continue;
        };
        let Some(kind) = kind_of(text(row, "rule")) else {
            continue;
        };
        groups
            .entry((kind.id.clone(), pid, started))
            .or_default()
            .push(row);
    }
    let mut out: Vec<Value> = groups
        .into_iter()
        .filter_map(|((id, pid, started), mut rows)| {
            let kind = catalogue().kinds.iter().find(|k| k.id == id)?;
            rows.sort_by_key(|r| number(r, "at").unwrap_or(0));
            Some(card(
                kind,
                pid,
                started,
                &rows,
                family_of(pid, started).as_deref(),
            ))
        })
        .collect();
    out.sort_by_key(|r| std::cmp::Reverse(number(r, "first_seen").unwrap_or(0)));
    out
}

fn card(kind: &Kind, pid: u32, started: u64, rows: &[&Value], family: Option<&str>) -> Value {
    let first = rows.first().copied().unwrap_or(&Value::Null);
    let agent = rows
        .iter()
        .map(|r| text(r, "agent_name"))
        .find(|n| !n.is_empty())
        .unwrap_or("an agent")
        .to_owned();
    let first_at = rows
        .iter()
        .filter_map(|r| number(r, "at"))
        .min()
        .unwrap_or(0);
    let last_at = rows
        .iter()
        .filter_map(|r| number(r, "last_at").or_else(|| number(r, "at")))
        .max()
        .unwrap_or(first_at);
    let times: u64 = rows.iter().map(|r| number(r, "count").unwrap_or(1)).sum();
    let mut rules: Vec<&str> = rows.iter().map(|r| text(r, "rule")).collect();
    rules.dedup();
    let target = text(first, "target");
    let what = if target.is_empty() {
        String::new()
    } else {
        format!(": {target}")
    };
    let more = if times > 1 {
        format!(" ({times} times, {} rules)", {
            let mut distinct = rules.clone();
            distinct.sort_unstable();
            distinct.dedup();
            distinct.len()
        })
    } else {
        String::new()
    };
    let headline = format!("{agent} {}{what}{more}", kind.verb);
    let evidence: Vec<Value> = rows
        .iter()
        .take(MAX_EVIDENCE)
        .map(|r| {
            json!({
                "rule": text(r, "rule"),
                "summary": text(r, "summary"),
                "target": text(r, "target"),
                "actor_pid": number(r, "actor_pid"),
                "actor_name": text(r, "actor_name"),
                "at": number(r, "at"),
                "count": number(r, "count").unwrap_or(1),
                "source": text(r, "source"),
                "container": text(r, "container"),
            })
        })
        .collect();
    json!({
        "id": format!("{}:{pid}:{started}", kind.id),
        "rule": kind.id,
        "kind": kind.id,
        "name": kind.name,
        "severity": kind.severity,
        "headline": headline,
        "why": kind.why,
        "actions": kind.actions.iter().map(|a| json!({"label": a})).collect::<Vec<_>>(),
        "agent": {
            "pid": pid,
            "started_at": started,
            "name": agent,
            "recognised": family.is_some(),
            "family": family,
        },
        "numbers": {
            "findings": times,
            "rules": rules.len(),
            "duration_ms": last_at.saturating_sub(first_at),
            "duration": crate::incidents::duration(last_at.saturating_sub(first_at)),
        },
        "evidence": {"findings": evidence},
        "first_at": first_at,
        "last_at": last_at,
        "first_seen": first_at,
        "last_seen": last_at,
        "limits": catalogue().limits,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn finding(rule: &str, agent: Option<(u32, u64)>, at: u64, target: &str) -> Value {
        let mut row = json!({
            "rule": rule, "at": at, "actor_pid": 9, "actor_name": "bash",
            "target": target, "summary": "s", "source": "ebpf",
        });
        if let Some((pid, started)) = agent
            && let Some(object) = row.as_object_mut()
        {
            object.insert("agent_pid".into(), json!(pid));
            object.insert("agent_started_at".into(), json!(started));
            object.insert("agent_name".into(), json!("opencode"));
        }
        row
    }

    #[test]
    fn the_shipped_catalogue_parses_and_every_rule_exists_once() {
        let kinds = kinds();
        assert!(kinds.len() >= 7, "{kinds:?}");
        let names: Vec<String> = crate::behaviour::rules()
            .iter()
            .map(|r| r.name.clone())
            .collect();
        let mut seen = std::collections::BTreeSet::new();
        for kind in kinds {
            assert!(!kind.name.is_empty() && !kind.verb.is_empty() && !kind.why.is_empty());
            assert!(matches!(kind.severity.as_str(), "critical" | "high"));
            for rule in &kind.rules {
                assert!(
                    names.contains(rule),
                    "{} names unknown rule {rule:?}",
                    kind.id
                );
                assert!(seen.insert(rule.clone()), "{rule:?} feeds two incidents");
            }
        }
    }

    #[test]
    fn findings_on_one_run_become_one_card_per_kind() {
        let run = Some((100, 5));
        let out = derive(
            &[
                finding("Schedule Cron Jobs", run, 10, "/var/spool/cron/u"),
                finding(
                    "Modify Shell Configuration File",
                    run,
                    20,
                    "/home/u/.bashrc",
                ),
                finding("Set Setuid or Setgid bit", run, 30, "/tmp/x"),
                // Another run, and a host finding no agent owns.
                finding("Schedule Cron Jobs", Some((200, 6)), 40, "/etc/crontab"),
                finding("Schedule Cron Jobs", None, 50, "/etc/crontab"),
                // A rule that feeds no named incident.
                finding("Run shell untrusted", run, 60, "bash"),
            ],
            &|pid, _| (pid == 100).then(|| "opencode".to_owned()),
        );
        assert_eq!(out.len(), 3, "{out:#?}");
        let persistence = out
            .iter()
            .find(|c| c["kind"] == "persistence" && c["agent"]["pid"] == 100)
            .unwrap();
        assert_eq!(
            persistence["evidence"]["findings"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(persistence["agent"]["recognised"], true);
        assert!(
            persistence["headline"]
                .as_str()
                .unwrap()
                .starts_with("opencode established persistence"),
            "{persistence}"
        );
        assert!(out.iter().any(|c| c["kind"] == "privilege_escalation"));
        let other = out.iter().find(|c| c["agent"]["pid"] == 200).unwrap();
        assert_eq!(other["agent"]["recognised"], false);
    }
}
