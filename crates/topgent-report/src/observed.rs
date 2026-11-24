//! Bounded Audit actions joined to event-time process identities.
use serde_json::{Value, json};
use topgent_collect::observed::{ActionKind, ObservedAction};
use topgent_core::lineage::{Lineage, ProcessKey};
use topgent_facts::{Access, UnixMillis};

pub(crate) const MAX_ACTIONS: usize = 2048;

/// Joins retained raw records again so a late lifecycle event can resolve them.
pub(crate) fn project(
    history: Value,
    actions: &[ObservedAction],
    lineage: &mut Lineage,
    agents: &[ProcessKey],
    boot: &str,
) -> Value {
    let history = if history.get("boot").and_then(Value::as_str) == Some(boot) {
        history
    } else {
        json!({})
    };
    let mut floor = history
        .get("floor")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let mut evicted = history.get("evicted").and_then(Value::as_u64).unwrap_or(0);
    let mut rows = std::collections::BTreeMap::new();
    for row in history
        .get("rows")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_ACTIONS)
    {
        if let Some(id) = order(row) {
            rows.insert(id, row.clone());
        }
    }
    for action in actions {
        let row = raw(action);
        if let Some(id) = order(&row)
            && id > floor
        {
            rows.entry(id).or_insert(row);
        }
    }
    while rows.len() > MAX_ACTIONS {
        if let Some((id, _)) = rows.pop_first() {
            floor = id;
            evicted = evicted.saturating_add(1);
        }
    }
    recover_names(rows.values(), lineage);
    for row in rows.values_mut() {
        resolve(row, lineage, agents);
    }
    let mut bytes: usize = rows.values().map(|r| r.to_string().len()).sum();
    while bytes > 6 * 1024 * 1024 {
        if let Some((id, row)) = rows.pop_first() {
            bytes = bytes.saturating_sub(row.to_string().len());
            floor = id;
            evicted = evicted.saturating_add(1);
        } else {
            break;
        }
    }
    json!({"boot":boot, "floor":floor, "evicted":evicted, "rows":rows.into_values().rev().collect::<Vec<_>>()})
}

/// What the action timeline can and cannot establish, and what it lost.
pub(crate) fn coverage_json(history: &Value, queue_losses: u64) -> Value {
    json!({
        "queue_losses": queue_losses,
        "retained_limit": MAX_ACTIONS,
        "evicted": history.get("evicted"),
        "detail": "Linux Audit metadata only. Read/write mean successful opens or related \
                   syscalls, not bytes transferred. Only configured Audit rules are visible; \
                   log-tail gaps and kernel losses are not fully measured. Unresolved actions \
                   stay unattributed.",
    })
}

fn raw(action: &ObservedAction) -> Value {
    let (kind, target, result) = match &action.kind {
        ActionKind::File { path, access } => (
            match access {
                Access::Read => "read",
                Access::Write => "write",
                Access::ReadWrite => "read_write",
                Access::Execute => "execute",
            },
            path.clone(),
            "succeeded",
        ),
        ActionKind::Connect {
            host,
            port,
            datagram,
            result,
        } => (
            if *datagram { "send" } else { "connect" },
            format!("{host}:{port}"),
            result.as_str(),
        ),
        ActionKind::Exec { program } => ("exec", program.clone(), "succeeded"),
    };
    json!({"record":action.record, "actor_pid":action.pid, "at":action.at.0,
        "program":action.program.as_deref().map(|p|p.rsplit('/').next().unwrap_or(p)),
        "lineage_at":action.lineage_at.0, "action":kind, "target":target, "result":result})
}

fn number(row: &Value, field: &str) -> Option<u64> {
    row.get(field)?.as_u64()
}
fn text<'a>(row: &'a Value, field: &str) -> Option<&'a str> {
    row.get(field)?.as_str()
}
fn pid(row: &Value, field: &str) -> Option<u32> {
    u32::try_from(number(row, field)?).ok().filter(|p| *p > 0)
}

/// A stable event identity, ordered by event time; one syscall may name several paths.
fn order(row: &Value) -> Option<String> {
    let record = text(row, "record")?;
    let serial = topgent_collect::observed::serial(record)?;
    let action = text(row, "action")?;
    if !matches!(
        action,
        "read" | "write" | "read_write" | "execute" | "exec" | "connect" | "send"
    ) {
        return None;
    }
    let target = text(row, "target")?;
    if target.len() > 4096 || target.chars().any(char::is_control) || record.len() > 80 {
        return None;
    }
    number(row, "lineage_at")?;
    Some(format!(
        "{:020}:{serial:020}:{:010}:{action}:{target}",
        number(row, "at")?,
        pid(row, "actor_pid")?
    ))
}

fn recover_names<'a>(rows: impl Iterator<Item = &'a Value>, lineage: &mut Lineage) {
    let mut execs: std::collections::BTreeMap<ProcessKey, Vec<String>> =
        std::collections::BTreeMap::new();
    for row in rows.filter(|r| text(r, "action") == Some("exec")) {
        if let (Some(pid), Some(at), Some(path)) = (
            pid(row, "actor_pid"),
            number(row, "lineage_at"),
            text(row, "target"),
        ) && let Some(key) = topgent_core::attributed::actor_at(lineage, pid, UnixMillis(at))
        {
            execs
                .entry(key)
                .or_default()
                .push(path.rsplit('/').next().unwrap_or(path).to_owned());
        }
    }
    for (key, names) in execs {
        if names.len() == 1
            && let Some(name) = names.first()
        {
            lineage.recover_exec_name(key, name);
        }
    }
}

fn resolve(row: &mut Value, lineage: &mut Lineage, agents: &[ProcessKey]) {
    let (Some(pid), Some(at)) = (pid(row, "actor_pid"), number(row, "lineage_at")) else {
        return;
    };
    let Some(found) = topgent_core::attributed::attribute(lineage, agents, pid, UnixMillis(at))
    else {
        return;
    };
    let Some(record) = lineage.get(found.actor) else {
        return;
    };
    // Never label an earlier action with the process's latest executable.
    // Audit exec records below give event-time names where available.
    let name = text(row, "program").unwrap_or("unknown").to_owned();
    let Some(row) = row.as_object_mut() else {
        return;
    };
    row.insert("actor_name".into(), json!(name));
    row.insert("actor_started_at".into(), json!(found.actor.started_at.0));
    row.insert("actor_state".into(), json!(record.state().as_str()));
    row.insert("agent_pid".into(), json!(found.agent.pid));
    row.insert("agent_started_at".into(), json!(found.agent.started_at.0));
    row.insert("chain".into(), json!(found.chain));
}

/// Adds only successful file opens to scoring. A connection attempt
/// remains in the action timeline; it is never turned into an open socket.
///
/// Each fact is the agent's, because the agent answers for what its
/// descendants do, and its probe names the process that actually acted.
pub(crate) fn file_facts(state: &Value, agents: &[ProcessKey]) -> Vec<topgent_facts::Fact> {
    state["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| file_fact(row, agents))
        .collect()
}

fn file_fact(row: &Value, agents: &[ProcessKey]) -> Option<topgent_facts::Fact> {
    use topgent_facts::{Claim, Confidence, Fact, Provenance, Subject};
    let agent = ProcessKey {
        pid: pid(row, "agent_pid")?,
        started_at: UnixMillis(number(row, "agent_started_at")?),
    };
    if !agents.contains(&agent) || text(row, "result")? != "succeeded" {
        return None;
    }
    let access = match text(row, "action")? {
        "read" => Access::Read,
        "write" => Access::Write,
        "read_write" => Access::ReadWrite,
        // An exec's program and loader: process creation, which the process
        // history holds. Not a file the agent chose to touch.
        _ => return None,
    };
    let probe = format!(
        "Linux Audit record {}; direct actor {} ({}); attributed through recorded ancestry",
        text(row, "record")?,
        pid(row, "actor_pid")?,
        text(row, "actor_name").unwrap_or("unknown")
    );
    Fact::new(
        topgent_facts::SCHEMA_VERSION,
        Subject::Process {
            pid: agent.pid,
            started_at: agent.started_at,
        },
        Claim::FileTouched {
            path: text(row, "target")?.to_owned(),
            access,
        },
        Provenance {
            collector: "filesystem_events".to_owned(),
            probe,
            confidence: Confidence::Certain,
            observed_at: UnixMillis(number(row, "at")?),
        },
    )
    .ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use topgent_core::lineage::Observation;
    fn key(pid: u32, at: u64) -> ProcessKey {
        ProcessKey {
            pid,
            started_at: UnixMillis(at),
        }
    }
    fn lineage() -> Lineage {
        let mut l = Lineage::new(64);
        for (pid, start, parent, name) in [
            (10, 100, None, "codex"),
            (11, 200, Some(10), "cat"),
            (99, 200, None, "control"),
        ] {
            l.observe(Observation {
                key: key(pid, start),
                parent_pid: parent,
                name: name.into(),
                exe: None,
                pid_namespace: None,
                at: UnixMillis(start),
                from_event: true,
            });
        }
        l.exited(key(11, 200), UnixMillis(300));
        l
    }
    fn read(pid: u32, record: &str, at: u64) -> ObservedAction {
        ObservedAction::new(
            record,
            pid,
            at,
            0,
            ActionKind::File {
                path: "/tmp/vault/credentials".into(),
                access: Access::Read,
            },
        )
    }
    #[test]
    fn exited_actor_survives_restart_without_double_counting() {
        let mut l = lineage();
        let a = read(11, "0.250:1", 250);
        let one = project(
            json!({}),
            std::slice::from_ref(&a),
            &mut l,
            &[key(10, 100)],
            "boot",
        );
        let two = project(one, &[a], &mut l, &[key(10, 100)], "boot");
        assert_eq!(two["rows"].as_array().unwrap().len(), 1);
        assert_eq!(two["rows"][0]["agent_pid"], 10);
        assert_eq!(two["rows"][0]["actor_pid"], 11);
        assert_eq!(two["rows"][0]["actor_state"], "exited");
        assert_eq!(two["rows"][0]["chain"], json!([11]));
    }
    #[test]
    fn unrelated_and_reused_pids_never_become_agent_actions() {
        let state = project(
            json!({}),
            &[read(99, "0.250:1", 250), read(11, "0.400:2", 400)],
            &mut lineage(),
            &[key(10, 100)],
            "boot",
        );
        assert_eq!(state["rows"].as_array().unwrap().len(), 2);
        assert!(
            state["rows"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["agent_pid"].is_null())
        );
    }
    #[test]
    fn unresolved_action_can_resolve_when_lineage_arrives_next_sweep() {
        let one = project(
            json!({}),
            &[read(11, "0.250:1", 250)],
            &mut Lineage::new(64),
            &[key(10, 100)],
            "boot",
        );
        let two = project(one, &[], &mut lineage(), &[key(10, 100)], "boot");
        assert_eq!(two["rows"][0]["agent_pid"], 10);
    }
    #[test]
    fn a_single_unread_exec_recovers_from_audit_without_changing_its_exit() {
        let mut l = lineage();
        l.exec_unread(key(11, 200), UnixMillis(220));
        let exec = ObservedAction::new(
            "0.219:8",
            11,
            219,
            0,
            ActionKind::Exec {
                program: "/usr/bin/cat".into(),
            },
        );
        project(
            json!({}),
            std::slice::from_ref(&exec),
            &mut l,
            &[key(10, 100)],
            "boot",
        );
        let r = l.get(key(11, 200)).unwrap();
        assert_eq!(r.exe.as_deref(), Some("cat"));
        assert!(!r.program_unread);
        assert_eq!(r.exited_at, Some(UnixMillis(300)));
        l.exec_unread(key(11, 200), UnixMillis(240));
        project(json!({}), &[exec], &mut l, &[key(10, 100)], "boot");
        assert!(
            l.get(key(11, 200)).unwrap().program_unread,
            "an older Audit exec must not name a later exec"
        );
    }
    #[test]
    fn only_successful_attributed_file_actions_feed_risk_with_direct_actor_evidence() {
        use topgent_facts::{Claim, Confidence, Fact, Provenance, Subject};
        let agents = [key(10, 100)];
        let mut file = read(11, "0.250:1", 250);
        file.program = Some("/usr/bin/cat".into());
        let failed = ObservedAction::new(
            "0.250:2",
            11,
            250,
            0,
            ActionKind::Connect {
                host: "127.0.0.1".into(),
                port: 9,
                datagram: false,
                result: topgent_collect::observed::ConnectResult::Failed,
            },
        );
        let state = project(
            json!({}),
            &[file, failed, read(99, "0.250:3", 250)],
            &mut lineage(),
            &agents,
            "boot",
        );
        let mut facts = file_facts(&state, &agents);
        assert_eq!(facts.len(), 1);
        assert!(
            facts[0]
                .provenance()
                .probe
                .contains("direct actor 11 (cat)")
        );
        for claim in [
            Claim::ProcessSeen {
                exe: "codex".into(),
                exe_path_known: true,
                uid: 1000,
                user: "test".into(),
            },
            Claim::AgentFamily {
                family: "codex".into(),
            },
            Claim::ResourceReachable {
                path: "/tmp/vault/credentials".into(),
                access: Access::Read,
                sensitive: true,
                evidence: topgent_facts::Reachability::AccountReadable,
            },
        ] {
            facts.push(
                Fact::new(
                    topgent_facts::SCHEMA_VERSION,
                    Subject::Process {
                        pid: 10,
                        started_at: UnixMillis(100),
                    },
                    claim,
                    Provenance {
                        collector: "process".into(),
                        probe: "fixture".into(),
                        confidence: Confidence::Certain,
                        observed_at: UnixMillis(250),
                    },
                )
                .unwrap(),
            );
        }
        let scored = topgent_core::analyse_at(&facts, &topgent_policy::Policy::default(), None);
        assert!(
            scored[0]
                .1
                .factors
                .iter()
                .any(|f| f.code.as_str() == "CREDENTIAL_ACCESS")
        );
        assert!(
            scored[0].0.endpoints.is_empty(),
            "failed connect is not an open socket"
        );
    }

    /// Running a program is process creation, which the process history
    /// already holds. Fed in as files the agent touched, a child's /bin/cat
    /// and the dynamic loader became paths its sandbox "denied".
    #[test]
    fn an_execs_program_and_loader_are_not_file_facts() {
        let agents = [key(10, 100)];
        let execute = ObservedAction::new(
            "0.250:4",
            11,
            250,
            0,
            ActionKind::File {
                path: "/bin/cat".into(),
                access: Access::Execute,
            },
        );
        let state = project(json!({}), &[execute], &mut lineage(), &agents, "boot");
        assert_eq!(
            state["rows"].as_array().map(Vec::len),
            Some(1),
            "kept in the timeline"
        );
        assert!(file_facts(&state, &agents).is_empty());
    }

    #[test]
    fn another_boot_does_not_reuse_saved_attribution() {
        let one = project(
            json!({}),
            &[read(11, "0.250:1", 250)],
            &mut lineage(),
            &[key(10, 100)],
            "old",
        );
        assert!(
            project(one, &[], &mut lineage(), &[], "new")["rows"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn bound_is_visible_and_evicted_records_cannot_reappear_on_replay() {
        let actions = (0..MAX_ACTIONS + 4)
            .map(|n| read(99, &format!("0.250:{n}"), 250))
            .collect::<Vec<_>>();
        let one = project(json!({}), &actions, &mut lineage(), &[], "boot");
        assert_eq!(one["rows"].as_array().unwrap().len(), MAX_ACTIONS);
        assert_eq!(one["evicted"], 4);
        let two = project(one, &actions, &mut lineage(), &[], "boot");
        assert_eq!(two["rows"].as_array().unwrap().len(), MAX_ACTIONS);
        assert_eq!(two["evicted"], 4);
    }
}
