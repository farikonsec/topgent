//! Feeding each sweep's process table into history, and reading it back out
//! per agent.
//!
//! Only processes that belong to an agent's tree are recorded, plus any
//! process already in history: that is what keeps a worker attributed after
//! its parent exits and init adopts it. Program names are kept without their
//! paths, as child processes always were.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};
use topgent_collect::process::ProcInfo;
use topgent_collect::process_events::{LifecycleEvent, LifecycleKind};
use topgent_core::Agent;
use topgent_core::lineage::{Lineage, Observation, ProcessKey};
use topgent_facts::UnixMillis;

/// Most history rows reported per agent.
const MAX_ROWS_PER_AGENT: usize = 200;
/// Deepest parent chain followed in one snapshot.
const MAX_DEPTH: usize = 64;

fn key_of(process: &ProcInfo) -> ProcessKey {
    ProcessKey {
        pid: process.pid,
        started_at: process.started_at,
    }
}

fn agent_key(agent: &Agent) -> ProcessKey {
    ProcessKey {
        pid: agent.id.pid,
        started_at: agent.id.started_at,
    }
}

fn basename(path: &str) -> String {
    path.rsplit(['/', '\\']).next().unwrap_or(path).to_owned()
}

/// Records one sweep: its view of every agent's process tree, then what the
/// kernel reported since the last sweep.
///
/// The snapshot goes first and is the only thing that marks a process gone,
/// so a process the kernel reports starting after the walk is never ended by
/// a walk that predates it. A sweep with no process table, as a replay or a
/// fixture has, records nothing from it: reading it as "every process has
/// gone" would end every history.
pub(crate) fn record(
    lineage: &mut Lineage,
    processes: &[ProcInfo],
    events: &[LifecycleEvent],
    agents: &[Agent],
    at: u64,
) {
    record_snapshot(lineage, processes, agents, at);
    record_events(lineage, events);
}

/// Applies the kernel's lifecycle events, in the order they happened.
///
/// A new process is recorded only when its parent is already recorded and
/// held that pid when the child started: every process in history descends
/// from an agent, and the host's other thousands of processes are not kept.
fn record_events(lineage: &mut Lineage, events: &[LifecycleEvent]) {
    let mut ordered: Vec<&LifecycleEvent> = events.iter().collect();
    ordered.sort_by_key(|event| event.at);
    for event in ordered {
        let key = match (event.kind, event.started_at) {
            (_, Some(started_at)) => ProcessKey {
                pid: event.pid,
                started_at,
            },
            // A new process with no readable start is keyed by its fork. It
            // ended before any sweep could see it, so no sweep key must match.
            (LifecycleKind::Fork { .. }, None) => ProcessKey {
                pid: event.pid,
                started_at: event.at,
            },
            // Anything else about a process whose start was unreadable is
            // matched to the recorded process that held that pid at the time.
            (_, None) => match lineage.resolve(event.pid, event.at) {
                Some(key) => key,
                None => continue,
            },
        };
        // A rename, exec or exit whose start disagrees with the recorded one
        // (events from two CPUs arriving out of order can give one process two
        // start readings) belongs to whichever recorded process held the pid.
        let key = match event.kind {
            LifecycleKind::Fork { .. } => key,
            _ if lineage.get(key).is_some() => key,
            _ => match lineage.resolve(event.pid, event.at) {
                Some(key) => key,
                None => continue,
            },
        };
        match event.kind {
            LifecycleKind::Fork { parent } => {
                let parent_key = lineage.resolve(parent, key.started_at);
                if lineage.get(key).is_none() && parent_key.is_none() {
                    continue;
                }
                // A fork copies its parent, name included; a line read too
                // late to carry a name starts from the parent's.
                let name = event.name.clone().unwrap_or_else(|| {
                    parent_key
                        .and_then(|parent| lineage.get(parent))
                        .map(|parent| parent.name.clone())
                        .unwrap_or_default()
                });
                lineage.observe(Observation {
                    key,
                    parent_pid: Some(parent),
                    name,
                    exe: None,
                    pid_namespace: event.pid_namespace,
                    at: event.at,
                    from_event: true,
                });
            }
            LifecycleKind::Exec => {
                let Some(record) = lineage.get(key) else {
                    continue;
                };
                let name = event.name.clone().unwrap_or_else(|| record.name.clone());
                if event.program.is_none() && event.path.is_none() {
                    // Gone before `/proc` could be read: the exec happened,
                    // the program is unknown.
                    lineage.exec_unread(key, event.at);
                }
                lineage.observe(Observation {
                    key,
                    parent_pid: None,
                    name,
                    // The full path when the kernel gave one, else the name.
                    exe: event.path.clone().or_else(|| event.program.clone()),
                    pid_namespace: event.pid_namespace,
                    at: event.at,
                    from_event: true,
                });
            }
            LifecycleKind::Rename => {
                let (Some(record), Some(name)) = (lineage.get(key), event.name.clone()) else {
                    continue;
                };
                let parent_pid = record.parent.map(|parent| parent.pid);
                lineage.observe(Observation {
                    key,
                    parent_pid,
                    name,
                    exe: None,
                    pid_namespace: None,
                    at: event.at,
                    from_event: true,
                });
            }
            LifecycleKind::Exit { code } => {
                if lineage.get(key).is_some() {
                    lineage.exited_with(key, event.at, code);
                }
            }
        }
    }
}

fn record_snapshot(lineage: &mut Lineage, processes: &[ProcInfo], agents: &[Agent], at: u64) {
    if processes.is_empty() {
        return;
    }
    let roots: BTreeSet<ProcessKey> = agents
        .iter()
        .filter(|agent| agent.family.is_some() || !agent.extensions.is_empty())
        .map(agent_key)
        .collect();
    let by_pid: BTreeMap<u32, &ProcInfo> = processes.iter().map(|p| (p.pid, p)).collect();
    let in_tree = |process: &ProcInfo| {
        let mut current = Some(process);
        for _ in 0..MAX_DEPTH {
            let Some(here) = current else { return false };
            if roots.contains(&key_of(here)) {
                return true;
            }
            current = here.parent.and_then(|parent| by_pid.get(&parent).copied());
        }
        false
    };
    for process in processes {
        let key = key_of(process);
        if lineage.get(key).is_none() && !in_tree(process) {
            continue;
        }
        lineage.observe(Observation {
            key,
            parent_pid: process.parent,
            name: process.name.clone(),
            exe: process.exe_path_known.then(|| basename(&process.exe)),
            pid_namespace: process.pid_namespace,
            at: UnixMillis(at),
            from_event: false,
        });
    }
    let live: BTreeSet<ProcessKey> = processes.iter().map(key_of).collect();
    lineage.missing(&live, UnixMillis(at));
}

/// Every agent's recorded descendants, running or not: the agents running
/// now, and `ended`, the agents this session saw that have since exited, so
/// an agent that is gone still shows what it started.
pub(crate) fn history_json(lineage: &Lineage, agents: &[Agent], ended: &[ProcessKey]) -> Value {
    let mut rows = Vec::new();
    let running = agents
        .iter()
        .filter(|agent| agent.family.is_some() || !agent.extensions.is_empty())
        .map(agent_key);
    let mut roots: Vec<ProcessKey> = running.collect();
    roots.extend(
        ended
            .iter()
            .filter(|key| !roots.contains(key))
            .copied()
            .collect::<Vec<_>>(),
    );
    for root in roots {
        let mut descendants = lineage.descendants(root);
        descendants.sort_by_key(|record| (record.first_seen, record.key));
        for record in descendants.into_iter().take(MAX_ROWS_PER_AGENT) {
            let ancestry = lineage.ancestry(record.key);
            let depth = ancestry
                .iter()
                .position(|key| *key == root)
                .map_or(0, |at| at + 1);
            rows.push(json!({
                "agent_pid": root.pid,
                "agent_started_at": root.started_at.0,
                "pid": record.key.pid,
                "started_at": record.key.started_at.0,
                "name": record.name,
                // The program, as the kernel or a sweep read it; never its
                // arguments. The journal stores no absolute path (text.rs,
                // `sanitize`), so one that came back redacted is left out
                // rather than shown as a placeholder.
                "exe": record.exe.as_deref().filter(|exe| *exe != "[REDACTED]"),
                "parent_pid": record.parent.map(|parent| parent.pid),
                "depth": depth,
                "state": record.state().as_str(),
                "first_seen": record.first_seen.0,
                "last_seen": record.last_seen.0,
                "gone_after": record.gone_after.map(|at| at.0),
                "exited_at": record.exited_at.map(|at| at.0),
                "exit_code": record.exit_code,
                "observed_by": if record.from_event { "kernel_event" } else { "sweep" },
                "reparented": record.reparented,
                "crossed_namespace": record.crossed_namespace,
                "exec_generation": record.exec_generation,
                "program_unread": record.program_unread,
                "previous_programs": record.previous_exes,
                "program": record.exe,
                "chain": ancestry
                    .iter()
                    .take_while(|key| **key != root)
                    .map(|key| key.pid)
                    .collect::<Vec<_>>(),
            }));
        }
    }
    Value::Array(rows)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::expect_used)]

    use super::{history_json, record};
    use topgent_collect::process::{Owner, ProcInfo};
    use topgent_collect::process_events::{LifecycleEvent, LifecycleKind};
    use topgent_core::lineage::Lineage;
    use topgent_core::{Agent, AgentId, IdentityKind};
    use topgent_facts::UnixMillis;

    fn process(pid: u32, started_at: u64, parent: Option<u32>, name: &str) -> ProcInfo {
        ProcInfo {
            pid,
            started_at: UnixMillis(started_at),
            exe: format!("/usr/bin/{name}"),
            exe_path_known: true,
            name: name.to_owned(),
            uid: 1_000,
            user: "u".to_owned(),
            parent,
            pid_namespace: None,
            family: None,
            owner: Owner::Unknown,
        }
    }

    fn agent(pid: u32, started_at: u64) -> Agent {
        Agent {
            id: AgentId {
                pid,
                started_at: UnixMillis(started_at),
            },
            family: Some("codex-cli".to_owned()),
            extensions: Vec::new(),
            exe: None,
            exe_path_known: true,
            uid: None,
            user: None,
            identity: IdentityKind::Unknown,
            model: None,
            model_source: None,
            models_seen: Vec::new(),
            parent_pid: None,
            children: Vec::new(),
            connectors: Vec::new(),
            endpoints: Vec::new(),
            resources: Vec::new(),
            invokes: Vec::new(),
            actions: Vec::new(),
            unevaluated: Vec::new(),
            discovery_confidence: topgent_facts::Confidence::Certain,
            evidence_confidence: std::collections::BTreeMap::new(),
            fact_count: 1,
        }
    }

    /// The live S4 scenario, as two sweeps: a shell the agent started holds a
    /// worker, then exits, and init adopts the worker.
    #[test]
    fn a_worker_left_behind_stays_in_its_agents_history() {
        let agents = [agent(100, 1_000)];
        let mut lineage = Lineage::new(64);
        record(
            &mut lineage,
            &[
                process(1, 0, None, "init"),
                process(100, 1_000, Some(1), "codex"),
                process(200, 2_000, Some(100), "sh"),
                process(201, 2_100, Some(200), "sleep"),
                process(300, 3_000, Some(1), "unrelated"),
            ],
            &[],
            &agents,
            5_000,
        );
        record(
            &mut lineage,
            &[
                process(1, 0, None, "init"),
                process(100, 1_000, Some(1), "codex"),
                process(201, 2_100, Some(1), "sleep"),
                process(300, 3_000, Some(1), "unrelated"),
            ],
            &[],
            &agents,
            9_000,
        );
        let rows = history_json(&lineage, &agents, &[]);
        let rows = rows.as_array().expect("rows");
        assert_eq!(rows.len(), 2, "{rows:#?}");
        assert_eq!(rows[0]["name"], "sh");
        assert_eq!(rows[0]["state"], "gone");
        assert_eq!(rows[0]["gone_after"], 9_000);
        assert_eq!(rows[1]["name"], "sleep");
        assert_eq!(rows[1]["state"], "running");
        assert_eq!(rows[1]["reparented"], true);
        assert_eq!(rows[1]["chain"], serde_json::json!([200]));
        assert_eq!(rows[1]["depth"], 2);
        assert!(
            lineage.records().all(|record| record.key.pid != 300),
            "a process outside every agent's tree is not recorded"
        );
    }

    fn event(
        kind: LifecycleKind,
        pid: u32,
        start: Option<u64>,
        name: &str,
        at: u64,
    ) -> LifecycleEvent {
        LifecycleEvent {
            kind,
            pid,
            started_at: start.map(UnixMillis),
            name: Some(name.to_owned()),
            program: Some(name.to_owned()),
            path: None,
            pid_namespace: None,
            uid: None,
            container: None,
            argv: None,
            loginuid: None,
            tty: None,
            cwd: None,
            at: UnixMillis(at),
        }
    }

    /// The S5 fixture as records: a child that lives six milliseconds between
    /// two sweeps. No sweep ever sees it; the kernel's three events do.
    #[test]
    fn a_child_shorter_than_a_sweep_is_recorded_from_kernel_events() {
        let agents = [agent(100, 1_000)];
        let mut lineage = Lineage::new(64);
        let table = [
            process(1, 0, None, "init"),
            process(100, 1_000, Some(1), "codex"),
        ];
        record(&mut lineage, &table, &[], &agents, 5_000);
        record(
            &mut lineage,
            &table,
            &[
                event(
                    LifecycleKind::Fork { parent: 100 },
                    300,
                    Some(6_000),
                    "codex",
                    6_000,
                ),
                // The exec arrives nameless (the process was gone before
                // `/proc` was read); the kernel's rename names it.
                event(LifecycleKind::Rename, 300, Some(6_000), "cat", 6_001),
                LifecycleEvent {
                    name: None,
                    program: None,
                    path: None,
                    pid_namespace: None,
                    ..event(LifecycleKind::Exec, 300, Some(6_000), "cat", 6_001)
                },
                // The race the live burst found: a child gone before its start
                // could be read. Fork keyed by its own time; the rename and
                // exit carry no start and must still land on that record.
                event(LifecycleKind::Fork { parent: 100 }, 600, None, "sh", 6_300),
                event(LifecycleKind::Rename, 600, None, "cat", 6_301),
                event(
                    LifecycleKind::Exit { code: Some(0) },
                    600,
                    None,
                    "cat",
                    6_304,
                ),
                // Out of order across CPUs: the fork keyed by its own time,
                // the rename carrying a different start reading.
                event(LifecycleKind::Fork { parent: 100 }, 700, None, "sh", 6_400),
                event(LifecycleKind::Rename, 700, Some(6_398), "cat", 6_401),
                event(
                    LifecycleKind::Exit { code: Some(0) },
                    300,
                    Some(6_000),
                    "cat",
                    6_006,
                ),
                // Somebody else's child: not recorded.
                event(
                    LifecycleKind::Fork { parent: 999 },
                    400,
                    Some(6_100),
                    "cron",
                    6_100,
                ),
                // An exit whose start was unreadable, matched by pid.
                event(
                    LifecycleKind::Fork { parent: 100 },
                    500,
                    Some(6_200),
                    "codex",
                    6_200,
                ),
                event(
                    LifecycleKind::Exit { code: Some(256) },
                    500,
                    None,
                    "sh",
                    6_250,
                ),
            ],
            &agents,
            9_000,
        );
        let rows = history_json(&lineage, &agents, &[]);
        let rows = rows.as_array().expect("rows");
        assert_eq!(rows.len(), 4, "{rows:#?}");
        let crossed = rows
            .iter()
            .find(|row| row["pid"] == 700)
            .expect("the out-of-order child");
        assert_eq!(
            crossed["name"], "cat",
            "renamed despite a second start reading"
        );
        let racing = rows
            .iter()
            .find(|row| row["pid"] == 600)
            .expect("the racing child");
        assert_eq!(racing["name"], "cat", "renamed despite an unreadable start");
        assert_eq!(racing["state"], "exited");
        let cat = &rows[0];
        assert_eq!(cat["name"], "cat");
        assert_eq!(cat["state"], "exited");
        assert_eq!(cat["exited_at"], 6_006);
        assert_eq!(cat["exit_code"], 0);
        assert_eq!(cat["observed_by"], "kernel_event");
        assert_eq!(rows[1]["exit_code"], 256);
        assert!(lineage.records().all(|record| record.key.pid != 400));
    }

    /// The live burst's miss: the grandchild forked as `sh`, exec'd `cat`
    /// and exited before `/proc` could be read. No rename either. The row
    /// must say it exec'd into an unreadable program, not stay `sh`.
    #[test]
    fn an_exec_gone_before_it_could_be_read_is_shown_as_unread() {
        let agents = [agent(100, 1_000)];
        let mut lineage = Lineage::new(64);
        let table = [process(100, 1_000, Some(1), "codex")];
        record(&mut lineage, &table, &[], &agents, 5_000);
        record(
            &mut lineage,
            &table,
            &[
                event(
                    LifecycleKind::Fork { parent: 100 },
                    800,
                    Some(6_000),
                    "sh",
                    6_000,
                ),
                LifecycleEvent {
                    name: None,
                    program: None,
                    path: None,
                    pid_namespace: None,
                    ..event(LifecycleKind::Exec, 800, Some(6_000), "", 6_001)
                },
                event(
                    LifecycleKind::Exit { code: Some(0) },
                    800,
                    Some(6_000),
                    "sh",
                    6_002,
                ),
            ],
            &agents,
            9_000,
        );
        let rows = history_json(&lineage, &agents, &[]);
        let row = rows
            .as_array()
            .expect("rows")
            .iter()
            .find(|row| row["pid"] == 800)
            .expect("the grandchild");
        assert_eq!(row["name"], "sh");
        assert_eq!(row["exec_generation"], 1);
        assert_eq!(row["program_unread"], true);
        assert!(row["program"].is_null());
    }

    /// The frozen-sensor run: the fork is read after the child is gone, and
    /// the sensor never saw the parent, so the line carries no name. A fork
    /// copies its parent, so the child starts with the parent's name.
    #[test]
    fn a_nameless_fork_takes_its_parents_name() {
        let agents = [agent(100, 1_000)];
        let mut lineage = Lineage::new(64);
        let table = [process(100, 1_000, Some(1), "codex")];
        record(&mut lineage, &table, &[], &agents, 5_000);
        record(
            &mut lineage,
            &table,
            &[LifecycleEvent {
                name: None,
                ..event(
                    LifecycleKind::Fork { parent: 100 },
                    900,
                    Some(6_000),
                    "",
                    6_000,
                )
            }],
            &agents,
            9_000,
        );
        let rows = history_json(&lineage, &agents, &[]);
        let row = rows
            .as_array()
            .expect("rows")
            .iter()
            .find(|row| row["pid"] == 900)
            .expect("the child");
        assert_eq!(row["name"], "codex");
    }

    #[test]
    fn a_sweep_without_a_process_table_ends_nothing() {
        let agents = [agent(100, 1_000)];
        let mut lineage = Lineage::new(64);
        record(
            &mut lineage,
            &[
                process(100, 1_000, None, "codex"),
                process(200, 2_000, Some(100), "sh"),
            ],
            &[],
            &agents,
            5_000,
        );
        record(&mut lineage, &[], &[], &agents, 9_000);
        assert!(lineage.records().all(|record| record.gone_after.is_none()));
    }
}
