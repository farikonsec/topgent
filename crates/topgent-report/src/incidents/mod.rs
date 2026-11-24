//! Workspace exfiltration: a program reads most of a workspace, then sends a
//! lot of data, or keeps retrying, somewhere that is not its model service.
//!
//! This is the one rule written for a person to read first. Each incident is
//! one agent run, with one sentence saying what happened in numbers, one
//! saying why it matters, what to do, and the evidence under it. The counts
//! come from the collector's running totals ([`topgent_collect::observed::tally`]),
//! which are kept before any queue or history bound, so 42,000 reads are
//! 42,000 and not the 2,048 the action history keeps.
//!
//! It is not tied to a product. A recognised agent is named; a program
//! Topgent does not recognise is reported by its own name, grouped with the
//! helper processes of the same program that it started, because the rule
//! is about what was done, not who claims to be an agent.
//!
//! What it cannot say: Topgent counts files opened and bytes written to a
//! socket. It reads neither, so an incident never claims the bytes sent were
//! those files. Every incident says so.
//!
//! # Layout
//!
//! - [`config`](mod@config): the rule's numbers and lists, from the data file.
//! - [`destinations`]: own service, names and workspace sizes.
//! - [`exfiltration`]: the workspace-exfiltration rule.
//! - [`secrets`]: credential-store and secret-read cards.
//! - [`scanning`]: many ports or hosts probed within minutes.
//! - [`destruction`]: read files deleted, renamed away or rewritten.
//! - [`card`]: the parts every card shares.
//! - [`flows`]: where each run's data went, fired or not.
//! - [`format`](mod@format): numbers in words.
//!
//! This file places processes on runs, merges their totals, and turns every
//! rule's output into the incident rows kept across sweeps.

pub(crate) mod card;
mod config;
mod destinations;
mod destruction;
mod exfiltration;
mod flows;
mod format;
mod scanning;
mod secrets;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};
use topgent_collect::observed::tally::{DestTotals, ProcessTotals, RootTotals, Totals};
use topgent_core::lineage::{Lineage, ProcessKey};
use topgent_facts::UnixMillis;

/// Most incidents kept.
pub(crate) const MAX_INCIDENTS: usize = 512;

pub(crate) use config::config;
pub(crate) use destinations::{Destinations, Live};
pub(crate) use format::duration;

use format::bytes;

use destinations::wall_ms;
use exfiltration::evaluate;
use flows::flow;
use secrets::secret_incidents;

/// Who an incident is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Run {
    /// The agent run, or for an unrecognised program its topmost process.
    pub key: ProcessKey,
    /// What to call it.
    pub name: String,
    /// The catalogue family, when recognised.
    pub family: Option<String>,
}

/// Places one process's totals on a run: the agent it descends from, or,
/// when it belongs to none, the topmost process of the same program above
/// it.
fn place(
    totals: &ProcessTotals,
    lineage: &Lineage,
    agents: &BTreeMap<ProcessKey, (String, Option<String>)>,
) -> Option<(Run, ProcessKey)> {
    let at = UnixMillis(totals.first_at);
    let keys: Vec<ProcessKey> = agents.keys().copied().collect();
    if let Some(found) = topgent_core::attributed::attribute(lineage, &keys, totals.pid, at) {
        let (name, family) = agents.get(&found.agent)?.clone();
        return Some((
            Run {
                key: found.agent,
                name,
                family,
            },
            found.actor,
        ));
    }
    let actor = topgent_core::attributed::actor_at(lineage, totals.pid, at)?;
    let program = lineage
        .get(actor)
        .map(|r| r.name.clone())
        .filter(|n| !n.is_empty());
    let mut top = actor;
    for ancestor in lineage.ancestry(actor) {
        let same = lineage
            .get(ancestor)
            .is_some_and(|r| Some(r.name.as_str()) == program.as_deref());
        if !same {
            break;
        }
        top = ancestor;
    }
    let name = program
        .or_else(|| totals.name.clone())
        .unwrap_or_else(|| "unknown program".to_owned());
    Some((
        Run {
            key: top,
            name,
            family: None,
        },
        actor,
    ))
}

/// One run's totals, merged across its processes.
#[derive(Debug, Default)]
struct Merged {
    roots: BTreeMap<String, RootTotals>,
    destinations: BTreeMap<(String, u16), DestTotals>,
    actors: BTreeSet<u32>,
    /// Recent file reads across the run's processes, by time.
    recent: Vec<(String, u64)>,
    /// Sensitive-looking files read across the run's processes, by path:
    /// when first read, its size then, and its class id.
    sensitive: BTreeMap<String, (u64, u64, String)>,
}

impl Merged {
    fn add(&mut self, totals: &ProcessTotals) {
        self.actors.insert(totals.pid);
        self.recent.extend(totals.recent_reads.iter().cloned());
        self.recent.sort_by_key(|(_, at)| *at);
        let excess = self.recent.len().saturating_sub(512);
        self.recent.drain(..excess);
        for (path, at, size, class) in &totals.sensitive_reads {
            self.sensitive
                .entry(path.clone())
                .or_insert_with(|| (*at, *size, class.clone()));
        }
        for root in &totals.roots {
            // Two processes reading one tree may read the same files, so the
            // larger count is kept, never the sum: low, not invented.
            let kept = self
                .roots
                .entry(root.root.clone())
                .or_insert_with(|| RootTotals {
                    root: root.root.clone(),
                    first_at: root.first_at,
                    last_at: root.last_at,
                    ..RootTotals::default()
                });
            if root.files > kept.files {
                kept.files = root.files;
                kept.top.clone_from(&root.top);
            }
            kept.history_files = kept.history_files.max(root.history_files);
            // Changes are each process's own, to files it read itself; the
            // busiest is kept, not a sum of two that may overlap.
            let busier = |c: &topgent_collect::observed::changes::ChangeTotals| {
                c.times.len() + c.rewritten as usize
            };
            if busier(&root.changes) > busier(&kept.changes) {
                kept.changes.clone_from(&root.changes);
            }
            kept.read_bytes = kept.read_bytes.max(root.read_bytes);
            kept.unsized_files = kept.unsized_files.max(root.unsized_files);
            kept.uncounted = kept.uncounted.max(root.uncounted);
            kept.first_at = kept.first_at.min(root.first_at);
            kept.last_at = kept.last_at.max(root.last_at);
        }
        for dest in &totals.destinations {
            let kept = self
                .destinations
                .entry((dest.host.clone(), dest.port))
                .or_insert_with(|| DestTotals {
                    host: dest.host.clone(),
                    port: dest.port,
                    first_at: dest.first_at,
                    last_at: dest.last_at,
                    ..DestTotals::default()
                });
            // Attempts and bytes are each one process's own calls: these add.
            kept.attempts = kept.attempts.saturating_add(dest.attempts);
            kept.connected = kept.connected.saturating_add(dest.connected);
            kept.in_progress = kept.in_progress.saturating_add(dest.in_progress);
            kept.failed = kept.failed.saturating_add(dest.failed);
            kept.bytes = kept.bytes.saturating_add(dest.bytes);
            // Two processes' bursts may not overlap in time, so the larger is
            // kept rather than the sum: low, not invented.
            if dest.burst_bytes > kept.burst_bytes {
                kept.burst_bytes = dest.burst_bytes;
                kept.burst_at = dest.burst_at;
            }
            // Per-minute bytes add across the run's processes: a secret
            // incident asks what left in the minutes after a read.
            for (minute, bytes) in &dest.minutes {
                match kept.minutes.iter_mut().find(|(m, _)| m == minute) {
                    Some((_, b)) => *b = b.saturating_add(*bytes),
                    None => kept.minutes.push((*minute, *bytes)),
                }
            }
            kept.first_at = kept.first_at.min(dest.first_at);
            kept.last_at = kept.last_at.max(dest.last_at);
        }
    }
}

/// Placements saved by earlier sweeps, by pid and first call.
fn saved_placements(history: &Value) -> BTreeMap<(u32, u64), (Run, ProcessKey)> {
    let mut placed = BTreeMap::new();
    for row in history
        .get("placed")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let n = |f: &str| row.get(f).and_then(Value::as_u64);
        let (Some(pid), Some(first), Some(rp), Some(rs), Some(ap), Some(as_)) = (
            n("pid"),
            n("first_at"),
            n("run_pid"),
            n("run_started_at"),
            n("actor_pid"),
            n("actor_started_at"),
        ) else {
            continue;
        };
        let (Ok(pid), Ok(rp), Ok(ap)) = (u32::try_from(pid), u32::try_from(rp), u32::try_from(ap))
        else {
            continue;
        };
        placed.insert(
            (pid, first),
            (
                Run {
                    key: ProcessKey {
                        pid: rp,
                        started_at: UnixMillis(rs),
                    },
                    name: row
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown program")
                        .to_owned(),
                    family: row.get("family").and_then(Value::as_str).map(str::to_owned),
                },
                ProcessKey {
                    pid: ap,
                    started_at: UnixMillis(as_),
                },
            ),
        );
    }
    placed
}

/// The run one process's totals belong to: its agent through process history,
/// then a placement saved before, then — when history has no fork event for
/// this pid (a short-lived process, or history under cap pressure) — the
/// process the tally itself named, so a complete finding is reported rather
/// than discarded.
fn run_for(
    process: &ProcessTotals,
    lineage: &Lineage,
    agents: &BTreeMap<ProcessKey, (String, Option<String>)>,
    placed: &BTreeMap<(u32, u64), (Run, ProcessKey)>,
) -> (Run, ProcessKey) {
    place(process, lineage, agents)
        .or_else(|| placed.get(&(process.pid, process.first_at)).cloned())
        .unwrap_or_else(|| {
            let key = ProcessKey {
                pid: process.pid,
                started_at: UnixMillis(process.first_at),
            };
            let name = process
                .name
                .clone()
                .unwrap_or_else(|| "unknown program".to_owned());
            (
                Run {
                    key,
                    name,
                    family: None,
                },
                key,
            )
        })
}

/// This sweep's incidents, merged into the saved `history`.
#[allow(clippy::too_many_lines)]
// Each argument is one thing a sweep hands the rule, and tests replace each
// one; a wrapper struct would only rename the list.
#[allow(clippy::too_many_arguments)]
pub(crate) fn project(
    history: &Value,
    totals: &Totals,
    lineage: &Lineage,
    agents: &BTreeMap<ProcessKey, (String, Option<String>)>,
    destinations: &mut dyn Destinations,
    tools_of: &dyn Fn(&BTreeSet<u32>) -> Vec<String>,
    honeytokens: &crate::honeytoken::Manifest,
    boot: &str,
) -> Value {
    let cfg = config();
    let same_boot = history.get("boot").and_then(Value::as_str) == Some(boot);
    // Where each process was placed before: a run's processes keep their run
    // after it ends, when history may no longer place them.
    let mut placed = if same_boot {
        saved_placements(history)
    } else {
        BTreeMap::new()
    };
    let mut runs: BTreeMap<ProcessKey, (Run, Merged)> = BTreeMap::new();
    for process in &totals.processes {
        let (run, actor) = run_for(process, lineage, agents, &placed);
        placed.insert((process.pid, process.first_at), (run.clone(), actor));
        runs.entry(run.key)
            .or_insert_with(|| (run.clone(), Merged::default()))
            .1
            .add(process);
    }

    let mut rows: BTreeMap<String, Value> = BTreeMap::new();
    if same_boot {
        for row in history
            .get("rows")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .take(MAX_INCIDENTS)
        {
            if let Some(id) = row.get("id").and_then(Value::as_str) {
                rows.insert(id.to_owned(), row.clone());
            }
        }
    }
    let flows: Vec<Value> = runs
        .values()
        .filter_map(|(run, merged)| flow(run, merged, destinations, cfg))
        .take(20)
        .collect();
    let now = wall_ms();
    for (run, merged) in runs.values() {
        let tools = tools_of(&merged.actors);
        let Some(mut incident) = evaluate(run, merged, &tools, destinations, cfg) else {
            continue;
        };
        let id = incident
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let first_seen = rows
            .get(&id)
            .and_then(|r| r.get("first_seen"))
            .and_then(Value::as_u64)
            .unwrap_or(now);
        // Totals restart with the collector. An incident never shrinks: the
        // saved one stands until the live one passes it.
        if let Some(saved) = rows.get(&id) {
            let number = |row: &Value, field: &str| {
                row.pointer(&format!("/numbers/{field}"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
            };
            if number(saved, "bytes_sent") > number(&incident, "bytes_sent")
                || number(saved, "files_read") > number(&incident, "files_read")
            {
                continue;
            }
        }
        if let Some(object) = incident.as_object_mut() {
            object.insert("first_seen".into(), json!(first_seen));
            object.insert("last_seen".into(), json!(now));
        }
        rows.insert(id, incident);
    }
    // Secret incidents: a credential store opened, or a secret read shortly
    // before data left. Derived from the same counters, keyed by which file.
    // A planted decoy's read raises its own card instead, once. Network
    // scanning is judged here too: it needs only the run's destinations.
    for (run, merged) in runs.values_mut() {
        let reads = std::mem::take(&mut merged.sensitive)
            .into_iter()
            .map(|(path, (at, size, class))| (path, at, size, class));
        let (planted, rest) = crate::honeytoken::incident::split(reads, honeytokens);
        merged.sensitive = rest
            .into_iter()
            .map(|(path, at, size, class)| (path, (at, size, class)))
            .collect();
        let decoy = crate::honeytoken::incident::card(run, &planted, honeytokens);
        let scan = scanning::card(run, merged, scanning::scanning());
        let destroyed = destruction::card(
            run,
            merged,
            &tools_of(&merged.actors),
            destruction::destroyed(),
        );
        for mut incident in decoy
            .into_iter()
            .chain(scan)
            .chain(destroyed)
            .chain(secret_incidents(run, merged, destinations, cfg))
        {
            let id = incident
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let first_seen = rows
                .get(&id)
                .and_then(|r| r.get("first_seen"))
                .and_then(Value::as_u64)
                .unwrap_or(now);
            if let Some(object) = incident.as_object_mut() {
                object.insert("first_seen".into(), json!(first_seen));
                object.insert("last_seen".into(), json!(now));
            }
            rows.insert(id, incident);
        }
    }
    let mut rows: Vec<Value> = rows.into_values().collect();
    rows.sort_by_key(|r| {
        std::cmp::Reverse(r.get("first_seen").and_then(Value::as_u64).unwrap_or(0))
    });
    let evicted = rows.len().saturating_sub(MAX_INCIDENTS);
    rows.truncate(MAX_INCIDENTS);
    let placed: Vec<Value> = placed
        .iter()
        .rev()
        .take(4_096)
        .map(|((pid, first), (run, actor))| {
            json!({
                "pid": pid, "first_at": first,
                "run_pid": run.key.pid, "run_started_at": run.key.started_at.0,
                "name": run.name, "family": run.family,
                "actor_pid": actor.pid, "actor_started_at": actor.started_at.0,
            })
        })
        .collect();
    json!({
        "boot": boot,
        "rows": rows,
        "evicted": history.get("evicted").and_then(Value::as_u64).filter(|_| same_boot).unwrap_or(0) + evicted as u64,
        "placed": placed,
        "flows": flows,
        "forgotten_processes": totals.forgotten,
        "saturated": totals.saturated,
    })
}

/// What the rule needs and whether this host gives it.
pub(crate) fn coverage(sensor_syscalls: bool) -> Value {
    let cfg = config();
    let t = &cfg.thresholds;
    let (state, detail) = if !cfg!(target_os = "linux") {
        (
            "unsupported",
            "File reads and bytes sent per process are not recorded on this platform.",
        )
    } else if sensor_syscalls {
        (
            "available",
            "Linux eBPF: file opens and bytes sent are counted per process. Dropped events are counted.",
        )
    } else {
        (
            "degraded",
            "Linux Audit only: reads of paths without an Audit rule and bytes sent are not observed. Run topgent-sensor for full coverage.",
        )
    };
    json!({
        "rule": cfg.rule,
        "summary": cfg.summary,
        "state": state,
        "detail": detail,
        "thresholds": {
            "files": t.harvest_files,
            "history_files": t.harvest_history_files,
            "bytes": t.egress_bytes,
            "attempts": t.egress_attempts,
            "window_ms": t.window_ms,
            "own_service_floor_bytes": t.own_service_floor_bytes,
            "run_percent": t.run_percent_other,
            "run_floor_bytes": t.run_floor_bytes,
        },
        "limits": [
            format!("A burst to the agent's own model service fires only from {}, so a smaller upload to its own vendor is not reported.", bytes(t.own_service_floor_bytes)),
        ],
    })
}
