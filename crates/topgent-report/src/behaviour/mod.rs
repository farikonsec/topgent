//! Runtime behaviour rules, evaluated on this host's own events.
//!
//! Every syscall the Audit reader hands the sweep, and every exec the
//! process sensor saw, is read as a rule event and checked against every
//! enabled rule in the pinned F catalogue. A rule that holds becomes a
//! finding, kept and placed on its agent by [`findings`].
//!
//! # Layout
//!
//! - [`event`]: one happening as the rules read it.
//! - [`syscall`]: `evt.*` and `fd.*` from the call.
//! - [`process`]: `proc.*`, `user.*` and `container.*` from process history.
//! - [`names`]: arguments by the names the rules expect.
//! - [`invocations`]: exec arguments, in memory only.
//! - [`findings`]: rows kept across sweeps, placed on agents.

mod audit_tree;
mod event;
pub(crate) mod findings;
mod invocations;
mod names;
mod process;
mod syscall;
pub(crate) mod temporal;

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock, PoisonError};

use serde_json::{Value, json};
use topgent_behaviour::catalogue::{Catalogue, Maturity, Rule};
use topgent_behaviour::eval::{Truth, evaluate};
use topgent_collect::Sweep;
use topgent_collect::process_events::LifecycleKind;
use topgent_core::lineage::Lineage;

use event::{Context, Happening, RuleEvent};
use invocations::{Invocation, Invocations};

/// Every rule in the pinned catalogue, resolved once.
pub(crate) fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        Catalogue::pinned()
            // OpenCode's own Bun worker maintains a loopback UDP endpoint on
            // port 5000. It never leaves the host, and treating every worker
            // as unexpected traffic turns a useful rule into permanent noise.
            // Keep the upstream expected-port list and add only this observed,
            // process-bound local exception.
            .map(|catalogue| {
                catalogue.with_macro(
                    "expected_udp_traffic",
                    "(fd.port in (expected_udp_ports) or (proc.name=\"Bun Pool\" and \
                     fd.ip in (127.0.0.1,\"::1\") and fd.port=5000))",
                )
            })
            .and_then(|catalogue| catalogue.compile())
            .unwrap_or_default()
    })
}

/// For each rule of [`rules`], in order, the event types it can fire on, or
/// `None` for any. Evaluating a rule on another type can only give
/// not-true, so it is skipped: an `openat` meets the rules about files, not
/// all of them (docs/ebpf/PLAN.md, E6).
fn rule_types() -> &'static [Option<std::collections::BTreeSet<String>>] {
    static TYPES: OnceLock<Vec<Option<std::collections::BTreeSet<String>>>> = OnceLock::new();
    TYPES.get_or_init(|| {
        rules()
            .iter()
            .map(|rule| topgent_behaviour::index::event_types(&rule.condition))
            .collect()
    })
}

/// A field's value as text, when the event has one.
fn text_field(event: &RuleEvent<'_>, name: &str) -> Option<String> {
    match <RuleEvent<'_> as topgent_behaviour::event::Event>::field(event, name, None) {
        topgent_behaviour::event::Field::Value(value) => Some(value),
        _ => None,
    }
}

/// The type a rule's `evt.type` reads for a happening.
const fn event_kind(happening: Happening<'_>) -> &'static str {
    match happening {
        Happening::Syscall(call) => call.event.syscall,
        Happening::Exec(_) => "execve",
    }
}

/// The enabled rules that can fire on an event of type `kind`.
fn candidate_rules(kind: &str) -> impl Iterator<Item = &'static Rule> + '_ {
    rules()
        .iter()
        .zip(rule_types())
        .filter(move |(rule, types)| {
            rule.enabled && types.as_ref().is_none_or(|types| types.contains(kind))
        })
        .map(|(rule, _)| rule)
}

/// Ancestry kept across sweeps (see [`audit_tree::AuditTree::absorb`]).
fn remembered_tree() -> &'static Mutex<audit_tree::AuditTree> {
    static TREE: OnceLock<Mutex<audit_tree::AuditTree>> = OnceLock::new();
    TREE.get_or_init(|| Mutex::new(audit_tree::AuditTree::default()))
}

fn invocations() -> &'static Mutex<Invocations> {
    static INVOCATIONS: Mutex<Invocations> = Mutex::new(Invocations::new());
    &INVOCATIONS
}

const fn maturity(maturity: Maturity) -> &'static str {
    match maturity {
        Maturity::Stable => "stable",
        Maturity::Incubating => "incubating",
        Maturity::Sandbox => "sandbox",
    }
}

/// Account names by uid, from the host's account database.
fn users() -> BTreeMap<u32, String> {
    std::fs::read_to_string("/etc/passwd")
        .unwrap_or_default()
        .lines()
        .take(10_000)
        .filter_map(|line| {
            let mut parts = line.split(':');
            let name = parts.next()?;
            let uid = parts.nth(1)?.parse().ok()?;
            Some((uid, name.chars().take(64).collect()))
        })
        .collect()
}

/// The pid namespace this process runs in, taken as the host's.
fn host_pid_namespace() -> Option<u64> {
    let link = std::fs::read_link("/proc/self/ns/pid").ok()?;
    let text = link.to_string_lossy();
    text.strip_prefix("pid:[")?.strip_suffix(']')?.parse().ok()
}

/// A short description of what the event touched, for the finding row.
fn target(happening: Happening<'_>) -> String {
    match happening {
        Happening::Exec(exec) => exec
            .program
            .clone()
            .or_else(|| exec.name.clone())
            .unwrap_or_default(),
        Happening::Syscall(call) => {
            let event = &call.event;
            if let Some(peer) = &event.sockaddr {
                return if peer.family == 1 {
                    peer.host.clone()
                } else {
                    format!("{}:{}", peer.host, peer.port)
                };
            }
            if matches!(event.syscall, "execve" | "execveat")
                && let Some(exe) = &event.exe
            {
                return exe.clone();
            }
            event
                .paths
                .iter()
                .find(|p| p.nametype != "PARENT")
                .or_else(|| event.paths.first())
                .map_or_else(|| event.syscall.to_owned(), |p| p.name.clone())
        }
    }
}

/// Most arguments read from a running process, and the longest one.
const MAX_ARGS: usize = 64;
const MAX_ARG: usize = 4_096;

/// A running process's arguments, bounded. Held in memory only.
fn read_cmdline(pid: u32) -> Option<Vec<String>> {
    use std::io::Read as _;
    let mut raw = Vec::new();
    std::fs::File::open(format!("/proc/{pid}/cmdline"))
        .ok()?
        .take((MAX_ARGS * MAX_ARG) as u64)
        .read_to_end(&mut raw)
        .ok()?;
    let argv: Vec<String> = raw
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .take(MAX_ARGS)
        .map(|arg| String::from_utf8_lossy(arg).chars().take(MAX_ARG).collect())
        .collect();
    (!argv.is_empty()).then_some(argv)
}

/// Remembers how each running process in an agent's tree was invoked, when
/// no exec record said. An agent that started before Topgent's Audit window
/// is the common case, and its children's rules read its command line.
fn remember_running(
    known: &mut Invocations,
    sweep: &Sweep,
    lineage: &Lineage,
    read: &dyn Fn(u32) -> Option<Vec<String>>,
) {
    for process in &sweep.processes {
        let key = topgent_core::lineage::ProcessKey {
            pid: process.pid,
            started_at: process.started_at,
        };
        if lineage.get(key).is_none()
            || known.of(key, topgent_facts::UnixMillis(u64::MAX)).is_some()
        {
            continue;
        }
        if let Some(argv) = read(process.pid) {
            known.record(
                process.pid,
                Invocation {
                    exe: process.exe_path_known.then(|| process.exe.clone()),
                    argv,
                    at: process.started_at,
                },
            );
        }
    }
}

/// A running process's pid namespace.
fn pid_namespace_of(pid: u32) -> Option<u64> {
    let link = std::fs::read_link(format!("/proc/{pid}/ns/pid")).ok()?;
    let text = link.to_string_lossy();
    text.strip_prefix("pid:[")?.strip_suffix(']')?.parse().ok()
}

/// The container id of a running process, read from its cgroup. Docker,
/// containerd, CRI-O and Podman each encode a 64-hex id in the cgroup path
/// (`.../docker-<hex>.scope`, `/docker/<hex>`, `.../crio-<hex>.scope`); the
/// short 12-character form is what the rules compare. None for a process with
/// no container cgroup, or one that has already exited.
fn container_from_cgroup(pid: u32) -> Option<String> {
    container_id_in_cgroup(&std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?)
}

/// The 12-character container id in a `/proc/<pid>/cgroup` body, if any.
fn container_id_in_cgroup(text: &str) -> Option<String> {
    for line in text.lines().take(64) {
        for token in line.rsplit(['/', '-', ':']) {
            let id = token.trim_end_matches(".scope");
            if id.len() >= 12 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Some(id.chars().take(12).collect());
            }
        }
    }
    None
}

/// What the host can be asked while rules are evaluated. Readers are
/// passed in, so the same evaluation runs on recorded fixtures.
pub(crate) struct Host<'a> {
    /// The host's own pid namespace.
    pub pid_namespace: Option<u64>,
    /// Account names by uid.
    pub users: &'a BTreeMap<u32, String>,
    /// A running process's arguments.
    pub cmdline: &'a dyn Fn(u32) -> Option<Vec<String>>,
    /// A running process's pid namespace.
    pub namespace_of: &'a dyn Fn(u32) -> Option<u64>,
    /// A running process's container id, read from its cgroup.
    pub container_of: &'a dyn Fn(u32) -> Option<String>,
    /// What the container runtime said about a container, by full id.
    pub runtime_of: &'a dyn Fn(
        &str,
    ) -> Option<
        std::sync::Arc<topgent_collect::container_context::ContainerContext>,
    >,
}

/// New finding rows from one sweep, read against this host.
pub(crate) fn evaluate_sweep(sweep: &Sweep, lineage: &Lineage) -> Vec<Value> {
    let users = users();
    let mut known = invocations().lock().unwrap_or_else(PoisonError::into_inner);
    let mut tree = remembered_tree()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    evaluate_with(
        &mut known,
        &mut tree,
        sweep,
        lineage,
        &Host {
            pid_namespace: host_pid_namespace(),
            users: &users,
            cmdline: &read_cmdline,
            namespace_of: &pid_namespace_of,
            container_of: &container_from_cgroup,
            runtime_of: &topgent_collect::container_context::context,
        },
    )
}

/// New finding rows from one sweep, read against `host`.
fn evaluate_with(
    known: &mut Invocations,
    tree: &mut audit_tree::AuditTree,
    sweep: &Sweep,
    lineage: &Lineage,
    host: &Host<'_>,
) -> Vec<Value> {
    // Exec arguments first, so an exec's own event can read them.
    {
        remember_running(known, sweep, lineage, host.cmdline);
        for call in &sweep.syscall_events {
            let event = &call.event;
            if matches!(event.syscall, "execve" | "execveat") && event.success {
                known.record(
                    event.pid,
                    Invocation {
                        exe: event.exe.clone(),
                        argv: event.argv.clone(),
                        at: call.lineage_at,
                    },
                );
            }
        }
        // The eBPF sensor reads an exec's arguments itself, and sends them
        // only when it read all of them.
        for exec in &sweep.process_events {
            if exec.kind == LifecycleKind::Exec
                && let Some(argv) = &exec.argv
            {
                known.record(
                    exec.pid,
                    Invocation {
                        exe: exec.path.clone(),
                        argv: argv.clone(),
                        at: exec.at,
                    },
                );
            }
        }
    }
    let known = &*known;
    tree.absorb(
        audit_tree::AuditTree::build(&sweep.syscall_events).with_lifecycle(&sweep.process_events),
    );
    let audit = &*tree;
    let ctx = Context {
        lineage,
        users: host.users,
        host_pid_namespace: host.pid_namespace,
        invocations: known,
        namespace_of: host.namespace_of,
        container_of: host.container_of,
        runtime_of: host.runtime_of,
        audit,
    };
    let happenings = sweep.syscall_events.iter().map(Happening::Syscall).chain(
        sweep
            .process_events
            .iter()
            .filter(|e| e.kind == LifecycleKind::Exec)
            .map(Happening::Exec),
    );
    let mut rows = Vec::new();
    for happening in happenings {
        let kind = event_kind(happening);
        let event = RuleEvent::new(happening, &ctx);
        for rule in candidate_rules(kind) {
            if evaluate(&rule.condition, &event) != Truth::True {
                continue;
            }
            let name = <RuleEvent<'_> as topgent_behaviour::event::Event>::field(
                &event,
                "proc.name",
                None,
            );
            let actor_name = match name {
                topgent_behaviour::event::Field::Value(name) => name,
                _ => String::new(),
            };
            // Whether this happened on the host or inside a container, so a
            // finding says which. "host", a container id, or empty when unknown.
            let container = text_field(&event, "container.id").unwrap_or_default();
            // The container's image, when its runtime said (E7).
            let image = text_field(&event, "container.image.repository");
            let (record, source, at) = match happening {
                Happening::Syscall(call) => (
                    call.event.record.clone(),
                    call.event.source.as_str(),
                    call.event.at,
                ),
                Happening::Exec(exec) => (String::new(), "process sensor", exec.at.0),
            };
            rows.push(json!({
                "rule": rule.name,
                "maturity": maturity(rule.maturity),
                "priority": rule.priority,
                "tags": rule.tags,
                "source": source,
                "record": record,
                "at": at,
                "lineage_at": happening.at().0,
                "actor_pid": happening.pid(),
                "actor_name": actor_name,
                "summary": topgent_behaviour::summaries::summary(&rule.name).unwrap_or(""),
                "container": container,
                "container_image": image,
                "target": target(happening),
            }));
        }
    }
    rows
}

/// The plain-English summary for a rule, empty when none is written.
pub(crate) fn summary_of(rule: &str) -> &'static str {
    topgent_behaviour::summaries::summary(rule).unwrap_or("")
}

/// The catalogue as this build carries it, and what can fire here.
pub(crate) fn catalogue_json() -> Value {
    // Counted for the source actually delivering syscalls: each lacks fields
    // the other has, and only eBPF names the container an event ran in.
    let source = if topgent_collect::observed::sensor_delivers() {
        "ebpf"
    } else {
        "audit"
    };
    catalogue_json_for(source)
}

/// The catalogue, with what can fire when `source` delivers the syscalls.
fn catalogue_json_for(source: &str) -> Value {
    let coverage = topgent_behaviour::fields::coverage();
    let rules = rules();
    let live_on = |name: &str| source_live(coverage, name, source);
    json!({
        "source": "F catalogue, pinned",
        "commit": Catalogue::pinned().map(|c| c.commit().to_owned()).unwrap_or_default(),
        "rules": rules.len(),
        "enabled": rules.iter().filter(|r| r.enabled).count(),
        "syscall_source": source,
        "live": coverage.iter().filter(|c| c.live_on(source)).count(),
        "live_by_source": {
            "audit": coverage.iter().filter(|c| c.live_on("audit")).count(),
            "ebpf": coverage.iter().filter(|c| c.live_on("ebpf")).count(),
        },
        "coverage": rules.iter().map(|rule| {
            let row = coverage.iter().find(|c| c.name == rule.name);
            json!({
                "rule": rule.name,
                "maturity": maturity(rule.maturity),
                "priority": rule.priority,
                "enabled": rule.enabled,
                "live": live_on(&rule.name),
                "needs": row.map(|c| c.needs.clone()).unwrap_or_default(),
                "desc": rule.desc,
                "summary": topgent_behaviour::summaries::summary(&rule.name).unwrap_or(""),
            })
        }).collect::<Vec<_>>(),
    })
}

fn source_live(
    coverage: &[topgent_behaviour::fields::RuleCoverage],
    rule: &str,
    source: &str,
) -> bool {
    coverage
        .iter()
        .find(|c| c.name == rule)
        .is_some_and(|c| c.live_on(source))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod cgroup_tests {
    use super::container_id_in_cgroup;

    #[test]
    fn a_docker_cgroup_yields_the_short_container_id() {
        let hex = "1b8f2a3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8";
        // cgroup v2 (docker), v1 (docker), and CRI-O forms.
        for line in [
            format!("0::/system.slice/docker-{hex}.scope"),
            format!("11:devices:/docker/{hex}"),
            format!("0::/kubepods.slice/crio-{hex}.scope"),
        ] {
            assert_eq!(container_id_in_cgroup(&line).as_deref(), Some(&hex[..12]));
        }
    }

    #[test]
    fn a_host_process_cgroup_has_no_container_id() {
        assert_eq!(container_id_in_cgroup("0::/init.scope"), None);
        assert_eq!(
            container_id_in_cgroup("0::/user.slice/user-1000.slice/session-1.scope"),
            None
        );
        assert_eq!(container_id_in_cgroup(""), None);
    }
}
