//! `proc.*`, `user.*` and `container.*`: who acted, and who started them.
//!
//! From the Audit record where it names them (process name, program path,
//! terminal, working directory, user ids), and otherwise from process
//! history as of the event: the parent and every ancestor, the start time,
//! the pid namespace. A chain that stops short of the root gives the
//! ancestors it has as a partial answer, never as the whole one.

use topgent_behaviour::event::Field;
use topgent_collect::audit_syscalls::CallSource;
use topgent_core::lineage::{Lineage, ProcessKey};

use super::event::{Happening, RuleEvent, flag, known, value};
use super::names;

/// The process's ancestors, nearest first, and whether they reach a process with no parent.
fn ancestors(lineage: &Lineage, actor: ProcessKey) -> (Vec<ProcessKey>, bool) {
    let chain = lineage.ancestry(actor);
    let reaches_root = match chain.last().or(Some(&actor)).and_then(|k| lineage.get(*k)) {
        // init, or a process with no parent at all, ends the chain.
        Some(root) => root.key.pid == 1 || root.parent_pid.is_none_or(|p| p == 0),
        None => false,
    };
    (chain, reaches_root)
}

fn name_of(lineage: &Lineage, key: ProcessKey) -> Option<String> {
    lineage.get(key).map(|record| record.name.clone())
}

/// A program path, only when history holds the whole path.
fn full_exe(lineage: &Lineage, key: ProcessKey) -> Option<String> {
    lineage
        .get(key)
        .and_then(|record| record.exe.clone())
        .filter(|exe| exe.starts_with('/'))
}

// A flat dispatch match over the provided field names; splitting the arms into
// helpers would scatter the vocabulary without making any of it clearer.
#[allow(clippy::too_many_lines)]
pub(super) fn field(event: &RuleEvent<'_>, name: &str, arg: Option<&str>) -> Field {
    let ctx = event.ctx;
    let lineage = ctx.lineage;
    let call = match event.happening {
        Happening::Syscall(call) => Some(&call.event),
        Happening::Exec(_) => None,
    };
    let at = event.happening.at();
    // For a process history does not hold, the pid's latest exec before the
    // event is the run that acted: the exec record is all that defines it.
    let run = event.actor.unwrap_or(ProcessKey {
        pid: event.happening.pid(),
        started_at: topgent_facts::UnixMillis(0),
    });
    let invocation = ctx.invocations.of(run, at);
    let record = event.actor.and_then(|actor| lineage.get(actor));
    let parent = record.and_then(|r| r.parent).or_else(|| {
        call.and_then(|c| c.ppid)
            .and_then(|ppid| topgent_core::attributed::actor_at(lineage, ppid, at))
    });
    match name {
        "proc.name" => known(
            call.and_then(|c| c.comm.clone())
                .or_else(|| record.map(|r| r.name.clone()))
                .or_else(|| match event.happening {
                    Happening::Exec(exec) => exec.name.clone(),
                    Happening::Syscall(_) => None,
                }),
        ),
        "proc.exepath" => known(
            call.and_then(|c| c.exe.clone())
                .or_else(|| match event.happening {
                    Happening::Exec(exec) => exec.path.clone(),
                    Happening::Syscall(_) => None,
                })
                .or_else(|| invocation.and_then(|i| i.exe.clone()))
                .or_else(|| event.actor.and_then(|a| full_exe(lineage, a))),
        ),
        "proc.is_exe_from_memfd" => match call.and_then(|c| c.exe.as_deref()) {
            Some(exe) => flag(exe.starts_with("/memfd:")),
            None => Field::Unknown,
        },
        "proc.exe" => known(invocation.and_then(|i| i.argv.first().cloned())),
        "proc.args" => known(invocation.map(|i| args(&i.argv))),
        "proc.cmdline" => {
            // The exec's own name for a process no history holds: found in
            // E7, when every exec outside an agent's tree had no command line.
            let comm = call
                .and_then(|c| c.comm.clone())
                .or_else(|| record.map(|r| r.name.clone()))
                .or_else(|| match event.happening {
                    Happening::Exec(exec) => exec.name.clone(),
                    Happening::Syscall(_) => None,
                });
            match (comm, invocation) {
                (Some(comm), Some(i)) => value(cmdline(&comm, &i.argv)),
                _ => Field::Unknown,
            }
        }
        "proc.pcmdline" => {
            // The parent from history, or the one the audit stream named.
            let via_lineage = parent
                .and_then(|p| name_of(lineage, p).zip(ctx.invocations.of(p, at)))
                .map(|(comm, i)| cmdline(&comm, &i.argv));
            let via_audit = ctx.audit.parent_of(event.happening.pid()).and_then(|ppid| {
                let key = ProcessKey {
                    pid: ppid,
                    started_at: topgent_facts::UnixMillis(0),
                };
                ctx.audit
                    .name(ppid)
                    .zip(ctx.invocations.of(key, at))
                    .map(|(comm, i)| cmdline(&comm, &i.argv))
            });
            known(via_lineage.or(via_audit))
        }
        "proc.pname" => known(parent.and_then(|p| name_of(lineage, p)).or_else(|| {
            ctx.audit
                .parent_of(event.happening.pid())
                .and_then(|ppid| ctx.audit.name(ppid))
        })),
        "proc.pexe" => known(
            parent
                .and_then(|p| {
                    ctx.invocations
                        .of(p, at)
                        .and_then(|i| i.exe.clone())
                        .or_else(|| full_exe(lineage, p))
                })
                .or_else(|| {
                    let ppid = ctx.audit.parent_of(event.happening.pid())?;
                    let key = ProcessKey {
                        pid: ppid,
                        started_at: topgent_facts::UnixMillis(0),
                    };
                    ctx.invocations.of(key, at).and_then(|i| i.exe.clone())
                }),
        ),
        "proc.aname" | "proc.aexe" => ancestor_field(event, name, arg),
        "proc.tty" => match call {
            Some(c) if c.source == CallSource::Audit => value(names::tty_number(c.tty.as_deref())),
            Some(c) => known(c.tty.clone()),
            None => match event.happening {
                Happening::Exec(exec) => {
                    known(exec.tty.map(|tty| if tty { "1" } else { "0" }.to_owned()))
                }
                Happening::Syscall(_) => Field::Unknown,
            },
        },
        "proc.cwd" => known(cwd(event).map(|cwd| {
            if cwd.ends_with('/') {
                cwd
            } else {
                format!("{cwd}/")
            }
        })),
        "proc.duration" => match event.actor {
            Some(actor) => {
                value((u128::from(at.0.saturating_sub(actor.started_at.0)) * 1_000_000).to_string())
            }
            None => Field::Unknown,
        },
        // The last NSpid value is the pid as seen in the process's innermost
        // namespace. Read it while the event is evaluated; a process that has
        // already exited stays Unknown rather than inheriting a reused pid.
        "proc.vpid" => known(namespace_pid(event.happening.pid()).map(|pid| pid.to_string())),
        "proc.is_vpgid_leader" => known(
            process_group(event.happening.pid())
                .map(|group| (group == event.happening.pid()).to_string()),
        ),
        "user.uid" => known(uid(event).map(|uid| uid.to_string())),
        // Named from the host's account database, which names host accounts
        // only: inside a container the same uid is whoever the container's
        // own `/etc/passwd` says, which Topgent does not read.
        // Inside a container, the container's own accounts name the uid,
        // when its runtime could be asked and its /etc/passwd read.
        "user.name" => match container_id(event) {
            Field::Value(id) if id != "host" => known(runtime(event).and_then(|context| {
                context
                    .accounts
                    .as_ref()
                    .and_then(|accounts| accounts.get(&uid(event)?).cloned())
            })),
            _ => known(uid(event).and_then(|uid| ctx.users.get(&uid).cloned())),
        },
        // Likewise: Audit's unset login uid is -1; the probe reads none.
        // Audit's unset login id is -1; the eBPF probe supplies the real
        // one through `auid` when this kernel records it, else nothing.
        "user.loginuid" => match call {
            Some(c) => match c.auid {
                Some(auid) => value(auid.to_string()),
                // Audit saw the call and its login id was unset; the eBPF
                // probe not reading one means this kernel has none.
                None if c.source == CallSource::Audit => value("-1"),
                None => Field::Unknown,
            },
            // An exec the eBPF source saw carries its own login id.
            None => match event.happening {
                Happening::Exec(exec) => known(exec.loginuid.map(|uid| uid.to_string())),
                Happening::Syscall(_) => Field::Unknown,
            },
        },
        "thread.cap_effective" => known(
            call.and_then(|c| c.capabilities)
                .map(|(e, _)| names::capabilities(e)),
        ),
        "thread.cap_permitted" => known(
            call.and_then(|c| c.capabilities)
                .map(|(_, p)| names::capabilities(p)),
        ),
        "container.id" => container_id(event),
        // A host process has no container image, pod or mounts, so those are
        // Absent. Inside a container they are what its runtime said, when it
        // could be asked; otherwise Unknown, never Absent, which would read as
        // "no image" and let a container rule match on emptiness.
        field if topgent_behaviour::fields::host_only_absent(field) => match container_id(event) {
            Field::Value(id) if id == "host" => Field::Absent,
            Field::Value(_) => {
                runtime(event).map_or(Field::Unknown, |context| from_runtime(&context, field, arg))
            }
            other => other,
        },
        _ => Field::Unknown,
    }
}

fn namespace_pid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    namespace_pid_from_status(&status)
}

fn namespace_pid_from_status(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))?
        .split_whitespace()
        .next_back()?
        .parse()
        .ok()
}

fn process_group(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    process_group_from_stat(&stat)
}

fn process_group_from_stat(stat: &str) -> Option<u32> {
    let after_name = stat.rsplit_once(") ")?.1;
    after_name.split_whitespace().nth(2)?.parse().ok()
}

/// What the container runtime said about the container the event ran in,
/// found by the full id the event itself carries (the eBPF source).
fn runtime(
    event: &RuleEvent<'_>,
) -> Option<std::sync::Arc<topgent_collect::container_context::ContainerContext>> {
    let id = match event.happening {
        Happening::Exec(exec) => exec.container.as_deref(),
        Happening::Syscall(call) => call.event.container.as_deref(),
    }?;
    (event.ctx.runtime_of)(id)
}

/// A container field from its runtime's answer. A container no kubelet
/// started has no pod: Absent. Mounts are not read yet: Unknown.
fn from_runtime(
    context: &topgent_collect::container_context::ContainerContext,
    field: &str,
    arg: Option<&str>,
) -> Field {
    match field {
        "container.image.repository" => known(context.image.clone()),
        "container.privileged" => known(context.privileged.map(|p| p.to_string())),
        "container.mount.dest" => match (&context.mounts, arg) {
            (Some(mounts), Some(pattern)) => mounts
                .iter()
                .find(|destination| mount_matches(destination, pattern))
                .cloned()
                .map_or(Field::Absent, Field::Value),
            (Some(_), None) => Field::Absent,
            (None, _) => Field::Unknown,
        },
        "k8s.ns.name" => context
            .k8s_namespace
            .clone()
            .map_or(Field::Absent, Field::Value),
        "k8s.pod.name" => context.k8s_pod.clone().map_or(Field::Absent, Field::Value),
        _ => Field::Unknown,
    }
}

fn mount_matches(destination: &str, pattern: &str) -> bool {
    pattern
        .strip_suffix('*')
        .map_or(destination == pattern, |prefix| {
            destination.starts_with(prefix)
        })
}

/// The real user id the event ran as: the call's, or the exec's when the
/// sensor read it in the kernel (the eBPF source).
fn uid(event: &RuleEvent<'_>) -> Option<u32> {
    match event.happening {
        Happening::Syscall(call) => call.event.uid,
        Happening::Exec(exec) => exec.uid,
    }
}

/// The working directory: the call's (Audit's `CWD`, or the eBPF source's
/// when the call had a relative path), or the exec's when the eBPF source
/// walked it.
fn cwd(event: &RuleEvent<'_>) -> Option<String> {
    match event.happening {
        Happening::Syscall(call) => call.event.cwd.clone(),
        Happening::Exec(exec) => exec.cwd.clone(),
    }
}

/// `proc.aname[n]`, `proc.aexe[n]`, and `proc.aname` for every ancestor.
fn ancestor_field(event: &RuleEvent<'_>, name: &str, arg: Option<&str>) -> Field {
    let lineage = event.ctx.lineage;
    // History holds the actor; or, for a process it does not hold, the
    // Audit record names its parent and history takes over from there.
    let exe = name == "proc.aexe";
    if let Some(actor) = event.actor {
        // The sensor holds the actor: walk its recorded ancestry.
        let (chain, reaches_root) = ancestors(lineage, actor);
        let read = |key: ProcessKey| {
            if exe {
                event
                    .ctx
                    .invocations
                    .of(key, event.happening.at())
                    .and_then(|i| i.exe.clone())
                    .or_else(|| full_exe(lineage, key))
            } else {
                name_of(lineage, key)
            }
        };
        return resolve_ancestor(arg, Some(actor), &chain, reaches_root, read);
    }
    // History does not hold this process. Rebuild its ancestry from the tree
    // the calls and lifecycle events built (every fork names its parent, every
    // eBPF call its chain), handing off to history for long-lived ancestors
    // the tree did not capture (a login shell, sshd, init). Only the union
    // reaches the root, and only a chain that reaches the root lets an
    // allowlist resolve to a definite miss. An exec is rebuilt the same way
    // as a call (found in E7: every exec outside an agent's tree had none).
    let actor_pid = event.happening.pid();
    let at = event.happening.at();
    let (pids, reaches_root) = merged_ancestry(event, actor_pid, at);
    let read = |pid: u32| {
        if exe {
            let key = ProcessKey {
                pid,
                started_at: topgent_facts::UnixMillis(0),
            };
            event
                .ctx
                .invocations
                .of(key, at)
                .and_then(|i| i.exe.clone())
                .or_else(|| {
                    topgent_core::attributed::actor_at(lineage, pid, at)
                        .and_then(|key| full_exe(lineage, key))
                })
        } else {
            event.ctx.audit.name(pid).or_else(|| {
                topgent_core::attributed::actor_at(lineage, pid, at)
                    .and_then(|key| name_of(lineage, key))
            })
        }
    };
    resolve_pids(arg, actor_pid, &pids, reaches_root, read)
}

/// The actor's ancestor pids, nearest first, and whether they reach the root.
/// Each parent link comes from the audit stream if it named one, otherwise
/// from the sensor's process history.
fn merged_ancestry(
    event: &RuleEvent<'_>,
    actor_pid: u32,
    at: topgent_facts::UnixMillis,
) -> (Vec<u32>, bool) {
    let audit = event.ctx.audit;
    let lineage = event.ctx.lineage;
    let parent_of = |pid: u32| {
        audit.parent_of(pid).or_else(|| {
            topgent_core::attributed::actor_at(lineage, pid, at)
                .and_then(|key| lineage.get(key))
                .and_then(|record| record.parent.map(|p| p.pid))
        })
    };
    let mut chain = Vec::new();
    let mut seen = std::collections::BTreeSet::from([actor_pid]);
    let mut current = actor_pid;
    for _ in 0..MAX_ANCESTRY {
        let Some(parent) = parent_of(current) else {
            return (chain, false);
        };
        if parent == 0 {
            return (chain, true);
        }
        if !seen.insert(parent) {
            return (chain, false);
        }
        chain.push(parent);
        if parent == 1 {
            return (chain, true);
        }
        current = parent;
    }
    (chain, false)
}

/// A cycle- and runaway-guard on the walk to the root.
const MAX_ANCESTRY: usize = 64;

/// `proc.aname`/`proc.aexe` over a pid chain rebuilt outside the sensor.
fn resolve_pids(
    arg: Option<&str>,
    actor_pid: u32,
    chain: &[u32],
    reaches_root: bool,
    read: impl Fn(u32) -> Option<String>,
) -> Field {
    if let Some(index) = arg {
        let Ok(index) = index.parse::<usize>() else {
            return Field::Unknown;
        };
        let pid = if index == 0 {
            Some(actor_pid)
        } else {
            chain.get(index - 1).copied()
        };
        match pid {
            Some(pid) => known(read(pid)),
            None if reaches_root => Field::Absent,
            None => Field::Unknown,
        }
    } else {
        let values: Vec<String> = chain.iter().filter_map(|&p| read(p)).collect();
        if reaches_root && values.len() == chain.len() {
            Field::Many(values)
        } else {
            Field::Partial(values)
        }
    }
}

/// `proc.aname`/`proc.aexe`, indexed or whole, from a resolved chain. Index 0
/// is the process itself; higher indices are its ancestors, nearest first. An
/// index past a chain that reaches the root is Absent; past one that does not
/// is Unknown, because a deeper ancestor may exist unseen.
fn resolve_ancestor(
    arg: Option<&str>,
    actor: Option<ProcessKey>,
    chain: &[ProcessKey],
    reaches_root: bool,
    read: impl Fn(ProcessKey) -> Option<String>,
) -> Field {
    if let Some(index) = arg {
        let Ok(index) = index.parse::<usize>() else {
            return Field::Unknown;
        };
        let key = if index == 0 {
            actor
        } else {
            chain.get(index - 1).copied()
        };
        match key {
            Some(key) => known(read(key)),
            None if reaches_root => Field::Absent,
            None => Field::Unknown,
        }
    } else {
        let values: Vec<String> = chain.iter().filter_map(|k| read(*k)).collect();
        if reaches_root && values.len() == chain.len() {
            Field::Many(values)
        } else {
            Field::Partial(values)
        }
    }
}

/// `host` for a process in the host's pid namespace. A process whose
/// namespace history did not record inherits its nearest ancestor's: a
/// fork stays in its parent's pid namespace.
fn container_id(event: &RuleEvent<'_>) -> Field {
    // The container the kernel's own cgroup id named at the moment of the
    // event (the eBPF source), in the short form the rules compare.
    let named = match event.happening {
        Happening::Exec(exec) => exec.container.as_deref(),
        Happening::Syscall(call) => call.event.container.as_deref(),
    };
    if let Some(id) = named {
        return value(id.chars().take(12).collect::<String>());
    }
    let Some(host) = event.ctx.host_pid_namespace else {
        return Field::Unknown;
    };
    let lineage = event.ctx.lineage;
    let pid = event.happening.pid();
    // What the kernel said about this very event comes first: it holds for a
    // process that was gone before anything could look.
    let carried = match event.happening {
        Happening::Exec(exec) => exec.pid_namespace,
        Happening::Syscall(call) => call.event.pid_namespace,
    };
    let namespace = carried.or_else(|| match event.actor {
        Some(actor) => std::iter::once(actor)
            .chain(lineage.ancestry(actor))
            .find_map(|key| lineage.get(key).and_then(|r| r.pid_namespace)),
        // Not in any agent's history: ask the process itself, if it runs.
        None => (event.ctx.namespace_of)(pid),
    });
    match namespace {
        Some(ns) if ns == host => value("host"),
        // A namespace that is not the host's: a container. Name it from the
        // process's cgroup where that is still readable; otherwise it is a
        // container Topgent cannot name, which is Unknown, never host.
        Some(_) => known((event.ctx.container_of)(pid)),
        // Namespace unresolved. A syscall in this stream was recorded by the
        // host's own auditd, which sees host-namespace calls unless container
        // auditing is configured; with no container signal at all, the honest
        // default for a host sensor is the host. Without this, every rule with
        // `not container` goes Unknown on a short-lived process that has already
        // exited by sweep time, and the sensor detects nothing on exactly the
        // events that matter most. An exec seen only by the process sensor keeps
        // the stricter Unknown, since that path is not the host audit stream.
        None => match event.happening {
            // Namespace unresolved on a host audit stream: a container cgroup
            // if one is still readable, otherwise the host default (see above).
            Happening::Syscall(call) if call.event.source == CallSource::Audit => {
                match (event.ctx.container_of)(pid) {
                    Some(id) => value(id),
                    None => value("host"),
                }
            }
            // The eBPF probe sees every namespace, so neither a call it did
            // not place in the host's nor a sensor exec is assumed there.
            Happening::Syscall(_) | Happening::Exec(_) => Field::Unknown,
        },
    }
}

fn args(argv: &[String]) -> String {
    argv.iter().skip(1).cloned().collect::<Vec<_>>().join(" ")
}

/// The command line as the rules read it: the process name, then the
/// arguments after the first.
fn cmdline(comm: &str, argv: &[String]) -> String {
    let rest = args(argv);
    if rest.is_empty() {
        comm.to_owned()
    } else {
        format!("{comm} {rest}")
    }
}

#[cfg(test)]
mod namespace_tests {
    use super::{namespace_pid_from_status, process_group_from_stat};

    #[test]
    fn innermost_namespace_pid_is_the_last_reported_value() {
        assert_eq!(
            namespace_pid_from_status("Name:\tsh\nNSpid:\t8123\t41\t1\n"),
            Some(1)
        );
        assert_eq!(namespace_pid_from_status("Name:\tsh\n"), None);
    }

    #[test]
    fn process_group_parsing_survives_spaces_and_parentheses_in_the_name() {
        assert_eq!(
            process_group_from_stat("44 (odd ) name) S 2 44 44 0"),
            Some(44)
        );
    }
}
