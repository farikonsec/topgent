//! Process ancestry rebuilt from the audit stream itself.
//!
//! The process sensor's history does not hold a process that lived and died
//! between two scans, so its parent and ancestors are unknown. F's
//! false-positive allowlists (a sensitive read *by a Qualys or Chef agent* is
//! ignored) test named ancestors, so an unknown ancestor makes the allowlist
//! Unknown, and `rule and not allowlist` then goes Unknown and never fires on
//! exactly the short-lived processes detection cares about most. Every audit
//! record names its own pid, parent pid and command, so the tree of what
//! spawned what can be rebuilt from the same events the rules read, filling the
//! gap without the process sensor.

use std::collections::BTreeMap;

use topgent_collect::observed::ObservedSyscall;

/// Most pids remembered across sweeps.
const MAX_REMEMBERED: usize = 32_768;

/// pid -> parent pid and command, as the audit records named them.
#[derive(Default)]
pub(super) struct AuditTree {
    parent: BTreeMap<u32, u32>,
    comm: BTreeMap<u32, String>,
}

impl AuditTree {
    /// Build the tree from one sweep's syscall records.
    pub(super) fn build(events: &[ObservedSyscall]) -> Self {
        let mut tree = Self::default();
        for observed in events {
            let event = &observed.event;
            if let Some(comm) = &event.comm {
                tree.comm.entry(event.pid).or_insert_with(|| comm.clone());
            }
            if let Some(ppid) = event.ppid {
                tree.parent.entry(event.pid).or_insert(ppid);
            }
            // The eBPF sensor names the whole chain at the moment of the
            // call: each link's parent is the next.
            let mut child = event.pid;
            for (pid, name) in &event.ancestors {
                tree.parent.entry(child).or_insert(*pid);
                if let Some(name) = name {
                    tree.comm.entry(*pid).or_insert_with(|| name.clone());
                }
                child = *pid;
            }
        }
        tree
    }

    /// Adds what the kernel's lifecycle events say: each fork's parent, and
    /// the name each process had. A process too short-lived to make a traced
    /// syscall (a `dpkg --version` lives a millisecond) is placed by its
    /// fork alone (found in E7).
    pub(super) fn with_lifecycle(
        mut self,
        events: &[topgent_collect::process_events::LifecycleEvent],
    ) -> Self {
        use topgent_collect::process_events::LifecycleKind;
        for event in events {
            if let LifecycleKind::Fork { parent } = event.kind {
                self.parent.entry(event.pid).or_insert(parent);
            }
            if let Some(name) = &event.name {
                // The latest name wins: an exec renames the process.
                self.comm.insert(event.pid, name.clone());
            }
        }
        self
    }

    /// Takes in one sweep's tree. What a new sweep says about a pid wins: a
    /// fork there is a new process under a reused pid. Kept across sweeps,
    /// because a process's parent often made its calls a sweep earlier than
    /// the child it matters for (found in E7: a container's `sh` started in
    /// one sweep, its `dpkg` ran in the next). Past [`MAX_REMEMBERED`] pids
    /// the older ones are forgotten whole, never guessed at.
    pub(super) fn absorb(&mut self, fresh: Self) {
        if self.parent.len() + fresh.parent.len() > MAX_REMEMBERED {
            self.parent.clear();
            self.comm.clear();
        }
        self.parent.extend(fresh.parent);
        self.comm.extend(fresh.comm);
    }

    /// The command the audit records gave this pid.
    pub(super) fn name(&self, pid: u32) -> Option<String> {
        self.comm.get(&pid).cloned()
    }

    /// This pid's parent, as the audit records named it.
    pub(super) fn parent_of(&self, pid: u32) -> Option<u32> {
        self.parent.get(&pid).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::AuditTree;
    use topgent_collect::audit_syscalls::parse;
    use topgent_collect::observed::ObservedSyscall;
    use topgent_facts::UnixMillis;

    /// The eBPF sensor names the chain with the call, so a short-lived
    /// process outside any agent's tree still has named ancestors.
    #[test]
    fn a_sensor_call_brings_its_whole_ancestry() {
        let line = r#"{"e":"sys","call":"openat","pid":40,"ppid":30,"ret":3,"path":"/etc/shadow","name":"cat","anc":[[30,"sudo"],[20,"sh"],[1,"systemd"]],"seq":1,"at":1}"#;
        let Some(topgent_collect::process_events::Line::Syscall(call)) =
            topgent_collect::process_events::parse_line(line)
        else {
            unreachable!("{line}")
        };
        let events = [ObservedSyscall {
            lineage_at: UnixMillis(1),
            event: call.event,
        }];
        let tree = AuditTree::build(&events);
        assert_eq!(tree.parent_of(40), Some(30));
        assert_eq!(tree.parent_of(30), Some(20));
        assert_eq!(tree.parent_of(20), Some(1));
        assert_eq!(tree.name(30).as_deref(), Some("sudo"));
        assert_eq!(tree.name(40).as_deref(), Some("cat"));
    }

    #[test]
    fn a_process_with_no_syscall_is_placed_by_its_fork() {
        use topgent_collect::process_events::{Line, parse_line};
        let events: Vec<_> = [
            r#"{"e":"fork","pid":40,"ppid":30,"name":"sh","at":1}"#,
            r#"{"e":"exec","pid":40,"name":"dpkg","at":2}"#,
        ]
        .into_iter()
        .filter_map(|line| match parse_line(line) {
            Some(Line::Event(event)) => Some(event),
            _ => None,
        })
        .collect();
        let tree = AuditTree::build(&[]).with_lifecycle(&events);
        assert_eq!(tree.parent_of(40), Some(30));
        assert_eq!(
            tree.name(40).as_deref(),
            Some("dpkg"),
            "the name after exec"
        );
    }

    #[test]
    fn a_parent_seen_a_sweep_earlier_is_remembered_and_a_new_fork_wins() {
        use topgent_collect::process_events::{Line, parse_line};
        let lifecycle = |lines: &[&str]| -> Vec<_> {
            lines
                .iter()
                .filter_map(|line| match parse_line(line) {
                    Some(Line::Event(event)) => Some(event),
                    _ => None,
                })
                .collect()
        };
        let mut kept = AuditTree::default();
        kept.absorb(AuditTree::build(&[]).with_lifecycle(&lifecycle(&[
            r#"{"e":"fork","pid":30,"ppid":20,"name":"shim","at":1}"#,
            r#"{"e":"exec","pid":30,"name":"sh","at":2}"#,
        ])));
        kept.absorb(AuditTree::build(&[]).with_lifecycle(&lifecycle(&[
            r#"{"e":"fork","pid":40,"ppid":30,"name":"sh","at":3}"#,
        ])));
        assert_eq!(
            (kept.parent_of(40), kept.parent_of(30)),
            (Some(30), Some(20))
        );
        assert_eq!(kept.name(30).as_deref(), Some("sh"));
        // pid 30 reused by a new process: its fork is the truth now.
        kept.absorb(AuditTree::build(&[]).with_lifecycle(&lifecycle(&[
            r#"{"e":"fork","pid":30,"ppid":99,"name":"cron","at":4}"#,
        ])));
        assert_eq!(kept.parent_of(30), Some(99));
        assert_eq!(kept.name(30).as_deref(), Some("cron"));
    }

    #[test]
    fn a_pid_gets_its_name_and_parent_from_the_audit_stream() {
        let audit = "\
type=SYSCALL msg=audit(1.0:1): arch=c00000b7 syscall=221 success=yes exit=0 ppid=30 pid=40 comm=\"cat\" exe=\"/usr/bin/cat\"\n\
type=SYSCALL msg=audit(1.1:2): arch=c00000b7 syscall=221 success=yes exit=0 ppid=20 pid=30 comm=\"bash\" exe=\"/usr/bin/bash\"\n";
        let events: Vec<ObservedSyscall> = parse(audit)
            .into_iter()
            .map(|event| ObservedSyscall {
                lineage_at: UnixMillis(event.at),
                event,
            })
            .collect();
        let tree = AuditTree::build(&events);
        assert_eq!(tree.name(40).as_deref(), Some("cat"));
        assert_eq!(tree.parent_of(40), Some(30));
        assert_eq!(tree.name(30).as_deref(), Some("bash"));
        assert_eq!(tree.parent_of(99), None);
    }
}
