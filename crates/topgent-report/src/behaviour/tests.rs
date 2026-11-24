//! The rules on a rogue agent's children, end to end.
//!
//! Recorded Audit records in, findings out: the same path a live sweep takes,
//! with the host's readers replaced by fixtures. An agent (`codex`, running
//! before Topgent's Audit window) has a shell child, and the shell does what
//! a compromised or careless agent does.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::collections::BTreeMap;

use serde_json::{Value, json};
use topgent_collect::Sweep;
use topgent_collect::audit_syscalls::parse;
use topgent_collect::observed::ObservedSyscall;
use topgent_collect::process::ProcInfo;
use topgent_core::lineage::{Lineage, Observation, ProcessKey};
use topgent_facts::UnixMillis;

use super::invocations::Invocations;
use super::{Host, evaluate_with};

const HOST_NS: u64 = 4_026_531_836;

/// No container runtime to ask.
fn no_context(
    _id: &str,
) -> Option<std::sync::Arc<topgent_collect::container_context::ContainerContext>> {
    None
}

fn key(pid: u32, started_at: u64) -> ProcessKey {
    ProcessKey {
        pid,
        started_at: UnixMillis(started_at),
    }
}

/// init → codex (the agent) → sh (its child), all on the host.
fn lineage() -> Lineage {
    let mut lineage = Lineage::new(64);
    for (pid, start, parent, name) in [
        (1, 0, None, "systemd"),
        (10, 1_000, Some(1), "codex"),
        (11, 2_000, Some(10), "sh"),
    ] {
        lineage.observe(Observation {
            key: key(pid, start),
            parent_pid: parent,
            name: name.into(),
            exe: None,
            pid_namespace: Some(HOST_NS),
            at: UnixMillis(start),
            from_event: true,
        });
    }
    lineage
}

/// A running process whose command line is read live, in memory.
fn running(pid: u32, started_at: u64, name: &str) -> ProcInfo {
    ProcInfo {
        pid,
        started_at: UnixMillis(started_at),
        exe: format!("/usr/bin/{name}"),
        exe_path_known: true,
        name: name.into(),
        uid: 1_000,
        user: "user".into(),
        parent: Some(1),
        pid_namespace: Some(HOST_NS),
        family: Some("codex-cli"),
        owner: topgent_collect::process::Owner::Unknown,
    }
}

fn findings(audit: &str) -> Vec<Value> {
    let events = parse(audit)
        .into_iter()
        .map(|event| ObservedSyscall {
            lineage_at: UnixMillis(event.at),
            event,
        })
        .collect();
    let sweep = Sweep {
        syscall_events: events,
        processes: vec![running(1, 0, "systemd"), running(10, 1_000, "codex")],
        ..Sweep::default()
    };
    let users = BTreeMap::from([(0, "root".to_owned()), (1000, "user".to_owned())]);
    let cmdline = |pid: u32| match pid {
        1 => Some(vec!["/sbin/init".to_owned()]),
        10 => Some(vec!["codex".to_owned(), "exec".to_owned()]),
        _ => None,
    };
    let namespace_of = |_pid: u32| Some(HOST_NS);
    let no_container = |_pid: u32| -> Option<String> { None };
    evaluate_with(
        &mut Invocations::new(),
        &mut super::audit_tree::AuditTree::default(),
        &sweep,
        &lineage(),
        &Host {
            pid_namespace: Some(HOST_NS),
            users: &users,
            cmdline: &cmdline,
            namespace_of: &namespace_of,
            container_of: &no_container,
            runtime_of: &no_context,
        },
    )
}

/// One syscall record group by `pid` with parent `parent`.
fn call(serial: u32, pid: u32, parent: u32, syscall: u32, body: &str, extra: &str) -> String {
    use std::fmt::Write as _;
    let id = format!("5.{serial:03}:{serial}");
    let mut out = format!(
        "type=SYSCALL msg=audit({id}): arch=c00000b7 syscall={syscall} {body} ppid={parent} pid={pid} auid=1000 uid=1000 tty=(none)\n"
    );
    for line in extra.lines().filter(|l| !l.trim().is_empty()) {
        let (kind, fields) = line.split_once(' ').unwrap();
        let _ = writeln!(out, "{kind} msg=audit({id}): {fields}");
    }
    out
}

fn fired(rows: &[Value]) -> Vec<(String, String)> {
    rows.iter()
        .map(|r| {
            (
                r["rule"].as_str().unwrap().to_owned(),
                r["actor_name"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

#[test]
fn a_child_reading_the_shadow_file_fires_on_that_child() {
    let audit = call(
        1,
        11,
        10,
        221,
        "success=yes exit=0 a0=0 a1=0 a2=0 a3=0 comm=\"cat\" exe=\"/usr/bin/cat\"",
        "type=CWD cwd=\"/tmp\"\ntype=EXECVE argc=2 a0=\"cat\" a1=\"/etc/shadow\"",
    ) + &call(
        2,
        11,
        10,
        56,
        "success=yes exit=3 a0=ffffff9c a1=0 a2=0 a3=0 comm=\"cat\" exe=\"/usr/bin/cat\"",
        "type=CWD cwd=\"/tmp\"\ntype=PATH item=0 name=\"/etc/shadow\" nametype=NORMAL",
    );
    let rows = findings(&audit);
    let fired = fired(&rows);
    assert!(
        fired.contains(&("Read sensitive file untrusted".to_owned(), "cat".to_owned())),
        "{fired:?}"
    );
    let row = rows
        .iter()
        .find(|r| r["rule"] == "Read sensitive file untrusted")
        .unwrap();
    assert_eq!(row["target"], "/etc/shadow");
    assert_eq!(row["actor_pid"], 11);
    assert!(
        row.get("argv").is_none() && !row.to_string().contains("\"exec\""),
        "no arguments kept"
    );
}

#[test]
fn log_truncation_network_tools_ptrace_and_shm_execution_each_fire() {
    let audit = call(
        1,
        11,
        10,
        56,
        "success=yes exit=3 a0=ffffff9c a1=0 a2=241 a3=0 comm=\"sh\" exe=\"/usr/bin/dash\"",
        "type=CWD cwd=\"/tmp\"\ntype=PATH item=0 name=\"/var/log/auth.log\" nametype=NORMAL",
    ) + &call(
        2,
        11,
        10,
        221,
        "success=yes exit=0 a0=0 a1=0 a2=0 a3=0 comm=\"nc\" exe=\"/usr/bin/nc.openbsd\"",
        "type=CWD cwd=\"/tmp\"\ntype=EXECVE argc=3 a0=\"nc\" a1=\"-l\" a2=\"4444\"",
    ) + &call(
        3,
        11,
        10,
        117,
        "success=yes exit=0 a0=10 a1=1 a2=0 a3=0 comm=\"sh\" exe=\"/usr/bin/dash\"",
        "",
    ) + &call(
        4,
        11,
        10,
        221,
        "success=yes exit=0 a0=0 a1=0 a2=0 a3=0 comm=\"x\" exe=\"/dev/shm/x\"",
        "type=CWD cwd=\"/dev/shm\"\ntype=EXECVE argc=1 a0=\"./x\"",
    );
    let fired = fired(&findings(&audit));
    for expected in [
        ("Clear Log Activities", "sh"),
        ("Launch Suspicious Network Tool on Host", "nc"),
        ("PTRACE attached to process", "sh"),
        ("Execution from /dev/shm", "x"),
    ] {
        assert!(
            fired.contains(&(expected.0.to_owned(), expected.1.to_owned())),
            "{expected:?} missing from {fired:?}"
        );
    }
}

/// The control: the same agent doing ordinary work fires nothing.
#[test]
fn ordinary_work_fires_no_rule() {
    let audit = call(
        1,
        11,
        10,
        221,
        "success=yes exit=0 a0=0 a1=0 a2=0 a3=0 comm=\"cat\" exe=\"/usr/bin/cat\"",
        "type=CWD cwd=\"/home/user/project\"\ntype=EXECVE argc=2 a0=\"cat\" a1=\"README.md\"",
    ) + &call(
        2,
        11,
        10,
        56,
        "success=yes exit=3 a0=ffffff9c a1=0 a2=0 a3=0 comm=\"cat\" exe=\"/usr/bin/cat\"",
        "type=CWD cwd=\"/home/user/project\"\ntype=PATH item=0 name=\"README.md\" nametype=NORMAL",
    ) + &call(
        3,
        11,
        10,
        56,
        "success=yes exit=4 a0=ffffff9c a1=0 a2=241 a3=1a4 comm=\"sh\" exe=\"/usr/bin/dash\"",
        "type=CWD cwd=\"/home/user/project\"\ntype=PATH item=0 name=\"build.log\" nametype=CREATE",
    );
    let fired = fired(&findings(&audit));
    assert!(fired.is_empty(), "{fired:?}");
}

/// A process outside every agent's tree still gets a finding: a host one,
/// with no agent. Attribution happens later, in `findings::project`.
#[test]
fn a_stranger_reading_the_shadow_file_is_a_host_finding() {
    let audit = call(
        1,
        99,
        1,
        221,
        "success=yes exit=0 a0=0 a1=0 a2=0 a3=0 comm=\"cat\" exe=\"/usr/bin/cat\"",
        "type=CWD cwd=\"/\"\ntype=EXECVE argc=2 a0=\"cat\" a1=\"/etc/shadow\"",
    ) + &call(
        2,
        99,
        1,
        56,
        "success=yes exit=3 a0=ffffff9c a1=0 a2=0 a3=0 comm=\"cat\" exe=\"/usr/bin/cat\"",
        "type=CWD cwd=\"/\"\ntype=PATH item=0 name=\"/etc/shadow\" nametype=NORMAL",
    );
    let rows = findings(&audit);
    let placed = super::findings::project(
        &serde_json::json!({}),
        rows,
        &lineage(),
        &[key(10, 1_000)],
        "b",
    );
    let host: Vec<&Value> = placed["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["actor_pid"] == 99)
        .collect();
    assert!(!host.is_empty(), "{placed}");
    assert!(
        host.iter().all(|r| r.get("agent_pid").is_none()),
        "not the agent's"
    );
}

/// Which fields left `rule` undecided on each event of `audit`: the question
/// to ask when a rule that should fire does not.
fn undecided(audit: &str, rule: &str) -> Vec<(String, std::collections::BTreeSet<String>)> {
    let events: Vec<ObservedSyscall> = parse(audit)
        .into_iter()
        .map(|event| ObservedSyscall {
            lineage_at: UnixMillis(event.at),
            event,
        })
        .collect();
    undecided_events(&events, rule)
}

fn undecided_events(
    events: &[ObservedSyscall],
    rule: &str,
) -> Vec<(String, std::collections::BTreeSet<String>)> {
    use super::event::{Context, Happening, RuleEvent};
    use std::cell::RefCell;
    use topgent_behaviour::event::{Event, Field};

    struct Spy<'a>(RuleEvent<'a>, RefCell<std::collections::BTreeSet<String>>);
    impl Event for Spy<'_> {
        fn field(&self, name: &str, arg: Option<&str>) -> Field {
            let answer = self.0.field(name, arg);
            if answer == Field::Unknown {
                self.1.borrow_mut().insert(name.to_owned());
            }
            answer
        }
    }
    let lineage = lineage();
    let mut known = Invocations::new();
    for call in events {
        if call.event.syscall == "execve" {
            known.record(
                call.event.pid,
                super::invocations::Invocation {
                    exe: call.event.exe.clone(),
                    argv: call.event.argv.clone(),
                    at: call.lineage_at,
                },
            );
        }
    }
    let users = BTreeMap::new();
    let namespace_of = |_pid: u32| Some(HOST_NS);
    let no_container = |_pid: u32| -> Option<String> { None };
    let audit = super::audit_tree::AuditTree::build(events);
    let ctx = Context {
        lineage: &lineage,
        users: &users,
        host_pid_namespace: Some(HOST_NS),
        invocations: &known,
        namespace_of: &namespace_of,
        container_of: &no_container,
        runtime_of: &no_context,
        audit: &audit,
    };
    let compiled = super::rules()
        .iter()
        .find(|r| r.name == rule)
        .expect("rule");
    events
        .iter()
        .map(|call| {
            let spy = Spy(
                RuleEvent::new(Happening::Syscall(call), &ctx),
                RefCell::default(),
            );
            let _ = topgent_behaviour::eval::evaluate(&compiled.condition, &spy);
            (call.event.record.clone(), spy.1.into_inner())
        })
        .collect()
}

/// A read by a process whose exec Topgent never saw cannot be checked
/// against the rule's exceptions for known command lines, so it stays
/// undecided, and says so, rather than firing or passing on a guess.
#[test]
fn an_unseen_exec_leaves_the_rule_undecided_and_names_why() {
    let audit = call(
        1,
        99,
        1,
        56,
        "success=yes exit=3 a0=ffffff9c a1=0 a2=0 a3=0 comm=\"cat\" exe=\"/usr/bin/cat\"",
        "type=CWD cwd=\"/\"\ntype=PATH item=0 name=\"/etc/shadow\" nametype=NORMAL",
    );
    let why = undecided(&audit, "Read sensitive file untrusted");
    assert!(why[0].1.contains("proc.cmdline"), "{why:?}");
    assert!(findings(&audit).is_empty(), "no finding on a guess");
}

/// An exec the eBPF source saw carries its full path to the rules; one the
/// process connector saw names the program only, so the path stays unknown
/// rather than guessed.
#[test]
fn a_sensor_exec_answers_its_path_only_when_the_kernel_gave_one() {
    use topgent_behaviour::event::{Event as _, Field};
    use topgent_collect::process_events::{LifecycleEvent, LifecycleKind};

    use super::audit_tree::AuditTree;
    use super::event::{Context, Happening, RuleEvent};

    let exec = |path: Option<&str>| LifecycleEvent {
        kind: LifecycleKind::Exec,
        pid: 12,
        started_at: Some(UnixMillis(3_000)),
        name: Some("nmap".into()),
        program: Some("nmap".into()),
        path: path.map(str::to_owned),
        pid_namespace: None,
        uid: None,
        container: None,
        argv: None,
        loginuid: None,
        tty: None,
        cwd: None,
        at: UnixMillis(3_001),
    };
    let lineage = lineage();
    let users = BTreeMap::new();
    let invocations = Invocations::new();
    let audit = AuditTree::build(&[]);
    let namespace_of = |_pid: u32| Some(HOST_NS);
    let no_container = |_pid: u32| -> Option<String> { None };
    let ctx = Context {
        lineage: &lineage,
        users: &users,
        host_pid_namespace: Some(HOST_NS),
        invocations: &invocations,
        namespace_of: &namespace_of,
        container_of: &no_container,
        runtime_of: &no_context,
        audit: &audit,
    };

    let from_ebpf = exec(Some("/usr/bin/nmap"));
    let event = RuleEvent::new(Happening::Exec(&from_ebpf), &ctx);
    for name in ["evt.arg.filename", "proc.exepath"] {
        assert_eq!(
            event.field(name, None),
            Field::Value("/usr/bin/nmap".into()),
            "{name}"
        );
    }

    let from_connector = exec(None);
    let event = RuleEvent::new(Happening::Exec(&from_connector), &ctx);
    assert_eq!(event.field("evt.arg.filename", None), Field::Unknown);
    assert_eq!(event.field("proc.exepath", None), Field::Unknown);
}

/// A short-lived exec is gone before any sweep can read its namespace. When
/// the kernel placed it in the host's at the moment of the exec (the eBPF
/// source), `not container` is decided and a host rule fires; without that,
/// the rule stays undecided rather than guess.
#[test]
fn a_host_rule_fires_on_a_gone_process_only_when_the_kernel_placed_it() {
    use topgent_collect::process_events::{LifecycleEvent, LifecycleKind};

    let exec = |pid_namespace: Option<u64>| LifecycleEvent {
        kind: LifecycleKind::Exec,
        // Not running, and not in any agent's history.
        pid: 4_000_001,
        started_at: Some(UnixMillis(3_000)),
        name: Some("nmap".into()),
        program: Some("nmap".into()),
        path: Some("/usr/bin/nmap".into()),
        pid_namespace,
        uid: None,
        container: None,
        argv: None,
        loginuid: None,
        tty: None,
        cwd: None,
        at: UnixMillis(3_001),
    };
    let rules_on = |event: LifecycleEvent| -> Vec<String> {
        let sweep = Sweep {
            process_events: vec![event],
            processes: vec![running(1, 0, "systemd")],
            ..Sweep::default()
        };
        let users = BTreeMap::new();
        let cmdline = |_pid: u32| -> Option<Vec<String>> { None };
        let gone = |_pid: u32| -> Option<u64> { None };
        let no_container = |_pid: u32| -> Option<String> { None };
        evaluate_with(
            &mut Invocations::new(),
            &mut super::audit_tree::AuditTree::default(),
            &sweep,
            &lineage(),
            &Host {
                pid_namespace: Some(HOST_NS),
                users: &users,
                cmdline: &cmdline,
                namespace_of: &gone,
                container_of: &no_container,
                runtime_of: &no_context,
            },
        )
        .iter()
        .filter_map(|finding| finding["rule"].as_str().map(str::to_owned))
        .collect()
    };
    let placed = rules_on(exec(Some(HOST_NS)));
    assert!(
        placed
            .iter()
            .any(|rule| rule == "Launch Suspicious Network Tool on Host"),
        "{placed:?}"
    );
    let unplaced = rules_on(exec(None));
    assert!(
        !unplaced
            .iter()
            .any(|rule| rule == "Launch Suspicious Network Tool on Host"),
        "no finding on a guess: {unplaced:?}"
    );
}

/// E4: calls from the eBPF sensor fire the same rules Audit's do, with no
/// Audit at all, and are labelled with their source. A rule whose
/// exceptions read the command line stays undecided for a process whose
/// exec arguments were never seen, and says so, rather than firing on a
/// guess (the eBPF source does not yet read exec arguments).
#[test]
fn sensor_calls_fire_the_same_rules_with_no_audit() {
    use topgent_collect::process_events::{Line, parse_line};
    let lines = [
        r#"{"e":"sys","call":"openat","pid":11,"uid":1000,"ret":3,"args":[4294967196,0,0,0],"path":"/etc/shadow","name":"cat","seq":1,"at":5001}"#,
        r#"{"e":"sys","call":"openat","pid":11,"uid":1000,"ret":3,"args":[4294967196,0,577,0],"path":"/var/log/auth.log","name":"sh","seq":2,"at":5002}"#,
        r#"{"e":"sys","call":"ptrace","pid":11,"uid":1000,"ret":0,"args":[0,0,0,0],"name":"sh","seq":3,"at":5003}"#,
        r#"{"e":"sys","call":"openat","pid":11,"uid":1000,"ret":3,"args":[4294967196,0,577,420],"path":"/etc/cron.d/job","name":"python3","seq":4,"at":5004}"#,
        r#"{"e":"sys","call":"openat","pid":11,"uid":1000,"ret":3,"args":[4294967196,0,0,0],"path":"/home/user/.ssh/id_rsa","name":"python3","seq":5,"at":5005}"#,
        r#"{"e":"sys","call":"openat","pid":11,"uid":1000,"ret":3,"args":[4294967196,0,577,420],"path":"/dev/evil","name":"python3","seq":6,"at":5006}"#,
    ];
    let events: Vec<ObservedSyscall> = lines
        .iter()
        .map(|line| {
            let Some(Line::Syscall(call)) = parse_line(line) else {
                unreachable!("{line}")
            };
            let mut event = call.event;
            event.record = format!("5.{:03}:{}", call.seq, call.seq);
            ObservedSyscall {
                lineage_at: UnixMillis(event.at),
                event,
            }
        })
        .collect();
    let sweep = Sweep {
        syscall_events: events.clone(),
        processes: vec![running(1, 0, "systemd"), running(10, 1_000, "codex")],
        ..Sweep::default()
    };
    let users = BTreeMap::from([(0, "root".to_owned()), (1000, "user".to_owned())]);
    let cmdline = |_pid: u32| None;
    let namespace_of = |_pid: u32| Some(HOST_NS);
    let no_container = |_pid: u32| -> Option<String> { None };
    let rows = evaluate_with(
        &mut Invocations::new(),
        &mut super::audit_tree::AuditTree::default(),
        &sweep,
        &lineage(),
        &Host {
            pid_namespace: Some(HOST_NS),
            users: &users,
            cmdline: &cmdline,
            namespace_of: &namespace_of,
            container_of: &no_container,
            runtime_of: &no_context,
        },
    );
    let fired = fired(&rows);
    for expected in [
        ("Clear Log Activities", "sh"),
        ("PTRACE anti-debug attempt", "sh"),
        ("Schedule Cron Jobs", "python3"),
        ("Read ssh information", "python3"),
        ("Create files below dev", "python3"),
    ] {
        assert!(
            fired.contains(&(expected.0.to_owned(), expected.1.to_owned())),
            "{expected:?} missing from {fired:?}"
        );
    }
    assert!(rows.iter().all(|r| r["source"] == "ebpf"), "{rows:?}");
    assert!(
        !fired
            .iter()
            .any(|(rule, _)| rule == "Read sensitive file untrusted")
    );
    let why = undecided_events(&events, "Read sensitive file untrusted");
    assert!(
        why.iter()
            .any(|(_, fields)| fields.contains("proc.cmdline")),
        "{why:?}"
    );

    // With the exec's arguments, which the eBPF sensor reads, the same read
    // is decided, and fires.
    let Some(Line::Event(exec)) = parse_line(
        r#"{"e":"exec","pid":11,"start":2000,"name":"cat","program":"cat","path":"/usr/bin/cat","argv":["cat","/etc/shadow"],"at":5000}"#,
    ) else {
        unreachable!()
    };
    let sweep = Sweep {
        process_events: vec![exec],
        ..sweep
    };
    let parent = |pid: u32| (pid == 10).then(|| vec!["codex".to_owned(), "exec".to_owned()]);
    let rows = evaluate_with(
        &mut Invocations::new(),
        &mut super::audit_tree::AuditTree::default(),
        &sweep,
        &lineage(),
        &Host {
            pid_namespace: Some(HOST_NS),
            users: &users,
            cmdline: &parent,
            namespace_of: &namespace_of,
            container_of: &no_container,
            runtime_of: &no_context,
        },
    );
    let fired = super::tests::fired(&rows);
    assert!(
        fired.contains(&("Read sensitive file untrusted".to_owned(), "cat".to_owned())),
        "{fired:?}"
    );
}

/// E4: the container the eBPF sensor named from an event's own cgroup is
/// the event's `container.id`, in the rules' short form, even once the
/// process has gone and nothing could read its `/proc/<pid>/cgroup`.
#[test]
fn a_sensor_event_names_its_container() {
    use super::event::{Context, Happening, RuleEvent};
    use topgent_behaviour::event::{Event, Field};
    use topgent_collect::process_events::{Line, parse_line};
    let id = "0123456789ab".to_owned() + &"c".repeat(52);
    let Some(Line::Event(exec)) = parse_line(&format!(
        r#"{{"e":"exec","pid":77,"name":"cat","uid":999,"ctr":"{id}","at":5000}}"#
    )) else {
        unreachable!()
    };
    let lineage = lineage();
    // The host names uid 999, but inside a container it is whoever the
    // container's own accounts say.
    let users = BTreeMap::from([(999, "hostuser".to_owned())]);
    let known = Invocations::new();
    let gone = |_pid: u32| None;
    let no_container = |_pid: u32| -> Option<String> { None };
    let audit = super::audit_tree::AuditTree::build(&[]);
    let ctx = Context {
        lineage: &lineage,
        users: &users,
        host_pid_namespace: Some(HOST_NS),
        invocations: &known,
        namespace_of: &gone,
        container_of: &no_container,
        runtime_of: &no_context,
        audit: &audit,
    };
    let event = RuleEvent::new(Happening::Exec(&exec), &ctx);
    assert_eq!(
        event.field("proc.cmdline", None),
        Field::Unknown,
        "no arguments were read for this exec"
    );
    assert_eq!(
        event.field("container.id", None),
        Field::Value("0123456789ab".to_owned())
    );
    assert_eq!(
        event.field("user.uid", None),
        Field::Value("999".to_owned())
    );
    assert_eq!(event.field("user.name", None), Field::Unknown);
    assert_eq!(
        event.field("container.image.repository", None),
        Field::Unknown,
        "no runtime was asked"
    );

    // With the runtime's answer (E7): the image, the privilege, no pod, and
    // the container's own name for uid 999.
    let answered = |_id: &str| {
        Some(std::sync::Arc::new(
            topgent_collect::container_context::ContainerContext {
                image: Some("forgex".to_owned()),
                privileged: Some(false),
                accounts: Some(BTreeMap::from([(999, "appuser".to_owned())])),
                ..Default::default()
            },
        ))
    };
    let ctx_known = Context {
        runtime_of: &answered,
        ..ctx
    };
    let event = RuleEvent::new(Happening::Exec(&exec), &ctx_known);
    for (field, expected) in [
        (
            "container.image.repository",
            Field::Value("forgex".to_owned()),
        ),
        ("container.privileged", Field::Value("false".to_owned())),
        ("k8s.pod.name", Field::Absent),
        ("container.mount.dest", Field::Unknown),
        ("user.name", Field::Value("appuser".to_owned())),
    ] {
        assert_eq!(event.field(field, None), expected, "{field}");
    }

    // What the probe never read is unknown, not "none".
    let Some(Line::Syscall(call)) = parse_line(
        r#"{"e":"sys","call":"openat","pid":77,"ret":3,"path":"/etc/shadow","seq":1,"at":5001}"#,
    ) else {
        unreachable!()
    };
    let observed = ObservedSyscall {
        lineage_at: UnixMillis(5001),
        event: call.event,
    };
    let event = RuleEvent::new(Happening::Syscall(&observed), &ctx);
    assert_eq!(event.field("proc.tty", None), Field::Unknown);
    assert_eq!(event.field("user.loginuid", None), Field::Unknown);
}

/// E5: the live count is the delivering source's. Each lacks fields the
/// other has, and only eBPF names containers.
#[test]
fn the_live_count_is_the_delivering_sources() {
    let audit = super::catalogue_json_for("audit");
    let ebpf = super::catalogue_json_for("ebpf");
    assert_eq!(audit["syscall_source"], "audit");
    assert_eq!(audit["live"], audit["live_by_source"]["audit"]);
    assert_eq!(ebpf["live"], ebpf["live_by_source"]["ebpf"]);
    let live = |report: &Value, rule: &str| {
        report["coverage"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["rule"] == rule)
            .unwrap()["live"]
            .as_bool()
            .unwrap()
    };
    for (rule, on_audit, on_ebpf) in [
        ("Unexpected UDP Traffic", false, true),
        ("Launch Remote File Copy Tools in Container", false, true),
        // Reads the login uid: Audit has it; eBPF now supplies it too (E8).
        ("Sudo Potential Privilege Escalation", true, true),
        // Reads the permitted capability set, which only eBPF supplies (E8).
        ("Change namespace privileges via unshare", false, true),
        ("Read environment variable from /proc files", false, false),
    ] {
        assert_eq!(live(&audit, rule), on_audit, "{rule} on audit");
        assert_eq!(live(&ebpf, rule), on_ebpf, "{rule} on ebpf");
    }
}

/// E7: an exec by a process outside any agent's tree has its command line
/// from the exec's own name and arguments.
#[test]
fn an_exec_outside_any_agents_tree_has_its_command_line() {
    use super::event::{Context, Happening, RuleEvent};
    use topgent_behaviour::event::{Event, Field};
    use topgent_collect::process_events::{Line, parse_line};
    let Some(Line::Event(exec)) = parse_line(
        r#"{"e":"exec","pid":4242,"name":"dpkg","argv":["dpkg","--version"],"at":5000}"#,
    ) else {
        unreachable!()
    };
    let lineage = lineage();
    let users = BTreeMap::new();
    let mut known = Invocations::new();
    known.record(
        4242,
        super::invocations::Invocation {
            exe: None,
            argv: vec!["dpkg".to_owned(), "--version".to_owned()],
            at: UnixMillis(5000),
        },
    );
    let gone = |_pid: u32| None;
    let no_container = |_pid: u32| -> Option<String> { None };
    let audit = super::audit_tree::AuditTree::build(&[]);
    let ctx = Context {
        lineage: &lineage,
        users: &users,
        host_pid_namespace: Some(HOST_NS),
        invocations: &known,
        namespace_of: &gone,
        container_of: &no_container,
        runtime_of: &no_context,
        audit: &audit,
    };
    let event = RuleEvent::new(Happening::Exec(&exec), &ctx);
    assert_eq!(
        event.field("proc.cmdline", None),
        Field::Value("dpkg --version".to_owned())
    );
}

/// Recorded events replayed through the whole path a sweep takes: the rules,
/// placement on the agent run, then the named incidents. Each event is an
/// ordinary file or metadata call; the rules decide what it means.
#[test]
fn replayed_events_become_named_incidents_on_the_agent() {
    let audit = call(
        1,
        11,
        10,
        56,
        "success=yes exit=3 a0=ffffff9c a1=0 a2=241 a3=1a4 comm=\"sh\" exe=\"/usr/bin/dash\"",
        "type=CWD cwd=\"/tmp\"\ntype=PATH item=0 name=\"/etc/cron.d/lab-job\" nametype=CREATE",
    ) + &call(
        2,
        11,
        10,
        56,
        "success=yes exit=3 a0=ffffff9c a1=0 a2=241 a3=0 comm=\"sh\" exe=\"/usr/bin/dash\"",
        "type=CWD cwd=\"/tmp\"\ntype=PATH item=0 name=\"/var/log/auth.log\" nametype=NORMAL",
    ) + &call(
        3,
        11,
        10,
        117,
        "success=yes exit=0 a0=10 a1=1 a2=0 a3=0 comm=\"sh\" exe=\"/usr/bin/dash\"",
        "",
    ) + &call(
        4,
        11,
        10,
        221,
        "success=yes exit=0 a0=0 a1=0 a2=0 a3=0 comm=\"x\" exe=\"/dev/shm/x\"",
        "type=CWD cwd=\"/dev/shm\"\ntype=EXECVE argc=1 a0=\"./x\"",
    ) + &call(
        5,
        11,
        10,
        56,
        "success=yes exit=3 a0=ffffff9c a1=0 a2=0 a3=0 comm=\"python3\" exe=\"/usr/bin/python3.13\"",
        "type=CWD cwd=\"/home/user\"\ntype=PATH item=0 name=\"/home/user/.ssh/id_rsa\" nametype=NORMAL",
    );
    let rows = findings(&audit);
    let placed = super::findings::project(&json!({}), rows, &lineage(), &[key(10, 1_000)], "b");
    let rows: Vec<Value> = placed["rows"].as_array().unwrap().clone();
    let incidents = crate::rule_incidents::derive(&rows, &|_, _| Some("codex-cli".to_owned()));
    let kinds: std::collections::BTreeSet<&str> = incidents
        .iter()
        .filter_map(|i| i["kind"].as_str())
        .collect();
    for expected in [
        "persistence",
        "covering_tracks",
        "privilege_escalation",
        "remote_control",
        "credential_hunting",
    ] {
        assert!(
            kinds.contains(expected),
            "{expected} missing: {incidents:#?}"
        );
    }
    for incident in &incidents {
        assert_eq!(incident["agent"]["pid"], 10, "{incident}");
        assert_eq!(incident["agent"]["recognised"], true);
        assert!(
            !incident["evidence"]["findings"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
}

/// The control: ordinary work by the same agent raises no named incident.
#[test]
fn ordinary_work_raises_no_named_incident() {
    let audit = call(
        1,
        11,
        10,
        56,
        "success=yes exit=4 a0=ffffff9c a1=0 a2=241 a3=1a4 comm=\"sh\" exe=\"/usr/bin/dash\"",
        "type=CWD cwd=\"/home/user/project\"\ntype=PATH item=0 name=\"build.log\" nametype=CREATE",
    );
    let placed = super::findings::project(
        &json!({}),
        findings(&audit),
        &lineage(),
        &[key(10, 1_000)],
        "b",
    );
    let rows: Vec<Value> = placed["rows"].as_array().unwrap().clone();
    assert!(crate::rule_incidents::derive(&rows, &|_, _| None).is_empty());
}
