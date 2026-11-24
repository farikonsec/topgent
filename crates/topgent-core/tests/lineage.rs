//! Process history that outlives the processes.
//!
//! Every fixture here is a sequence a real host produces: a pid reused, a
//! program that execs another, a shell that exits and leaves its child to be
//! adopted by init, records that arrive in the wrong order. The question each
//! answers is the same: after the process is gone, can Topgent still say who
//! it was and whose it was, and never say that of the wrong process?

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::collections::BTreeSet;

use topgent_core::lineage::{Lineage, Observation, ProcessKey, ProcessState};
use topgent_facts::UnixMillis;

fn key(pid: u32, started_at: u64) -> ProcessKey {
    ProcessKey {
        pid,
        started_at: UnixMillis(started_at),
    }
}

fn seen(pid: u32, started_at: u64, parent_pid: Option<u32>, name: &str, at: u64) -> Observation {
    Observation {
        key: key(pid, started_at),
        parent_pid,
        name: name.to_owned(),
        exe: Some(format!("/usr/bin/{name}")),
        pid_namespace: None,
        at: UnixMillis(at),
        from_event: false,
    }
}

const AGENT: (u32, u64) = (100, 1_000);

fn with_agent() -> Lineage {
    let mut lineage = Lineage::new(1_024);
    lineage.observe(seen(AGENT.0, AGENT.1, Some(1), "codex", 1_000));
    lineage
}

fn pids(records: &[&topgent_core::lineage::ProcessRecord]) -> Vec<u32> {
    let mut pids: Vec<u32> = records.iter().map(|record| record.key.pid).collect();
    pids.sort_unstable();
    pids
}

/// A shell that starts a worker and exits: the worker is adopted by init and
/// its parent pid becomes 1. It is still the agent's worker.
#[test]
fn a_detached_worker_stays_attributed_after_its_parent_exits_and_it_is_reparented() {
    let mut lineage = with_agent();
    lineage.observe(seen(200, 2_000, Some(100), "sh", 2_000));
    lineage.observe(seen(201, 2_100, Some(200), "sleep", 2_100));
    // Next sweep: the shell is gone and init has adopted the worker.
    lineage.missing(
        &BTreeSet::from([key(100, 1_000), key(201, 2_100)]),
        UnixMillis(9_000),
    );
    lineage.observe(seen(201, 2_100, Some(1), "sleep", 9_000));

    let agent = key(AGENT.0, AGENT.1);
    assert_eq!(pids(&lineage.descendants(agent)), vec![200, 201]);
    let worker = lineage.get(key(201, 2_100)).expect("worker kept");
    assert_eq!(worker.parent, Some(key(200, 2_000)), "the parent it had");
    assert!(worker.reparented, "and that it was adopted");
    assert_eq!(worker.state(), ProcessState::Running);
    let shell = lineage.get(key(200, 2_000)).expect("shell kept");
    assert_eq!(shell.state(), ProcessState::Gone);
    assert_eq!(
        lineage.ancestry(key(201, 2_100)),
        vec![key(200, 2_000), agent],
        "the chain survives the middle of it exiting"
    );
}

/// A pid is reused once its process is gone. The new occupant is a different
/// process and inherits nothing.
#[test]
fn a_reused_pid_inherits_nothing() {
    let mut lineage = with_agent();
    lineage.observe(seen(300, 3_000, Some(100), "cat", 3_000));
    lineage.missing(&BTreeSet::from([key(100, 1_000)]), UnixMillis(4_000));
    // Same pid, later start, parented by something that is not the agent.
    lineage.observe(seen(300, 5_000, Some(1), "cron", 5_000));

    let agent = key(AGENT.0, AGENT.1);
    let descendants = lineage.descendants(agent);
    assert_eq!(descendants.len(), 1);
    assert_eq!(descendants[0].key, key(300, 3_000));
    assert_eq!(lineage.get(key(300, 5_000)).unwrap().parent, None);
}

/// Two processes can hold one pid within the same second. With start times in
/// whole seconds they were one identity; with the kernel's own start time they
/// are two.
#[test]
fn a_pid_reused_inside_one_second_is_still_two_processes() {
    let mut lineage = with_agent();
    lineage.observe(seen(400, 6_010, Some(100), "sh", 6_010));
    lineage.missing(&BTreeSet::from([key(100, 1_000)]), UnixMillis(6_500));
    lineage.observe(seen(400, 6_930, Some(1), "other", 6_930));
    assert!(lineage.get(key(400, 6_010)).is_some());
    assert!(lineage.get(key(400, 6_930)).is_some());
    assert_eq!(pids(&lineage.descendants(key(AGENT.0, AGENT.1))), vec![400]);
    assert_eq!(
        lineage.descendants(key(AGENT.0, AGENT.1))[0].key,
        key(400, 6_010)
    );
}

/// A child's parent is the process that held the parent pid when the child
/// started, not whichever process holds it now.
#[test]
fn a_parent_is_resolved_as_of_the_childs_start() {
    let mut lineage = with_agent();
    // pid 500 was the agent's shell, exited, and was reused.
    lineage.observe(seen(500, 7_000, Some(100), "sh", 7_000));
    lineage.observe(seen(501, 7_100, Some(500), "curl", 7_100));
    lineage.exited(key(500, 7_000), UnixMillis(7_200));
    lineage.observe(seen(500, 8_000, Some(1), "unrelated", 8_000));
    assert_eq!(
        lineage.get(key(501, 7_100)).unwrap().parent,
        Some(key(500, 7_000))
    );
    // A child of the new occupant is not the agent's.
    lineage.observe(seen(502, 8_100, Some(500), "ls", 8_100));
    assert_eq!(
        lineage.get(key(502, 8_100)).unwrap().parent,
        Some(key(500, 8_000))
    );
    assert!(!pids(&lineage.descendants(key(AGENT.0, AGENT.1))).contains(&502));
}

/// `exec` keeps the process and replaces the program. The history says both.
#[test]
fn an_exec_keeps_the_identity_and_records_the_program_it_replaced() {
    let mut lineage = with_agent();
    lineage.observe(seen(600, 9_000, Some(100), "sh", 9_000));
    let mut after = seen(600, 9_000, Some(100), "python3", 9_500);
    after.exe = Some("/usr/bin/python3".to_owned());
    lineage.observe(after);
    let record = lineage.get(key(600, 9_000)).unwrap();
    assert_eq!(record.exec_generation, 1);
    assert_eq!(record.exe.as_deref(), Some("/usr/bin/python3"));
    assert_eq!(record.previous_exes, vec!["/usr/bin/sh".to_owned()]);
}

/// Records arrive out of order: a child before its parent, an exit before the
/// process was ever seen. Nothing is guessed while waiting, and everything
/// resolves once the missing record arrives.
#[test]
fn out_of_order_records_resolve_when_the_missing_one_arrives() {
    let mut lineage = Lineage::new(1_024);
    lineage.exited(key(701, 10_100), UnixMillis(10_300));
    lineage.observe(seen(701, 10_100, Some(700), "cat", 10_100));
    assert_eq!(
        lineage.get(key(701, 10_100)).unwrap().parent,
        None,
        "not yet"
    );
    assert_eq!(
        lineage.get(key(701, 10_100)).unwrap().state(),
        ProcessState::Exited
    );
    lineage.observe(seen(700, 10_000, Some(1), "codex", 10_000));
    assert_eq!(
        lineage.get(key(701, 10_100)).unwrap().parent,
        Some(key(700, 10_000))
    );
}

/// The same records in any order build the same history.
#[test]
fn replay_order_does_not_change_the_history() {
    let records = [
        seen(AGENT.0, AGENT.1, Some(1), "codex", 1_000),
        seen(200, 2_000, Some(100), "sh", 2_000),
        seen(201, 2_100, Some(200), "sleep", 2_100),
        seen(202, 2_200, Some(201), "cat", 2_200),
    ];
    let build = |order: &[usize]| {
        let mut lineage = Lineage::new(1_024);
        for index in order {
            lineage.observe(records[*index].clone());
        }
        lineage
            .records()
            .map(|record| (record.key, record.parent))
            .collect::<Vec<_>>()
    };
    let expected = build(&[0, 1, 2, 3]);
    for order in [[3, 2, 1, 0], [1, 3, 0, 2], [2, 0, 3, 1]] {
        assert_eq!(build(&order), expected, "{order:?}");
    }
}

/// A container's processes live in their own pid namespace. The host sees
/// host pids, so the link to the process that started the container holds,
/// and the boundary is recorded rather than hidden.
#[test]
fn a_pid_namespace_boundary_is_recorded_and_does_not_break_the_chain() {
    let mut lineage = with_agent();
    let mut runtime = seen(800, 11_000, Some(100), "docker", 11_000);
    runtime.pid_namespace = Some(4_026_531_836);
    lineage.observe(runtime);
    let mut inside = seen(801, 11_100, Some(800), "node", 11_100);
    inside.pid_namespace = Some(4_026_532_999);
    lineage.observe(inside);
    let record = lineage.get(key(801, 11_100)).unwrap();
    assert_eq!(record.parent, Some(key(800, 11_000)));
    assert!(record.crossed_namespace);
    assert!(!lineage.get(key(800, 11_000)).unwrap().crossed_namespace);
}

/// A snapshot that does not see a process says it is gone, not that it exited
/// then. The last sighting and the exit are different facts.
#[test]
fn a_process_missing_from_a_snapshot_is_gone_not_exited() {
    let mut lineage = with_agent();
    lineage.observe(seen(900, 12_000, Some(100), "sleep", 12_500));
    lineage.missing(&BTreeSet::from([key(100, 1_000)]), UnixMillis(15_000));
    let record = lineage.get(key(900, 12_000)).unwrap();
    assert_eq!(record.state(), ProcessState::Gone);
    assert_eq!(record.last_seen, UnixMillis(12_500));
    assert_eq!(record.exited_at, None);
    // Seen again: a snapshot missed it, and it is running after all.
    lineage.observe(seen(900, 12_000, Some(100), "sleep", 16_000));
    assert_eq!(
        lineage.get(key(900, 12_000)).unwrap().state(),
        ProcessState::Running
    );
}

/// The history is bounded. Finished processes are dropped oldest first; a
/// running one never is.
#[test]
fn the_history_is_bounded_and_keeps_what_is_running() {
    let mut lineage = Lineage::new(8);
    lineage.observe(seen(AGENT.0, AGENT.1, Some(1), "codex", 1_000));
    for n in 0..20_u32 {
        let start = 20_000 + u64::from(n) * 10;
        lineage.observe(seen(1_000 + n, start, Some(100), "task", start));
        lineage.exited(key(1_000 + n, start), UnixMillis(start + 5));
    }
    assert!(lineage.len() <= 8);
    assert!(
        lineage.get(key(AGENT.0, AGENT.1)).is_some(),
        "running, kept"
    );
    assert!(
        lineage.get(key(1_019, 20_190)).is_some(),
        "newest finished kept"
    );
    assert!(
        lineage.get(key(1_000, 20_000)).is_none(),
        "oldest finished dropped"
    );
}

/// A parent loop in hostile or corrupt input must not hang a walk.
#[test]
fn ancestry_stops_on_a_loop() {
    let mut lineage = Lineage::new(64);
    lineage.observe(seen(10, 100, Some(11), "a", 100));
    lineage.observe(seen(11, 100, Some(10), "b", 100));
    assert!(lineage.ancestry(key(10, 100)).len() <= 64);
}

/// The live burst's miss: a shell's child execs `cat` and is gone within a
/// millisecond, before its program or name can be read. The kernel said it
/// exec'd. Keeping the shell's program as if it still ran would be a claim
/// the evidence does not support; the record says the exec happened and the
/// program is unknown.
#[test]
fn an_exec_whose_program_was_unreadable_is_recorded_as_unknown_not_as_the_old_program() {
    let mut lineage = with_agent();
    lineage.observe(seen(300, 3_000, Some(100), "sh", 3_000));
    lineage.exec_unread(key(300, 3_000), UnixMillis(3_001));
    let record = lineage.get(key(300, 3_000)).expect("recorded");
    assert_eq!(record.exec_generation, 1);
    assert_eq!(record.exe, None, "the old program is not the current one");
    assert_eq!(record.previous_exes, vec!["/usr/bin/sh".to_owned()]);
    assert!(record.program_unread);
    // A later readable exec replaces the unknown.
    lineage.observe(Observation {
        exe: Some("/usr/bin/cat".to_owned()),
        ..seen(300, 3_000, Some(100), "cat", 3_002)
    });
    let record = lineage.get(key(300, 3_000)).expect("recorded");
    assert!(!record.program_unread);
    assert_eq!(record.exe.as_deref(), Some("/usr/bin/cat"));
}
