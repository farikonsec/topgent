//! Whose action was this?
//!
//! Each fixture is a sequence a real host produces: a `cat` that read a file
//! and exited before any sweep, a pid reused a moment later, a process that
//! belongs to no agent at all. After the process is gone, is the action still
//! pinned on the right process and the right agent, and never on the wrong one?

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use topgent_core::attributed::attribute;
use topgent_core::lineage::{Lineage, Observation, ProcessKey};
use topgent_facts::UnixMillis;

fn key(pid: u32, started_at: u64) -> ProcessKey {
    ProcessKey {
        pid,
        started_at: UnixMillis(started_at),
    }
}

fn seen(lineage: &mut Lineage, pid: u32, started_at: u64, parent: Option<u32>, name: &str) {
    lineage.observe(Observation {
        key: key(pid, started_at),
        parent_pid: parent,
        name: name.to_owned(),
        exe: None,
        pid_namespace: None,
        at: UnixMillis(started_at),
        from_event: true,
    });
}

const AGENT: ProcessKey = ProcessKey {
    pid: 100,
    started_at: UnixMillis(1_000),
};

/// agent 100 → sh 200 → cat 201, which lived ten milliseconds.
fn burst() -> Lineage {
    let mut lineage = Lineage::new(1_024);
    seen(&mut lineage, 1, 0, None, "init");
    seen(&mut lineage, 100, 1_000, Some(1), "codex");
    seen(&mut lineage, 200, 2_000, Some(100), "sh");
    seen(&mut lineage, 201, 3_000, Some(200), "cat");
    lineage.exited_with(key(201, 3_000), UnixMillis(3_010), Some(0));
    lineage
}

#[test]
fn a_read_by_a_child_that_has_exited_is_pinned_on_it_and_its_agent() {
    let found = attribute(&burst(), &[AGENT], 201, UnixMillis(3_005)).expect("attributed");
    assert_eq!(found.actor, key(201, 3_000));
    assert_eq!(found.agent, AGENT);
    assert_eq!(found.chain, vec![200, 201]);
}

#[test]
fn the_agents_own_action_has_no_chain() {
    let found = attribute(&burst(), &[AGENT], 100, UnixMillis(3_005)).expect("attributed");
    assert_eq!(found.actor, AGENT);
    assert!(found.chain.is_empty());
}

/// The control: the same file read by a shell nobody's agent started.
#[test]
fn a_process_outside_every_agent_is_not_attributed() {
    let mut lineage = burst();
    seen(&mut lineage, 900, 2_500, Some(1), "bash");
    assert_eq!(attribute(&lineage, &[AGENT], 900, UnixMillis(3_005)), None);
    assert_eq!(
        attribute(&lineage, &[AGENT], 4_242, UnixMillis(3_005)),
        None,
        "unknown pid"
    );
}

/// pid 201 is reused by an unrelated process after `cat` exits. Its action
/// is not the agent's, and nothing between the two runs is anyone's.
#[test]
fn a_reused_pid_never_inherits_the_agents_attribution() {
    let mut lineage = burst();
    seen(&mut lineage, 201, 5_000, Some(1), "ssh");
    assert_eq!(attribute(&lineage, &[AGENT], 201, UnixMillis(5_500)), None);
    assert_eq!(
        attribute(&lineage, &[AGENT], 201, UnixMillis(4_000)),
        None,
        "between runs"
    );
    assert_eq!(
        attribute(&lineage, &[AGENT], 201, UnixMillis(3_005)).map(|found| found.actor),
        Some(key(201, 3_000)),
        "the first run is still itself"
    );
}

/// An agent that starts another agent: the nearer one answers for its child.
#[test]
fn a_nested_agents_child_is_pinned_on_the_nearer_agent() {
    let mut lineage = burst();
    seen(&mut lineage, 300, 2_200, Some(100), "claude");
    seen(&mut lineage, 301, 2_300, Some(300), "curl");
    let inner = key(300, 2_200);
    let found = attribute(&lineage, &[AGENT, inner], 301, UnixMillis(2_400)).expect("found");
    assert_eq!(found.agent, inner);
    assert_eq!(found.chain, vec![301]);
}

/// Audit stamps records with the kernel's coarse clock, a tick behind. On
/// Kali the credential read of a `cat` that lived 2 ms was stamped 2 ms
/// before the start the process connector recorded for it.
#[test]
fn a_record_stamped_a_tick_before_its_actors_start_is_still_its_actors() {
    let found = attribute(&burst(), &[AGENT], 201, UnixMillis(2_998)).expect("attributed");
    assert_eq!(found.actor, key(201, 3_000));
}

/// The same early stamp, but another run of that pid ended a moment before:
/// either could have acted, so neither is chosen.
#[test]
fn an_early_stamp_between_two_runs_of_one_pid_is_nobodys() {
    let mut lineage = Lineage::new(1_024);
    seen(&mut lineage, 1, 0, None, "init");
    seen(&mut lineage, 100, 1_000, Some(1), "codex");
    seen(&mut lineage, 201, 2_000, Some(1), "ssh");
    lineage.exited_with(key(201, 2_000), UnixMillis(2_997), Some(0));
    seen(&mut lineage, 201, 3_000, Some(100), "cat");
    assert_eq!(attribute(&lineage, &[AGENT], 201, UnixMillis(2_998)), None);
}

/// Slack for a coarse clock is not a licence to reach back arbitrarily.
#[test]
fn a_record_well_before_its_actors_start_is_not_attributed() {
    assert_eq!(attribute(&burst(), &[AGENT], 201, UnixMillis(2_950)), None);
}

/// The live Kali miss: the `cat` lived 3 ms, so it had already exited by the
/// end of the slack. The record still belongs to the one run that started
/// within the slack after its stamp.
#[test]
fn an_early_stamp_finds_a_run_that_exited_within_the_slack() {
    let mut lineage = Lineage::new(1_024);
    seen(&mut lineage, 1, 0, None, "init");
    seen(&mut lineage, 100, 1_000, Some(1), "codex");
    seen(&mut lineage, 201, 3_000, Some(100), "cat");
    lineage.exited_with(key(201, 3_000), UnixMillis(3_003), Some(0));
    let found = attribute(&lineage, &[AGENT], 201, UnixMillis(2_999)).expect("attributed");
    assert_eq!(found.actor, key(201, 3_000));
}
