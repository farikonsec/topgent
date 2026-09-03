//! Scoring, without spawning anything.
//!
//! The fixture and the scorer are separate binaries so they cannot share a bug.
//! These tests keep the scorer honest on its own: every number below is checked
//! against a fact stream written by hand, so a change in the scoring rules
//! fails here rather than quietly moving a published result.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

use topgent_facts::{
    Claim, Confidence, Fact, Provenance, Reachability, SCHEMA_VERSION, Subject, UnixMillis,
};
use topgent_lab::bench::{
    GROUND_TRUTH_SCHEMA, GroundTruth, TruthProcess, TruthResource, TruthSocket, evaluate,
};

const SWEEP_MS: u64 = 1_000;

fn provenance() -> Provenance {
    Provenance {
        collector: "process".to_owned(),
        probe: "process table sweep".to_owned(),
        confidence: Confidence::Certain,
        observed_at: UnixMillis(1_756_000_000_000),
    }
}

fn fact(subject: Subject, claim: Claim) -> Fact {
    Fact::new(SCHEMA_VERSION, subject, claim, provenance()).unwrap()
}

fn process_subject(pid: u32) -> Subject {
    Subject::Process {
        pid,
        started_at: UnixMillis(1_755_900_000_000),
    }
}

fn truth() -> GroundTruth {
    GroundTruth {
        schema: GROUND_TRUTH_SCHEMA,
        root_pid: 100,
        root_exe: "/tmp/topgent-fixture-agent".to_owned(),
        started_at_ms: 1_756_000_000_000,
        ended_at_ms: 1_756_000_008_000,
        processes: vec![
            TruthProcess {
                pid: 100,
                name: "topgent-fixture-agent".to_owned(),
                parent_pid: 0,
                depth: 0,
                lifetime_ms: 8_000,
            },
            TruthProcess {
                pid: 101,
                name: "topgent-fixture-agent".to_owned(),
                parent_pid: 100,
                depth: 1,
                lifetime_ms: 8_000,
            },
            TruthProcess {
                pid: 102,
                name: "topgent-fixture-agent".to_owned(),
                parent_pid: 100,
                depth: 1,
                lifetime_ms: 40,
            },
        ],
        resources: vec![
            TruthResource {
                path: "/tmp/fixture/readable.txt".to_owned(),
                readable: true,
            },
            TruthResource {
                path: "/tmp/fixture/denied.txt".to_owned(),
                readable: false,
            },
        ],
        sockets: vec![TruthSocket {
            protocol: "tcp".to_owned(),
            local_port: 39_001,
            listening: true,
        }],
    }
}

fn seen(pid: u32) -> Fact {
    fact(
        process_subject(pid),
        Claim::ProcessSeen {
            exe: "/tmp/topgent-fixture-agent".to_owned(),
            exe_path_known: true,
            uid: 501,
            user: "operator".to_owned(),
        },
    )
}

#[test]
fn a_resident_process_is_recalled_and_a_short_lived_one_is_not() {
    let report = evaluate(&truth(), &[seen(100), seen(101)], SWEEP_MS);
    assert_eq!(report.processes.expected, 3);
    assert_eq!(report.processes.matched, 2);
    assert_eq!(report.lifetimes.resident.recall(), Some(1.0));
    assert_eq!(report.lifetimes.short_lived.recall(), Some(0.0));
    assert_eq!(report.lifetimes.short_lived.missed(), 1);
}

#[test]
fn an_empty_expectation_has_no_recall_rather_than_perfect_recall() {
    let mut empty = truth();
    empty.processes.clear();
    empty.sockets.clear();
    let report = evaluate(&empty, &[], SWEEP_MS);
    assert_eq!(report.processes.recall(), None);
    assert_eq!(report.sockets.recall(), None);
}

#[test]
fn the_fixture_being_called_an_agent_is_a_false_positive() {
    let facts = vec![
        seen(100),
        fact(
            process_subject(100),
            Claim::AgentFamily {
                family: "claude-code".to_owned(),
            },
        ),
    ];
    let report = evaluate(&truth(), &facts, SWEEP_MS);
    assert_eq!(report.false_agents, 1);
    // The false positive is called out, and the zeros still carry their own
    // reasons: one is not a substitute for the others.
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.metric == "false_agents"),
        "{:?}",
        report.notes
    );
}

#[test]
fn an_agent_family_on_an_unrelated_process_is_not_counted() {
    let facts = vec![
        seen(100),
        fact(
            process_subject(999),
            Claim::AgentFamily {
                family: "claude-code".to_owned(),
            },
        ),
    ];
    assert_eq!(evaluate(&truth(), &facts, SWEEP_MS).false_agents, 0);
}

#[test]
fn a_parent_edge_counts_only_when_the_parent_is_right() {
    let right = evaluate(
        &truth(),
        &[
            seen(101),
            fact(
                process_subject(101),
                Claim::ProcessParent { parent_pid: 100 },
            ),
        ],
        SWEEP_MS,
    );
    assert_eq!(right.ancestry.matched, 1);

    let wrong = evaluate(
        &truth(),
        &[
            seen(101),
            fact(process_subject(101), Claim::ProcessParent { parent_pid: 7 }),
        ],
        SWEEP_MS,
    );
    assert_eq!(wrong.ancestry.observed, 1);
    assert_eq!(wrong.ancestry.matched, 0);
}

#[test]
fn a_path_that_only_resolves_does_not_agree_with_a_readable_path() {
    let reachable = |path: &str, evidence| {
        fact(
            Subject::Resource {
                path: path.to_owned(),
            },
            Claim::ResourceReachable {
                path: path.to_owned(),
                access: topgent_facts::Access::Read,
                sensitive: true,
                evidence,
            },
        )
    };
    let report = evaluate(
        &truth(),
        &[
            reachable("/tmp/fixture/readable.txt", Reachability::PathResolves),
            reachable("/tmp/fixture/denied.txt", Reachability::PathResolves),
        ],
        SWEEP_MS,
    );
    assert_eq!(report.reachability.answered, 2);
    // `path_resolves` does not establish readability, so it agrees with the
    // denied path and disagrees with the readable one.
    assert_eq!(report.reachability.agreed, 1);
    assert_eq!(report.reachability.disagreed, 1);
    assert_eq!(report.reachability.accuracy(), Some(0.5));
}

#[test]
fn an_account_readable_answer_agrees_with_a_readable_path() {
    let report = evaluate(
        &truth(),
        &[fact(
            Subject::Resource {
                path: "/tmp/fixture/readable.txt".to_owned(),
            },
            Claim::ResourceReachable {
                path: "/tmp/fixture/readable.txt".to_owned(),
                access: topgent_facts::Access::Read,
                sensitive: true,
                evidence: Reachability::AccountReadable,
            },
        )],
        SWEEP_MS,
    );
    assert_eq!(report.reachability.agreed, 1);
    assert_eq!(report.reachability.disagreed, 0);
}

#[test]
fn a_clean_run_explains_every_structural_zero() {
    let report = evaluate(&truth(), &[seen(100)], SWEEP_MS);
    assert_eq!(report.false_agents, 0);
    let metrics: Vec<_> = report
        .notes
        .iter()
        .map(|note| note.metric.as_str())
        .collect();
    assert_eq!(metrics, ["ancestry", "sockets", "reachability"]);
    for note in &report.notes {
        assert!(note.text.len() > 40, "{note:?}");
    }
}

#[test]
fn a_socket_is_matched_on_the_port_the_fixture_recorded() {
    let report = evaluate(
        &truth(),
        &[fact(
            process_subject(100),
            Claim::SocketOpen {
                protocol: topgent_facts::Protocol::Tcp,
                host: "127.0.0.1".to_owned(),
                port: 39_001,
                direction: topgent_facts::Direction::Listening,
                opened_at: None,
                bytes: None,
                basis: topgent_facts::MatchBasis::Unreported,
            },
        )],
        SWEEP_MS,
    );
    assert_eq!(report.sockets.matched, 1);
    assert_eq!(report.sockets.recall(), Some(1.0));
}

#[test]
fn the_lifetime_split_is_reported_with_the_interval_it_used() {
    let report = evaluate(&truth(), &[], 5_000);
    assert_eq!(report.lifetimes.sweep_interval_ms, 5_000);
    assert_eq!(report.lifetimes.resident.expected, 2);
    assert_eq!(report.lifetimes.short_lived.expected, 1);
}

#[test]
fn a_ground_truth_from_another_schema_is_not_accepted() {
    let mut future = truth();
    future.schema = GROUND_TRUTH_SCHEMA + 1;
    assert!(!future.is_known_schema());
    assert!(truth().is_known_schema());
}
