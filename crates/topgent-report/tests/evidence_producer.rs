//! What must hold for a sweep to become evidence anyone can check.
//!
//! These tests exist because the evidence format was complete and unreachable:
//! every record type, the chain, the checkpoints and the verifier were built
//! and tested, and no scan produced one. The tests below are about the path
//! between the two, so they check the joins rather than re-checking the crate
//! underneath.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

use topgent_collect::{CapabilityState, CollectorRun};
use topgent_evidence::{Canonical, CollectionCoverage, Limitation, Origin, Reader, SensorKey};
use topgent_facts::{Claim, Confidence, Fact, Provenance, Subject, UnixMillis};
use topgent_report::{bundle_from_sweep, coverage_for, limitations_for, redaction_gate};

/// A time inside the window records are accepted in.
const OBSERVED: u64 = 1_756_000_000_000;

fn origin() -> Origin {
    Origin {
        host_id: "host".to_owned(),
        boot_id: "boot".to_owned(),
        sensor_instance: "instance".to_owned(),
    }
}

fn key() -> SensorKey {
    SensorKey::from_seed([7_u8; 32]).expect("a fixed seed is a usable key")
}

fn run(collector: &'static str, state: CapabilityState, dropped: Option<u64>) -> CollectorRun {
    CollectorRun {
        collector,
        state,
        fact_count: 0,
        duration_ms: 0,
        detail: None,
        dropped_events: dropped,
        boundary: None,
    }
}

fn fact_from(collector: &str, pid: u32, exe: &str) -> Fact {
    Fact::new(
        topgent_facts::SCHEMA_VERSION,
        Subject::Process {
            pid,
            started_at: UnixMillis(OBSERVED),
        },
        Claim::ProcessSeen {
            exe: exe.to_owned(),
            exe_path_known: true,
            uid: 501,
            user: "someone".to_owned(),
        },
        Provenance {
            collector: collector.to_owned(),
            probe: "test".to_owned(),
            confidence: Confidence::Certain,
            observed_at: UnixMillis(OBSERVED),
        },
    )
    .expect("a well-formed fact")
}

#[test]
fn a_sweep_becomes_a_bundle_that_verifies_under_a_key_held_elsewhere() {
    let facts = vec![
        fact_from("process", 10, "/usr/bin/one"),
        fact_from("process", 11, "/usr/bin/two"),
    ];
    let runs = vec![run("process", CapabilityState::Available, None)];
    let key = key();

    let bundle = bundle_from_sweep(&facts, &runs, &[], &origin(), &key, 400)
        .expect("the sweep is admissible");

    assert_eq!(bundle.ledger().record_count(), 2);
    assert_eq!(
        bundle.checkpoints().len(),
        1,
        "one checkpoint covers the run"
    );

    // The verifier is handed only the public half, exactly as an operator would
    // hold it. A bundle that could nominate its own key would prove nothing.
    let verdict = bundle.verify(&[key.public().clone()]);
    assert!(
        verdict.is_intact(),
        "a freshly written bundle must verify: {:?}",
        verdict.breaches()
    );
}

#[test]
fn a_written_bundle_reads_back_as_the_same_bundle() {
    let facts = vec![fact_from("process", 10, "/usr/bin/one")];
    let runs = vec![run("process", CapabilityState::Available, None)];
    let bundle = bundle_from_sweep(&facts, &runs, &[], &origin(), &key(), 400).expect("admissible");

    let bytes = Canonical::of(&bundle);
    let read_back = Reader::read::<topgent_evidence::Bundle>(&bytes).expect("decodes");

    assert_eq!(read_back.digest(), bundle.digest());
    assert_eq!(read_back.ledger().record_count(), 1);
}

#[test]
fn sequence_follows_canonical_order_not_the_order_collectors_returned_them() {
    let runs = vec![run("process", CapabilityState::Available, None)];
    let forwards = vec![
        fact_from("process", 10, "/usr/bin/one"),
        fact_from("process", 11, "/usr/bin/two"),
    ];
    let backwards = vec![
        fact_from("process", 11, "/usr/bin/two"),
        fact_from("process", 10, "/usr/bin/one"),
    ];

    let first =
        bundle_from_sweep(&forwards, &runs, &[], &origin(), &key(), 400).expect("admissible");
    let second =
        bundle_from_sweep(&backwards, &runs, &[], &origin(), &key(), 400).expect("admissible");

    assert_eq!(
        first.digest(),
        second.digest(),
        "the same facts in a different arrival order must produce the same bundle"
    );
}

#[test]
fn a_fact_naming_a_collector_that_did_not_run_is_refused() {
    let facts = vec![fact_from("ghost", 10, "/usr/bin/one")];
    let runs = vec![run("process", CapabilityState::Available, None)];

    let error = bundle_from_sweep(&facts, &runs, &[], &origin(), &key(), 400)
        .expect_err("a fact with no collector run cannot be given a coverage");

    assert!(
        error.to_string().contains("ghost"),
        "the error names the collector: {error}"
    );
}

#[test]
fn the_gate_refuses_a_field_holding_content_rather_than_metadata() {
    // Nothing in the fact vocabulary is prose. Every field is a path, a process
    // name, a user name or a host name. A value this long is content that has
    // arrived somewhere it must never reach, and the whole bundle is refused
    // rather than the field being truncated: a shortened record still says it
    // observed something it did not.
    let long = "a".repeat(topgent_report::evidence::MAX_ADMISSIBLE_TEXT + 1);
    let smuggled = Fact::new(
        topgent_facts::SCHEMA_VERSION,
        Subject::Resource { path: long.clone() },
        Claim::FileTouched {
            path: "/tmp/x".to_owned(),
            access: topgent_facts::Access::Read,
        },
        Provenance {
            collector: "filesystem".to_owned(),
            probe: "test".to_owned(),
            confidence: Confidence::Certain,
            observed_at: UnixMillis(OBSERVED),
        },
    )
    .expect("a well-formed fact");

    assert!(
        redaction_gate(&smuggled).is_err(),
        "an oversized subject path must be refused"
    );

    let runs = vec![run("filesystem", CapabilityState::Available, None)];
    let error = bundle_from_sweep(&[smuggled], &runs, &[], &origin(), &key(), 400)
        .expect_err("the gate refuses the whole bundle, not just the field");
    assert!(
        error.to_string().contains("subject.path"),
        "the refusal names the field: {error}"
    );
}

#[test]
fn the_gate_refuses_content_in_a_claim_field_as_well_as_a_subject() {
    let long = "b".repeat(topgent_report::evidence::MAX_ADMISSIBLE_TEXT + 1);
    let smuggled = Fact::new(
        topgent_facts::SCHEMA_VERSION,
        Subject::Process {
            pid: 1,
            started_at: UnixMillis(OBSERVED),
        },
        Claim::FileTouched {
            path: long,
            access: topgent_facts::Access::Read,
        },
        Provenance {
            collector: "filesystem".to_owned(),
            probe: "test".to_owned(),
            confidence: Confidence::Certain,
            observed_at: UnixMillis(OBSERVED),
        },
    )
    .expect("a well-formed fact");

    let error = redaction_gate(&smuggled).expect_err("an oversized claim path must be refused");
    assert!(
        error.to_string().contains("claim.path"),
        "the refusal names the field: {error}"
    );
}

#[test]
fn the_gate_refuses_an_oversized_probe_string() {
    let smuggled = Fact::new(
        topgent_facts::SCHEMA_VERSION,
        Subject::Process {
            pid: 1,
            started_at: UnixMillis(OBSERVED),
        },
        Claim::ProcessSeen {
            exe: "/usr/bin/one".to_owned(),
            exe_path_known: true,
            uid: 0,
            user: "root".to_owned(),
        },
        Provenance {
            collector: "process".to_owned(),
            probe: "c".repeat(topgent_report::evidence::MAX_ADMISSIBLE_TEXT + 1),
            confidence: Confidence::Certain,
            observed_at: UnixMillis(OBSERVED),
        },
    )
    .expect("a well-formed fact");

    assert!(
        redaction_gate(&smuggled).is_err(),
        "the probe string is where a command line would arrive"
    );
}

#[test]
fn a_collector_that_reported_loss_can_never_claim_completeness() {
    let lossy = run("network_event", CapabilityState::Available, Some(3));
    assert_eq!(coverage_for(&lossy), CollectionCoverage::LossObserved);
    assert!(
        limitations_for(&lossy).contains(&Limitation::EventsDropped),
        "loss is stated on the record, not left to the reader"
    );
}

#[test]
fn only_a_collector_that_measured_zero_drops_may_say_complete() {
    let measured = run("network_event", CapabilityState::Available, Some(0));
    assert_eq!(
        coverage_for(&measured),
        CollectionCoverage::CompleteForWindow
    );

    // A collector that does not account for drops has said nothing about the
    // interval between two sweeps, so it gets the weaker word.
    let unmeasured = run("process", CapabilityState::Available, None);
    assert_eq!(coverage_for(&unmeasured), CollectionCoverage::SnapshotOnly);
}

#[test]
fn an_unsupported_or_refused_collector_is_never_recorded_as_healthy() {
    assert_eq!(
        coverage_for(&run("reach", CapabilityState::Unsupported, None)),
        CollectionCoverage::Unsupported
    );
    assert_eq!(
        coverage_for(&run("reach", CapabilityState::PermissionRequired, None)),
        CollectionCoverage::CollectorDegraded
    );
    assert_eq!(
        coverage_for(&run("reach", CapabilityState::Error, None)),
        CollectionCoverage::CollectorDegraded
    );
}

#[test]
fn replaying_one_bundle_twice_produces_identical_output() {
    let facts = vec![
        fact_from("process", 10, "/usr/bin/one"),
        fact_from("process", 11, "/usr/bin/two"),
    ];
    let runs = vec![run("process", CapabilityState::Available, None)];
    let bundle = bundle_from_sweep(&facts, &runs, &[], &origin(), &key(), 400).expect("admissible");
    let policy = topgent_policy::Policy::default();

    let first = topgent_report::replay(&bundle, &policy).to_string();
    let second = topgent_report::replay(&bundle, &policy).to_string();

    assert_eq!(first, second, "a replay that reads a clock is not a replay");
}

#[test]
fn a_replay_names_the_bundle_it_came_from() {
    let facts = vec![fact_from("process", 10, "/usr/bin/one")];
    let runs = vec![run("process", CapabilityState::Available, None)];
    let bundle = bundle_from_sweep(&facts, &runs, &[], &origin(), &key(), 400).expect("admissible");

    let projected = topgent_report::replay(&bundle, &topgent_policy::Policy::default());

    assert_eq!(
        projected["bundle_digest"].as_str(),
        Some(bundle.digest().as_str()),
        "a finding that cannot name its source is not reproducible"
    );
    assert_eq!(projected["record_count"].as_u64(), Some(1));
    assert_eq!(
        projected["observed_through"].as_u64(),
        Some(OBSERVED),
        "the projection is dated from the bundle, never from now"
    );
}

/// The facts that make one process a recognised agent.
///
/// A `ProcessSeen` alone is a process, not an agent; recognition needs the
/// family claim the detection collector emits. Both facts go into the bundle so
/// the claims written from the scoring have records to cite.
fn agent_facts(pid: u32) -> Vec<Fact> {
    vec![
        fact_from("process", pid, "/usr/bin/claude"),
        Fact::new(
            topgent_facts::SCHEMA_VERSION,
            Subject::Process {
                pid,
                started_at: UnixMillis(OBSERVED),
            },
            Claim::AgentFamily {
                family: "claude-code".to_owned(),
            },
            Provenance {
                collector: "process".to_owned(),
                probe: "test".to_owned(),
                confidence: Confidence::Certain,
                observed_at: UnixMillis(OBSERVED),
            },
        )
        .expect("a well-formed fact"),
    ]
}

/// The scoring of those facts, as the live path would produce it.
fn scored_agent(pid: u32) -> (topgent_core::Agent, topgent_core::Risk) {
    let scored = topgent_core::analyse_with(&agent_facts(pid), &topgent_policy::Policy::default());
    scored
        .into_iter()
        .next()
        .expect("a recognised family makes one agent")
}

#[test]
fn every_risk_factor_becomes_a_claim_that_cites_its_records() {
    let facts = agent_facts(10);
    let runs = vec![run("process", CapabilityState::Available, None)];
    let scored = vec![scored_agent(10)];

    let bundle =
        bundle_from_sweep(&facts, &runs, &scored, &origin(), &key(), 400).expect("admissible");

    let factors = scored
        .first()
        .map(|(_, risk)| risk.factors.len())
        .unwrap_or_default();
    assert_eq!(
        bundle.ledger().claim_count(),
        factors,
        "one claim per factor, so a number on a screen can be walked back"
    );
    for claim in bundle.ledger().claims() {
        assert!(
            !claim.referenced().is_empty(),
            "a claim that cites nothing is not evidence"
        );
        assert!(
            claim.statement().len() > 3,
            "a claim has to say what it found"
        );
    }
}

#[test]
fn a_claim_names_the_rule_version_that_drew_it() {
    let facts = agent_facts(10);
    let runs = vec![run("process", CapabilityState::Available, None)];
    let scored = vec![scored_agent(10)];

    let bundle =
        bundle_from_sweep(&facts, &runs, &scored, &origin(), &key(), 400).expect("admissible");

    for claim in bundle.ledger().claims() {
        assert_eq!(
            claim.rule().version,
            topgent_report::RULE_CATALOGUE_VERSION,
            "a finding read years later has to say which rules produced it"
        );
        assert!(claim.rule().name.starts_with("risk."));
    }
}

#[test]
fn an_agent_with_no_records_in_the_bundle_gets_no_claims() {
    // The scored agent is pid 99; the bundle holds records for pid 10 only.
    // Writing a claim here would produce a citation to nothing.
    let facts = agent_facts(10);
    let runs = vec![run("process", CapabilityState::Available, None)];
    let scored = vec![scored_agent(99)];

    let bundle =
        bundle_from_sweep(&facts, &runs, &scored, &origin(), &key(), 400).expect("admissible");

    assert_eq!(bundle.ledger().claim_count(), 0);
}

#[test]
fn a_bundle_carrying_claims_still_verifies() {
    let facts = agent_facts(10);
    let runs = vec![run("process", CapabilityState::Available, None)];
    let scored = vec![scored_agent(10)];
    let key = key();

    let bundle =
        bundle_from_sweep(&facts, &runs, &scored, &origin(), &key, 400).expect("admissible");

    let verdict = bundle.verify(&[key.public().clone()]);
    assert!(
        verdict.is_intact(),
        "claims must not break the chain: {:?}",
        verdict.breaches()
    );
}

#[test]
fn a_claim_is_never_more_covered_than_its_weakest_record() {
    // The reach collector accounts for no drops, so its records are snapshots.
    // A claim resting on one of them may not say more than snapshot_only.
    let facts = agent_facts(10);
    let runs = vec![run("process", CapabilityState::Available, None)];
    let scored = vec![scored_agent(10)];

    let bundle =
        bundle_from_sweep(&facts, &runs, &scored, &origin(), &key(), 400).expect("admissible");

    for claim in bundle.ledger().claims() {
        assert_eq!(claim.coverage(), CollectionCoverage::SnapshotOnly);
    }
}

#[test]
fn a_simulation_never_reaches_an_enforcement_path() {
    // The guarantee is structural, not a promise: `simulate` takes a bundle and
    // two policies and returns a value. It holds no handle to anything that
    // could act. This asserts the output says so, so a reader of the JSON
    // cannot mistake a simulation for something that happened.
    let facts = agent_facts(10);
    let runs = vec![run("process", CapabilityState::Available, None)];
    let scored = vec![scored_agent(10)];
    let bundle =
        bundle_from_sweep(&facts, &runs, &scored, &origin(), &key(), 400).expect("admissible");
    let policy = topgent_policy::Policy::default();

    let diff = topgent_report::simulate(&bundle, &policy, &policy);

    assert_eq!(
        diff["enforcement"].as_str(),
        Some("none: a simulation never executes a response")
    );
    assert_eq!(
        diff["agents_changed"].as_u64(),
        Some(0),
        "a policy compared with itself changes nothing"
    );
}

#[test]
fn an_exception_removes_a_finding_and_says_which_exception_did_it() {
    let facts = agent_facts(10);
    let runs = vec![run("process", CapabilityState::Available, None)];
    let scored = vec![scored_agent(10)];
    let bundle =
        bundle_from_sweep(&facts, &runs, &scored, &origin(), &key(), 400).expect("admissible");
    let baseline = topgent_policy::Policy::default();

    let Some((_, risk)) = scored.first() else {
        panic!("one agent");
    };
    let Some(target) = risk.factors.first() else {
        // Nothing fired for this fixture, so there is nothing to suppress and
        // the test would pass for the wrong reason.
        return;
    };

    let mut candidate = topgent_policy::Policy::default();
    candidate.exceptions.push(topgent_policy::Exception {
        name: "accepted-for-this-test".to_owned(),
        factor: target.code.as_str().to_owned(),
        family: None,
        target: None,
        reason: "fixture".to_owned(),
        created_by: "test".to_owned(),
        created_at: OBSERVED - 1,
        expires_at: OBSERVED + 1_000,
    });

    let diff = topgent_report::simulate(&bundle, &baseline, &candidate);

    assert_eq!(diff["agents_changed"].as_u64(), Some(1));
    let change = &diff["changes"][0];
    assert!(
        change["stopped_matching"]
            .as_array()
            .is_some_and(|list| !list.is_empty()),
        "the finding stopped: {change}"
    );
    assert_eq!(
        change["suppressed"]["after"][0]["exception"].as_str(),
        Some("accepted-for-this-test"),
        "a suppression that left no trace would be indistinguishable from the \
         finding never happening"
    );
}

#[test]
fn an_expired_exception_suppresses_nothing() {
    let facts = agent_facts(10);
    let runs = vec![run("process", CapabilityState::Available, None)];
    let scored = vec![scored_agent(10)];
    let bundle =
        bundle_from_sweep(&facts, &runs, &scored, &origin(), &key(), 400).expect("admissible");
    let baseline = topgent_policy::Policy::default();

    let Some((_, risk)) = scored.first() else {
        panic!("one agent");
    };
    let Some(target) = risk.factors.first() else {
        return;
    };

    let mut candidate = topgent_policy::Policy::default();
    candidate.exceptions.push(topgent_policy::Exception {
        name: "long-since-expired".to_owned(),
        factor: target.code.as_str().to_owned(),
        family: None,
        target: None,
        reason: "fixture".to_owned(),
        created_by: "test".to_owned(),
        created_at: OBSERVED - 10_000,
        expires_at: OBSERVED - 5_000,
    });

    let diff = topgent_report::simulate(&bundle, &baseline, &candidate);

    assert_eq!(
        diff["agents_changed"].as_u64(),
        Some(0),
        "an acceptance that has run out is not an acceptance"
    );
}
