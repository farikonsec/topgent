//! The public surface cannot change without somebody agreeing to it.
//!
//! The fingerprint below is not decoration. It is the whole point: an ordinary
//! refactor that renames a fact field, drops a coverage state or adds a
//! collector will fail this test, and the failure prints what moved so a
//! reviewer can decide whether it was meant.
//!
//! **When this test fails and the change was intended:** run it, read the diff
//! it prints, satisfy yourself that every line is deliberate, bump the schema
//! version the change belongs to, and update `EXPECTED` in one commit that
//! says why.

#![allow(
    clippy::expect_used,
    clippy::manual_assert,
    clippy::panic,
    clippy::unwrap_used
)]

use topgent_facts::{Claim, Subject, UnixMillis};
use topgent_lab::contract::{
    contract, listed_claims, listed_subjects, shape_of_claim, shape_of_subject,
};

/// The fingerprint of the contract this build ships.
///
/// Changing this constant is how a contract change is agreed to. Changing it
/// to make a red test go green, without reading the diff, defeats every other
/// guarantee in this file.
const EXPECTED: &str = "83bfbe126022dac35d1e01e6958c69ae9147d54d5788767c5cd30f454ba2caf3";

#[test]
fn the_public_contract_has_not_changed_by_accident() {
    let current = contract();
    if current.fingerprint() != EXPECTED {
        // Rebuild the expected contract from the constant is impossible: a hash
        // is one-way. So the diff is against nothing, and the render is printed
        // instead, which is what a reviewer needs to see.
        panic!(
            "the public contract changed.\n\nfingerprint now: {}\nexpected:        {EXPECTED}\n\n\
             current contract:\n{}\n\
             If every line above is deliberate, bump the schema version it belongs to \
             and update EXPECTED in the same commit.",
            current.fingerprint(),
            current.render()
        );
    }
}

#[test]
fn a_contract_diff_names_what_moved() {
    let mine = contract();
    let mut theirs = contract();
    theirs
        .sections
        .first_mut()
        .expect("a contract has sections")
        .entries
        .push("invented=1".to_owned());

    let diff = mine.diff(&theirs);

    assert_eq!(diff.len(), 1, "one added entry is one diff line: {diff:?}");
    assert!(
        diff.first().is_some_and(|line| line.contains("invented=1")),
        "the diff names the entry: {diff:?}"
    );
}

#[test]
fn a_removed_entry_shows_as_removed() {
    let mine = contract();
    let mut theirs = contract();
    theirs
        .sections
        .first_mut()
        .expect("a contract has sections")
        .entries
        .clear();

    let diff = mine.diff(&theirs);

    assert!(!diff.is_empty());
    assert!(
        diff.iter().all(|line| line.starts_with("- ")),
        "clearing a section only removes: {diff:?}"
    );
}

#[test]
fn every_subject_variant_is_listed_in_the_contract() {
    // The exhaustive match in the contract module guarantees each variant has
    // a shape. This guarantees the shape is one the contract actually lists,
    // which is the other half of the coupling.
    let subjects = [
        Subject::Process {
            pid: 1,
            started_at: UnixMillis(0),
        },
        Subject::Resource {
            path: "/tmp/x".to_owned(),
        },
        Subject::Endpoint {
            host: "example.test".to_owned(),
            port: 443,
        },
    ];
    assert_eq!(subjects.len(), listed_subjects().len());
    for subject in &subjects {
        let shape = shape_of_subject(subject);
        assert!(
            listed_subjects().contains(&shape),
            "{shape} is not in the contract"
        );
    }
}

#[test]
fn every_claim_variant_is_listed_in_the_contract() {
    let claims = sample_claims();
    assert_eq!(
        claims.len(),
        listed_claims().len(),
        "a claim variant was added without a sample here, so the contract \
         cannot be checked against it"
    );
    let mut seen: Vec<&str> = claims.iter().map(shape_of_claim).collect();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), claims.len(), "two variants share one shape");
    for shape in seen {
        assert!(
            listed_claims().contains(&shape),
            "{shape} is not in the contract"
        );
    }
}

#[test]
fn the_contract_covers_every_section_it_claims_to() {
    let contract = contract();
    let names: Vec<&str> = contract
        .sections
        .iter()
        .map(|section| section.name)
        .collect();
    for expected in [
        "schema_versions",
        "fact_subjects",
        "fact_claims",
        "fact_scalars",
        "evidence_quality",
        "risk_codes",
        "factor_maturity",
        "grades",
        "policy_signals",
        "policy_operators",
        "item_vocabulary",
        "item_operators",
        "policy_thresholds",
        "collectors",
    ] {
        assert!(names.contains(&expected), "{expected} is missing");
    }
    for section in &contract.sections {
        assert!(
            !section.entries.is_empty(),
            "{} is empty, so it protects nothing",
            section.name
        );
    }
}

/// One instance of every claim variant.
fn sample_claims() -> Vec<Claim> {
    use topgent_facts::{
        Access, ConnectionOutcome, Direction, DnsOutcome, MatchBasis, Protocol, Reachability,
    };
    vec![
        Claim::ProcessSeen {
            exe: "/usr/bin/x".to_owned(),
            exe_path_known: true,
            uid: 0,
            user: "root".to_owned(),
        },
        Claim::ProcessParent { parent_pid: 1 },
        Claim::ChildProcessSeen {
            pid: 2,
            name: "sh".to_owned(),
            depth: 1,
        },
        Claim::SocketOpen {
            protocol: Protocol::Tcp,
            host: "example.test".to_owned(),
            port: 443,
            direction: Direction::Outbound,
            opened_at: None,
            bytes: None,
            basis: MatchBasis::ExactTuple,
        },
        Claim::SocketClosed {
            host: "example.test".to_owned(),
            port: 443,
            direction: Direction::Outbound,
            duration_ms: 1,
        },
        Claim::ConnectionAttempt {
            host: "example.test".to_owned(),
            port: 443,
            direction: Direction::Outbound,
            outcome: ConnectionOutcome::Allowed,
        },
        Claim::TrafficObserved {
            protocol: Protocol::Udp,
            host: "example.test".to_owned(),
            port: 53,
            direction: Direction::Outbound,
            packets: 1,
            first_seen: topgent_facts::UnixMillis(1),
            last_seen: topgent_facts::UnixMillis(2),
        },
        Claim::DnsQueryObserved {
            name: "example.test".to_owned(),
            query_type: 1,
            outcome: DnsOutcome::Answered,
        },
        Claim::FileTouched {
            path: "/tmp/x".to_owned(),
            access: Access::Read,
        },
        Claim::PermissionDeclared {
            path: "/tmp/**".to_owned(),
            access: Access::Write,
            granted: true,
        },
        Claim::ResourceReachable {
            path: "~/.ssh/id_rsa".to_owned(),
            access: Access::Read,
            sensitive: true,
            evidence: Reachability::AccountReadable,
        },
        Claim::AgentFamily {
            family: "claude-code".to_owned(),
        },
        Claim::EditorExtensionActive {
            family: "cline".to_owned(),
            extension_id: "pub.pkg".to_owned(),
        },
        Claim::ModelInUse {
            provider: "anthropic".to_owned(),
            model: "opus".to_owned(),
        },
        Claim::ConnectorDeclared {
            name: "mcp".to_owned(),
            access: Access::Read,
        },
        Claim::InvokesAgent {
            target_pid: 3,
            via: "mcp".to_owned(),
        },
        Claim::SubjectNotEvaluated {
            reason: "another owner".to_owned(),
        },
        Claim::ActionTaken {
            action: "stop".to_owned(),
            succeeded: true,
        },
    ]
}
