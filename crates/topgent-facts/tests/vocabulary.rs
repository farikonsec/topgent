//! Unit coverage for the fact vocabulary.
//!
//! Every branch in the crate is reachable from here without an operating system,
//! which is the point of the crate having no dependencies and no I/O.

// Test code asserts; production code does not. The workspace denies these so a
// panic can never reach a user, and lifts them here so tests can be tests.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use topgent_facts::{
    Access, Claim, Confidence, ConnectionOutcome, Direction, Fact, FactError, Provenance,
    SCHEMA_VERSION, SchemaVersion, Subject, Tri, UnixMillis,
};

fn prov() -> Provenance {
    Provenance {
        collector: "process".to_owned(),
        probe: "lsof -i -n -P".to_owned(),
        confidence: Confidence::Certain,
        observed_at: UnixMillis(1_724_300_000_000),
    }
}

fn proc_subject() -> Subject {
    Subject::Process {
        pid: 66493,
        started_at: UnixMillis(1_724_200_000_000),
    }
}

fn seen() -> Claim {
    Claim::ProcessSeen {
        exe_path_known: true,
        exe: "/usr/local/bin/claude".to_owned(),
        uid: 501,
        user: "testuser".to_owned(),
    }
}

#[test]
fn a_well_formed_fact_is_accepted_and_readable() {
    let f = Fact::new(SCHEMA_VERSION, proc_subject(), seen(), prov()).unwrap();

    assert_eq!(f.schema(), SCHEMA_VERSION);
    assert_eq!(f.subject(), &proc_subject());
    assert_eq!(f.claim(), &seen());
    assert_eq!(f.provenance(), &prov());
    assert_eq!(f.observed_at(), UnixMillis(1_724_300_000_000));
    assert_eq!(f.confidence(), Confidence::Certain);
}

#[test]
fn a_fact_from_an_unknown_schema_is_refused_rather_than_guessed_at() {
    let future = SchemaVersion(SCHEMA_VERSION.0 + 1);
    let err = Fact::new(future, proc_subject(), seen(), prov()).unwrap_err();

    assert_eq!(
        err,
        FactError::UnknownSchema {
            found: future,
            expected: SCHEMA_VERSION,
        }
    );
    // Derived, not spelled out. A literal here breaks on every schema bump
    // while testing nothing about the bump.
    assert!(
        err.to_string()
            .contains(&format!("unknown fact schema {future}"))
    );
    assert!(
        err.to_string()
            .contains(&format!("speaks {SCHEMA_VERSION}"))
    );
}

#[test]
fn an_unattributed_fact_is_not_admissible() {
    for (field, p) in [
        (
            "collector",
            Provenance {
                collector: "   ".to_owned(),
                ..prov()
            },
        ),
        (
            "probe",
            Provenance {
                probe: String::new(),
                ..prov()
            },
        ),
    ] {
        let err = Fact::new(SCHEMA_VERSION, proc_subject(), seen(), p).unwrap_err();
        assert_eq!(err, FactError::MissingProvenance { field });
        assert!(err.to_string().contains(field));
    }
}

#[test]
fn schema_versions_print_as_v_numbers() {
    assert_eq!(SchemaVersion(1).to_string(), "v1");
    assert_eq!(SchemaVersion(41).to_string(), "v41");
}

#[test]
fn confidence_carries_a_weight_and_a_label() {
    let all = [
        Confidence::Possible,
        Confidence::Likely,
        Confidence::Certain,
    ];
    let weights: Vec<f32> = all.iter().map(|c| c.weight()).collect();
    let labels: Vec<&str> = all.iter().map(|c| c.label()).collect();

    assert_eq!(weights, vec![0.4, 0.7, 1.0]);
    assert_eq!(labels, vec!["Possible", "Probable", "Confirmed"]);
    // Ordering is load-bearing: the fold keeps the strongest signal per agent.
    assert!(Confidence::Certain > Confidence::Likely);
    assert!(Confidence::Likely > Confidence::Possible);
}

#[test]
fn unknown_is_never_treated_as_permission() {
    assert!(Tri::Yes.is_yes());
    assert!(!Tri::No.is_yes());
    assert!(!Tri::Unknown.is_yes());
}

#[test]
fn combining_answers_lets_yes_win_then_no_then_unknown() {
    use Tri::{No, Unknown, Yes};
    let cases = [
        (Yes, Yes, Yes),
        (Yes, No, Yes),
        (No, Yes, Yes),
        (Yes, Unknown, Yes),
        (Unknown, Yes, Yes),
        (No, No, No),
        (No, Unknown, No),
        (Unknown, No, No),
        (Unknown, Unknown, Unknown),
    ];
    for (a, b, want) in cases {
        assert_eq!(a.or(b), want, "{a:?}.or({b:?})");
    }

    assert_eq!(Yes.label(), "yes");
    assert_eq!(No.label(), "no");
    assert_eq!(Unknown.label(), "unknown");
}

#[test]
fn only_read_leaves_a_resource_unchanged() {
    assert!(!Access::Read.is_mutating());
    assert!(Access::Write.is_mutating());
    assert!(Access::ReadWrite.is_mutating());
    assert!(Access::Execute.is_mutating());

    assert_eq!(Access::Read.label(), "read");
    assert_eq!(Access::Write.label(), "write");
    assert_eq!(Access::ReadWrite.label(), "read, write");
    assert_eq!(Access::Execute.label(), "execute");
}

#[test]
fn only_a_process_subject_has_a_pid() {
    assert_eq!(proc_subject().pid(), Some(66493));
    assert_eq!(
        Subject::Resource {
            path: "~/.ssh/id_ed25519".to_owned()
        }
        .pid(),
        None
    );
    assert_eq!(
        Subject::Endpoint {
            host: "api.anthropic.com".to_owned(),
            port: 443,
        }
        .pid(),
        None
    );
}

#[test]
fn every_claim_has_a_stable_kind() {
    let claims = [
        seen(),
        Claim::ProcessParent { parent_pid: 1 },
        Claim::SocketOpen {
            protocol: topgent_facts::Protocol::Tcp,
            bytes: None,
            basis: topgent_facts::MatchBasis::Unreported,
            opened_at: None,
            host: "api.anthropic.com".to_owned(),
            port: 443,
            direction: Direction::Outbound,
        },
        Claim::SocketClosed {
            host: "api.anthropic.com".to_owned(),
            port: 443,
            direction: Direction::Outbound,
            duration_ms: 250,
        },
        Claim::ConnectionAttempt {
            host: "api.anthropic.com".to_owned(),
            port: 443,
            direction: Direction::Outbound,
            outcome: ConnectionOutcome::Allowed,
        },
        Claim::DnsQueryObserved {
            name: "api.anthropic.com".to_owned(),
            query_type: 1,
            outcome: topgent_facts::DnsOutcome::Answered,
        },
        Claim::FileTouched {
            path: "~/Projects".to_owned(),
            access: Access::Read,
        },
        Claim::PermissionDeclared {
            path: "~/Projects/topgent/**".to_owned(),
            access: Access::Write,
            granted: true,
        },
        Claim::ResourceReachable {
            path: "~/.ssh/id_ed25519".to_owned(),
            access: Access::Read,
            sensitive: true,
            evidence: topgent_facts::Reachability::AccountReadable,
        },
        Claim::AgentFamily {
            family: "claude-code".to_owned(),
        },
        Claim::EditorExtensionActive {
            family: "cline".to_owned(),
            extension_id: "saoudrizwan.claude-dev".to_owned(),
        },
        Claim::ModelInUse {
            provider: "anthropic".to_owned(),
            model: "claude-opus-5".to_owned(),
        },
        Claim::ConnectorDeclared {
            name: "filesystem".to_owned(),
            access: Access::ReadWrite,
        },
        Claim::InvokesAgent {
            target_pid: 71204,
            via: "mcp".to_owned(),
        },
        Claim::ActionTaken {
            action: "kill".to_owned(),
            succeeded: true,
        },
    ];

    let kinds: Vec<&str> = claims.iter().map(Claim::kind).collect();
    assert_eq!(
        kinds,
        vec![
            "process_seen",
            "process_parent",
            "socket_open",
            "socket_closed",
            "connection_attempt",
            "dns_query_observed",
            "file_touched",
            "permission_declared",
            "resource_reachable",
            "agent_family",
            "editor_extension_active",
            "model_in_use",
            "connector_declared",
            "invokes_agent",
            "action_taken",
        ]
    );

    // Kinds are the join key in logs and tests, so they must stay unique.
    let mut sorted = kinds.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), kinds.len());
}

#[test]
fn the_vocabulary_is_inspectable_for_debugging() {
    // Debug output is what a collector author sees when a fact is refused, so it
    // has to render rather than being a derive nobody ever exercises.
    let f = Fact::new(SCHEMA_VERSION, proc_subject(), seen(), prov()).unwrap();
    let shown = format!("{f:?}");
    assert!(shown.contains("66493"));
    assert!(shown.contains("Certain"));

    assert!(format!("{:?}", Direction::Listening).contains("Listening"));
    assert!(format!("{:?}", Tri::Unknown).contains("Unknown"));
    assert!(format!("{:?}", Access::ReadWrite).contains("ReadWrite"));
    assert!(format!("{:?}", UnixMillis(7)).contains('7'));
}
