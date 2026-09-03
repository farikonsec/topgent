//! The M1 contract: canonical bytes, construction refusals, and traversal.
//!
//! The golden test is the load-bearing one. Every id, and later every
//! signature, is taken over the bytes this crate produces, so a change to the
//! encoding silently invalidates every id ever written. Pinning the bytes makes
//! that change fail here instead of in someone's archive.

// Test code asserts; production code does not. The workspace denies these so a
// panic can never reach a user, and lifts them here so tests can be tests.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use topgent_evidence::{
    Assessment, AttributionQuality, CollectionCoverage, DerivedClaim, EVIDENCE_SCHEMA,
    EvidenceError, EvidenceRecord, Ledger, LedgerError, Limitation, MAX_FIELD_BYTES,
    MAX_LIMITATIONS, Origin, RuleId,
};
use topgent_facts::{
    Access, Claim, Confidence, Fact, Provenance, Reachability, SCHEMA_VERSION, Subject, UnixMillis,
};

const OBSERVED: u64 = 1_756_000_000_000;

fn origin() -> Origin {
    Origin {
        host_id: "sha256:host".to_owned(),
        boot_id: "boot-7".to_owned(),
        sensor_instance: "sensor-1".to_owned(),
    }
}

fn provenance() -> Provenance {
    Provenance {
        collector: "process".to_owned(),
        probe: "process table sweep".to_owned(),
        confidence: Confidence::Certain,
        observed_at: UnixMillis(OBSERVED),
    }
}

fn subject() -> Subject {
    Subject::Process {
        pid: 4242,
        started_at: UnixMillis(1_755_900_000_000),
    }
}

fn seen() -> Fact {
    Fact::new(
        SCHEMA_VERSION,
        subject(),
        Claim::ProcessSeen {
            exe: "/usr/local/bin/claude".to_owned(),
            exe_path_known: true,
            uid: 501,
            user: "operator".to_owned(),
        },
        provenance(),
    )
    .unwrap()
}

fn reachable() -> Fact {
    Fact::new(
        SCHEMA_VERSION,
        Subject::Resource {
            path: "/home/operator/.aws/credentials".to_owned(),
        },
        Claim::ResourceReachable {
            path: "/home/operator/.aws/credentials".to_owned(),
            access: Access::Read,
            sensitive: true,
            evidence: Reachability::AccountReadable,
        },
        provenance(),
    )
    .unwrap()
}

fn record(sequence: u64, fact: Fact, limitations: Vec<Limitation>) -> EvidenceRecord {
    EvidenceRecord::new(
        EVIDENCE_SCHEMA,
        origin(),
        sequence,
        1,
        CollectionCoverage::SnapshotOnly,
        limitations,
        fact,
    )
    .unwrap()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// The pinned encoding of the record built by `record(1, seen(), [ConfinementUnknown])`.
///
/// Fact schema 3, most recently bumped by `Claim::SubjectNotEvaluated`;
/// the version travels in every record, so a change to any claim moves these
/// bytes even for a record of a different kind. That is the schema doing its
/// job, not a fixture that needs loosening.
///
/// Read it field by field; every length is a big-endian `u32` and every string
/// follows its own length. A change to any line here changes every evidence id
/// Topgent has ever written, which is why the bytes are pinned and not the hash.
const GOLDEN_RECORD: &[&str] = &[
    "0001", // envelope schema v1
    "0000000b",
    "7368613235363a686f7374", // host_id "sha256:host"
    "00000006",
    "626f6f742d37", // boot_id "boot-7"
    "00000008",
    "73656e736f722d31", // sensor_instance "sensor-1"
    "0000000000000001", // sequence 1
    "00000001",         // collector_version 1
    "03",               // coverage snapshot_only
    "00000001",
    "00",   // 1 limitation: confinement_unknown
    "0003", // fact schema v3
    "00000007",
    "70726f63657373",   // subject kind "process"
    "00001092",         // pid 4242
    "00000198d3cbb700", // started_at
    "0000000c",
    "70726f636573735f7365656e", // claim kind "process_seen"
    "00000015",
    "2f7573722f6c6f63616c2f62696e2f636c61756465", // exe
    "01",                                         // exe_path_known true
    "000001f5",                                   // uid 501
    "00000008",
    "6f70657261746f72", // user "operator"
    "00000007",
    "70726f63657373", // collector "process"
    "00000013",
    "70726f63657373207461626c65207377656570", // probe
    "00000007",
    "6365727461696e",   // confidence "certain"
    "00000198d9c19800", // observed_at
];

#[test]
fn the_canonical_bytes_of_a_record_are_pinned() {
    let record = record(1, seen(), vec![Limitation::ConfinementUnknown]);
    assert_eq!(hex(&record.canonical_bytes()), GOLDEN_RECORD.concat());
}

#[test]
fn the_pinned_id_survives_a_rebuild() {
    let record = record(1, seen(), vec![Limitation::ConfinementUnknown]);
    assert_eq!(
        record.id().as_str(),
        "4b37cb7a639cf6ae7014251d13525508b33d5abfc4d730a6dffec26b177996b2"
    );
}

#[test]
fn an_id_is_the_digest_of_those_bytes() {
    let record = record(1, seen(), vec![Limitation::ConfinementUnknown]);
    assert_eq!(record.id().as_str().len(), 64);
    assert_eq!(record.id().short(), &record.id().as_str()[..12]);
    assert_eq!(
        record.id().as_str(),
        topgent_evidence::digest_of(&record).as_str()
    );
}

#[test]
fn two_records_differing_only_in_sequence_have_different_ids() {
    assert_ne!(
        record(1, seen(), Vec::new()).id(),
        record(2, seen(), Vec::new()).id()
    );
}

#[test]
fn limitations_are_order_independent() {
    let one = record(
        1,
        seen(),
        vec![Limitation::ConfinementUnknown, Limitation::NoAccessCheck],
    );
    let other = record(
        1,
        seen(),
        vec![
            Limitation::NoAccessCheck,
            Limitation::ConfinementUnknown,
            Limitation::NoAccessCheck,
        ],
    );
    assert_eq!(one.id(), other.id());
    assert_eq!(one.limitations().len(), 2);
}

#[test]
fn an_unknown_envelope_schema_is_refused() {
    let error = EvidenceRecord::new(
        EVIDENCE_SCHEMA + 1,
        origin(),
        1,
        1,
        CollectionCoverage::SnapshotOnly,
        Vec::new(),
        seen(),
    )
    .unwrap_err();
    assert_eq!(
        error,
        EvidenceError::UnknownSchema {
            found: EVIDENCE_SCHEMA + 1,
            expected: EVIDENCE_SCHEMA,
        }
    );
}

#[test]
fn a_blank_origin_field_is_refused() {
    let mut blank = origin();
    blank.boot_id = "   ".to_owned();
    let error = EvidenceRecord::new(
        EVIDENCE_SCHEMA,
        blank,
        1,
        1,
        CollectionCoverage::SnapshotOnly,
        Vec::new(),
        seen(),
    )
    .unwrap_err();
    assert_eq!(error, EvidenceError::BlankField { field: "boot_id" });
}

#[test]
fn an_oversized_field_is_refused() {
    let mut huge = origin();
    huge.host_id = "h".repeat(MAX_FIELD_BYTES + 1);
    let error = EvidenceRecord::new(
        EVIDENCE_SCHEMA,
        huge,
        1,
        1,
        CollectionCoverage::SnapshotOnly,
        Vec::new(),
        seen(),
    )
    .unwrap_err();
    assert_eq!(
        error,
        EvidenceError::FieldTooLarge {
            field: "host_id",
            bytes: MAX_FIELD_BYTES + 1,
        }
    );
}

#[test]
fn a_malformed_time_is_refused() {
    let stale = Fact::new(
        SCHEMA_VERSION,
        subject(),
        Claim::AgentFamily {
            family: "claude-code".to_owned(),
        },
        Provenance {
            observed_at: UnixMillis(0),
            ..provenance()
        },
    )
    .unwrap();
    let error = EvidenceRecord::new(
        EVIDENCE_SCHEMA,
        origin(),
        1,
        1,
        CollectionCoverage::SnapshotOnly,
        Vec::new(),
        stale,
    )
    .unwrap_err();
    assert_eq!(error, EvidenceError::TimeOutOfRange { found: 0 });
}

#[test]
fn too_many_limitations_are_refused() {
    let flood = std::iter::repeat_n(Limitation::SensorGap, MAX_LIMITATIONS + 1).collect();
    let error = EvidenceRecord::new(
        EVIDENCE_SCHEMA,
        origin(),
        1,
        1,
        CollectionCoverage::SnapshotOnly,
        flood,
        seen(),
    )
    .unwrap_err();
    assert_eq!(
        error,
        EvidenceError::TooManyLimitations {
            count: MAX_LIMITATIONS + 1,
        }
    );
}

fn assessment() -> Assessment {
    Assessment::new(AttributionQuality::Strong, CollectionCoverage::SnapshotOnly)
        .limited_by(Limitation::ConfinementUnknown)
}

fn rule() -> RuleId {
    RuleId {
        name: "resource.account_readable".to_owned(),
        version: 1,
    }
}

fn claim_over(supporting: Vec<topgent_evidence::EvidenceId>) -> DerivedClaim {
    DerivedClaim::new(
        rule(),
        subject(),
        "the agent's account could read /home/operator/.aws/credentials".to_owned(),
        assessment(),
        supporting,
        Vec::new(),
    )
    .unwrap()
}

#[test]
fn a_claim_with_no_supporting_evidence_is_refused() {
    let error = DerivedClaim::new(
        rule(),
        subject(),
        "something happened".to_owned(),
        assessment(),
        Vec::new(),
        Vec::new(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        topgent_evidence::ClaimError::NoSupportingEvidence { .. }
    ));
}

#[test]
fn a_claim_that_hides_its_contradictions_is_refused() {
    let support = record(1, seen(), Vec::new());
    let against = record(2, reachable(), Vec::new());
    let error = DerivedClaim::new(
        rule(),
        subject(),
        "the agent is running".to_owned(),
        Assessment::new(AttributionQuality::Exact, CollectionCoverage::SnapshotOnly),
        vec![support.id().clone()],
        vec![against.id().clone()],
    )
    .unwrap_err();
    assert!(matches!(
        error,
        topgent_evidence::ClaimError::ContradictionIgnored {
            reported: AttributionQuality::Exact,
            contradicting: 1,
        }
    ));
}

#[test]
fn contradictions_are_admitted_when_the_quality_says_so() {
    let support = record(1, seen(), Vec::new());
    let against = record(2, reachable(), Vec::new());
    let claim = DerivedClaim::new(
        rule(),
        subject(),
        "the agent is running".to_owned(),
        Assessment::new(
            AttributionQuality::Contradicted,
            CollectionCoverage::SnapshotOnly,
        ),
        vec![support.id().clone()],
        vec![against.id().clone()],
    )
    .unwrap();
    assert_eq!(claim.contradicting().len(), 1);
}

#[test]
fn a_claim_naming_absent_evidence_is_refused() {
    let orphan = record(9, reachable(), Vec::new());
    let claim = claim_over(vec![orphan.id().clone()]);
    let mut ledger = Ledger::new();
    let error = ledger.add_claim(claim.clone()).unwrap_err();
    assert_eq!(
        error,
        LedgerError::MissingEvidence {
            claim: claim.id().clone(),
            missing: orphan.id().clone(),
        }
    );
}

#[test]
fn the_same_record_arriving_twice_is_not_a_duplicate() {
    let record = record(1, seen(), Vec::new());
    let mut ledger = Ledger::new();
    ledger.add_record(record.clone()).unwrap();
    ledger.add_record(record).unwrap();
    assert_eq!(ledger.record_count(), 1);
}

#[test]
fn insertion_order_does_not_reach_the_ledger() {
    let first = record(1, seen(), Vec::new());
    let second = record(2, reachable(), vec![Limitation::ConfinementUnknown]);
    let third = record(3, seen(), vec![Limitation::OwnerUnresolved]);
    let claim = claim_over(vec![first.id().clone(), second.id().clone()]);

    let mut forwards = Ledger::new();
    for each in [&first, &second, &third] {
        forwards.add_record(each.clone()).unwrap();
    }
    forwards.add_claim(claim.clone()).unwrap();

    let mut backwards = Ledger::new();
    for each in [&third, &second, &first] {
        backwards.add_record(each.clone()).unwrap();
    }
    backwards.add_claim(claim).unwrap();

    assert_eq!(forwards.digest(), backwards.digest());
    assert_eq!(forwards, backwards);
}

#[test]
fn a_claim_explains_itself_down_to_the_records() {
    let first = record(1, seen(), Vec::new());
    let second = record(2, reachable(), vec![Limitation::ConfinementUnknown]);
    let claim = claim_over(vec![first.id().clone(), second.id().clone()]);
    let mut ledger = Ledger::new();
    ledger.add_record(first.clone()).unwrap();
    ledger.add_record(second.clone()).unwrap();
    ledger.add_claim(claim.clone()).unwrap();

    let derivation = ledger.explain(claim.id()).unwrap();
    assert_eq!(derivation.supporting.len(), 2);
    let rendered = derivation.render();
    assert!(rendered.contains("resource.account_readable@v1"));
    assert!(rendered.contains("quality  strong"));
    assert!(rendered.contains("coverage  snapshot_only"));
    assert!(rendered.contains(first.id().short()));
    assert!(rendered.contains(second.id().short()));
    assert!(rendered.contains("confinement_unknown"));
}

#[test]
fn a_short_id_resolves_only_while_it_is_unambiguous() {
    let first = record(1, seen(), Vec::new());
    let claim = claim_over(vec![first.id().clone()]);
    let mut ledger = Ledger::new();
    ledger.add_record(first).unwrap();
    ledger.add_claim(claim.clone()).unwrap();

    assert_eq!(ledger.resolve_claim(claim.id().short()), Some(&claim));
    assert_eq!(ledger.resolve_claim("zzzz"), None);
    assert_eq!(ledger.resolve_claim(""), Some(&claim));
}

#[test]
fn exact_beside_snapshot_only_is_legal_and_is_not_complete() {
    let assessment = Assessment::new(AttributionQuality::Exact, CollectionCoverage::SnapshotOnly);
    assert!(!assessment.permits_completeness());
    assert!(
        Assessment::new(
            AttributionQuality::Weak,
            CollectionCoverage::CompleteForWindow
        )
        .permits_completeness()
    );
}

#[test]
fn a_chain_is_no_stronger_than_its_weakest_link() {
    assert_eq!(
        AttributionQuality::Exact.weakest(AttributionQuality::Weak),
        AttributionQuality::Weak
    );
    assert_eq!(
        CollectionCoverage::CompleteForWindow.weakest(CollectionCoverage::LossObserved),
        CollectionCoverage::LossObserved
    );
}

#[test]
fn a_record_survives_the_round_trip() {
    let original = record(
        7,
        seen(),
        vec![Limitation::ConfinementUnknown, Limitation::SensorGap],
    );
    let read_back = topgent_evidence::round_trip(&original).unwrap();
    assert_eq!(read_back, original);
    assert_eq!(read_back.id(), original.id());
}

#[test]
fn every_claim_shape_survives_the_round_trip() {
    let shapes = [
        Claim::ProcessSeen {
            exe: "/usr/bin/codex".to_owned(),
            exe_path_known: false,
            uid: 0,
            user: String::new(),
        },
        Claim::ProcessParent { parent_pid: 1 },
        Claim::ChildProcessSeen {
            pid: 900,
            name: "nmap".to_owned(),
            depth: 2,
        },
        Claim::SocketOpen {
            protocol: topgent_facts::Protocol::Udp,
            host: "*".to_owned(),
            port: 0,
            direction: topgent_facts::Direction::Listening,
            opened_at: None,
            bytes: Some(topgent_facts::ByteCounters {
                sent: 12,
                received: 0,
            }),
            basis: topgent_facts::MatchBasis::WildcardLocal,
        },
        Claim::SocketClosed {
            host: "10.0.0.2".to_owned(),
            port: 443,
            direction: topgent_facts::Direction::Outbound,
            duration_ms: 4200,
        },
        Claim::ConnectionAttempt {
            host: "10.0.0.2".to_owned(),
            port: 443,
            direction: topgent_facts::Direction::Outbound,
            outcome: topgent_facts::ConnectionOutcome::Blocked,
        },
        Claim::DnsQueryObserved {
            name: "example.com".to_owned(),
            query_type: 28,
            outcome: topgent_facts::DnsOutcome::NotFound,
        },
        Claim::FileTouched {
            path: "/etc/hosts".to_owned(),
            access: Access::ReadWrite,
        },
        Claim::PermissionDeclared {
            path: "~/.ssh/**".to_owned(),
            access: Access::Read,
            granted: false,
        },
        Claim::ResourceReachable {
            path: "/tmp/x".to_owned(),
            access: Access::Execute,
            sensitive: false,
            evidence: Reachability::PathResolves,
        },
        Claim::AgentFamily {
            family: "claude-code".to_owned(),
        },
        Claim::EditorExtensionActive {
            family: "cline".to_owned(),
            extension_id: "saoudrizwan.claude-dev".to_owned(),
        },
        Claim::ModelInUse {
            provider: "local".to_owned(),
            model: "llama3".to_owned(),
        },
        Claim::ConnectorDeclared {
            name: "filesystem".to_owned(),
            access: Access::Write,
        },
        Claim::InvokesAgent {
            target_pid: 4243,
            via: "mcp".to_owned(),
        },
        Claim::ActionTaken {
            action: "kill".to_owned(),
            succeeded: true,
        },
    ];
    for shape in shapes {
        let fact = Fact::new(SCHEMA_VERSION, subject(), shape.clone(), provenance()).unwrap();
        let original = record(1, fact, Vec::new());
        assert_eq!(
            topgent_evidence::round_trip(&original).unwrap(),
            original,
            "{} did not survive",
            shape.kind()
        );
    }
}

#[test]
fn a_ledger_survives_the_round_trip_and_keeps_its_digest() {
    let first = record(1, seen(), Vec::new());
    let second = record(2, reachable(), vec![Limitation::ConfinementUnknown]);
    let claim = claim_over(vec![first.id().clone(), second.id().clone()]);
    let mut ledger = Ledger::new();
    ledger.add_record(first).unwrap();
    ledger.add_record(second).unwrap();
    ledger.add_claim(claim).unwrap();

    let read_back: Ledger = topgent_evidence::round_trip(&ledger).unwrap();
    assert_eq!(read_back.digest(), ledger.digest());
    assert_eq!(read_back.claim_count(), 1);
    assert_eq!(read_back.record_count(), 2);
}

#[test]
fn an_unknown_claim_kind_is_refused_rather_than_skipped() {
    let mut bytes = record(1, seen(), Vec::new()).canonical_bytes();
    let needle = b"process_seen";
    let at = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .unwrap();
    bytes[at..at + needle.len()].copy_from_slice(b"process_XXXX");
    let error = topgent_evidence::Reader::read::<EvidenceRecord>(&bytes).unwrap_err();
    assert_eq!(
        error,
        topgent_evidence::DecodeError::UnknownVariant {
            vocabulary: "claim",
            found: "process_XXXX".to_owned(),
        }
    );
}

#[test]
fn a_truncated_record_does_not_read_as_a_shorter_one() {
    let bytes = record(1, seen(), Vec::new()).canonical_bytes();
    for cut in 1..bytes.len() {
        assert!(
            topgent_evidence::Reader::read::<EvidenceRecord>(&bytes[..cut]).is_err(),
            "{cut} bytes read back as a record"
        );
    }
}

#[test]
fn a_length_prefix_larger_than_the_input_allocates_nothing() {
    let bytes = [0u8, 1, 0, 0, 0, 11, 0xff, 0xff, 0xff, 0xff];
    let error = topgent_evidence::Reader::read::<EvidenceRecord>(&bytes).unwrap_err();
    assert!(matches!(
        error,
        topgent_evidence::DecodeError::LengthTooLarge { .. }
    ));
}

#[test]
fn trailing_bytes_are_refused() {
    let mut bytes = record(1, seen(), Vec::new()).canonical_bytes();
    bytes.push(0);
    assert_eq!(
        topgent_evidence::Reader::read::<EvidenceRecord>(&bytes).unwrap_err(),
        topgent_evidence::DecodeError::TrailingBytes { remaining: 1 }
    );
}

#[test]
fn a_ledger_holding_a_dangling_reference_is_refused_on_load() {
    let first = record(1, seen(), Vec::new());
    let claim = claim_over(vec![first.id().clone()]);

    // A bundle claiming no records at all, then a claim that names one. The
    // shape a stripped or partially disclosed bundle would have.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend_from_slice(&topgent_evidence::Canonical::of(&claim));

    let error = topgent_evidence::Reader::read::<Ledger>(&bytes).unwrap_err();
    assert!(
        matches!(error, topgent_evidence::DecodeError::Rejected { ref reason } if reason.contains("absent")),
        "{error}"
    );
}

#[test]
fn only_a_complete_tuple_is_claimed_as_exact() {
    use topgent_evidence::quality::from_match_basis;
    use topgent_facts::MatchBasis;

    for unrelaxed in [MatchBasis::ExactTuple, MatchBasis::KernelEvent] {
        let assessment = from_match_basis(unrelaxed);
        assert_eq!(
            assessment.quality,
            AttributionQuality::Exact,
            "{unrelaxed:?}"
        );
        assert!(assessment.limitations.is_empty(), "{unrelaxed:?}");
    }

    for relaxed in [MatchBasis::WildcardLocal, MatchBasis::Listener] {
        let assessment = from_match_basis(relaxed);
        assert_eq!(assessment.quality, AttributionQuality::Weak, "{relaxed:?}");
        assert_eq!(assessment.limitations, [Limitation::PartialTuple]);
    }
}

#[test]
fn an_owner_with_no_stated_basis_says_so_in_the_limitation() {
    use topgent_evidence::quality::from_match_basis;
    let assessment = from_match_basis(topgent_facts::MatchBasis::Unreported);
    assert_eq!(assessment.quality, AttributionQuality::Weak);
    assert_eq!(assessment.limitations, [Limitation::ProvenanceUnreported]);
    assert!(!assessment.permits_completeness());
}

#[test]
fn no_socket_attribution_ever_claims_completeness() {
    use topgent_evidence::quality::from_match_basis;
    for basis in [
        topgent_facts::MatchBasis::ExactTuple,
        topgent_facts::MatchBasis::WildcardLocal,
        topgent_facts::MatchBasis::Listener,
        topgent_facts::MatchBasis::Unreported,
        topgent_facts::MatchBasis::KernelEvent,
    ] {
        assert!(
            !from_match_basis(basis).permits_completeness(),
            "{basis:?} claimed completeness"
        );
    }
}

#[test]
fn the_appended_limitation_did_not_move_the_others() {
    // Tags are the wire format. Inserting rather than appending would change
    // every evidence id ever written, so the order is pinned here.
    let tags = [
        Limitation::ConfinementUnknown,
        Limitation::ForeignCredentials,
        Limitation::NoAccessCheck,
        Limitation::OwnerUnresolved,
        Limitation::SnapshotAncestry,
        Limitation::PartialTuple,
        Limitation::EventsDropped,
        Limitation::SensorGap,
        Limitation::ProvenanceUnreported,
    ];
    for (expected, limitation) in tags.into_iter().enumerate() {
        let bytes = topgent_evidence::Canonical::of(&limitation);
        assert_eq!(
            bytes,
            [u8::try_from(expected).unwrap()],
            "{limitation:?} moved"
        );
        assert_eq!(
            topgent_evidence::Reader::read::<Limitation>(&bytes).unwrap(),
            limitation
        );
    }
}

#[test]
fn a_kernel_event_is_exact_without_a_tuple_having_been_matched() {
    use topgent_facts::MatchBasis;
    // Two routes to the same strength. A socket table is a snapshot that has
    // to be searched; an audit record carries the process the kernel itself
    // attributed the syscall to. Neither leaves anything to infer, and calling
    // the second `exact_tuple` would claim a match that never happened.
    assert!(MatchBasis::KernelEvent.is_exact());
    assert!(MatchBasis::ExactTuple.is_exact());
    assert!(!MatchBasis::WildcardLocal.is_exact());
    assert_ne!(
        MatchBasis::KernelEvent.as_str(),
        MatchBasis::ExactTuple.as_str()
    );
    assert!(MatchBasis::ExactTuple < MatchBasis::KernelEvent);

    let bytes = topgent_evidence::Canonical::of(&MatchBasis::KernelEvent);
    assert_eq!(
        topgent_evidence::Reader::read::<MatchBasis>(&bytes).unwrap(),
        MatchBasis::KernelEvent
    );
}
