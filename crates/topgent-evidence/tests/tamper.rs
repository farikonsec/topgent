//! The tampering matrix.
//!
//! One test per way a bundle can be attacked, each asserting the specific
//! breach rather than "verification failed". A verifier that rejects everything
//! passes a boolean test suite and is useless, so every case below names what
//! the verifier is expected to say.
//!
//! What none of this establishes: that the sensor observed correctly, or that
//! nothing was missed. Those are separate questions, and
//! [`Verdict::IntactWithGaps`] is where the second one lives.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

use topgent_evidence::{
    Assessment, AttributionQuality, Breach, Bundle, Canonical, Chain, ChainEntry,
    CollectionCoverage, DerivedClaim, EVIDENCE_SCHEMA, EvidenceRecord, Ledger, Limitation, Origin,
    PublicKey, Reader, Rotation, RuleId, SensorKey, Verdict,
};
use topgent_facts::{Claim, Confidence, Fact, Provenance, SCHEMA_VERSION, Subject, UnixMillis};

const OBSERVED: u64 = 1_756_000_000_000;

fn origin() -> Origin {
    Origin {
        host_id: "sha256:host-a".to_owned(),
        boot_id: "boot-7".to_owned(),
        sensor_instance: "sensor-1".to_owned(),
    }
}

fn other_origin() -> Origin {
    Origin {
        host_id: "sha256:host-b".to_owned(),
        boot_id: "boot-9".to_owned(),
        sensor_instance: "sensor-2".to_owned(),
    }
}

fn key(seed: u8) -> SensorKey {
    SensorKey::from_seed([seed; 32]).unwrap()
}

fn record_at(origin: Origin, sequence: u64, pid: u32) -> EvidenceRecord {
    let fact = Fact::new(
        SCHEMA_VERSION,
        Subject::Process {
            pid,
            started_at: UnixMillis(1_755_900_000_000),
        },
        Claim::ProcessSeen {
            exe: "/usr/local/bin/claude".to_owned(),
            exe_path_known: true,
            uid: 501,
            user: "operator".to_owned(),
        },
        Provenance {
            collector: "process".to_owned(),
            probe: "process table sweep".to_owned(),
            confidence: Confidence::Certain,
            observed_at: UnixMillis(OBSERVED),
        },
    )
    .unwrap();
    EvidenceRecord::new(
        EVIDENCE_SCHEMA,
        origin,
        sequence,
        1,
        CollectionCoverage::SnapshotOnly,
        vec![Limitation::ConfinementUnknown],
        fact,
    )
    .unwrap()
}

fn record(sequence: u64) -> EvidenceRecord {
    record_at(
        origin(),
        sequence,
        4000 + u32::try_from(sequence).unwrap_or(0),
    )
}

/// Three records, one claim, one checkpoint, signed by key 7.
fn sealed_bundle() -> (Bundle, SensorKey) {
    let signing = key(7);
    let mut bundle = Bundle::new(origin());
    let first = record(1);
    let first_id = first.id().clone();
    bundle.append(first).unwrap();
    bundle.append(record(2)).unwrap();
    bundle.append(record(3)).unwrap();
    bundle
        .add_claim(
            DerivedClaim::new(
                RuleId {
                    name: "agent.anchored_identity".to_owned(),
                    version: 1,
                },
                Subject::Process {
                    pid: 4001,
                    started_at: UnixMillis(1_755_900_000_000),
                },
                "the process is an agent of a recognised family".to_owned(),
                Assessment::new(AttributionQuality::Strong, CollectionCoverage::SnapshotOnly),
                vec![first_id],
                Vec::new(),
            )
            .unwrap(),
        )
        .unwrap();
    bundle.seal(&signing);
    (bundle, signing)
}

fn trusted(key: &SensorKey) -> Vec<PublicKey> {
    vec![key.public().clone()]
}

/// Rebuilds a bundle with the same parts but a different chain.
fn with_chain(bundle: &Bundle, chain: Chain) -> Bundle {
    Bundle::from_parts(
        bundle.ledger().clone(),
        chain,
        bundle.keys().to_vec(),
        bundle.rotations().to_vec(),
        bundle.checkpoints().to_vec(),
    )
}

#[test]
fn an_untouched_bundle_verifies() {
    let (bundle, signing) = sealed_bundle();
    match bundle.verify(&trusted(&signing)) {
        Verdict::Intact(summary) => {
            assert_eq!(summary.records, 3);
            assert_eq!(summary.claims, 1);
            assert_eq!(summary.through_sequence, 3);
            assert_eq!(summary.key_id, *signing.id());
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_bundle_survives_the_round_trip_and_still_verifies() {
    let (bundle, signing) = sealed_bundle();
    let bytes = Canonical::of(&bundle);
    let read_back: Bundle = Reader::read(&bytes).unwrap();
    assert_eq!(read_back, bundle);
    assert!(read_back.verify(&trusted(&signing)).is_intact());
}

#[test]
fn mutation_of_a_record_is_caught() {
    let (bundle, signing) = sealed_bundle();
    let mut bytes = Canonical::of(&bundle);
    let needle = b"/usr/local/bin/claude";
    let at = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .unwrap();
    bytes[at + 1] = b'X';

    // A record is addressed by the digest of its own bytes, so an edited record
    // answers to an id nothing points at any more. Which layer notices depends
    // on whether a claim or only the chain referenced it, and both are correct:
    // the point is that no path leads to a bundle that reads as intact.
    match Reader::read::<Bundle>(&bytes) {
        Err(error) => {
            let reason = error.to_string();
            assert!(reason.contains("absent"), "{reason}");
        }
        Ok(read_back) => {
            let verdict = read_back.verify(&trusted(&signing));
            assert!(!verdict.is_intact(), "{verdict:?}");
            assert!(
                verdict
                    .breaches()
                    .iter()
                    .any(|breach| matches!(breach, Breach::UnchainedReference { .. })),
                "{verdict:?}"
            );
        }
    }
}

#[test]
fn deleting_a_record_leaves_the_chain_pointing_at_nothing() {
    let (bundle, signing) = sealed_bundle();
    let mut thinned = Ledger::new();
    for record in bundle.ledger().records() {
        if record.sequence() != 2 {
            thinned.add_record(record.clone()).unwrap();
        }
    }
    let stripped = Bundle::from_parts(
        thinned,
        bundle.chain().clone(),
        bundle.keys().to_vec(),
        bundle.rotations().to_vec(),
        bundle.checkpoints().to_vec(),
    );
    let verdict = stripped.verify(&trusted(&signing));
    assert!(
        verdict
            .breaches()
            .iter()
            .any(|breach| matches!(breach, Breach::UnchainedReference { sequence: 2, .. })),
        "{verdict:?}"
    );
}

#[test]
fn inserting_a_record_outside_the_chain_is_caught() {
    let (bundle, signing) = sealed_bundle();
    let mut widened = bundle.ledger().clone();
    let smuggled = record(99);
    let smuggled_id = smuggled.id().clone();
    widened.add_record(smuggled).unwrap();
    let widened = Bundle::from_parts(
        widened,
        bundle.chain().clone(),
        bundle.keys().to_vec(),
        bundle.rotations().to_vec(),
        bundle.checkpoints().to_vec(),
    );
    let verdict = widened.verify(&trusted(&signing));
    assert!(
        verdict
            .breaches()
            .iter()
            .any(|breach| matches!(breach, Breach::RecordNotInChain { id } if *id == smuggled_id)),
        "{verdict:?}"
    );
}

#[test]
fn reordering_two_entries_breaks_the_links() {
    let (bundle, signing) = sealed_bundle();
    let mut entries = bundle.chain().entries().to_vec();
    entries.swap(1, 2);
    let reordered = with_chain(&bundle, Chain::from_parts(origin(), entries));
    let verdict = reordered.verify(&trusted(&signing));
    assert!(
        verdict
            .breaches()
            .iter()
            .any(|breach| matches!(breach, Breach::ChainBroken { .. })),
        "{verdict:?}"
    );
    assert!(
        verdict
            .breaches()
            .iter()
            .any(|breach| matches!(breach, Breach::OutOfOrder { .. })),
        "{verdict:?}"
    );
}

#[test]
fn truncating_the_chain_is_caught_by_the_signature() {
    let (bundle, signing) = sealed_bundle();
    let mut entries = bundle.chain().entries().to_vec();
    entries.pop();
    let cut = with_chain(&bundle, Chain::from_parts(origin(), entries));
    let verdict = cut.verify(&trusted(&signing));
    assert!(
        verdict.breaches().iter().any(|breach| matches!(
            breach,
            Breach::CheckpointBeyondChain {
                through_sequence: 3,
                highest: 2
            }
        )),
        "{verdict:?}"
    );
}

#[test]
fn a_forged_entry_hash_is_recomputed_and_refused() {
    let (bundle, signing) = sealed_bundle();
    let mut entries = bundle.chain().entries().to_vec();
    let victim = entries[1].clone();
    entries[1] = ChainEntry::from_parts(
        victim.previous().cloned(),
        victim.sequence(),
        victim.record_id().clone(),
        entries[0].hash().clone(),
    );
    let forged = with_chain(&bundle, Chain::from_parts(origin(), entries));
    let verdict = forged.verify(&trusted(&signing));
    assert!(
        verdict
            .breaches()
            .iter()
            .any(|breach| matches!(breach, Breach::EntryAltered { sequence: 2, .. })),
        "{verdict:?}"
    );
}

#[test]
fn a_duplicate_sequence_is_caught() {
    let (bundle, signing) = sealed_bundle();
    let mut entries = bundle.chain().entries().to_vec();
    entries[2] = ChainEntry::from_parts(
        entries[2].previous().cloned(),
        entries[1].sequence(),
        entries[2].record_id().clone(),
        entries[2].hash().clone(),
    );
    let doubled = with_chain(&bundle, Chain::from_parts(origin(), entries));
    let verdict = doubled.verify(&trusted(&signing));
    assert!(
        verdict
            .breaches()
            .iter()
            .any(|breach| matches!(breach, Breach::DuplicateSequence { sequence: 2 })),
        "{verdict:?}"
    );
}

#[test]
fn a_record_replayed_from_another_host_is_caught() {
    let (bundle, signing) = sealed_bundle();
    let mut widened = bundle.ledger().clone();
    let foreign = record_at(other_origin(), 4, 4004);
    let foreign_id = foreign.id().clone();
    widened.add_record(foreign).unwrap();
    let replayed = Bundle::from_parts(
        widened,
        bundle.chain().clone(),
        bundle.keys().to_vec(),
        bundle.rotations().to_vec(),
        bundle.checkpoints().to_vec(),
    );
    let verdict = replayed.verify(&trusted(&signing));
    assert!(
        verdict
            .breaches()
            .iter()
            .any(|breach| matches!(breach, Breach::ForeignOrigin { id, .. } if *id == foreign_id)),
        "{verdict:?}"
    );
}

#[test]
fn relabelling_the_origin_breaks_the_checkpoint_signature() {
    let (bundle, signing) = sealed_bundle();
    let relabelled = with_chain(
        &bundle,
        Chain::from_parts(other_origin(), bundle.chain().entries().to_vec()),
    );
    let verdict = relabelled.verify(&trusted(&signing));
    assert!(
        verdict
            .breaches()
            .iter()
            .any(|breach| matches!(breach, Breach::CheckpointOrigin { .. })),
        "{verdict:?}"
    );
}

#[test]
fn the_wrong_trusted_key_makes_the_signer_unknown() {
    let (bundle, _) = sealed_bundle();
    let stranger = key(200);
    let verdict = bundle.verify(&trusted(&stranger));
    assert!(
        verdict
            .breaches()
            .iter()
            .any(|breach| matches!(breach, Breach::UnknownKey { .. })),
        "{verdict:?}"
    );
}

#[test]
fn no_trusted_key_at_all_verifies_nothing() {
    let (bundle, _) = sealed_bundle();
    let verdict = bundle.verify(&[]);
    assert!(!verdict.is_intact());
}

#[test]
fn a_bundle_with_no_checkpoint_is_unsigned() {
    let mut bundle = Bundle::new(origin());
    bundle.append(record(1)).unwrap();
    let verdict = bundle.verify(&[]);
    assert_eq!(verdict.breaches(), [Breach::NoCheckpoint]);
}

#[test]
fn a_rotated_key_signs_for_the_records_after_the_handover() {
    let first = key(7);
    let second = key(9);
    let mut bundle = Bundle::new(origin());
    bundle.append(record(1)).unwrap();
    bundle.append(record(2)).unwrap();
    bundle.rotate(Rotation::sign(&first, second.public(), 3));
    bundle.append(record(3)).unwrap();
    bundle.seal(&second);

    let verdict = bundle.verify(&trusted(&first));
    match verdict {
        Verdict::Intact(summary) => assert_eq!(summary.key_id, *second.id()),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_key_that_handed_over_may_not_sign_afterwards() {
    let first = key(7);
    let second = key(9);
    let mut bundle = Bundle::new(origin());
    bundle.append(record(1)).unwrap();
    bundle.append(record(2)).unwrap();
    bundle.append(record(3)).unwrap();
    bundle.rotate(Rotation::sign(&first, second.public(), 2));
    bundle.seal(&first);

    let verdict = bundle.verify(&trusted(&first));
    assert!(
        verdict.breaches().iter().any(|breach| matches!(
            breach,
            Breach::RetiredKey {
                retired_from: 2,
                ..
            }
        )),
        "{verdict:?}"
    );
}

#[test]
fn a_rotation_nobody_authorised_is_refused() {
    let first = key(7);
    let stranger = key(200);
    let attacker = key(201);
    let mut bundle = Bundle::new(origin());
    bundle.append(record(1)).unwrap();
    // Signed by a key the verifier never trusted, handing authority to another.
    bundle.rotate(Rotation::sign(&stranger, attacker.public(), 1));
    bundle.seal(&attacker);

    let verdict = bundle.verify(&trusted(&first));
    assert!(
        verdict
            .breaches()
            .iter()
            .any(|breach| matches!(breach, Breach::UnknownKey { .. })),
        "{verdict:?}"
    );
    assert!(!verdict.is_intact());
}

#[test]
fn a_gap_is_reported_without_calling_the_bundle_broken() {
    let signing = key(7);
    let mut bundle = Bundle::new(origin());
    bundle.append(record(1)).unwrap();
    bundle.append(record(5)).unwrap();
    bundle.seal(&signing);

    match bundle.verify(&trusted(&signing)) {
        Verdict::IntactWithGaps { summary, gaps } => {
            assert_eq!(summary.records, 2);
            assert_eq!(gaps.len(), 1);
            assert_eq!(gaps[0].after, 1);
            assert_eq!(gaps[0].before, 5);
            assert!(gaps[0].to_string().contains("3 record(s) missing"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_interrupted_write_does_not_read_as_a_shorter_bundle() {
    let (bundle, _) = sealed_bundle();
    let bytes = Canonical::of(&bundle);
    for cut in 1..bytes.len() {
        assert!(
            Reader::read::<Bundle>(&bytes[..cut]).is_err(),
            "{cut} bytes read back as a bundle"
        );
    }
}

#[test]
fn a_flipped_signature_byte_is_caught() {
    let (bundle, signing) = sealed_bundle();
    let mut bytes = Canonical::of(&bundle);
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let read_back: Bundle = Reader::read(&bytes).unwrap();
    let verdict = read_back.verify(&trusted(&signing));
    assert!(
        verdict
            .breaches()
            .iter()
            .any(|breach| matches!(breach, Breach::BadSignature { .. })),
        "{verdict:?}"
    );
}

#[test]
fn every_breach_says_what_it_expected() {
    let (bundle, _) = sealed_bundle();
    for breach in bundle.verify(&[]).breaches() {
        let rendered = breach.to_string();
        assert!(rendered.len() > 20, "{rendered}");
        assert!(!rendered.contains("failed"), "{rendered}");
    }
}
