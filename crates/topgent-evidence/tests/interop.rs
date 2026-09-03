//! The cross-language fixture.
//!
//! Milestone M8 asks for a verification fixture that stops a verifier from
//! sharing the producer's serialization bug. A second implementation written
//! against `docs/EVIDENCE-BUNDLE-FORMAT.md` and this file will disagree with a
//! Rust-side mistake; a second implementation that reuses this crate will not.
//!
//! Everything below is deterministic: fixed key seeds, fixed timestamps, fixed
//! pids. Regenerate with `TOPGENT_REGENERATE_FIXTURES=1 cargo test -p
//! topgent-evidence --test interop`, and read the diff before committing it. A
//! change here changes every id and signature Topgent has ever written.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

use std::fmt::Write as _;

use topgent_evidence::{
    Assessment, AttributionQuality, Bundle, Canonical, CollectionCoverage, DerivedClaim,
    EVIDENCE_SCHEMA, EvidenceRecord, Limitation, Origin, Reader, RuleId, SensorKey, Verdict,
};
use topgent_facts::{
    Access, Claim, Confidence, Fact, Provenance, Reachability, SCHEMA_VERSION, Subject, UnixMillis,
};

const OBSERVED: u64 = 1_756_000_000_000;
const STARTED: u64 = 1_755_900_000_000;

fn fixture_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn origin() -> Origin {
    Origin {
        host_id: "sha256:0f1e2d3c".to_owned(),
        boot_id: "boot-fixture".to_owned(),
        sensor_instance: "sensor-fixture".to_owned(),
    }
}

fn provenance(collector: &str) -> Provenance {
    Provenance {
        collector: collector.to_owned(),
        probe: "fixture".to_owned(),
        confidence: Confidence::Certain,
        observed_at: UnixMillis(OBSERVED),
    }
}

fn record(sequence: u64, subject: Subject, claim: Claim, collector: &str) -> EvidenceRecord {
    let fact = Fact::new(SCHEMA_VERSION, subject, claim, provenance(collector)).unwrap();
    EvidenceRecord::new(
        EVIDENCE_SCHEMA,
        origin(),
        sequence,
        1,
        CollectionCoverage::SnapshotOnly,
        vec![Limitation::ConfinementUnknown],
        fact,
    )
    .unwrap()
}

/// The bundle every language's verifier is expected to agree about.
fn deterministic_bundle() -> (Bundle, SensorKey) {
    let key = SensorKey::from_seed([42; 32]).unwrap();
    let agent = Subject::Process {
        pid: 4242,
        started_at: UnixMillis(STARTED),
    };
    let seen = record(
        1,
        agent.clone(),
        Claim::ProcessSeen {
            exe: "/usr/local/bin/claude".to_owned(),
            exe_path_known: true,
            uid: 501,
            user: "operator".to_owned(),
        },
        "process",
    );
    let family = record(
        2,
        agent.clone(),
        Claim::AgentFamily {
            family: "claude-code".to_owned(),
        },
        "process",
    );
    let reachable = record(
        3,
        Subject::Resource {
            path: "/home/operator/.aws/credentials".to_owned(),
        },
        Claim::ResourceReachable {
            path: "/home/operator/.aws/credentials".to_owned(),
            access: Access::Read,
            sensitive: true,
            evidence: Reachability::AccountReadable,
        },
        "reach",
    );
    let supporting = vec![seen.id().clone(), reachable.id().clone()];

    let mut bundle = Bundle::new(origin());
    bundle.append(seen).unwrap();
    bundle.append(family).unwrap();
    bundle.append(reachable).unwrap();
    bundle
        .add_claim(
            DerivedClaim::new(
                RuleId {
                    name: "resource.account_readable".to_owned(),
                    version: 1,
                },
                agent,
                "the agent's account could read /home/operator/.aws/credentials".to_owned(),
                Assessment::new(AttributionQuality::Strong, CollectionCoverage::SnapshotOnly)
                    .limited_by(Limitation::ConfinementUnknown),
                supporting,
                Vec::new(),
            )
            .unwrap(),
        )
        .unwrap();
    bundle.seal(&key);
    (bundle, key)
}

/// The values a second implementation must reproduce, one per line.
fn manifest(bundle: &Bundle, key: &SensorKey) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "public_key {}", key.public().to_hex());
    let _ = writeln!(out, "key_id {}", key.id());
    let _ = writeln!(out, "bundle_digest {}", bundle.digest());
    for record in bundle.ledger().records() {
        let _ = writeln!(
            out,
            "record {} seq {} kind {}",
            record.id(),
            record.sequence(),
            record.fact().claim().kind()
        );
    }
    for entry in bundle.chain().entries() {
        let _ = writeln!(
            out,
            "entry seq {} hash {} previous {}",
            entry.sequence(),
            entry.hash(),
            entry.previous().map_or("-", |hash| hash.as_str())
        );
    }
    for claim in bundle.ledger().claims() {
        let _ = writeln!(
            out,
            "claim {} rule {} quality {} coverage {}",
            claim.id(),
            claim.rule(),
            claim.quality().as_str(),
            claim.coverage().as_str()
        );
    }
    for checkpoint in bundle.checkpoints() {
        let _ = writeln!(
            out,
            "checkpoint through {} count {} head {} signature {}",
            checkpoint.body().through_sequence,
            checkpoint.body().entry_count,
            checkpoint.body().head,
            hex(checkpoint.signature().bytes())
        );
    }
    out
}

/// Writes or compares one fixture file.
fn pinned(name: &str, produced: &str) {
    let path = fixture_dir().join(name);
    if std::env::var_os("TOPGENT_REGENERATE_FIXTURES").is_some() {
        std::fs::create_dir_all(fixture_dir()).unwrap();
        std::fs::write(&path, produced).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "{}: {error}. Regenerate with TOPGENT_REGENERATE_FIXTURES=1",
            path.display()
        )
    });
    assert_eq!(
        produced,
        expected,
        "{} no longer matches. Every id and signature Topgent has written depends on this.",
        path.display()
    );
}

#[test]
fn the_interoperability_bundle_is_pinned() {
    let (bundle, key) = deterministic_bundle();
    pinned("bundle.hex", &format!("{}\n", hex(&Canonical::of(&bundle))));
    pinned("bundle.manifest", &manifest(&bundle, &key));
}

#[test]
fn the_pinned_bytes_read_back_and_verify() {
    let (_, key) = deterministic_bundle();
    let text = std::fs::read_to_string(fixture_dir().join("bundle.hex"))
        .expect("the fixture exists; regenerate with TOPGENT_REGENERATE_FIXTURES=1");
    let bytes: Vec<u8> = text
        .trim()
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let bundle: Bundle = Reader::read(&bytes).unwrap();
    match bundle.verify(&[key.public().clone()]) {
        Verdict::Intact(summary) => {
            assert_eq!(summary.records, 3);
            assert_eq!(summary.claims, 1);
            assert_eq!(summary.through_sequence, 3);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_key_survives_the_hex_round_trip() {
    let key = SensorKey::from_seed([42; 32]).unwrap();
    let hex = key.public().to_hex();
    assert_eq!(hex.len(), 64);
    assert_eq!(
        topgent_evidence::PublicKey::from_hex(&hex).unwrap(),
        *key.public()
    );
    assert!(topgent_evidence::PublicKey::from_hex("zz").is_err());
}
