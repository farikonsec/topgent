//! Process-level contract for `topgent evidence`.
//!
//! The M1 exit test runs here rather than in a library: the claim is that a
//! reader holding nothing but a bundle file can walk from a statement to the
//! records behind it, and only a separate process actually demonstrates that.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

use std::process::Command;

/// One directory per call, not one per process. Every test here writes a
/// bundle, the harness runs them in parallel, and a shared name means one test
/// reads the file another is halfway through writing.
static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

use topgent_evidence::{
    Assessment, AttributionQuality, Bundle, CollectionCoverage, DerivedClaim, EVIDENCE_SCHEMA,
    EvidenceRecord, Limitation, Origin, RuleId, SensorKey,
};
use topgent_facts::{
    Access, Claim, Confidence, Fact, Provenance, Reachability, SCHEMA_VERSION, Subject, UnixMillis,
};

const OBSERVED: u64 = 1_756_000_000_000;

fn provenance(collector: &str) -> Provenance {
    Provenance {
        collector: collector.to_owned(),
        probe: "process table sweep".to_owned(),
        confidence: Confidence::Certain,
        observed_at: UnixMillis(OBSERVED),
    }
}

fn agent() -> Subject {
    Subject::Process {
        pid: 4242,
        started_at: UnixMillis(1_755_900_000_000),
    }
}

fn record(sequence: u64, claim: Claim, subject: Subject, collector: &str) -> EvidenceRecord {
    let fact = Fact::new(SCHEMA_VERSION, subject, claim, provenance(collector)).unwrap();
    EvidenceRecord::new(
        EVIDENCE_SCHEMA,
        Origin {
            host_id: "sha256:host".to_owned(),
            boot_id: "boot-7".to_owned(),
            sensor_instance: "sensor-1".to_owned(),
        },
        sequence,
        1,
        CollectionCoverage::SnapshotOnly,
        vec![Limitation::ConfinementUnknown],
        fact,
    )
    .unwrap()
}

fn signing_key() -> SensorKey {
    SensorKey::from_seed([7; 32]).expect("a seed yields a key")
}

/// A bundle holding two records, the one claim derived from them, and a signature.
fn bundle() -> (std::path::PathBuf, String) {
    let seen = record(
        1,
        Claim::ProcessSeen {
            exe: "/usr/local/bin/claude".to_owned(),
            exe_path_known: true,
            uid: 501,
            user: "operator".to_owned(),
        },
        agent(),
        "process",
    );
    let reachable = record(
        2,
        Claim::ResourceReachable {
            path: "/home/operator/.aws/credentials".to_owned(),
            access: Access::Read,
            sensitive: true,
            evidence: Reachability::AccountReadable,
        },
        Subject::Resource {
            path: "/home/operator/.aws/credentials".to_owned(),
        },
        "reach",
    );
    let claim = DerivedClaim::new(
        RuleId {
            name: "resource.account_readable".to_owned(),
            version: 1,
        },
        agent(),
        "the agent's account could read /home/operator/.aws/credentials".to_owned(),
        Assessment::new(AttributionQuality::Strong, CollectionCoverage::SnapshotOnly)
            .limited_by(Limitation::ConfinementUnknown),
        vec![seen.id().clone(), reachable.id().clone()],
        Vec::new(),
    )
    .unwrap();
    let claim_id = claim.id().as_str().to_owned();

    let mut bundle = Bundle::new(Origin {
        host_id: "sha256:host".to_owned(),
        boot_id: "boot-7".to_owned(),
        sensor_instance: "sensor-1".to_owned(),
    });
    bundle.append(seen).unwrap();
    bundle.append(reachable).unwrap();
    bundle.add_claim(claim).unwrap();
    bundle.seal(&signing_key());

    // One directory per call, not one per process. Every test here writes a
    // bundle, the harness runs them in parallel, and a shared name means one
    // test reads the file another is halfway through writing. That surfaced as
    // exit 2 where 1 was expected, on Linux only, because the timing there is
    // different rather than because anything about Linux is.
    let ordinal = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "topgent-evidence-cli-{}-{ordinal}",
        std::process::id()
    ));
    // nosemgrep: rust.lang.security.temp-dir.temp-dir - test fixture, not a trust boundary
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("bundle.tgev");
    std::fs::write(&path, topgent_evidence::Canonical::of(&bundle)).unwrap();
    (path, claim_id)
}

fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_topgent"))
        .args(args)
        .output()
        .expect("topgent runs");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn explain_walks_a_claim_down_to_its_records() {
    let (path, claim_id) = bundle();
    let (code, out, err) = run(&[
        "evidence",
        "explain",
        &claim_id,
        "--bundle",
        &path.to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("resource.account_readable@v1"), "{out}");
    assert!(out.contains("quality  strong"), "{out}");
    assert!(out.contains("coverage  snapshot_only"), "{out}");
    assert!(out.contains("derived from 2 record(s)"), "{out}");
    assert!(out.contains("process_seen"), "{out}");
    assert!(out.contains("resource_reachable"), "{out}");
    assert!(out.contains("confinement_unknown"), "{out}");
}

#[test]
fn a_short_id_is_enough_while_it_is_unambiguous() {
    let (path, claim_id) = bundle();
    let (code, out, _) = run(&[
        "evidence",
        "explain",
        &claim_id[..12],
        "--bundle",
        &path.to_string_lossy(),
    ]);
    assert_eq!(code, 0);
    assert!(out.contains("derived from 2 record(s)"));
}

#[test]
fn an_unknown_claim_id_exits_one() {
    let (path, _) = bundle();
    let (code, _, err) = run(&[
        "evidence",
        "explain",
        "ffffffffffff",
        "--bundle",
        &path.to_string_lossy(),
    ]);
    assert_eq!(code, 1);
    assert!(err.contains("no single claim matches"));
}

#[test]
fn verify_against_a_held_key_reports_what_it_did_and_did_not_establish() {
    let (path, _) = bundle();
    let hex = signing_key().public().to_hex();
    let (code, out, err) = run(&[
        "evidence",
        "verify",
        "--bundle",
        &path.to_string_lossy(),
        "--key",
        &hex,
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("intact through sequence 2"), "{out}");
    assert!(out.contains("does not say the sensor was right"), "{out}");
}

#[test]
fn verify_refuses_to_run_without_being_told_which_key_to_trust() {
    let (path, _) = bundle();
    let (code, _, err) = run(&["evidence", "verify", "--bundle", &path.to_string_lossy()]);
    assert_eq!(code, 2);
    assert!(err.contains("--key"), "{err}");
}

#[test]
fn self_verification_says_it_established_no_origin() {
    let (path, _) = bundle();
    let (code, out, _) = run(&[
        "evidence",
        "verify",
        "--bundle",
        &path.to_string_lossy(),
        "--self",
    ]);
    assert_eq!(code, 0);
    assert!(out.contains("nothing here establishes origin"), "{out}");
}

#[test]
fn a_wrong_key_is_not_a_pass() {
    let (path, _) = bundle();
    let stranger = SensorKey::from_seed([200; 32]).unwrap();
    let (code, _, err) = run(&[
        "evidence",
        "verify",
        "--bundle",
        &path.to_string_lossy(),
        "--key",
        &stranger.public().to_hex(),
    ]);
    assert_eq!(code, 2);
    assert!(err.contains("not trusted"), "{err}");
}

#[test]
fn a_flipped_byte_stops_the_bundle_loading() {
    let (path, _) = bundle();
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    let broken = path.with_extension("broken");
    std::fs::write(&broken, bytes).unwrap();
    let hex = signing_key().public().to_hex();
    let (code, _, err) = run(&[
        "evidence",
        "verify",
        "--bundle",
        &broken.to_string_lossy(),
        "--key",
        &hex,
    ]);
    assert_eq!(code, 2, "{err}");
    assert!(!err.is_empty());
}

#[test]
fn a_missing_bundle_is_a_usage_error() {
    let (code, _, err) = run(&["evidence", "list"]);
    assert_eq!(code, 2);
    assert!(err.contains("--bundle"));
}

#[test]
fn list_prints_quality_and_coverage_on_every_line() {
    let (path, _) = bundle();
    let (code, out, _) = run(&["evidence", "list", "--bundle", &path.to_string_lossy()]);
    assert_eq!(code, 0);
    assert!(out.contains("strong"));
    assert!(out.contains("snapshot_only"));
}
