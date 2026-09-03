//! The M0 lint, as a rule suite and as a gate over the repository's own prose.
//!
//! Two halves. The first pins each rule against text written to trip it, so a
//! rule that stops working fails here rather than silently passing everything.
//! The second runs the rules over the documents and user-facing strings the
//! project actually ships.

// Test code asserts; production code does not. The workspace denies these so a
// panic can never reach a user, and lifts them here so tests can be tests.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use topgent_lab::overclaim::{Rule, audit, audit_rust};

#[test]
fn a_strong_claim_without_a_quality_is_refused() {
    let findings = audit("Topgent detects all outbound connections.");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule, Rule::Unqualified("detects all"));
}

#[test]
fn the_same_claim_beside_a_coverage_state_is_allowed() {
    assert!(
        audit("Detects all connections alive at sweep time; coverage is SnapshotOnly.").is_empty()
    );
}

#[test]
fn a_sentence_that_denies_the_claim_is_not_a_claim() {
    assert!(audit("Topgent never guarantees that every file was seen.").is_empty());
}

#[test]
fn a_banned_phrase_survives_no_qualifier() {
    let findings = audit("Exact attribution means the sensor cannot be evaded.");
    assert!(
        findings
            .iter()
            .any(|found| found.rule == Rule::Banned("cannot be evaded"))
    );
}

#[test]
fn tamper_proof_is_refused_in_favour_of_tamper_evident() {
    assert!(
        audit("The journal is tamper-proof.")
            .iter()
            .any(|found| found.rule == Rule::Banned("tamper-proof"))
    );
    assert!(audit("The journal is tamper-evident.").is_empty());
}

#[test]
fn signing_may_not_be_described_as_proof_of_truth() {
    let findings = audit("The Ed25519 signature proves the sensor observed reality.");
    assert!(
        findings
            .iter()
            .any(|found| found.rule == Rule::SignatureOverclaim)
    );
}

#[test]
fn signing_described_as_integrity_alone_passes() {
    assert!(
        audit("Signing detects modification after collection; it does not establish truth.")
            .iter()
            .all(|found| found.rule != Rule::SignatureOverclaim)
    );
}

#[test]
fn a_confidence_percentage_needs_a_benchmark_behind_it() {
    assert!(
        audit("Attribution confidence is 94%.")
            .iter()
            .any(|found| found.rule == Rule::UncalibratedPercentage)
    );
    assert!(
        audit("Benchmark output reports attribution confidence at 94%.")
            .iter()
            .all(|found| found.rule != Rule::UncalibratedPercentage)
    );
}

#[test]
fn a_reserved_word_inside_a_longer_word_does_not_fire() {
    assert!(
        audit("Completeness is a property of one collector.")
            .iter()
            .all(|found| found.rule != Rule::Unqualified("complete"))
    );
}

#[test]
fn the_allow_marker_exempts_one_line_only() {
    let text = "This guarantees delivery.\nThis guarantees delivery. overclaim-ok: quoting a rejected claim\nThis guarantees delivery.";
    let findings = audit(text);
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].line, 1);
    assert_eq!(findings[1].line, 3);
}

#[test]
fn a_claim_carrying_its_own_denial_word_still_fires() {
    assert!(
        audit("Topgent never misses a connection.")
            .iter()
            .any(|found| found.rule == Rule::Unqualified("never misses"))
    );
}

#[test]
fn denying_a_banned_phrase_is_permitted() {
    assert!(audit("Topgent is not a tamper-proof agent and does not claim to be.").is_empty());
}

#[test]
fn a_rust_comment_is_not_a_claim_but_a_string_still_is() {
    let source =
        "// the label is always drawn\nlet warning = \"Topgent detects all connections.\";";
    let findings = audit_rust(source);
    assert!(!findings.is_empty());
    assert!(findings.iter().all(|found| found.line == 2));
}

/// Repository root, from this crate's manifest directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/<name> sits two levels below the repository root")
        .to_path_buf()
}

/// Every file the lint governs.
///
/// `docs/NORMATIVE-CLAIMS.md` is excluded because it is the document that
/// defines the banned vocabulary and necessarily contains every phrase in it.
/// `topgent-evidence` is governed because its own doc comments are where the
/// quality vocabulary is explained, and an overclaim there would propagate.
fn governed_files(root: &Path) -> Vec<PathBuf> {
    let mut files = vec![
        root.join("README.md"),
        root.join("THREAT-MODEL.md"),
        root.join("CHANGELOG.md"),
    ];
    for crate_name in [
        "topgent-ui",
        "topgent-report",
        "topgent-cli",
        "topgent-evidence",
        "topgent-verify",
    ] {
        collect(
            &root.join("crates").join(crate_name).join("src"),
            "rs",
            &mut files,
        );
    }
    files.retain(|path| path.exists());
    files
}

/// Appends every file under `dir` with the given extension.
fn collect(dir: &Path, extension: &str, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, extension, out);
        } else if path.extension().is_some_and(|found| found == extension)
            && !path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with('.'))
        {
            // Dot-prefixed names are never source. macOS `tar` leaves an
            // AppleDouble `._foo.rs` beside every file carrying an extended
            // attribute, and those are not UTF-8, so a sync from a Mac used to
            // fail this test with "stream did not contain valid UTF-8" and no
            // file name.
            out.push(path);
        }
    }
}

#[test]
fn the_shipped_prose_makes_no_unsupported_claim() {
    let root = repo_root();
    let mut report = String::new();
    for path in governed_files(&root) {
        let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!("{}: {error}", path.display());
        });
        let relative = path.strip_prefix(&root).unwrap_or(&path).display();
        let findings = if path.extension().is_some_and(|found| found == "rs") {
            audit_rust(&text)
        } else {
            audit(&text)
        };
        for found in findings {
            let _ = writeln!(
                report,
                "{relative}:{} {}\n    {}",
                found.line,
                found.rule.reason(),
                found.text
            );
        }
    }
    assert!(report.is_empty(), "overclaims found:\n{report}");
}
