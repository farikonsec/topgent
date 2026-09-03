//! End to end for `topgent lab benchmark`.
//!
//! Spawns the real fixture and runs the real collectors, because the thing
//! being demonstrated is that two independent programs agree about one
//! controlled run. A mocked sweep would demonstrate nothing.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

use std::process::Command;

/// The fixture binary, built by `cargo test --workspace` alongside this one.
fn fixture() -> std::path::PathBuf {
    let binary = std::path::PathBuf::from(env!("CARGO_BIN_EXE_topgent"));
    let directory = binary.parent().expect("the test binary has a directory");
    let path = directory.join(format!(
        "topgent-fixture-agent{}",
        std::env::consts::EXE_SUFFIX
    ));
    assert!(
        path.exists(),
        "{} is missing; build it with `cargo build -p topgent-lab --bin topgent-fixture-agent`",
        path.display()
    );
    path
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
fn the_benchmark_scores_a_real_fixture_run() {
    let path = fixture();
    let (code, out, err) = run(&[
        "lab",
        "benchmark",
        "--hold-ms",
        "2000",
        "--fixture",
        &path.to_string_lossy(),
        "--json",
    ]);
    assert_eq!(code, 0, "{err}");

    let report: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    assert!(report["root_pid"].as_u64().unwrap_or(0) > 0, "{out}");
    assert!(
        report["processes"]["expected"].as_u64().unwrap_or(0) >= 3,
        "the fixture creates a root and at least two children: {out}"
    );
    // Recognised by default, so exactly the root should be classified. A
    // descendant promoted to an agent of its own is the defect here, and it is
    // a different defect from an unrecognised process being picked up at all.
    assert_eq!(
        report["recognised"].as_bool(),
        Some(true),
        "the default run should be the recognised one: {out}"
    );
    assert_eq!(
        report["false_agents"].as_u64(),
        Some(1),
        "exactly the fixture root should be classified as an agent: {out}"
    );
    assert!(
        !report["collectors"]
            .as_array()
            .unwrap_or(&Vec::new())
            .is_empty(),
        "{out}"
    );
}

#[test]
fn a_resident_fixture_process_is_seen_and_a_short_lived_one_is_not() {
    let path = fixture();
    let (code, out, err) = run(&[
        "lab",
        "benchmark",
        "--hold-ms",
        "2000",
        "--fixture",
        &path.to_string_lossy(),
        "--json",
    ]);
    assert_eq!(code, 0, "{err}");
    let report: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");

    let resident = &report["lifetimes"]["resident"];
    assert!(
        resident["matched"].as_u64().unwrap_or(0) > 0,
        "no resident fixture process was seen at all: {out}"
    );
    let short = &report["lifetimes"]["short_lived"];
    assert!(
        short["expected"].as_u64().unwrap_or(0) > 0,
        "the fixture must create something short-lived to measure: {out}"
    );
}

#[test]
fn the_text_report_explains_every_structural_zero() {
    let path = fixture();
    let (code, out, err) = run(&[
        "lab",
        "benchmark",
        "--hold-ms",
        "1500",
        "--fixture",
        &path.to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("why the zeros are zero"), "{out}");
    assert!(out.contains("declared inventory only"), "{out}");
    assert!(
        out.contains("the fixture ran under a name the catalogue knows"),
        "{out}"
    );
    assert!(out.contains("not\naccuracy against the world"), "{out}");
}

#[test]
fn a_missing_fixture_is_reported_rather_than_guessed_at() {
    let (code, _, err) = run(&["lab", "benchmark", "--fixture", "/nonexistent/fixture"]);
    assert_eq!(code, 2);
    assert!(!err.is_empty(), "{err}");
}

#[test]
fn the_unrecognised_run_still_proves_a_plain_process_is_left_alone() {
    let path = fixture();
    let (code, out, err) = run(&[
        "lab",
        "benchmark",
        "--hold-ms",
        "1500",
        "--fixture",
        &path.to_string_lossy(),
        "--unrecognised",
        "--json",
    ]);
    assert_eq!(code, 0, "{err}");
    let report: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    assert_eq!(report["recognised"].as_bool(), Some(false), "{out}");
    assert_eq!(
        report["false_agents"].as_u64(),
        Some(0),
        "an unrecognised fixture process was classified as an agent: {out}"
    );
}
