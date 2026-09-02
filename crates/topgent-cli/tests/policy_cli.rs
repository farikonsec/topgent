//! Process-level contracts for CI policy exit codes and output streams.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

use serde_json::{Value, json};
use std::process::Command;

fn checked_in_fixture(outcome: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/policy")
        .join(outcome)
        .join("topgent-report.json")
}

fn fixture(name: &str, value: &Value) -> std::path::PathBuf {
    let directory = std::env::temp_dir().join(format!("topgent-policy-cli-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join(name);
    std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
    path
}

/// A coverage table naming every rule this build's catalogue declares.
///
/// Was a single `{"rule":"TEST"}` entry, which the gate had no way to tell from
/// a complete table: `all()` on a one-element array is the same `true` as on an
/// empty one.
fn coverage(state: &str) -> Vec<Value> {
    topgent_policy::catalogue::builtin()
        .expect("the built-in catalogue loads")
        .factors
        .iter()
        .map(|factor| {
            json!({
                "rule": factor.code, "sensor": factor.sensor,
                "state": state, "verification": "automated",
            })
        })
        .collect()
}

fn report(grade: &str, disposition: &str, state: &str) -> Value {
    json!({
        "agents": [{"asset_id":"urn:topgent:agent:test", "grade":grade}],
        "assets": [{"id":"urn:topgent:model:test", "kind":"model", "disposition":disposition}],
        "coverage": coverage(state)
    })
}

#[test]
fn policy_check_has_distinct_pass_violation_error_and_coverage_exit_codes() {
    let binary = env!("CARGO_BIN_EXE_topgent");
    let passing = fixture("pass.json", &report("LOW", "approved", "available"));
    let violation = fixture(
        "violation.json",
        &report("CRITICAL", "disallowed", "available"),
    );
    let incomplete = fixture("incomplete.json", &report("LOW", "approved", "unsupported"));
    let malformed = fixture("malformed.json", &json!({"agents":"wrong"}));

    let pass = Command::new(binary)
        .args(["policy", "check", "--input"])
        .arg(&passing)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(pass.status.code(), Some(0));
    assert!(pass.stderr.is_empty());
    let pass_json: Value = serde_json::from_slice(&pass.stdout).unwrap();
    assert_eq!(pass_json["passed"], true);

    let fail = Command::new(binary)
        .args(["policy", "check", "--input"])
        .arg(&violation)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(fail.status.code(), Some(1));
    assert!(fail.stderr.is_empty());
    assert_eq!(
        serde_json::from_slice::<Value>(&fail.stdout).unwrap()["violations"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    let error = Command::new(binary)
        .args(["policy", "check", "--input"])
        .arg(&malformed)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(error.status.code(), Some(2));
    assert!(error.stdout.is_empty());
    assert!(!error.stderr.is_empty());

    let coverage = Command::new(binary)
        .args(["policy", "check", "--input"])
        .arg(&incomplete)
        .args(["--require-coverage", "--json"])
        .output()
        .unwrap();
    assert_eq!(coverage.status.code(), Some(3));
    assert!(coverage.stderr.is_empty());
    let coverage_json: Value = serde_json::from_slice(&coverage.stdout).unwrap();
    assert_eq!(coverage_json["coverage_complete"], false);
}

#[test]
fn invalid_threshold_is_an_operational_error_and_machine_stdout_stays_clean() {
    let output = Command::new(env!("CARGO_BIN_EXE_topgent"))
        .args(["policy", "check", "--threshold", "severe", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid threshold"));
}

#[test]
fn checked_in_fixture_repositories_have_stable_exit_and_stream_contracts() {
    let binary = env!("CARGO_BIN_EXE_topgent");
    let cases = [
        ("pass", 0, true),
        ("violation", 1, true),
        ("incomplete", 3, true),
        ("error", 2, false),
    ];
    for (name, expected, json_stdout) in cases {
        let mut command = Command::new(binary);
        command
            .args(["policy", "check", "--input"])
            .arg(checked_in_fixture(name))
            .args(["--require-coverage", "--json"]);
        let first = command.output().unwrap();
        let second = Command::new(binary)
            .args(["policy", "check", "--input"])
            .arg(checked_in_fixture(name))
            .args(["--require-coverage", "--json"])
            .output()
            .unwrap();
        assert_eq!(first.status.code(), Some(expected), "fixture {name}");
        assert_eq!(first.stdout, second.stdout, "fixture {name}");
        assert_eq!(first.stderr, second.stderr, "fixture {name}");
        if json_stdout {
            assert!(first.stderr.is_empty(), "fixture {name}");
            let _: Value = serde_json::from_slice(&first.stdout).unwrap();
        } else {
            assert!(first.stdout.is_empty(), "fixture {name}");
            assert!(!first.stderr.is_empty(), "fixture {name}");
        }
    }
}

#[test]
fn explicit_unicode_input_works_from_a_read_only_unrelated_directory() {
    let root = std::env::temp_dir().join(format!(
        "topgent policy fixture ünicode {}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let report_path = root.join("réport file.json");
    std::fs::copy(checked_in_fixture("pass"), &report_path).unwrap();
    let unrelated = root.join("read only cwd");
    std::fs::create_dir_all(&unrelated).unwrap();
    let mut permissions = std::fs::metadata(&unrelated).unwrap().permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(&unrelated, permissions).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_topgent"))
        .current_dir(&unrelated)
        .args(["policy", "check", "--input"])
        .arg(&report_path)
        .arg("--json")
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("NO_PROXY", "")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["passed"],
        true
    );
}

#[test]
fn coverage_exit_code_has_documented_precedence_over_a_violation() {
    let mixed = fixture(
        "violation-and-incomplete.json",
        &report("CRITICAL", "disallowed", "unsupported"),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_topgent"))
        .args(["policy", "check", "--input"])
        .arg(mixed)
        .args(["--require-coverage", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["coverage_complete"], false);
    assert_eq!(result["violations"].as_array().unwrap().len(), 2);
}

#[test]
fn a_report_saved_by_windows_tooling_is_still_a_report() {
    // PowerShell's default redirection writes UTF-8 with a byte-order mark, so
    // the obvious way to save a report on Windows produced
    // "expected value at line 1 column 1" and no clue why. The mark is not part
    // of the document, and refusing a file over it refuses the user's own
    // tooling rather than anything wrong with their report.
    let source = checked_in_fixture("pass");
    let document = std::fs::read_to_string(&source).expect("the pass fixture is present");
    let marked = std::env::temp_dir().join(format!("topgent-bom-{}.json", std::process::id()));
    std::fs::write(&marked, format!("\u{feff}{document}")).expect("the marked copy is written");

    let output = Command::new(env!("CARGO_BIN_EXE_topgent"))
        .args(["policy", "check", "--input"])
        .arg(&marked)
        .arg("--json")
        .output()
        .expect("the evaluator runs");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("a verdict is printed");
    assert_eq!(value["passed"], true);

    // A file that is genuinely not JSON is still refused, and says so.
    let broken = std::env::temp_dir().join(format!("topgent-broken-{}.json", std::process::id()));
    std::fs::write(&broken, "\u{feff}not json at all").expect("the broken copy is written");
    let refused = Command::new(env!("CARGO_BIN_EXE_topgent"))
        .args(["policy", "check", "--input"])
        .arg(&broken)
        .arg("--json")
        .output()
        .expect("the evaluator runs");
    assert_eq!(refused.status.code(), Some(2));
    assert!(!refused.stderr.is_empty(), "a refusal has to say why");

    let _ = std::fs::remove_file(&marked);
    let _ = std::fs::remove_file(&broken);
}
