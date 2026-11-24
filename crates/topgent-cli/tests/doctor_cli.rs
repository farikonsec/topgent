//! Process-level contracts for install diagnostics in `topgent doctor`.

#![allow(clippy::expect_used)]

use serde_json::Value;
use std::process::Command;

#[test]
fn doctor_json_reports_the_executable_layout_and_helpers() {
    let output = Command::new(env!("CARGO_BIN_EXE_topgent"))
        .args(["doctor", "--json"])
        .output()
        .expect("doctor runs");
    assert!(matches!(output.status.code(), Some(0 | 1)));
    let value: Value = serde_json::from_slice(&output.stdout).expect("doctor JSON");
    let deployment = value
        .get("deployment")
        .and_then(Value::as_object)
        .expect("deployment");
    assert!(deployment.get("mode").is_some_and(Value::is_string));
    assert!(deployment.get("helpers").is_some_and(Value::is_array));
}

#[test]
fn doctor_text_has_a_visible_install_line() {
    let output = Command::new(env!("CARGO_BIN_EXE_topgent"))
        .arg("doctor")
        .output()
        .expect("doctor runs");
    assert!(matches!(output.status.code(), Some(0 | 1)));
    let text = String::from_utf8(output.stdout).expect("text output");
    assert!(text.contains("install"), "{text}");
    assert!(text.contains("helpers"), "{text}");
}
