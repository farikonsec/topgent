//! Process-level contracts for durable approval resolution.

#![allow(clippy::unwrap_used)]

use std::process::Command;

#[test]
fn approval_cli_rejects_malformed_identity_and_requires_explicit_execution_consent() {
    for args in [
        vec!["approval", "resolve"],
        vec!["approval", "resolve", "approval-x", "pid", "1000", "deny"],
        vec!["approval", "resolve", "approval-x", "42", "start", "deny"],
        vec!["approval", "resolve", "approval-x", "42", "1000", "maybe"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_topgent"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }

    let output = Command::new(env!("CARGO_BIN_EXE_topgent"))
        .args([
            "approval",
            "resolve",
            "approval-42-1000-test",
            "42",
            "1000",
            "approve",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--yes"));
}
