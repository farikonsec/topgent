//! Process-level contracts for the family validation CLI.

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]

use serde_json::Value;
use std::process::Command;

#[test]
fn catalogue_is_machine_readable_and_separates_verified_from_catalogued() {
    let output = Command::new(env!("CARGO_BIN_EXE_topgent"))
        .args(["lab", "catalogue", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    let families = value["families"].as_array().expect("families array");
    assert_eq!(families.len(), 19);
    // An extension-only family is still a family: it has no executable to
    // match, and its identity is the exact extension id.
    assert!(families.iter().any(|family| {
        family["id"] == "copilot-chat"
            && family["verified_platforms"]
                .as_array()
                .is_some_and(|platforms| platforms.iter().any(|item| item == "macos-aarch64"))
    }));
    assert!(families.iter().any(|family| {
        family["id"] == "opencode"
            && family["provenance_required"] == true
            && family["verified_platforms"]
                .as_array()
                .is_some_and(|platforms| platforms.iter().any(|item| item == "linux-aarch64"))
    }));
}

#[test]
fn invalid_family_state_and_listener_are_usage_errors() {
    for args in [
        vec!["lab", "assert", "invented", "absent", "--json"],
        vec!["lab", "assert", "goose", "maybe", "--json"],
        vec!["lab", "assert", "goose", "running", "--listener", "zero"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_topgent"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}
