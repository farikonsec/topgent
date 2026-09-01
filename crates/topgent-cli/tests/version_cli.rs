//! The version a build reports must be the version it was built from.
//!
//! The header printed above every scan carried a literal `0.1.0` for the whole
//! of 0.1.x and kept printing it after the manifest moved to 0.2.0, so a
//! published binary answered two different versions depending on which part of
//! it you asked. Nothing caught that, because nothing compared the two.

#![allow(clippy::expect_used)]

use std::process::Command;

fn run(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_topgent"))
        .args(args)
        .output()
        .expect("the binary runs");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn the_version_flag_answers_the_version_it_was_built_from() {
    let expected = format!("topgent {}", env!("CARGO_PKG_VERSION"));
    for flag in ["--version", "-V"] {
        assert_eq!(
            run(&[flag]).trim(),
            expected,
            "{flag} must report the build's own version"
        );
    }
}

/// A scan header naming a different version from `--version` is the defect this
/// file exists for. The scan itself touches the host, so this asserts only that
/// the version it prints is the built one.
#[test]
fn the_scan_header_names_the_same_version_as_the_flag() {
    let header = run(&[]);
    let version = env!("CARGO_PKG_VERSION");
    assert!(
        header.contains(&format!("topgent {version}")),
        "the scan header must name {version}, got:\n{header}"
    );
}
