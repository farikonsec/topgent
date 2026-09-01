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

/// Unix only: Windows has no pid 1, so `stop 1` there is correctly "no
/// process". The Windows protected set is covered in `topgent-enforce`.
///
/// `topgent stop 1` printed "this would stop systemd ... re-run with --yes".
/// The enforcement crate refuses a protected process at the point of
/// signalling, so the prompt was describing something that could not happen,
/// and inviting the operator to try it. Found on a Linux lab host.
#[cfg(not(windows))]
#[test]
fn stopping_the_init_process_is_refused_rather_than_offered() {
    let output = Command::new(env!("CARGO_BIN_EXE_topgent"))
        .args(["stop", "1"])
        .output()
        .expect("the binary runs");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("refusing pid 1"),
        "pid 1 must be refused outright, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("--yes"),
        "a protected process must not be offered behind a confirmation:\n{stderr}"
    );
}
