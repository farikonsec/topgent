//! Runs the scenario suite against a built binary, not against this source tree.
//!
//! `TOPGENT_BIN` names the binary under test. Left unset it falls back to the
//! release build beside this workspace, which is the nearest thing to the
//! shipped artefact that is available without unpacking an archive. Pointing it
//! at a binary extracted from a release archive is the intended use, and is
//! what makes acceptance question 9 answerable.
//!
//! The suite is skipped, loudly, when no binary can be found. A silent skip
//! here would be the exact failure the safeguards below exist to prevent, so
//! the skip prints what it looked for.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;

use topgent_lab::scenario::{Suite, current_platform, judge};

/// Where the suite lives, and the working directory scenarios are run from.
fn scenarios_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scenarios")
}

/// The binary under test.
fn binary() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("TOPGENT_BIN") {
        let path = PathBuf::from(explicit);
        return path.is_file().then_some(path);
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|crates| crates.parent())
        .map(PathBuf::from)?;
    for profile in ["release", "debug"] {
        let candidate = root.join("target").join(profile).join(if cfg!(windows) {
            "topgent.exe"
        } else {
            "topgent"
        });
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn load() -> Suite {
    let path = scenarios_dir().join("cli.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

#[test]
fn the_suite_declares_what_it_holds() {
    // Checked before anything runs. A suite that lost half its cases to a bad
    // merge must not pass with the half that remains.
    load().validate().expect("the shipped suite is well formed");
}

#[test]
fn every_supported_platform_has_something_to_run() {
    let suite = load();
    for platform in topgent_lab::scenario::PLATFORMS {
        assert!(
            !suite.applicable(platform).is_empty(),
            "no scenario applies to {platform}, so a green run there means nothing"
        );
    }
}

#[test]
fn the_shipped_binary_behaves_as_the_scenarios_describe() {
    let suite = load();
    suite.validate().expect("well formed");

    let Some(binary) = binary() else {
        panic!(
            "no binary to test. Set TOPGENT_BIN to the artefact under test, or \
             run `cargo build --release` first. Looked in target/release and \
             target/debug."
        );
    };

    let platform = current_platform();
    let applicable = suite.applicable(platform);
    assert!(
        !applicable.is_empty(),
        "every scenario was skipped on {platform}; a run that executes nothing \
         must not report success"
    );

    let mut ran = 0_usize;
    let mut failures: Vec<String> = Vec::new();
    for scenario in applicable {
        let output = Command::new(&binary)
            .args(&scenario.args)
            .current_dir(scenarios_dir())
            .output()
            .unwrap_or_else(|error| panic!("{}: {error}", binary.display()));
        ran += 1;
        let outcome = judge(
            scenario,
            output.status.code().unwrap_or(-1),
            &String::from_utf8_lossy(&output.stdout),
            &String::from_utf8_lossy(&output.stderr),
        );
        if !outcome.passed {
            for reason in outcome.failures {
                failures.push(format!("{}: {reason}", outcome.id));
            }
        }
    }

    assert!(ran > 0, "nothing ran");
    assert!(
        failures.is_empty(),
        "{ran} scenarios ran against {}, {} failed:\n  {}",
        binary.display(),
        failures.len(),
        failures.join("\n  ")
    );
}
