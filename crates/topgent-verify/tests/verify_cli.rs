//! Process-level contract for the offline verifier.
//!
//! It runs against the checked-in interoperability fixture, so this suite also
//! catches a format change that the producing crate's own tests would accept.

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

/// The fixture, read as bytes.
fn fixture() -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../topgent-evidence/tests/fixtures/bundle.hex");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    text.trim()
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

/// The public key named in the fixture manifest.
fn fixture_key() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../topgent-evidence/tests/fixtures/bundle.manifest");
    let text = std::fs::read_to_string(path).unwrap();
    text.lines()
        .find_map(|line| line.strip_prefix("public_key "))
        .expect("the manifest names the public key")
        .to_owned()
}

fn written(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    // One directory per call. A shared name lets one test read a bundle another
    // is halfway through writing, which is a race the harness runs in parallel
    // by default and which shows up as a wrong exit code rather than as a
    // corrupt file.
    let ordinal = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let directory =
        std::env::temp_dir().join(format!("topgent-verify-{}-{ordinal}", std::process::id()));
    // nosemgrep: rust.lang.security.temp-dir.temp-dir - test fixture, not a trust boundary
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_topgent-verify"))
        .args(args)
        .output()
        .expect("the verifier runs");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn the_fixture_verifies_under_its_own_key() {
    let path = written("bundle.tgev", &fixture());
    let (code, out, err) = run(&[&path.to_string_lossy(), "--key", &fixture_key()]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("intact through sequence 3"), "{out}");
    assert!(out.contains("3 record(s), 1 claim(s)"), "{out}");
}

#[test]
fn a_pass_says_what_it_did_not_establish() {
    let path = written("bundle.tgev", &fixture());
    let (_, out, _) = run(&[&path.to_string_lossy(), "--key", &fixture_key()]);
    assert!(out.contains("whether anything was missed"), "{out}");
    assert!(out.contains("separate questions"), "{out}");
}

#[test]
fn a_flipped_byte_is_never_a_pass() {
    let mut bytes = fixture();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    let path = written("broken.tgev", &bytes);
    let (code, _, _) = run(&[&path.to_string_lossy(), "--key", &fixture_key()]);
    assert_ne!(code, 0);
}

#[test]
fn a_stranger_key_is_refused_by_name() {
    let path = written("bundle.tgev", &fixture());
    let stranger = "0".repeat(64);
    let (code, _, err) = run(&[&path.to_string_lossy(), "--key", &stranger]);
    assert_ne!(code, 0);
    assert!(!err.is_empty(), "{err}");
}

#[test]
fn self_verification_declares_itself() {
    let path = written("bundle.tgev", &fixture());
    let (code, out, _) = run(&[&path.to_string_lossy(), "--self"]);
    assert_eq!(code, 0);
    assert!(out.contains("internal consistency only"), "{out}");
    assert!(
        out.contains("says nothing about where it came from"),
        "{out}"
    );
}

#[test]
fn refusing_to_guess_which_key_to_trust() {
    let path = written("bundle.tgev", &fixture());
    let (code, _, err) = run(&[&path.to_string_lossy()]);
    assert_eq!(code, 3);
    assert!(err.contains("--key"), "{err}");
}

#[test]
fn no_arguments_prints_usage() {
    let (code, out, _) = run(&[]);
    assert_eq!(code, 3);
    assert!(out.contains("topgent-verify"), "{out}");
}
