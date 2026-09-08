//! What binds a record to a machine, and what happens when that binding is weak.
//!
//! A chain that does not name a host, a boot and a sensor instance can be
//! spliced with records from somewhere else and will still verify. These tests
//! are about the three values, and about the honesty of the one that degrades.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use topgent_report::{BootBinding, origin_at, sensor_key};

fn scratch(name: &str) -> std::path::PathBuf {
    // nosemgrep: rust.lang.security.temp-dir.temp-dir - test fixture, per-process name, not a trust boundary
    let dir = std::env::temp_dir().join(format!("topgent-identity-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

#[test]
fn the_host_identity_is_the_same_on_the_second_call() {
    let dir = scratch("host-stable");

    let (first, _) = origin_at(&dir).expect("an origin");
    let (second, _) = origin_at(&dir).expect("an origin");

    assert_eq!(
        first.host_id, second.host_id,
        "two bundles from one installation must claim one host"
    );
    assert!(!first.host_id.is_empty());
}

#[test]
fn a_new_state_directory_is_a_new_host() {
    // Stated rather than hidden: clearing the state directory produces a new
    // identity, and bundles written either side of that will not appear to come
    // from the same machine.
    let (first, _) = origin_at(&scratch("host-a")).expect("an origin");
    let (second, _) = origin_at(&scratch("host-b")).expect("an origin");

    assert_ne!(first.host_id, second.host_id);
}

#[test]
fn every_sensor_instance_is_distinct() {
    let dir = scratch("instance");

    let (first, _) = origin_at(&dir).expect("an origin");
    let (second, _) = origin_at(&dir).expect("an origin");

    assert_ne!(
        first.sensor_instance, second.sensor_instance,
        "sequence numbers are only meaningful within one instance, so two \
         runs must never share one"
    );
}

#[test]
fn the_boot_binding_says_which_guarantee_this_platform_gives() {
    let dir = scratch("boot");
    let (origin, binding) = origin_at(&dir).expect("an origin");

    assert!(!origin.boot_id.is_empty());
    // Linux publishes a boot identifier; the other two do not, and the build
    // reports the weaker guarantee rather than implying the stronger one.
    if cfg!(target_os = "linux") {
        assert_eq!(binding, BootBinding::Boot);
    } else {
        assert_eq!(binding, BootBinding::Session);
        assert_eq!(binding.as_str(), "session");
    }
}

#[test]
fn the_signing_key_survives_a_restart() {
    let dir = scratch("key");

    let first = sensor_key(&dir).expect("a key");
    let second = sensor_key(&dir).expect("a key");

    assert_eq!(
        first.public().to_hex(),
        second.public().to_hex(),
        "an operator who recorded the key once must not have to record it again"
    );
}

#[test]
fn two_installations_do_not_share_a_signing_key() {
    let first = sensor_key(&scratch("key-a")).expect("a key");
    let second = sensor_key(&scratch("key-b")).expect("a key");

    assert_ne!(first.public().to_hex(), second.public().to_hex());
}
