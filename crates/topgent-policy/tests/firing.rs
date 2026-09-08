//! What a firing condition must and must not be able to do.
//!
//! The point of moving a factor's gate into data is that an operator can tune
//! it and two catalogues can be compared. The point of it being *typed* data
//! is that a mistake in a catalogue is caught on load with a location, rather
//! than presenting as a factor that quietly never fires. These tests are about
//! both halves.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use topgent_policy::{Firing, Signal, Signals, Thresholds};

fn parse(json: &str) -> Firing {
    serde_json::from_str(json).expect("a well-formed condition")
}

fn agent() -> Signals {
    Signals::default()
}

#[test]
fn a_flag_signal_reads_as_a_yes_or_no() {
    let condition = parse(r#"{"is": "can_execute"}"#);
    let th = Thresholds::default();

    assert!(!condition.holds(&agent(), &th));
    assert!(condition.holds(
        &Signals {
            can_execute: true,
            ..agent()
        },
        &th
    ));
}

#[test]
fn a_count_compares_against_a_literal() {
    let condition = parse(r#"{"at_least": ["latent_secret_count", 1]}"#);
    let th = Thresholds::default();

    assert!(!condition.holds(&agent(), &th));
    assert!(condition.holds(
        &Signals {
            latent_secret_count: 1,
            ..agent()
        },
        &th
    ));
}

#[test]
fn a_named_threshold_is_read_from_the_policy_in_force() {
    // The whole reason a threshold can be named rather than copied: an operator
    // who raises `network_spread` must not have to find every condition that
    // mentioned the old number.
    let condition = parse(r#"{"at_least": ["outbound_count", {"threshold": "network_spread"}]}"#);
    let signals = Signals {
        outbound_count: 6,
        ..agent()
    };

    assert!(condition.holds(&signals, &Thresholds::default()));
    assert!(!condition.holds(
        &signals,
        &Thresholds {
            network_spread: 20,
            ..Thresholds::default()
        }
    ));
}

#[test]
fn all_and_any_combine_without_precedence_to_get_wrong() {
    let both =
        parse(r#"{"all": [{"is": "can_execute"}, {"at_least": ["latent_secret_count", 1]}]}"#);
    let either =
        parse(r#"{"any": [{"is": "can_execute"}, {"at_least": ["latent_secret_count", 1]}]}"#);
    let th = Thresholds::default();
    let only_shell = Signals {
        can_execute: true,
        ..agent()
    };

    assert!(!both.holds(&only_shell, &th));
    assert!(either.holds(&only_shell, &th));
    assert!(both.holds(
        &Signals {
            can_execute: true,
            latent_secret_count: 1,
            ..agent()
        },
        &th
    ));
}

#[test]
fn an_empty_all_is_true_and_an_empty_any_is_false() {
    // Stated in a test because both are conventions rather than deductions, and
    // a catalogue that relies on the wrong one silently changes what fires.
    let th = Thresholds::default();
    assert!(parse(r#"{"all": []}"#).holds(&agent(), &th));
    assert!(!parse(r#"{"any": []}"#).holds(&agent(), &th));
}

#[test]
fn a_signal_this_build_does_not_know_fails_to_parse() {
    // The failure is at load, with a location, rather than a factor that never
    // fires and looks exactly like a quiet host.
    let error = serde_json::from_str::<Firing>(r#"{"is": "can_teleport"}"#)
        .expect_err("an unknown signal is refused");
    assert!(
        error.to_string().contains("can_teleport"),
        "the error names the signal: {error}"
    );
}

#[test]
fn an_operator_this_build_does_not_know_fails_to_parse() {
    let error = serde_json::from_str::<Firing>(r#"{"roughly": ["fact_count", 3]}"#)
        .expect_err("an unknown operator is refused");
    assert!(!error.to_string().is_empty());
}

#[test]
fn a_threshold_this_build_does_not_know_fails_to_parse() {
    assert!(
        serde_json::from_str::<Firing>(
            r#"{"at_least": ["outbound_count", {"threshold": "vibes"}]}"#
        )
        .is_err()
    );
}

#[test]
fn a_condition_that_can_never_hold_is_reported_as_unsatisfiable() {
    let th = Thresholds::default();
    // A flag counted as though it were a quantity. This is the shape a factor
    // takes when someone edits a condition and gets the signal kind wrong.
    assert!(!parse(r#"{"at_least": ["can_execute", 4]}"#).is_satisfiable(&th));
    assert!(!parse(r#"{"any": []}"#).is_satisfiable(&th));
    assert!(!parse(r#"{"below": ["fact_count", 0]}"#).is_satisfiable(&th));
    assert!(parse(r#"{"at_least": ["fact_count", 4]}"#).is_satisfiable(&th));
}

#[test]
fn a_condition_names_every_signal_it_reads() {
    let condition = parse(
        r#"{"any": [
             {"all": [{"is": "can_execute"}, {"at_least": ["drift_count", 1]}]},
             {"not": {"is": "is_sandboxed"}}
           ]}"#,
    );

    assert_eq!(
        condition.signals(),
        vec![Signal::CanExecute, Signal::IsSandboxed, Signal::DriftCount],
        "the list is what lets a catalogue be checked against the sensors present"
    );
}

#[test]
fn every_signal_has_a_wire_name_and_a_value() {
    // A signal added to the vocabulary without a value would evaluate as zero
    // for every agent, which is a factor that never fires.
    let signals = Signals {
        can_execute: true,
        can_write_broadly: true,
        is_sandboxed: true,
        exe_path_known: true,
        family_known: true,
        outbound_count: 1,
        distinct_hosts: 1,
        max_ports_to_one_host: 1,
        latent_secret_count: 1,
        drift_count: 1,
        invokes_count: 1,
        children_count: 1,
        connector_count: 1,
        endpoint_count: 1,
        resource_count: 1,
        unevaluated_count: 1,
        fact_count: 1,
    };
    for signal in Signal::all() {
        assert!(!signal.as_str().is_empty());
        assert_eq!(signals.count(signal), 1, "{} has no value", signal.as_str());
    }
}
