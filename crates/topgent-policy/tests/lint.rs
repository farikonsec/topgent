//! A catalogue that loads is not the same as a catalogue that works.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use topgent_policy::{Thresholds, catalogue, lint::WarningCode};

#[test]
fn the_shipped_catalogue_has_no_unsatisfiable_condition() {
    // This one is a defect, not an observation: a condition that can never hold
    // means a factor nobody is ever told about.
    let catalogue = catalogue::builtin().expect("the built-in catalogue loads");
    let warnings = topgent_policy::lint::lint(catalogue, &Thresholds::default(), None);

    let unsatisfiable: Vec<_> = warnings
        .iter()
        .filter(|warning| warning.code == WarningCode::UnsatisfiableCondition)
        .collect();
    assert!(
        unsatisfiable.is_empty(),
        "shipped factors that can never fire: {unsatisfiable:?}"
    );
}

#[test]
fn the_shipped_catalogue_scores_something_for_every_factor() {
    let catalogue = catalogue::builtin().expect("the built-in catalogue loads");
    let warnings = topgent_policy::lint::lint(catalogue, &Thresholds::default(), None);

    assert!(
        !warnings
            .iter()
            .any(|warning| warning.code == WarningCode::ScoresNothing),
        "a factor worth zero points cannot change a grade"
    );
}

#[test]
fn an_absent_sensor_list_means_unchecked_and_never_all_present() {
    // The distinction the signature exists to keep: passing nothing must not
    // read as "every sensor works", which would report a clean catalogue on a
    // host collecting nothing.
    let catalogue = catalogue::builtin().expect("the built-in catalogue loads");

    let unchecked = topgent_policy::lint::lint(catalogue, &Thresholds::default(), None);
    let none_working = topgent_policy::lint::lint(catalogue, &Thresholds::default(), Some(&[]));

    assert!(
        none_working.len() > unchecked.len(),
        "a host with no working sensors must produce more warnings, not the same"
    );
    assert!(
        none_working
            .iter()
            .any(|warning| warning.code == WarningCode::SensorUnavailableHere)
    );
}

#[test]
fn every_warning_says_what_it_means_for_the_results() {
    // A code alone makes the reader guess, which is how a warning gets ignored.
    for code in [
        WarningCode::UnsatisfiableCondition,
        WarningCode::SensorUnavailableHere,
        WarningCode::ScoresNothing,
        WarningCode::NoTechniqueMapping,
        WarningCode::Unproven,
    ] {
        assert!(code.as_str().starts_with("POLICY_"));
        assert!(!code.label().is_empty());
        assert!(
            code.impact().len() > 60,
            "{} explains nothing",
            code.as_str()
        );
    }
}

#[test]
fn a_warning_points_at_a_position_in_the_file() {
    let catalogue = catalogue::builtin().expect("the built-in catalogue loads");
    let warnings = topgent_policy::lint::lint(catalogue, &Thresholds::default(), Some(&[]));

    for warning in &warnings {
        assert!(warning.index >= 1, "positions are one-based for a reader");
        assert!(warning.index <= catalogue.factors.len());
        assert!(!warning.factor.is_empty());
        assert!(warning.to_string().contains(&warning.factor));
    }
}

#[test]
fn every_shipped_factor_declares_a_maturity_and_all_are_stable() {
    // All twenty are stable because shipping them switched on has always meant
    // exactly that. Re-grading them against their verification evidence would
    // change scores on every host, which is a decision with consequences and
    // not one to make as a side effect of introducing the field.
    let catalogue = catalogue::builtin().expect("the built-in catalogue loads");
    for entry in &catalogue.factors {
        assert_eq!(
            entry.maturity,
            topgent_policy::Maturity::Stable,
            "{} is not stable but is shipped on",
            entry.code
        );
    }
}

#[test]
fn a_factor_below_stable_does_not_fire_until_it_is_opted_into() {
    use topgent_policy::{Maturity, Signals};
    let catalogue = catalogue::builtin().expect("the built-in catalogue loads");
    let th = Thresholds::default();
    let signals = Signals {
        can_execute: true,
        ..Signals::default()
    };

    // The shipped factor is stable, so it fires either way. The gate is proved
    // on the maturity value rather than by mutating the catalogue, because the
    // catalogue is compiled in and cannot be swapped at runtime by design.
    assert!(catalogue.fires("ARBITRARY_EXECUTION", &signals, &th));
    assert!(Maturity::Stable.on_by_default());
    for below in [
        Maturity::Sandbox,
        Maturity::Experimental,
        Maturity::Incubating,
        Maturity::Deprecated,
    ] {
        assert!(!below.on_by_default(), "{} must be opt-in", below.as_str());
    }
}

#[test]
fn maturity_and_verification_are_separate_questions() {
    // Five factors have never been shown working end to end and are still
    // shipped on. That is a real state of affairs, and one field could not
    // express it.
    let catalogue = catalogue::builtin().expect("the built-in catalogue loads");
    let unproven = catalogue
        .factors
        .iter()
        .filter(|entry| matches!(entry.verification.as_str(), "degraded" | "unavailable"))
        .count();
    assert!(
        unproven > 0,
        "if this reaches zero the test has stopped proving anything; \
         check whether the fields have been collapsed"
    );
    for entry in &catalogue.factors {
        assert_eq!(entry.maturity, topgent_policy::Maturity::Stable);
    }
}
