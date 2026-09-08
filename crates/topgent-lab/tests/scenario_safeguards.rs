//! The safeguards, which matter more than the scenarios.
//!
//! Each test here is one way a suite can pass while proving nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use topgent_lab::scenario::{Scenario, Suite, SuiteError, judge};

fn scenario(id: &str) -> Scenario {
    Scenario {
        id: id.to_owned(),
        description: "a case".to_owned(),
        platforms: vec!["macos".to_owned()],
        args: vec!["--version".to_owned()],
        expect_exit: 0,
        expect_stdout: vec!["topgent ".to_owned()],
        must_not_appear: vec!["panicked".to_owned()],
    }
}

fn suite(scenarios: Vec<Scenario>) -> Suite {
    Suite {
        schema_version: 1,
        expected_scenarios: scenarios.len(),
        scenarios,
    }
}

#[test]
fn a_suite_that_lost_cases_does_not_pass_with_the_ones_that_remain() {
    let mut broken = suite(vec![scenario("a"), scenario("b")]);
    broken.expected_scenarios = 5;

    assert_eq!(
        broken.validate(),
        Err(SuiteError::Miscounted {
            declared: 5,
            found: 2
        })
    );
}

#[test]
fn a_case_with_no_negative_assertion_is_refused() {
    // A tool that printed everything would satisfy every positive expectation
    // ever written, so a case without a negative control proves nothing.
    let mut weak = scenario("weak");
    weak.must_not_appear.clear();

    assert_eq!(
        suite(vec![weak]).validate(),
        Err(SuiteError::NoNegativeControl {
            id: "weak".to_owned()
        })
    );
}

#[test]
fn a_case_that_can_never_run_is_refused() {
    let mut orphan = scenario("orphan");
    orphan.platforms.clear();

    assert_eq!(
        suite(vec![orphan]).validate(),
        Err(SuiteError::NoPlatform {
            id: "orphan".to_owned()
        })
    );
}

#[test]
fn a_mistyped_platform_is_refused_rather_than_silently_skipping() {
    // `mac` is not `macos`. Left unchecked, the case would be filtered out on
    // every platform and the suite would stay green having never run it.
    let mut typo = scenario("typo");
    typo.platforms = vec!["mac".to_owned()];

    assert_eq!(
        suite(vec![typo]).validate(),
        Err(SuiteError::UnknownPlatform {
            id: "typo".to_owned(),
            platform: "mac".to_owned()
        })
    );
}

#[test]
fn two_cases_cannot_share_an_identifier() {
    assert_eq!(
        suite(vec![scenario("same"), scenario("same")]).validate(),
        Err(SuiteError::DuplicateId {
            id: "same".to_owned()
        })
    );
}

#[test]
fn a_wrong_exit_code_fails_the_case() {
    let outcome = judge(&scenario("exit"), 2, "topgent 0.4.0", "");
    assert!(!outcome.passed);
    assert!(
        outcome.failures.iter().any(|line| line.contains("exit 2")),
        "{:?}",
        outcome.failures
    );
}

#[test]
fn a_missing_expectation_fails_the_case() {
    let outcome = judge(&scenario("missing"), 0, "something else", "");
    assert!(!outcome.passed);
    assert!(
        outcome
            .failures
            .iter()
            .any(|line| line.contains("does not contain")),
        "{:?}",
        outcome.failures
    );
}

#[test]
fn a_banned_string_fails_the_case_even_when_it_is_only_on_stderr() {
    // A panic message goes to stderr. A harness that only read stdout would
    // pass a run that crashed after printing the right thing.
    let outcome = judge(
        &scenario("banned"),
        0,
        "topgent 0.4.0",
        "thread 'main' panicked at ...",
    );
    assert!(!outcome.passed);
    assert!(
        outcome
            .failures
            .iter()
            .any(|line| line.contains("must not")),
        "{:?}",
        outcome.failures
    );
}

#[test]
fn a_case_that_holds_passes() {
    let outcome = judge(&scenario("good"), 0, "topgent 0.4.0", "");
    assert!(outcome.passed, "{:?}", outcome.failures);
    assert!(outcome.failures.is_empty());
}
