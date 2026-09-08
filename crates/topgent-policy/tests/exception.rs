//! An exception is a hole in the thing that is supposed to be watching.
//!
//! Each test below is one of the ways that hole becomes permanent, anonymous
//! or wider than intended.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use topgent_policy::{Exception, ExceptionError, exception::MAX_WINDOW_MS};

const DAY: u64 = 86_400_000;
const CREATED: u64 = 1_756_000_000_000;

fn sound() -> Exception {
    Exception {
        name: "aws-creds-on-my-laptop".to_owned(),
        factor: "SECRET_REACHABLE".to_owned(),
        family: None,
        target: Some(".aws/credentials".to_owned()),
        reason: "Sandbox account, reviewed 2026-09-06.".to_owned(),
        created_by: "farik".to_owned(),
        created_at: CREATED,
        expires_at: CREATED + 30 * DAY,
    }
}

#[test]
fn a_sound_exception_validates() {
    sound().validate().expect("this one is complete");
}

#[test]
fn an_acceptance_with_no_owner_or_no_reason_is_refused() {
    // Six months later the only thing that makes a suppression reviewable is
    // knowing who accepted it and why.
    for (field, mutate) in [
        (
            "reason",
            (|e: &mut Exception| e.reason = "  ".to_owned()) as fn(&mut Exception),
        ),
        ("created_by", |e: &mut Exception| e.created_by.clear()),
        ("name", |e: &mut Exception| e.name = " ".to_owned()),
    ] {
        let mut exception = sound();
        mutate(&mut exception);
        assert_eq!(
            exception.validate(),
            Err(ExceptionError::Blank { field }),
            "a blank {field} must be refused"
        );
    }
}

#[test]
fn an_exception_that_never_expires_cannot_be_written() {
    // There is no "never" in the type. The nearest thing is an expiry at or
    // before creation, and that is refused rather than read as forever.
    let mut exception = sound();
    exception.expires_at = exception.created_at;
    assert!(matches!(
        exception.validate(),
        Err(ExceptionError::NotDated { .. })
    ));

    exception.expires_at = 0;
    assert!(matches!(
        exception.validate(),
        Err(ExceptionError::NotDated { .. })
    ));
}

#[test]
fn an_acceptance_cannot_run_longer_than_a_year() {
    let mut exception = sound();
    exception.expires_at = exception.created_at + MAX_WINDOW_MS + DAY;
    assert!(matches!(
        exception.validate(),
        Err(ExceptionError::TooLong { .. })
    ));

    exception.expires_at = exception.created_at + MAX_WINDOW_MS;
    exception.validate().expect("exactly a year is allowed");
}

#[test]
fn an_exception_naming_a_factor_that_does_not_exist_is_refused() {
    let mut exception = sound();
    exception.factor = "SECRET_REACHABEL".to_owned();
    assert_eq!(
        exception.validate(),
        Err(ExceptionError::UnknownFactor {
            factor: "SECRET_REACHABEL".to_owned()
        }),
        "a typo must not silently suppress nothing"
    );
}

#[test]
fn expiry_is_measured_against_the_moment_being_scored() {
    // Replaying last month's bundle must give last month's answer. An
    // exception that was in force then is in force in that replay, whatever
    // the clock says now.
    let exception = sound();
    assert!(!exception.active_at(CREATED - DAY), "not yet accepted");
    assert!(exception.active_at(CREATED));
    assert!(exception.active_at(CREATED + 29 * DAY));
    assert!(
        !exception.active_at(CREATED + 30 * DAY),
        "the expiry is exclusive: on the day it expires it no longer applies"
    );
    assert!(!exception.active_at(CREATED + 400 * DAY));
}

#[test]
fn scope_narrows_and_never_widens_past_one_factor() {
    let exception = sound();

    assert!(exception.covers(
        "SECRET_REACHABLE",
        None,
        "~/.aws/credentials is within reach"
    ));
    assert!(
        !exception.covers(
            "ARBITRARY_EXECUTION",
            None,
            "~/.aws/credentials is within reach"
        ),
        "an exception never reaches a factor it did not name"
    );
    assert!(
        !exception.covers("SECRET_REACHABLE", None, "~/.ssh/id_rsa is within reach"),
        "a target that does not match is not covered"
    );
}

#[test]
fn an_exception_scoped_to_a_family_ignores_other_families() {
    let mut exception = sound();
    exception.family = Some("claude-code".to_owned());

    assert!(exception.covers(
        "SECRET_REACHABLE",
        Some("claude-code"),
        "~/.aws/credentials"
    ));
    assert!(!exception.covers("SECRET_REACHABLE", Some("aider"), "~/.aws/credentials"));
    assert!(
        !exception.covers("SECRET_REACHABLE", None, "~/.aws/credentials"),
        "an unrecognised agent is not the family that was named"
    );
}

#[test]
fn the_widest_possible_exception_is_still_one_factor() {
    let mut exception = sound();
    exception.family = None;
    exception.target = None;

    assert!(exception.covers("SECRET_REACHABLE", Some("anything"), "anything at all"));
    assert!(!exception.covers("BROAD_WRITE", Some("anything"), "anything at all"));
}
