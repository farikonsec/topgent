//! What the deeper-visibility offer must always say.
//!
//! The state itself depends on the host and is not asserted here. What is
//! asserted is that the offer is honest whatever the host answers: it never
//! claims a capability it did not verify, it always says what it would not
//! give, and a grant always comes with the exact step and the way back.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use topgent_collect::capture::{Remedy, State, offer};

#[test]
fn the_offer_always_says_what_it_would_not_give() {
    // Listed before the gains in the dialog, on purpose. A capability sold on
    // what it cannot do is one nobody can consent to.
    let offer = offer();
    assert!(!offer.limits.is_empty());
    let text = offer.limits.join(" ").to_ascii_lowercase();
    assert!(text.contains("tls"), "the content limit must be stated");
    assert!(
        text.contains("attribution"),
        "the attribution limit must be stated, since this is what people assume it fixes"
    );
}

#[test]
fn the_offer_always_says_what_it_asks_for() {
    let offer = offer();
    assert!(!offer.privilege.is_empty());
    assert!(!offer.gains.is_empty());
}

#[test]
fn a_grant_always_carries_the_exact_step_and_the_way_back() {
    // An offer that says "needs permission" and not which one, or that cannot
    // be undone, is not a decision anybody can take.
    match offer().state {
        State::NeedsGrant { missing, remedy } => {
            assert!(!missing.trim().is_empty());
            match remedy {
                Remedy::Command {
                    command,
                    effect,
                    undo,
                } => {
                    assert!(!command.trim().is_empty());
                    assert!(!effect.trim().is_empty());
                    assert!(!undo.trim().is_empty(), "a grant with no undo is a trap");
                }
                Remedy::Install { what, source } => {
                    assert!(!what.trim().is_empty());
                    assert!(!source.trim().is_empty());
                }
            }
        }
        // A grant that landed and needs a restart carries its own sentence and
        // must never read as a failure: telling somebody their successful
        // grant did not work is the worst of the answers.
        State::NeedsRestart { detail } => {
            assert!(!detail.trim().is_empty());
            assert!(
                detail.contains("restart"),
                "it has to say what to do next: {detail}"
            );
        }
        // Every other state is a valid answer for some host, and the tests
        // below cover what each must carry.
        State::Available | State::Unsupported { .. } | State::Unknown { .. } => {}
    }
}

#[test]
fn a_state_that_could_not_be_checked_never_reads_as_available() {
    // The distinction that matters most: "we asked and the answer was no" and
    // "we could not ask" are different, and reporting the second as the first
    // is a monitor guessing.
    let state = offer().state;
    if let State::Unknown { detail } = &state {
        assert!(!detail.trim().is_empty());
        assert_ne!(state.as_str(), "available");
    }
    assert!(!state.as_str().is_empty());
}

#[test]
fn only_a_grantable_state_offers_a_button() {
    let offer = offer();
    assert_eq!(
        offer.state.is_grantable(),
        matches!(offer.state, State::NeedsGrant { .. }),
        "the button is offered exactly when there is something to grant"
    );
}

#[test]
fn the_rendered_offer_leads_with_the_state_and_names_both_sides() {
    let rendered = offer().to_string();
    assert!(rendered.starts_with("deeper network visibility: "));
    assert!(rendered.contains("it would show:"));
    assert!(rendered.contains("it would still not show:"));
}

#[test]
fn probing_is_side_effect_free_and_repeatable() {
    // It opens a device or reads a file to learn whether it can, and does
    // nothing with the answer. Two calls must agree.
    assert_eq!(offer().state.as_str(), offer().state.as_str());
}

#[test]
fn the_indicator_never_claims_capture_is_running() {
    // Nothing in this build reads packets. A status saying capture was on
    // while no code consumed the grant would be the most misleading string in
    // the interface, so the word is checked rather than trusted.
    for label in [
        State::Available.label(),
        State::NeedsRestart {
            detail: String::new(),
        }
        .label(),
        State::NeedsGrant {
            missing: String::new(),
            remedy: Remedy::Install {
                what: String::new(),
                source: String::new(),
            },
        }
        .label(),
        State::Unsupported {
            reason: String::new(),
        }
        .label(),
        State::Unknown {
            detail: String::new(),
        }
        .label(),
    ] {
        assert!(
            label.starts_with("Packet capture: "),
            "every state names the same thing: {label}"
        );
        let rest = label.trim_start_matches("Packet capture: ");
        assert_ne!(rest, "on", "nothing here is on");
        assert!(
            !rest.contains("running") || rest.contains("not"),
            "{label} claims capture is running"
        );
    }
}

#[test]
fn every_state_says_something_and_only_one_cannot_be_acted_on() {
    // A control that is present and inert teaches people to ignore it, so
    // every state opens the dialog except the one where there is nothing any
    // answer could change.
    assert!(State::Available.is_actionable());
    assert!(
        State::NeedsRestart {
            detail: String::new()
        }
        .is_actionable()
    );
    assert!(
        !State::Unsupported {
            reason: String::new()
        }
        .is_actionable()
    );
}

/// A helper anyone can write to is not run.
///
/// The path comes from `current_exe`, which is not evidence of anything on its
/// own. What guards the execution is the file itself: it must not be writable
/// by anyone but its owner, and its owner must be root or this account.
/// Running one that fails that would be handing a capability to somebody
/// else's program.
#[cfg(unix)]
#[test]
fn a_world_writable_helper_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = std::env::temp_dir().join(format!("topgent-helper-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("topgent-capture");
    let Ok(()) = std::fs::write(&path, b"#!/bin/sh\nexit 0\n") else {
        return;
    };

    let ok = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).is_ok();
    assert!(ok && topgent_collect::capture::helper::safe_to_run(&path));

    let ok = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).is_ok();
    assert!(
        ok && !topgent_collect::capture::helper::safe_to_run(&path),
        "a world-writable helper was accepted"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Turning capture off has to actually turn it off.
///
/// The interface used to offer a way to switch this capability on and no way
/// to switch it back off, which is a bad bargain in a tool whose whole claim
/// is that it takes no privilege it does not need. Stopping needs no password,
/// takes effect at once, and is remembered so a sweep does not quietly start
/// it again.
#[test]
fn capture_can_be_switched_off_and_back_on() {
    use topgent_collect::capture::live;

    live::stop();
    assert!(live::stopped_by_operator(), "the choice was not remembered");
    assert!(!live::running(), "it is still reading packets");
    assert_eq!(live::status(), "off");

    // Starting again may still fail for want of a permission, which is a
    // different answer from "switched off" and has to read differently.
    let _ = live::start();
    assert!(
        !live::stopped_by_operator(),
        "starting did not clear the choice"
    );
    assert_ne!(live::status(), "off");

    // Left as it was found.
    live::stop();
}
