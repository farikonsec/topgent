//! Every account-scoped collector states that it is account-scoped.
//!
//! Milestone M7 of `docs/MAJOR_UPGRADE_RESEARCH_PLAN.md` owns replacing the
//! sensor's own credentials with the target's. Until a privileged helper
//! exists, the honest half is to say so, and to say it somewhere a reader sees
//! rather than in a source comment.
//!
//! The failure this guards against is silence rather than a wrong answer. A
//! collector that skips an agent owned by another account is doing the right
//! thing; a report where that skip is indistinguishable from "nothing was
//! found" is not.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

use topgent_collect::default_collectors;

/// Collectors whose answer is scoped to the account Topgent runs as.
const ACCOUNT_SCOPED: &[&str] = &["config", "reach"];

#[test]
fn an_account_scoped_collector_says_so_in_its_boundary() {
    let collectors = default_collectors();
    for id in ACCOUNT_SCOPED {
        let collector = collectors
            .iter()
            .find(|candidate| candidate.id() == *id)
            .unwrap_or_else(|| panic!("{id} is not among the default collectors"));
        let boundary = collector.boundary().unwrap_or_else(|| {
            panic!("{id} answers only for one account and declares no boundary")
        });
        let lowered = boundary.to_lowercase();
        assert!(
            lowered.contains("account"),
            "{id} declares a boundary that does not mention the account it answers for: {boundary}"
        );
    }
}

#[test]
fn the_reachability_boundary_names_all_three_limits() {
    let collectors = default_collectors();
    let reach = collectors
        .iter()
        .find(|candidate| candidate.id() == "reach")
        .expect("the reach collector is a default");
    let boundary = reach.boundary().expect("reach declares a boundary");
    let lowered = boundary.to_lowercase();
    // The constraints of `docs/NORMATIVE-CLAIMS.md` §3.4 that a reader cannot
    // recover from the numbers: whose account, and over what. The third differs
    // by platform, so it is checked separately below.
    for expected in ["account", "inventory"] {
        assert!(
            lowered.contains(expected),
            "the reachability boundary omits `{expected}`: {boundary}"
        );
    }
    // Windows has no access check in this build, so no reachability finding is
    // ever raised there and a Windows score is not comparable with the others.
    // A boundary that did not say so would let a reader take the lower number
    // for the safer machine.
    #[cfg(windows)]
    {
        assert!(
            lowered.contains("no access check") && lowered.contains("not comparable"),
            "the Windows boundary does not say the score cannot be compared: {boundary}"
        );
    }
    #[cfg(not(windows))]
    {
        assert!(
            lowered.contains("permission model"),
            "the boundary does not name what it answers against: {boundary}"
        );
        assert!(
            lowered.contains("skipped rather than answered for"),
            "the boundary does not say what happens to an agent owned by somebody else: {boundary}"
        );
    }
}

#[test]
fn a_boundary_is_a_sentence_rather_than_a_label() {
    for collector in default_collectors() {
        if let Some(boundary) = collector.boundary() {
            assert!(
                boundary.len() > 40 && boundary.contains(' '),
                "{} declares a boundary too terse to act on: {boundary}",
                collector.id()
            );
        }
    }
}
