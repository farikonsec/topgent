//! The policy is the one place detection is tuned and the one file a user edits,
//! so its load, save, defaults, malformed-file behaviour and rule editing are
//! pinned here. Everything runs against a temp file, so no test touches the real
//! `~/.config` and the tests are safe to run in parallel.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;
use topgent_policy::{AssetPolicy, Condition, Disposition, Policy, ResponseMode, Rule, Severity};

fn temp(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "topgent-policy-test-{tag}-{}.json",
        std::process::id()
    ))
}

#[test]
fn a_fresh_install_has_sensible_defaults() {
    let p = Policy::default();
    assert_eq!(p.weights.recon_fanout, 60);
    assert_eq!(p.weights.arbitrary_execution, 30);
    assert_eq!(p.thresholds.recon_hosts, 12);
    assert_eq!(p.thresholds.recon_ports, 8);
    assert!(p.watchlist.is_empty());
    // The credential watchlist covers the obvious secrets.
    let paths: Vec<&str> = p.sensitive.iter().map(|s| s.path.as_str()).collect();
    assert!(paths.contains(&".ssh/id_ed25519"));
    assert!(paths.contains(&".aws/credentials"));
}

#[test]
fn a_policy_round_trips_through_its_file() {
    let path = temp("roundtrip");
    let _ = std::fs::remove_file(&path);

    let mut p = Policy::default();
    p.weights.recon_fanout = 77;
    p.add_rule(Rule {
        path: ".ssh".to_owned(),
        condition: Condition::Write,
        severity: Severity::Critical,
        response: ResponseMode::Kill,
    });
    p.save_to(&path).unwrap();

    let back = Policy::load_from(&path);
    assert_eq!(back.weights.recon_fanout, 77);
    assert_eq!(back.watchlist.len(), 1);
    assert_eq!(back.watchlist[0].path, ".ssh");
    assert_eq!(back.watchlist[0].condition, Condition::Write);
    assert_eq!(back.watchlist[0].severity, Severity::Critical);
    assert_eq!(back.watchlist[0].response, ResponseMode::Kill);

    std::fs::remove_file(&path).unwrap();
}

#[test]
fn an_absent_file_is_the_defaults_not_a_crash() {
    let path = temp("absent");
    let _ = std::fs::remove_file(&path);
    let p = Policy::load_from(&path);
    assert_eq!(
        p.weights.recon_fanout,
        Policy::default().weights.recon_fanout
    );
}

#[test]
fn a_malformed_file_falls_back_to_defaults_rather_than_failing_to_start() {
    let path = temp("garbage");
    std::fs::write(&path, "{ this is not json ]").unwrap();
    let p = Policy::load_from(&path);
    // A mistyped config must never stop a security tool starting.
    assert_eq!(p.weights.arbitrary_execution, 30);
    assert!(p.watchlist.is_empty());
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn a_partial_file_keeps_defaults_for_everything_it_omits() {
    let path = temp("partial");
    // Only one weight set; serde(default) fills the rest.
    std::fs::write(&path, r#"{ "weights": { "recon_fanout": 99 } }"#).unwrap();
    let p = Policy::load_from(&path);
    assert_eq!(p.weights.recon_fanout, 99);
    assert_eq!(p.weights.arbitrary_execution, 30, "other weights defaulted");
    assert!(!p.sensitive.is_empty(), "sensitive list defaulted");
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn old_watchlist_rules_migrate_to_alert_without_rewriting_the_file() {
    let path = temp("response-migration");
    std::fs::write(
        &path,
        r#"{"watchlist":[{"path":".ssh","condition":"reachable","severity":"critical"}]}"#,
    )
    .unwrap();
    let policy = Policy::load_from(&path);
    assert_eq!(policy.watchlist[0].response, ResponseMode::Alert);
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn adding_a_rule_for_the_same_path_and_condition_replaces_it() {
    let mut p = Policy::default();
    p.add_rule(Rule {
        path: ".ssh".to_owned(),
        condition: Condition::Reachable,
        severity: Severity::Points(20),
        response: ResponseMode::Alert,
    });
    p.add_rule(Rule {
        path: ".ssh".to_owned(),
        condition: Condition::Reachable,
        severity: Severity::Critical,
        response: ResponseMode::Alert,
    });
    assert_eq!(
        p.watchlist.len(),
        1,
        "same path+condition is replaced, not duplicated"
    );
    assert_eq!(p.watchlist[0].severity, Severity::Critical);

    // A different condition on the same path is a separate rule.
    p.add_rule(Rule {
        path: ".ssh".to_owned(),
        condition: Condition::Write,
        severity: Severity::Points(40),
        response: ResponseMode::Alert,
    });
    assert_eq!(p.watchlist.len(), 2);
}

#[test]
fn removing_a_rule_by_index_is_bounds_safe() {
    let mut p = Policy::default();
    p.add_rule(Rule {
        path: "a".to_owned(),
        condition: Condition::Reachable,
        severity: Severity::Points(10),
        response: ResponseMode::Alert,
    });
    p.add_rule(Rule {
        path: "b".to_owned(),
        condition: Condition::Reachable,
        severity: Severity::Points(10),
        response: ResponseMode::Alert,
    });

    assert!(!p.remove_rule(5)); // out of range: a no-op, never a panic
    assert_eq!(p.watchlist.len(), 2);

    assert!(p.remove_rule(0));
    assert_eq!(p.watchlist.len(), 1);
    assert_eq!(p.watchlist[0].path, "b");
}

#[test]
fn asset_decisions_default_replace_scope_and_prefer_agent_specific_policy() {
    let mut policy = Policy::default();
    let id = "urn:topgent:endpoint:example.com:443";
    assert_eq!(
        policy.asset_disposition(id, Some("codex-cli")),
        Disposition::Unreviewed
    );

    policy.set_asset_disposition(AssetPolicy {
        asset_id: id.to_owned(),
        agent_family: None,
        disposition: Disposition::Approved,
    });
    policy.set_asset_disposition(AssetPolicy {
        asset_id: id.to_owned(),
        agent_family: Some("codex-cli".to_owned()),
        disposition: Disposition::Restricted,
    });
    assert_eq!(
        policy.asset_disposition(id, Some("codex-cli")),
        Disposition::Restricted
    );
    assert_eq!(
        policy.asset_disposition(id, Some("claude-code")),
        Disposition::Approved
    );

    policy.set_asset_disposition(AssetPolicy {
        asset_id: id.to_owned(),
        agent_family: Some("codex-cli".to_owned()),
        disposition: Disposition::Disallowed,
    });
    assert_eq!(policy.assets.len(), 2);
    assert_eq!(
        policy.asset_disposition(id, Some("codex-cli")),
        Disposition::Disallowed
    );

    policy.set_asset_disposition(AssetPolicy {
        asset_id: id.to_owned(),
        agent_family: Some("codex-cli".to_owned()),
        disposition: Disposition::Unreviewed,
    });
    assert_eq!(policy.assets.len(), 1);
    assert_eq!(
        policy.asset_disposition(id, Some("codex-cli")),
        Disposition::Approved
    );
}

#[test]
fn severity_and_condition_render_and_score_as_stated() {
    assert_eq!(Severity::Critical.points(), 100);
    assert_eq!(Severity::Points(35).points(), 35);
    assert_eq!(Condition::Reachable.label(), "can reach");
    assert_eq!(Condition::Observed.label(), "has touched");
    assert_eq!(Condition::Write.label(), "can write to");
}

#[test]
fn the_policy_path_lives_under_the_config_home() {
    let p = Policy::path();
    assert!(p.ends_with("topgent/policy.json"), "{}", p.display());
}
