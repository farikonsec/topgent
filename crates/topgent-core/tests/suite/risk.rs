//! The risk model, tested factor by factor.
//!
//! Every assertion here is about a number a user will read next to a sentence
//! explaining it. A score that cannot be explained is a bug, so the tests check
//! the explanation as well as the arithmetic.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use crate::fixtures;

use crate::fixtures::Stream;
use topgent_core::{
    FactorCode, Grade, analyse, assess, assess_with, extension_asset_id, fold, remediations,
};
use topgent_facts::{Access, Claim, Confidence, Direction, Subject};
use topgent_policy::{AssetPolicy, Condition, Disposition, Policy, Rule, Severity};

fn only(facts: &[topgent_facts::Fact]) -> topgent_core::Agent {
    let g = fold(facts);
    assert_eq!(g.agents.len(), 1);
    g.agents.into_iter().next().unwrap()
}

fn codes(risk: &topgent_core::Risk) -> Vec<FactorCode> {
    risk.factors.iter().map(|f| f.code).collect()
}

#[test]
fn the_worked_example_scores_as_critical_and_says_why() {
    let agent = only(&fixtures::busy_agent());
    let risk = assess(&agent);

    assert_eq!(risk.grade, Grade::Critical);
    assert_eq!(risk.identity_multiplier, 100);
    assert_eq!(
        codes(&risk),
        vec![
            FactorCode::ArbitraryExecution,
            FactorCode::BroadWrite,
            FactorCode::SecretReachable,
            FactorCode::UnrestrictedNetwork,
            FactorCode::SecretReachable,
            FactorCode::AgentChain,
            FactorCode::ExfiltrationPath,
            FactorCode::DeclarationDrift,
        ],
        "highest points first, ties broken by code so the list is stable"
    );

    // 30 + 20 + 15 + 15 + 12 + 12 + 12 + 10 = 126, capped at 100.
    assert_eq!(risk.score, 100);

    // Every factor prints a source. A factor that cannot is not a factor.
    for f in &risk.factors {
        assert!(!f.title.is_empty(), "{:?} has no title", f.code);
        assert!(!f.source.is_empty(), "{:?} has no source", f.code);
    }
}

#[test]
fn a_quiet_local_service_scores_low() {
    let agent = only(&fixtures::quiet_service());
    let risk = assess(&agent);

    assert_eq!(risk.score, 0);
    assert_eq!(risk.grade, Grade::Low);
    assert!(risk.factors.is_empty());
    assert_eq!(risk.identity_multiplier, 75, "its own account, not yours");
    assert!(remediations(&risk).is_empty(), "nothing to fix");
}

#[test]
fn each_factor_fires_only_on_its_own_evidence() {
    let base = || {
        Stream::new(1)
            .seen("/bin/a", 501, "testuser")
            .declares("~/w", Access::Read, true)
    };

    let exec = assess(&only(&base().declares("*", Access::Execute, true).build()));
    assert_eq!(codes(&exec), vec![FactorCode::ArbitraryExecution]);
    assert_eq!(exec.score, 30);

    let write = assess(&only(&base().declares("~/**", Access::Write, true).build()));
    assert_eq!(codes(&write), vec![FactorCode::BroadWrite]);
    assert_eq!(write.score, 20);

    let drift = assess(&only(
        &base()
            .declares("~/w", Access::Read, true)
            .touched("~/elsewhere", Access::Read)
            .build(),
    ));
    assert_eq!(codes(&drift), vec![FactorCode::DeclarationDrift]);
    assert_eq!(drift.score, 10);
    assert!(drift.factors[0].title.contains("~/elsewhere"));

    let chain = assess(&only(&base().invokes(4242, "mcp").build()));
    assert_eq!(codes(&chain), vec![FactorCode::AgentChain]);
    assert_eq!(chain.score, 12);
    assert!(chain.factors[0].title.contains('1'));
}

#[test]
fn every_watchlist_condition_can_force_critical() {
    let cases = [
        (
            Condition::Reachable,
            Stream::new(1)
                .seen("/bin/a", 501, "testuser")
                .reachable("/canary", Access::Read, false)
                .build(),
        ),
        (
            Condition::Observed,
            Stream::new(1)
                .seen("/bin/a", 501, "testuser")
                .touched("/canary", Access::Read)
                .build(),
        ),
        (
            Condition::Write,
            Stream::new(1)
                .seen("/bin/a", 501, "testuser")
                .declares("/canary", Access::Write, true)
                .build(),
        ),
    ];

    for (condition, facts) in cases {
        let mut policy = Policy::default();
        policy.watchlist.push(Rule {
            path: "/canary".to_owned(),
            condition,
            severity: Severity::Critical,
            response: topgent_policy::ResponseMode::Alert,
        });
        let risk = assess_with(&only(&facts), &policy);
        assert_eq!(risk.grade, Grade::Critical, "{condition:?}");
        assert!(
            risk.factors
                .iter()
                .any(|factor| factor.code == FactorCode::Watchlist && factor.points == 100),
            "{condition:?}"
        );
    }
}

#[test]
fn the_network_factor_waits_for_a_real_spread_of_destinations() {
    let with = |n: u16| {
        let mut s =
            Stream::new(1)
                .seen("/bin/a", 501, "testuser")
                .declares("~/w", Access::Read, true);
        for i in 0..n {
            s = s.socket(&format!("host{i}.example"), 443, Direction::Outbound);
        }
        assess(&only(&s.build()))
    };

    assert!(codes(&with(4)).is_empty(), "four is not a pattern");
    let five = with(5);
    assert_eq!(codes(&five), vec![FactorCode::UnrestrictedNetwork]);
    assert_eq!(five.score, 15);
    assert!(five.factors[0].source.contains('5'));
}

#[test]
fn listening_sockets_do_not_count_as_outbound_reach() {
    let mut s = Stream::new(1).seen("/bin/a", 501, "testuser");
    for i in 0..8 {
        s = s.socket(&format!("h{i}"), 1024 + i, Direction::Listening);
    }
    let risk = assess(&only(&s.build()));
    assert!(!codes(&risk).contains(&FactorCode::UnrestrictedNetwork));
    assert!(codes(&risk).contains(&FactorCode::ExposedListener));
}

#[test]
fn a_second_reachable_credential_is_worth_less_than_the_first() {
    let one = assess(&only(
        &Stream::new(1)
            .seen("/bin/a", 501, "testuser")
            .declares("~/w", Access::Read, true)
            .reachable("~/.ssh/id_ed25519", Access::Read, true)
            .build(),
    ));
    assert_eq!(one.score, 15);

    let two = assess(&only(
        &Stream::new(1)
            .seen("/bin/a", 501, "testuser")
            .declares("~/w", Access::Read, true)
            .reachable("~/.aws/credentials", Access::Read, true)
            .reachable("~/.ssh/id_ed25519", Access::Read, true)
            .build(),
    ));
    assert_eq!(two.score, 27, "15 for the first, 12 for the next");
    assert_eq!(
        codes(&two),
        vec![FactorCode::SecretReachable, FactorCode::SecretReachable]
    );
}

#[test]
fn a_credential_in_reach_only_becomes_a_path_when_something_can_act_on_it() {
    let secret_only = assess(&only(
        &Stream::new(1)
            .seen("/bin/a", 501, "testuser")
            .declares("~/w", Access::Read, true)
            .reachable("~/.ssh/id_ed25519", Access::Read, true)
            .build(),
    ));
    assert_eq!(codes(&secret_only), vec![FactorCode::SecretReachable]);

    let shell_only = assess(&only(
        &Stream::new(1)
            .seen("/bin/a", 501, "testuser")
            .declares("*", Access::Execute, true)
            .build(),
    ));
    assert_eq!(codes(&shell_only), vec![FactorCode::ArbitraryExecution]);

    // Together they are more than the sum: a complete path from reading a
    // credential to sending it somewhere.
    let both = assess(&only(
        &Stream::new(1)
            .seen("/bin/a", 501, "testuser")
            .declares("*", Access::Execute, true)
            .reachable("~/.ssh/id_ed25519", Access::Read, true)
            .build(),
    ));
    assert!(
        codes(&both).contains(&FactorCode::ExfiltrationPath),
        "{:?}",
        codes(&both)
    );
    assert_eq!(
        both.score,
        secret_only.score + shell_only.score + 12,
        "the compound factor is the difference"
    );
}

#[test]
fn a_reachable_path_that_holds_nothing_worth_taking_is_not_a_factor() {
    let risk = assess(&only(
        &Stream::new(1)
            .seen("/bin/a", 501, "testuser")
            .reachable("~/Documents", Access::Read, false)
            .build(),
    ));
    assert!(risk.factors.is_empty(), "sensitivity gates the factor");
}

#[test]
fn a_service_identity_reduces_every_factor_by_a_quarter() {
    let facts = |declared: bool| {
        let mut s = Stream::new(1).seen("/bin/a", 501, "testuser");
        if declared {
            s = s.declares("*", Access::Execute, true);
        } else {
            s = s.connector("shell", Access::Execute);
        }
        s.build()
    };

    let delegated = assess(&only(&facts(true)));
    let service = assess(&only(&facts(false)));

    assert_eq!(delegated.identity_multiplier, 100);
    assert_eq!(delegated.score, 30);
    assert_eq!(service.identity_multiplier, 75);
    assert_eq!(service.score, 22, "30 × 75%, truncated");
}

#[test]
fn an_agent_whose_owner_is_unknown_sits_between_the_two() {
    let risk = assess(&only(
        &Stream::new(1)
            // Owner unstated by the operating system, which the contract
            // carries as uid zero. The process fact is required: the fold no
            // longer builds an agent out of a family claim alone.
            .seen_unrecognised("/usr/bin/python3", 0, "unknown")
            .family("unclassified")
            .connector("shell", Access::Execute)
            .build(),
    ));
    assert_eq!(risk.identity_multiplier, 85);
    assert_eq!(risk.score, 25, "30 × 85%, truncated");
}

#[test]
fn grades_band_the_score_and_read_without_colour() {
    let cases = [
        (0, Grade::Low, "LOW", 1),
        (34, Grade::Low, "LOW", 1),
        (35, Grade::Medium, "MEDIUM", 2),
        (59, Grade::Medium, "MEDIUM", 2),
        (60, Grade::High, "HIGH", 3),
        (79, Grade::High, "HIGH", 3),
        (80, Grade::Critical, "CRITICAL", 4),
        (100, Grade::Critical, "CRITICAL", 4),
    ];
    for (score, grade, label, pips) in cases {
        assert_eq!(Grade::from_score(score), grade, "score {score}");
        assert_eq!(grade.label(), label);
        assert_eq!(grade.pips(), pips);
    }
    assert!(Grade::Critical > Grade::High);
    assert!(Grade::Medium > Grade::Low);
}

#[test]
fn every_factor_code_has_a_name_and_a_remedy() {
    let all = [
        FactorCode::ArbitraryExecution,
        FactorCode::BroadWrite,
        FactorCode::UnrestrictedNetwork,
        FactorCode::SecretReachable,
        FactorCode::DeclarationDrift,
        FactorCode::AgentChain,
        FactorCode::ExfiltrationPath,
        FactorCode::ReconFanout,
        FactorCode::SandboxEscape,
        FactorCode::Watchlist,
        FactorCode::ExposedListener,
        FactorCode::OffensiveTool,
        FactorCode::ProcessExplosion,
        FactorCode::SuspiciousEndpoint,
        FactorCode::PrivatePeer,
        FactorCode::MetadataService,
        FactorCode::CredentialAccess,
        FactorCode::PersistenceWrite,
        FactorCode::SelfTampering,
    ];
    let mut names: Vec<&str> = all.iter().map(|c| c.as_str()).collect();
    for c in all {
        let (action, site) = c.remedy();
        assert!(!action.is_empty(), "{c:?}");
        assert!(!site.is_empty(), "{c:?}");
        assert!(format!("{c:?}").len() > 3);
    }
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), all.len(), "codes must stay unique");

    // The multiplier ladder is part of the risk contract, so it is asserted
    // alongside the factor codes rather than only in the fold's tests.
    let order = topgent_core::risk::identity_order();
    assert_eq!(order[0].multiplier(), 100);
    assert_eq!(order[1].multiplier(), 85);
    assert_eq!(order[2].multiplier(), 75);
    assert_eq!(order[0].label(), "delegated human");
}

#[test]
fn the_fix_list_is_one_entry_per_problem_worth_what_fixing_it_returns() {
    let risk = assess(&only(&fixtures::busy_agent()));
    let fixes = remediations(&risk);

    let cancels: Vec<FactorCode> = fixes.iter().map(|f| f.cancels).collect();
    let mut unique = cancels.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(
        cancels.len(),
        unique.len(),
        "two reachable secrets are one filesystem problem"
    );

    // Non-adjacent duplicates are still merged, and their points summed.
    let secret = fixes
        .iter()
        .find(|f| f.cancels == FactorCode::SecretReachable)
        .unwrap();
    assert_eq!(secret.points, 27, "15 + 12");
    assert_eq!(secret.site, "filesystem");

    // Strongest first.
    for pair in fixes.windows(2) {
        assert!(pair[0].points >= pair[1].points);
    }
    assert_eq!(fixes[0].cancels, FactorCode::ArbitraryExecution);
}

#[test]
fn confidence_travels_with_the_factor_it_produced() {
    let mut s = Stream::new(1)
        .seen("/bin/a", 501, "testuser")
        .declares("~/w", Access::Read, true)
        .confidence(Confidence::Possible);
    for i in 0..6 {
        s = s.socket(&format!("h{i}"), 443, Direction::Outbound);
    }
    let risk = assess(&only(&s.build()));

    // The socket collector was only guessing, and the factor says so rather than
    // presenting an inference as an observation.
    assert_eq!(risk.factors[0].code, FactorCode::UnrestrictedNetwork);
    assert_eq!(risk.factors[0].confidence, Confidence::Possible);
}

#[test]
fn a_coding_agent_that_starts_scanning_jumps_to_critical() {
    use topgent_facts::Direction;

    // Before: a normal agent, one model endpoint. Not critical on network alone.
    let calm = assess(&only(
        &Stream::new(1)
            .seen("/bin/a", 501, "testuser")
            .declares("~/w", Access::Read, true)
            .socket("api.anthropic.com", 443, Direction::Outbound)
            .build(),
    ));
    assert!(!codes(&calm).contains(&FactorCode::ReconFanout));

    // After: the same agent, now reaching out to fifteen hosts at once.
    let mut rogue =
        Stream::new(1)
            .seen("/bin/a", 501, "testuser")
            .declares("~/w", Access::Read, true);
    for i in 0..15 {
        rogue = rogue.socket(&format!("192.168.1.{i}"), 22, Direction::Outbound);
    }
    let scan = assess(&only(&rogue.build()));

    assert!(
        codes(&scan).contains(&FactorCode::ReconFanout),
        "{:?}",
        codes(&scan)
    );
    // A bare scanner with nothing else is already High; the point is that active
    // scanning demands attention on its own, before you count anything it holds.
    assert!(scan.grade >= Grade::High, "scanning must demand attention");
    // The scanning factor is the loudest thing in the list.
    assert_eq!(scan.factors[0].code, FactorCode::ReconFanout);
    assert!(scan.score >= 60 && scan.score > calm.score + 45);

    // The same scan on a coding agent that already holds shell is Critical.
    let mut armed =
        Stream::new(2)
            .seen("/bin/a", 501, "testuser")
            .declares("*", Access::Execute, true);
    for i in 0..15 {
        armed = armed.socket(&format!("192.168.1.{i}"), 22, Direction::Outbound);
    }
    assert_eq!(assess(&only(&armed.build())).grade, Grade::Critical);
}

#[test]
fn scanning_a_single_host_across_many_ports_also_fires() {
    use topgent_facts::Direction;
    let mut s = Stream::new(1)
        .seen("/bin/a", 501, "testuser")
        .declares("~/w", Access::Read, true);
    for port in [21, 22, 23, 25, 80, 110, 143, 443, 3389] {
        s = s.socket("10.10.10.10", port, Direction::Outbound);
    }
    let risk = assess(&only(&s.build()));
    assert!(codes(&risk).contains(&FactorCode::ReconFanout));
    assert!(
        risk.factors
            .iter()
            .any(|f| f.source.contains("ports open to a single host"))
    );

    // A service-account agent that starts scanning is High too: active scanning
    // is not discounted by identity the way latent capability is.
    let mut svc = Stream::new(9).seen("/bin/ollama", 501, "testuser");
    for i in 0..14 {
        svc = svc.socket(
            &format!("10.0.0.{i}"),
            22,
            topgent_facts::Direction::Outbound,
        );
    }
    let svc_risk = assess(&only(&svc.build()));
    assert_eq!(svc_risk.identity_multiplier, 75);
    assert!(svc_risk.grade >= Grade::High, "score {}", svc_risk.score);
}

#[test]
fn metadata_only_rogue_signals_are_independent_and_explainable() {
    let offensive = assess(&only(
        &Stream::new(1)
            .seen("/bin/claude", 501, "testuser")
            .child(40, "/usr/local/bin/nmap", 2)
            .build(),
    ));
    assert_eq!(codes(&offensive), vec![FactorCode::OffensiveTool]);
    assert!(offensive.factors[0].source.contains("pid 40"));

    let listener = assess(&only(
        &Stream::new(1)
            .seen("/bin/claude", 501, "testuser")
            .socket("*", 4444, Direction::Listening)
            .build(),
    ));
    assert_eq!(codes(&listener), vec![FactorCode::ExposedListener]);
    assert!(listener.factors[0].title.contains("4444"));

    let raw = assess(&only(
        &Stream::new(1)
            .seen("/bin/claude", 501, "testuser")
            .socket("203.0.113.9", 4444, Direction::Outbound)
            .build(),
    ));
    assert_eq!(codes(&raw), vec![FactorCode::SuspiciousEndpoint]);

    let lateral = assess(&only(
        &Stream::new(1)
            .seen("/bin/claude", 501, "testuser")
            .socket("192.168.50.20", 22, Direction::Outbound)
            .build(),
    ));
    assert_eq!(codes(&lateral), vec![FactorCode::PrivatePeer]);

    let metadata = assess(&only(
        &Stream::new(1)
            .seen("/bin/claude", 501, "testuser")
            .socket("169.254.169.254", 80, Direction::Outbound)
            .build(),
    ));
    assert_eq!(codes(&metadata), vec![FactorCode::MetadataService]);
}

#[test]
fn process_explosion_uses_the_policy_threshold_and_ignores_small_trees() {
    let build = |count: u32| {
        let mut s = Stream::new(1).seen("/bin/claude", 501, "testuser");
        for pid in 10..10 + count {
            s = s.child(pid, "helper", 1);
        }
        assess(&only(&s.build()))
    };
    assert!(!codes(&build(19)).contains(&FactorCode::ProcessExplosion));
    assert!(codes(&build(20)).contains(&FactorCode::ProcessExplosion));
}

#[test]
fn observed_sensitive_persistence_and_topgent_writes_are_distinct() {
    let credential = assess(&only(
        &Stream::new(1)
            .seen("/bin/claude", 501, "testuser")
            .reachable("~/.ssh/id_ed25519", Access::Read, true)
            .touched("~/.ssh/id_ed25519", Access::Read)
            .build(),
    ));
    assert_eq!(codes(&credential), vec![FactorCode::CredentialAccess]);

    let persistence = assess(&only(
        &Stream::new(1)
            .seen("/bin/claude", 501, "testuser")
            .touched("~/Library/LaunchAgents/evil.plist", Access::Write)
            .build(),
    ));
    assert_eq!(codes(&persistence), vec![FactorCode::PersistenceWrite]);

    let tamper = assess(&only(
        &Stream::new(1)
            .seen("/bin/claude", 501, "testuser")
            .touched("~/.config/topgent/policy.json", Access::Write)
            .build(),
    ));
    assert_eq!(codes(&tamper), vec![FactorCode::SelfTampering]);
}

#[test]
fn loopback_listeners_and_normal_https_are_not_rogue_behaviour() {
    let risk = assess(&only(
        &Stream::new(1)
            .seen("/bin/ollama", 501, "testuser")
            .socket("127.0.0.1", 11434, Direction::Listening)
            .socket("203.0.113.20", 443, Direction::Outbound)
            .child(2, "cargo", 1)
            .build(),
    ));
    assert!(risk.factors.is_empty(), "{:#?}", risk.factors);
}

#[test]
fn a_disallowed_asset_is_critical_but_unreviewed_and_approved_assets_are_not() {
    let agent = only(
        &Stream::new(1)
            .seen("/bin/codex", 501, "testuser")
            .family("codex-cli")
            .socket("api.openai.com", 443, Direction::Outbound)
            .build(),
    );
    assert!(assess(&agent).factors.is_empty());

    let mut policy = Policy::default();
    policy.set_asset_disposition(AssetPolicy {
        asset_id: "urn:topgent:endpoint:api.openai.com%3A443".to_owned(),
        agent_family: Some("codex-cli".to_owned()),
        disposition: Disposition::Approved,
    });
    assert!(assess_with(&agent, &policy).factors.is_empty());

    policy.set_asset_disposition(AssetPolicy {
        asset_id: "urn:topgent:endpoint:api.openai.com%3A443".to_owned(),
        agent_family: Some("codex-cli".to_owned()),
        disposition: Disposition::Disallowed,
    });
    let risk = assess_with(&agent, &policy);
    assert_eq!(codes(&risk), vec![FactorCode::DisallowedAsset]);
    assert_eq!(risk.score, 80);
    assert_eq!(risk.grade, Grade::Critical);
    assert!(risk.factors[0].title.contains("api.openai.com:443"));

    let mut agent_policy = Policy::default();
    agent_policy.set_asset_disposition(AssetPolicy {
        asset_id: "urn:topgent:agent:codex-cli%3Auid501".to_owned(),
        agent_family: Some("codex-cli".to_owned()),
        disposition: Disposition::Disallowed,
    });
    let agent_risk = assess_with(&agent, &agent_policy);
    assert_eq!(codes(&agent_risk), vec![FactorCode::DisallowedAsset]);
    assert!(agent_risk.factors[0].title.contains("codex-cli"));
}

#[test]
fn a_disallowed_shared_host_extension_is_scored_without_relabelling_the_host() {
    let host = Subject::Process {
        pid: 42,
        started_at: fixtures::at(100),
    };
    let agent = only(&[
        fixtures::host_process(host.clone()),
        fixtures::fact(
            host,
            Claim::EditorExtensionActive {
                family: "continue".to_owned(),
                extension_id: "continue.continue".to_owned(),
            },
        ),
    ]);
    assert_eq!(agent.family, None);

    let id = extension_asset_id("continue", "continue.continue");
    let mut policy = Policy::default();
    policy.set_asset_disposition(AssetPolicy {
        asset_id: id.0,
        agent_family: Some("continue".to_owned()),
        disposition: Disposition::Disallowed,
    });
    let risk = assess_with(&agent, &policy);
    assert_eq!(codes(&risk), [FactorCode::DisallowedAsset]);
    assert!(risk.factors[0].title.contains("continue"));
}

#[test]
fn a_sandboxed_agent_reaching_outside_its_sandbox_is_critical() {
    use topgent_facts::Direction;
    // Declares a sandbox (marker path, denied), then opens outbound network.
    let escaped = assess(&only(
        &Stream::new(1)
            .seen("/bin/codex", 501, "testuser")
            .declares("<sandbox>", Access::Execute, false)
            .socket("8.8.8.8", 53, Direction::Outbound)
            .build(),
    ));
    assert!(
        codes(&escaped).contains(&FactorCode::SandboxEscape),
        "{:?}",
        codes(&escaped)
    );
    assert_eq!(escaped.grade, Grade::Critical);

    // A sandboxed agent that stays put is not flagged.
    let contained = assess(&only(
        &Stream::new(2)
            .seen("/bin/codex", 501, "testuser")
            .declares("<sandbox>", Access::Execute, false)
            .build(),
    ));
    assert!(!codes(&contained).contains(&FactorCode::SandboxEscape));
}

#[test]
fn analyse_folds_and_scores_in_one_call() {
    let mut facts = fixtures::busy_agent();
    facts.extend(fixtures::quiet_service());

    let out = analyse(&facts);

    assert_eq!(out.len(), 2);
    assert_eq!(out[0].0.id.pid, 998);
    assert_eq!(out[0].1.grade, Grade::Low);
    assert_eq!(out[1].0.id.pid, 66493);
    assert_eq!(out[1].1.grade, Grade::Critical);
}

#[test]
fn risk_is_inspectable_for_debugging() {
    let risk = assess(&only(&fixtures::busy_agent()));
    let shown = format!("{risk:?}");
    assert!(shown.contains("Critical"));
    assert!(shown.contains("ArbitraryExecution"));
    assert_eq!(risk, risk.clone());
}

#[test]
fn a_grade_label_round_trips_and_orders_by_severity() {
    // Grades are compared as bands, never as text: reading a direction out of
    // a sentence is how "CRITICAL to HIGH" was reported as an escalation.
    for grade in [Grade::Low, Grade::Medium, Grade::High, Grade::Critical] {
        assert_eq!(Grade::from_label(grade.label()), Some(grade));
    }
    assert_eq!(Grade::from_label("critical"), Some(Grade::Critical));
    assert_eq!(Grade::from_label("severe"), None);
    assert_eq!(Grade::from_label(""), None);
    assert!(Grade::Low < Grade::Medium);
    assert!(Grade::Medium < Grade::High);
    assert!(Grade::High < Grade::Critical);
}
