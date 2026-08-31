use crate::fixtures::{Stream, at};
use topgent_core::{
    MAX_NETWORK_SAMPLES, NETWORK_BASELINE_EXPIRY_MS, NETWORK_HISTORY_RETENTION_MS,
    NetworkBaselineState, NetworkVerdict, build_network_baselines, fold, merge_network_history,
};
use topgent_facts::Direction;

#[test]
fn history_counts_sweeps_without_claiming_connection_counts() {
    let facts = Stream::new(10)
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .socket("api.openai.com", 443, Direction::Outbound)
        .build();
    let agents = fold(&facts).agents;
    let first = merge_network_history(&[], &agents, 1_000, 100);
    let second = merge_network_history(&first, &agents, 2_000, 100);
    assert!(second.iter().any(|record| {
        record.host == "api.openai.com"
            && record.first_seen == 1_000
            && record.last_seen == 2_000
            && record.observations == 2
    }));
}

#[test]
fn pid_reuse_creates_a_separate_history_identity() {
    let old_facts = Stream::new(10)
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .socket("api.openai.com", 443, Direction::Outbound)
        .build();
    let new_facts = Stream::new_at(10, at(9_000))
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .socket("api.openai.com", 443, Direction::Outbound)
        .build();
    let old = merge_network_history(&[], &fold(&old_facts).agents, 1_000, 100);
    let merged = merge_network_history(&old, &fold(&new_facts).agents, 9_500, 100);
    assert_eq!(merged.len(), 2);
    assert!(merged.iter().all(|record| record.observations == 1));
}

#[test]
fn snapshot_visibility_records_disappearance_and_reappearance_without_claiming_connections() {
    let facts = Stream::new(10)
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .socket("api.openai.com", 443, Direction::Outbound)
        .build();
    let agents = fold(&facts).agents;
    let visible = merge_network_history(&[], &agents, 1_000, 100);
    let absent = merge_network_history(&visible, &[], 2_000, 100);
    assert!(absent.iter().any(|record| {
        !record.currently_observed
            && record.last_visibility_change == 2_000
            && record.visibility_changes == 2
            && record.observations == 1
    }));

    let visible_again = merge_network_history(&absent, &agents, 3_000, 100);
    assert!(visible_again.iter().any(|record| {
        record.currently_observed
            && record.last_visibility_change == 3_000
            && record.visibility_changes == 3
            && record.observations == 2
    }));
}

#[test]
fn metadata_rules_are_prioritized_and_loopback_is_not_exposed() {
    let facts = Stream::new(10)
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .socket("169.254.169.254", 80, Direction::Outbound)
        .socket("203.0.113.7", 4444, Direction::Outbound)
        .socket("10.0.0.8", 22, Direction::Outbound)
        .socket("0.0.0.0", 8080, Direction::Listening)
        .socket("127.0.0.1", 4173, Direction::Listening)
        .build();
    let history = merge_network_history(&[], &fold(&facts).agents, 1_000, 100);
    let verdict = |host: &str| {
        history
            .iter()
            .find(|record| record.host == host)
            .map(|r| r.verdict)
    };
    assert_eq!(
        verdict("169.254.169.254"),
        Some(NetworkVerdict::MetadataService)
    );
    assert_eq!(
        verdict("203.0.113.7"),
        Some(NetworkVerdict::SuspiciousEndpoint)
    );
    assert_eq!(verdict("10.0.0.8"), Some(NetworkVerdict::PrivatePeer));
    assert_eq!(verdict("0.0.0.0"), Some(NetworkVerdict::ExposedListener));
    assert_eq!(verdict("127.0.0.1"), Some(NetworkVerdict::Observed));
}

#[test]
fn history_is_bounded_by_least_recent_observation() {
    let facts = Stream::new(10)
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .socket("a.example", 443, Direction::Outbound)
        .socket("b.example", 443, Direction::Outbound)
        .socket("c.example", 443, Direction::Outbound)
        .build();
    let history = merge_network_history(&[], &fold(&facts).agents, 1_000, 2);
    assert_eq!(history.len(), 2);
}

#[test]
fn history_expires_by_age_at_the_documented_boundary_and_rejects_future_records() {
    let facts = Stream::new(10)
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .socket("api.openai.com", 443, Direction::Outbound)
        .build();
    let agents = fold(&facts).agents;
    let history = merge_network_history(&[], &agents, 1_000, 100);

    let at_boundary =
        merge_network_history(&history, &[], 1_000 + NETWORK_HISTORY_RETENTION_MS, 100);
    assert_eq!(at_boundary.len(), 1);
    let expired = merge_network_history(&history, &[], 1_001 + NETWORK_HISTORY_RETENTION_MS, 100);
    assert!(expired.is_empty());

    let mut future = history;
    assert!(future.first_mut().is_some_and(|record| {
        record.last_seen = 50_000;
        true
    }));
    assert!(merge_network_history(&future, &[], 49_999, 100).is_empty());
    assert_eq!(
        merge_network_history(&future, &agents, 49_999, 100).len(),
        1
    );
}

#[test]
fn per_endpoint_sample_history_is_bounded_and_keeps_the_newest_sweeps() {
    let facts = Stream::new(10)
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .socket("api.openai.com", 443, Direction::Outbound)
        .build();
    let agents = fold(&facts).agents;
    let mut history = Vec::new();
    for sample in 0..(MAX_NETWORK_SAMPLES + 20) {
        history = merge_network_history(&history, &agents, sample as u64 * 1_000, 100);
    }
    assert!(history.iter().any(|record| {
        record.sample_times.len() == MAX_NETWORK_SAMPLES
            && record.sample_times.first().copied() == Some(20_000)
            && record.sample_times.last().copied() == Some(83_000)
    }));
}

#[test]
fn baseline_warms_freezes_expires_and_does_not_learn_late_endpoints() {
    let initial_facts = Stream::new(10)
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .socket("api.openai.com", 443, Direction::Outbound)
        .build();
    let initial_agents = fold(&initial_facts).agents;
    let mut history = Vec::new();
    for sample in 1..=4 {
        history = merge_network_history(&history, &initial_agents, sample * 1_000, 100);
    }
    assert!(
        build_network_baselines(&history, 4_000)
            .iter()
            .any(|baseline| {
                baseline.state == NetworkBaselineState::Collecting && baseline.ready_at.is_none()
            })
    );

    history = merge_network_history(&history, &initial_agents, 5_000, 100);
    assert!(
        build_network_baselines(&history, 5_000)
            .iter()
            .any(|baseline| {
                baseline.state == NetworkBaselineState::Ready
                    && baseline.ready_at == Some(5_000)
                    && baseline.known_hosts.contains("api.openai.com")
                    && baseline.known_ports.contains(&443)
            })
    );

    let late_facts = Stream::new(10)
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .socket("new.example", 8443, Direction::Outbound)
        .build();
    history = merge_network_history(&history, &fold(&late_facts).agents, 6_000, 100);
    assert!(
        build_network_baselines(&history, 6_000)
            .iter()
            .any(|baseline| {
                baseline.state == NetworkBaselineState::Ready
                    && !baseline.known_hosts.contains("new.example")
                    && !baseline.known_ports.contains(&8443)
            })
    );
    assert!(
        build_network_baselines(&history, 6_000 + NETWORK_BASELINE_EXPIRY_MS + 1)
            .iter()
            .all(|baseline| baseline.state == NetworkBaselineState::Expired)
    );
}

#[test]
fn process_restart_creates_a_fresh_collecting_baseline() {
    let old_facts = Stream::new(10)
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .socket("api.openai.com", 443, Direction::Outbound)
        .build();
    let old_agents = fold(&old_facts).agents;
    let mut history = Vec::new();
    for sample in 1..=5 {
        history = merge_network_history(&history, &old_agents, sample * 1_000, 100);
    }
    let restarted_facts = Stream::new_at(10, at(9_000))
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .socket("api.openai.com", 443, Direction::Outbound)
        .build();
    history = merge_network_history(&history, &fold(&restarted_facts).agents, 10_000, 100);
    let baselines = build_network_baselines(&history, 10_000);
    assert_eq!(baselines.len(), 2);
    assert!(
        baselines
            .iter()
            .any(|baseline| baseline.state == NetworkBaselineState::Ready)
    );
    assert!(baselines.iter().any(|baseline| {
        baseline.agent_started_at == 9_000
            && baseline.state == NetworkBaselineState::Collecting
            && baseline.retained_samples == 1
    }));
}
