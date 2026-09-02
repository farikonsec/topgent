use crate::fixtures::Stream;
use topgent_core::{
    ACTIVITY_RETENTION_MS, Activity, ActivityEvent, ActivityKind, ActivityNetwork, LinkCertainty,
    NetworkActivityPhase, build_activity, fold, merge_activity_history,
};
use topgent_facts::{Access, Confidence, ConnectionOutcome, Direction, DnsOutcome, UnixMillis};

#[test]
fn connection_attempts_are_visible_without_becoming_open_endpoints() {
    let facts = Stream::new_at(42, UnixMillis(1_000))
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .connection_attempt("203.0.113.10", 443, ConnectionOutcome::Allowed)
        .connection_attempt("198.51.100.20", 22, ConnectionOutcome::Blocked)
        .build();
    let agents = fold(&facts).agents;
    assert!(
        agents
            .first()
            .is_some_and(|agent| agent.endpoints.is_empty())
    );
    let activity = build_activity(&facts, &agents);
    let phases = activity
        .events
        .iter()
        .filter_map(|event| event.network.as_ref().map(|network| network.phase))
        .collect::<Vec<_>>();
    assert_eq!(
        phases,
        vec![NetworkActivityPhase::Allowed, NetworkActivityPhase::Blocked]
    );
}

fn lifecycle_history(pid: u32, started_at: u64, times: &[u64]) -> Activity {
    Activity {
        events: times
            .iter()
            .enumerate()
            .map(|(index, at)| ActivityEvent {
                id: format!("activity:{pid}:{started_at}:closed:{index}"),
                sequence: u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1),
                parent_id: None,
                agent_pid: pid,
                agent_started_at: started_at,
                actor_pid: pid,
                at: *at,
                kind: ActivityKind::Network,
                title: "Closed connection to 203.0.113.10:443".to_owned(),
                detail: "outbound · 203.0.113.10:443 · duration 100 ms".to_owned(),
                confidence: Confidence::Certain,
                collector: "network_events".to_owned(),
                probe: "Linux Audit connect/close".to_owned(),
                network: Some(ActivityNetwork {
                    host: "203.0.113.10".to_owned(),
                    port: 443,
                    direction: Direction::Outbound,
                    phase: NetworkActivityPhase::Closed,
                    duration_ms: Some(100),
                }),
            })
            .collect(),
        links: Vec::new(),
        paths: Vec::new(),
    }
}

#[test]
fn activity_keeps_direct_attribution_separate_from_correlated_attack_paths() {
    let facts = Stream::new(10)
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .child(11, "curl", 1)
        .reachable("~/.ssh/id_ed25519", Access::Read, true)
        .touched("~/.ssh/id_ed25519", Access::Read)
        .socket("203.0.113.10", 443, Direction::Outbound)
        .action("kill", true)
        .build();
    let agents = fold(&facts).agents;
    let activity = build_activity(&facts, &agents);

    assert!(
        activity
            .events
            .iter()
            .any(|event| { event.kind == ActivityKind::Process && event.actor_pid == 11 })
    );
    assert!(
        activity
            .links
            .iter()
            .any(|link| { link.relation == "spawned" && link.certainty == LinkCertainty::Direct })
    );
    assert!(activity.links.iter().any(|link| {
        link.relation == "observed socket" && link.certainty == LinkCertainty::Attributed
    }));
    assert_eq!(activity.paths.len(), 1);
    assert!(
        activity
            .paths
            .iter()
            .all(|path| path.certainty == LinkCertainty::Correlated)
    );
    assert!(
        activity
            .paths
            .iter()
            .all(|path| path.explanation.contains("does not prove"))
    );
}

#[test]
fn socket_snapshots_are_structured_as_observations_not_connection_opens() {
    let facts = Stream::new(10)
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .socket("api.openai.com", 443, Direction::Outbound)
        .build();
    let activity = build_activity(&facts, &fold(&facts).agents);
    assert!(activity.events.iter().any(|event| {
        event.title == "Observed endpoint api.openai.com:443"
            && event.network.as_ref().is_some_and(|network| {
                network.phase == NetworkActivityPhase::Observed
                    && network.duration_ms.is_none()
                    && network.host == "api.openai.com"
                    && network.port == 443
            })
    }));
}

#[test]
fn reachability_without_an_observed_read_never_becomes_an_activity_path() {
    let facts = Stream::new(10)
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .reachable("~/.ssh/id_ed25519", Access::Read, true)
        .socket("203.0.113.10", 443, Direction::Outbound)
        .build();
    let agents = fold(&facts).agents;
    let activity = build_activity(&facts, &agents);
    assert!(activity.paths.is_empty());
    assert!(
        !activity
            .events
            .iter()
            .any(|event| event.kind == ActivityKind::File)
    );
}

#[test]
fn activity_is_stable_when_facts_arrive_out_of_order() {
    let facts = Stream::new(10)
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .child(11, "curl", 1)
        .socket("203.0.113.10", 443, Direction::Outbound)
        .build();
    let forward = build_activity(&facts, &fold(&facts).agents);
    let mut reversed = facts;
    reversed.reverse();
    let backward = build_activity(&reversed, &fold(&reversed).agents);
    assert_eq!(forward, backward);
}

#[test]
#[allow(clippy::expect_used)]
fn activity_has_monotonic_sequences_and_explicit_direct_parents() {
    let facts = Stream::new_at(42, UnixMillis(1_000))
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .child(43, "curl", 1)
        .socket("203.0.113.10", 443, Direction::Outbound)
        .build();
    let activity = build_activity(&facts, &fold(&facts).agents);
    let root = activity
        .events
        .iter()
        .find(|event| event.kind == ActivityKind::Started)
        .expect("root event");
    assert_eq!(root.sequence, 0);
    assert_eq!(root.parent_id, None);
    let mut sequences = activity
        .events
        .iter()
        .filter(|event| event.kind != ActivityKind::Started)
        .map(|event| event.sequence)
        .collect::<Vec<_>>();
    sequences.sort_unstable();
    assert_eq!(sequences, (1..=sequences.len() as u64).collect::<Vec<_>>());
    assert!(activity.events.iter().any(|event| {
        event.kind == ActivityKind::Process && event.parent_id.as_deref() == Some(root.id.as_str())
    }));
    assert!(
        activity
            .events
            .iter()
            .any(|event| { event.kind == ActivityKind::Network && event.parent_id.is_none() })
    );
}

#[test]
#[allow(clippy::expect_used)]
fn exact_descendant_activity_is_attributed_through_its_process_event() {
    let mut facts = Stream::new_at(42, UnixMillis(1_000))
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .child(43, "curl", 1)
        .build();
    facts.extend(
        Stream::new_at(43, UnixMillis(1_500))
            // A descendant, not an agent. It is anchored by the parent naming
            // it as a child, which is the only third way into the fold.
            .seen_unrecognised("/usr/bin/curl", 501, "testuser")
            .touched("~/.ssh/id_ed25519", Access::Read)
            .socket("203.0.113.10", 443, Direction::Outbound)
            .build(),
    );
    let activity = build_activity(&facts, &fold(&facts).agents);
    let child = activity
        .events
        .iter()
        .find(|event| event.kind == ActivityKind::Process && event.actor_pid == 43)
        .expect("child process event");
    let attributed = activity
        .events
        .iter()
        .filter(|event| matches!(event.kind, ActivityKind::File | ActivityKind::Network))
        .collect::<Vec<_>>();
    assert_eq!(attributed.len(), 2);
    assert!(attributed.iter().all(|event| {
        event.agent_pid == 42
            && event.agent_started_at == 1_000
            && event.actor_pid == 43
            && event.parent_id.as_deref() == Some(child.id.as_str())
    }));
    assert!(attributed.iter().all(|event| {
        activity.links.iter().any(|link| {
            link.from == child.id && link.to == event.id && link.certainty == LinkCertainty::Direct
        })
    }));
}

#[test]
fn ambiguous_or_reused_descendant_identity_fails_closed() {
    let mut shared = Stream::new_at(42, UnixMillis(1_000))
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .child(50, "helper", 1)
        .build();
    shared.extend(
        Stream::new_at(44, UnixMillis(1_100))
            .seen("/opt/claude", 501, "testuser")
            .family("claude-code")
            .child(50, "helper", 1)
            .build(),
    );
    shared.extend(
        Stream::new_at(50, UnixMillis(1_500))
            .seen_unrecognised("/usr/bin/helper", 501, "testuser")
            .touched("/tmp/shared", Access::Write)
            .build(),
    );
    let activity = build_activity(&shared, &fold(&shared).agents);
    assert!(
        !activity
            .events
            .iter()
            .any(|event| { event.kind == ActivityKind::File && event.actor_pid == 50 })
    );

    let mut reused = Stream::new_at(42, UnixMillis(1_000))
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .child(51, "helper", 1)
        .build();
    reused.extend(
        Stream::new_at(51, UnixMillis(1_400))
            .seen_unrecognised("/usr/bin/old-helper", 501, "testuser")
            .build(),
    );
    reused.extend(
        Stream::new_at(51, UnixMillis(1_600))
            .seen_unrecognised("/usr/bin/new-helper", 501, "testuser")
            .socket("198.51.100.20", 443, Direction::Outbound)
            .build(),
    );
    let activity = build_activity(&reused, &fold(&reused).agents);
    assert!(
        !activity
            .events
            .iter()
            .any(|event| { event.kind == ActivityKind::Network && event.actor_pid == 51 })
    );
}

#[test]
#[allow(clippy::expect_used)]
fn durable_sequences_survive_restart_clock_skew_and_pid_reuse() {
    let first_facts = Stream::new_at(42, UnixMillis(1_000))
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .socket("203.0.113.10", 443, Direction::Outbound)
        .build();
    let first = build_activity(&first_facts, &fold(&first_facts).agents);
    let persisted = merge_activity_history(&Activity::default(), &first, 5_000, 100);
    let old_sequences = persisted
        .events
        .iter()
        .map(|event| (event.id.clone(), event.sequence))
        .collect::<std::collections::BTreeMap<_, _>>();

    let mut late = persisted
        .events
        .iter()
        .find(|event| event.kind == ActivityKind::Network)
        .cloned()
        .expect("network event");
    late.id.push_str(":late");
    late.at = 900;
    late.sequence = 1;
    let current = Activity {
        events: vec![late.clone()],
        links: Vec::new(),
        paths: Vec::new(),
    };
    let merged = merge_activity_history(&persisted, &current, 6_000, 100);
    for event in &persisted.events {
        assert_eq!(
            merged
                .events
                .iter()
                .find(|candidate| candidate.id == event.id)
                .map(|candidate| candidate.sequence),
            old_sequences.get(&event.id).copied()
        );
    }
    let late_sequence = merged
        .events
        .iter()
        .find(|event| event.id == late.id)
        .map(|event| event.sequence)
        .expect("late event retained");
    assert!(late_sequence > old_sequences.values().copied().max().unwrap_or(0));
    assert_eq!(
        merge_activity_history(&merged, &current, 7_000, 100)
            .events
            .iter()
            .find(|event| event.id == late.id)
            .map(|event| event.sequence),
        Some(late_sequence),
        "restart replay must not renumber an existing event"
    );

    let mut legacy = persisted.clone();
    for event in &mut legacy.events {
        if event.kind != ActivityKind::Started {
            event.sequence = 0;
        }
    }
    let migrated = merge_activity_history(&legacy, &Activity::default(), 7_000, 100);
    let migrated_sequences = migrated
        .events
        .iter()
        .filter(|event| event.kind != ActivityKind::Started)
        .map(|event| event.sequence)
        .collect::<std::collections::BTreeSet<_>>();
    assert!(migrated_sequences.iter().all(|sequence| *sequence > 0));
    assert_eq!(
        migrated_sequences.len(),
        migrated
            .events
            .iter()
            .filter(|event| event.kind != ActivityKind::Started)
            .count()
    );

    let reused_facts = Stream::new_at(42, UnixMillis(8_000))
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .socket("198.51.100.20", 443, Direction::Outbound)
        .build();
    let reused = build_activity(&reused_facts, &fold(&reused_facts).agents);
    let both = merge_activity_history(&merged, &reused, 9_000, 100);
    assert!(both.events.iter().any(|event| {
        event.agent_started_at == 8_000
            && event.kind == ActivityKind::Started
            && event.sequence == 0
    }));
}

#[test]
fn a_closed_socket_is_timed_activity_but_not_a_current_endpoint() {
    let facts = Stream::new(10)
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .socket_closed("203.0.113.10", 443, Direction::Outbound, 750)
        .build();
    let agents = fold(&facts).agents;
    assert!(
        agents
            .first()
            .is_some_and(|agent| agent.endpoints.is_empty())
    );
    let activity = build_activity(&facts, &agents);
    assert!(activity.events.iter().any(|event| {
        event.title == "Closed connection to 203.0.113.10:443"
            && event.detail.contains("duration 750 ms")
            && event.network.as_ref().is_some_and(|network| {
                network.host == "203.0.113.10"
                    && network.port == 443
                    && network.direction == Direction::Outbound
                    && network.phase == NetworkActivityPhase::Closed
                    && network.duration_ms == Some(750)
            })
    }));
    assert!(
        activity
            .links
            .iter()
            .any(|link| link.relation == "closed socket")
    );
}

#[test]
fn history_survives_scans_without_crossing_reused_pid_identity() {
    let first_facts = Stream::new_at(42, UnixMillis(1_000))
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .socket("203.0.113.10", 443, Direction::Outbound)
        .build();
    let first = build_activity(&first_facts, &fold(&first_facts).agents);
    let second_facts = Stream::new_at(42, UnixMillis(1_500))
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .touched("/tmp/new-run", Access::Write)
        .build();
    let second = build_activity(&second_facts, &fold(&second_facts).agents);

    let merged = merge_activity_history(&first, &second, 3_000, 100);
    assert!(
        merged
            .events
            .iter()
            .any(|event| event.agent_started_at == 1_000)
    );
    assert!(
        merged
            .events
            .iter()
            .any(|event| event.agent_started_at == 1_500)
    );
    assert!(merged.paths.is_empty());
    assert!(merged.links.iter().all(|link| {
        merged
            .events
            .iter()
            .find(|event| event.id == link.from)
            .zip(merged.events.iter().find(|event| event.id == link.to))
            .is_some_and(|(from, to)| from.agent_started_at == to.agent_started_at)
    }));
}

#[test]
fn history_is_deduplicated_retained_and_bounded_without_dangling_links() {
    let facts = Stream::new(42)
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .child(43, "curl", 1)
        .socket("203.0.113.10", 443, Direction::Outbound)
        .build();
    let current = build_activity(&facts, &fold(&facts).agents);
    let merged = merge_activity_history(&current, &current, 3_000, 2);
    assert_eq!(merged.events.len(), 2);
    assert!(
        merged
            .events
            .iter()
            .any(|event| event.kind == ActivityKind::Started)
    );
    assert!(merged.links.iter().all(|link| {
        merged.events.iter().any(|event| event.id == link.from)
            && merged.events.iter().any(|event| event.id == link.to)
    }));

    let expired = merge_activity_history(
        &current,
        &topgent_core::Activity::default(),
        ACTIVITY_RETENTION_MS + 10_000,
        100,
    );
    assert!(expired.events.is_empty());
    assert!(expired.links.is_empty());

    let empty = merge_activity_history(&current, &current, 3_000, 0);
    assert!(empty.events.is_empty());
    assert!(empty.links.is_empty());
    assert!(empty.paths.is_empty());
}

#[test]
fn exact_completed_lifecycles_create_a_non_scoring_periodicity_path_at_threshold() {
    let history = lifecycle_history(42, 500, &[1_000, 2_000, 3_000, 4_000, 5_000]);
    let merged = merge_activity_history(&history, &Activity::default(), 6_000, 100);
    assert!(merged.paths.iter().any(|path| {
        path.id.contains("periodic-lifecycle")
            && path.events.len() == 5
            && path.title.contains("203.0.113.10:443")
            && path.explanation.contains("not proof of beaconing")
            && path.certainty == LinkCertainty::Correlated
    }));
}

#[test]
fn lifecycle_periodicity_rejects_below_threshold_jitter_and_pid_reuse_mixtures() {
    let below = lifecycle_history(42, 500, &[1_000, 2_000, 3_000, 4_000]);
    assert!(
        merge_activity_history(&below, &Activity::default(), 6_000, 100)
            .paths
            .is_empty()
    );

    let jitter = lifecycle_history(42, 500, &[1_000, 2_000, 3_000, 4_500, 5_500]);
    assert!(
        merge_activity_history(&jitter, &Activity::default(), 6_000, 100)
            .paths
            .is_empty()
    );

    let first = lifecycle_history(42, 500, &[1_000, 2_000, 3_000]);
    let second = lifecycle_history(42, 700, &[4_000, 5_000, 6_000]);
    let split = merge_activity_history(&first, &second, 7_000, 100);
    assert!(split.paths.is_empty());
}

#[test]
fn lifecycle_periodicity_accepts_exact_jitter_and_interval_boundaries() {
    let exact_jitter = lifecycle_history(42, 500, &[1_000, 2_000, 3_200, 4_200, 5_200]);
    assert_eq!(
        merge_activity_history(&exact_jitter, &Activity::default(), 6_000, 100)
            .paths
            .len(),
        1
    );

    let hour = 60 * 60 * 1_000;
    let exact_maximum = lifecycle_history(
        42,
        500,
        &[1, 1 + hour, 1 + 2 * hour, 1 + 3 * hour, 1 + 4 * hour],
    );
    assert_eq!(
        merge_activity_history(&exact_maximum, &Activity::default(), 2 + 4 * hour, 100)
            .paths
            .len(),
        1
    );
}

#[test]
fn lifecycle_periodicity_rejects_just_outside_jitter_and_interval_boundaries() {
    let excess_jitter = lifecycle_history(42, 500, &[1_000, 2_000, 3_201, 4_201, 5_201]);
    assert!(
        merge_activity_history(&excess_jitter, &Activity::default(), 6_000, 100)
            .paths
            .is_empty()
    );

    let too_fast = lifecycle_history(42, 500, &[1_000, 1_999, 2_998, 3_997, 4_996]);
    assert!(
        merge_activity_history(&too_fast, &Activity::default(), 6_000, 100)
            .paths
            .is_empty()
    );
}

#[test]
fn a_name_lookup_is_a_question_asked_not_a_destination_reached() {
    // Resolving a name is not connecting to it. The timeline has to say what
    // was asked and what the resolver said, and must not turn either into an
    // endpoint the agent reached.
    let facts = Stream::new(1)
        .seen("/bin/agent", 501, "testuser")
        .family("claude-code")
        .dns_query("api.anthropic.com", 1, DnsOutcome::Answered)
        .dns_query("nowhere.invalid", 1, DnsOutcome::NotFound)
        .build();

    let graph = fold(&facts);
    let activity = build_activity(&facts, &graph.agents);

    let lookups: Vec<_> = activity
        .events
        .iter()
        .filter(|event| event.title.starts_with("Name lookup"))
        .collect();
    assert_eq!(lookups.len(), 2);
    let titles: Vec<&str> = lookups.iter().map(|event| event.title.as_str()).collect();
    assert_eq!(
        titles,
        [
            "Name lookup answered: api.anthropic.com",
            "Name lookup not found: nowhere.invalid",
        ]
    );
    assert!(
        lookups
            .iter()
            .all(|event| event.kind == ActivityKind::Network)
    );

    // A lookup carries no network endpoint: it is a question, and rendering it
    // as a connection would claim traffic that may never have happened.
    assert!(lookups.iter().all(|event| event.network.is_none()));

    // And it never becomes a current endpoint on the agent.
    assert!(
        graph
            .agents
            .iter()
            .flat_map(|agent| &agent.endpoints)
            .all(|endpoint| endpoint.host != "api.anthropic.com")
    );
}
