//! The fold, tested by replaying fact streams.
//!
//! No mocks and no operating system: every test here is a list of facts in and
//! an agent graph out, which is the whole reason the core is pure.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use crate::fixtures;

use crate::fixtures::{Stream, at, endpoint_subject, resource_subject};
use topgent_core::{IdentityKind, RejectReason, fold, fold_with_home};
use topgent_facts::{Access, Claim, Direction, Subject, Tri};

#[test]
fn one_process_becomes_one_agent_carrying_what_was_seen() {
    let facts = Stream::new(66493)
        .seen("/usr/local/bin/claude", 501, "testuser")
        .family("claude-code")
        .model("anthropic", "claude-opus-5")
        .parent(1)
        .build();

    let g = fold(&facts);
    assert_eq!(g.agents.len(), 1);

    let a = &g.agents[0];
    assert_eq!(a.id.pid, 66493);
    assert_eq!(a.exe.as_deref(), Some("/usr/local/bin/claude"));
    assert_eq!(a.uid, Some(501));
    assert_eq!(a.user.as_deref(), Some("testuser"));
    assert_eq!(a.family.as_deref(), Some("claude-code"));
    assert_eq!(
        a.model,
        Some(("anthropic".to_owned(), "claude-opus-5".to_owned()))
    );
    assert_eq!(a.parent_pid, Some(1));
    assert_eq!(a.fact_count, 4, "one per builder call");
}

#[test]
fn multiple_agent_extensions_share_one_real_host_without_claiming_its_family() {
    let subject = Subject::Process {
        pid: 42,
        started_at: at(100),
    };
    // The editor collector emits both, and the fold anchors on both: a host
    // process with no verified extension is not an agent, and an extension
    // claim with no process behind it has no owner or executable evidence.
    let mut facts = vec![
        fixtures::fact(
            subject.clone(),
            Claim::ProcessSeen {
                exe: "/Applications/Visual Studio Code.app/Contents/MacOS/Electron".to_owned(),
                exe_path_known: true,
                uid: 501,
                user: "testuser".to_owned(),
            },
        ),
        fixtures::fact(
            subject.clone(),
            Claim::EditorExtensionActive {
                family: "roo-code".to_owned(),
                extension_id: "rooveterinaryinc.roo-cline".to_owned(),
            },
        ),
    ];
    facts.push(fixtures::fact(
        subject,
        Claim::EditorExtensionActive {
            family: "cline".to_owned(),
            extension_id: "saoudrizwan.claude-dev".to_owned(),
        },
    ));

    let graph = fold(&facts);
    let host = &graph.agents[0];
    assert_eq!(host.id.pid, 42);
    assert_eq!(host.family, None, "the shared host is not relabelled");
    assert_eq!(host.extensions.len(), 2);
    assert_eq!(host.extensions[0].family, "roo-code");
    assert_eq!(host.extensions[1].family, "cline");

    facts.reverse();
    assert_eq!(fold(&facts), graph, "extension order is deterministic");
}

#[test]
fn a_recycled_pid_does_not_inherit_the_previous_occupants_findings() {
    let mut facts = Stream::new_at(4242, at(100))
        .seen("/bin/first", 501, "testuser")
        .declares("~/.ssh", Access::Read, true)
        .build();
    facts.extend(
        Stream::new_at(4242, at(900))
            .seen("/bin/second", 501, "testuser")
            .build(),
    );

    let g = fold(&facts);

    assert_eq!(g.agents.len(), 2, "same pid, different start, two agents");
    assert_eq!(g.agents[0].exe.as_deref(), Some("/bin/first"));
    assert_eq!(g.agents[1].exe.as_deref(), Some("/bin/second"));
    assert!(g.agents[1].resources.is_empty());
    // Ambiguous by pid alone, so the convenience lookup refuses to guess.
    assert!(g.by_pid(4242).is_none());
}

#[test]
fn shuffling_the_input_cannot_change_the_output() {
    let facts = fixtures::busy_agent();
    let baseline = fold(&facts);
    let n = facts.len();

    // Reversal plus every rotation. Deterministic, so a failure reproduces.
    let mut reversed = facts.clone();
    reversed.reverse();
    assert_eq!(fold(&reversed), baseline, "reversed");

    for k in 1..n {
        let mut rotated = Vec::with_capacity(n);
        rotated.extend_from_slice(&facts[k..]);
        rotated.extend_from_slice(&facts[..k]);
        assert_eq!(fold(&rotated), baseline, "rotated by {k}");
    }
}

#[test]
fn a_fact_that_names_no_process_is_reported_rather_than_dropped() {
    let facts = vec![
        fixtures::fact(
            resource_subject("~/.ssh/id_ed25519"),
            Claim::FileTouched {
                path: "~/.ssh/id_ed25519".to_owned(),
                access: Access::Read,
            },
        ),
        fixtures::fact(
            endpoint_subject("api.anthropic.com", 443),
            Claim::AgentFamily {
                family: "mystery".to_owned(),
            },
        ),
    ];

    let g = fold(&facts);

    assert!(g.agents.is_empty());
    assert_eq!(g.rejected.len(), 2);
    assert!(
        g.rejected
            .iter()
            .all(|r| r.reason == RejectReason::UnanchoredSubject)
    );
    // Sorted for stable reporting.
    assert_eq!(g.rejected[0].claim_kind, "agent_family");
    assert_eq!(g.rejected[1].claim_kind, "file_touched");
}

/// The finding: the filesystem, network-event and DNS collectors build their
/// pid maps from every visible process and emit process-subject facts without
/// requiring the subject to be a recognised agent, and the fold built an
/// `Agent` for any of them. With audit sensors live, an unrelated shell that
/// opened a watched file arrived in the inventory with a risk score.
#[test]
fn a_process_nothing_recognised_is_not_an_agent_however_much_it_did() {
    let facts = Stream::new(9001)
        .seen_unrecognised("/bin/bash", 501, "testuser")
        .touched("~/.ssh/id_ed25519", Access::Read)
        .socket("198.51.100.20", 443, Direction::Outbound)
        .build();

    let g = fold(&facts);
    assert!(g.agents.is_empty(), "a shell was scored as an agent");

    // Kept rather than dropped, so an attribution defect stays findable.
    assert_eq!(g.rejected.len(), facts.len());
    assert!(
        g.rejected
            .iter()
            .all(|r| r.reason == RejectReason::UnanchoredIdentity)
    );
    assert!(
        g.rejected
            .iter()
            .all(|r| r.subject.map(|id| id.pid) == Some(9001)),
        "the refused facts do not say what they were about"
    );
}

/// Neither half of the anchor is enough alone, and the order they arrive in
/// cannot matter.
#[test]
fn an_agent_needs_both_a_process_and_something_that_says_what_it_is() {
    // A family claim with no process behind it: no executable, no owner.
    assert!(
        fold(&Stream::new(1).family("claude-code").build())
            .agents
            .is_empty()
    );
    // A process with nothing saying what it is.
    assert!(
        fold(
            &Stream::new(2)
                .seen_unrecognised("/bin/bash", 501, "testuser")
                .build()
        )
        .agents
        .is_empty()
    );
    // Both, in either order.
    let mut both = Stream::new(3)
        .seen_unrecognised("/usr/local/bin/claude", 501, "testuser")
        .family("claude-code")
        .build();
    assert_eq!(fold(&both).agents.len(), 1);
    both.reverse();
    assert_eq!(fold(&both).agents.len(), 1, "anchoring is order-dependent");
}

/// An editor host is an agent because a verified extension is active inside it,
/// not because the host process exists. Both facts are needed, in either order.
#[test]
fn an_editor_host_is_anchored_by_its_extension_and_not_by_being_a_process() {
    let subject = Subject::Process {
        pid: 42,
        started_at: at(100),
    };
    assert!(
        fold(&[fixtures::host_process(subject.clone())])
            .agents
            .is_empty(),
        "every editor window would be an agent"
    );

    let mut both = vec![
        fixtures::host_process(subject.clone()),
        fixtures::fact(
            subject,
            Claim::EditorExtensionActive {
                family: "cline".to_owned(),
                extension_id: "saoudrizwan.claude-dev".to_owned(),
            },
        ),
    ];
    assert_eq!(fold(&both).agents.len(), 1);
    both.reverse();
    assert_eq!(fold(&both).agents.len(), 1);
}

/// A descendant is not an agent, however much it did. Anchoring descendants as
/// well put a blank inventory row behind every helper an agent had spawned —
/// nineteen of them on one lab host — while the activity timeline was already
/// attributing their facts to the agent that spawned them, from the fact stream
/// rather than from the inventory.
#[test]
fn a_descendant_is_attributed_to_its_agent_rather_than_becoming_one() {
    let mut facts = Stream::new(10)
        .seen("/opt/codex", 501, "testuser")
        .family("codex-cli")
        .child(11, "curl", 1)
        .build();
    facts.extend(
        Stream::new(11)
            .seen_unrecognised("/usr/bin/curl", 501, "testuser")
            .touched("~/.ssh/id_ed25519", Access::Read)
            .build(),
    );

    let graph = fold(&facts);
    let pids: Vec<u32> = graph.agents.iter().map(|a| a.id.pid).collect();
    assert_eq!(pids, vec![10], "a helper process became an agent");
    assert!(
        graph
            .rejected
            .iter()
            .any(|r| r.subject.map(|id| id.pid) == Some(11)),
        "the helper's facts vanished instead of being kept as refused"
    );

    // The activity timeline still shows what the helper did, under the agent
    // that spawned it.
    let activity = topgent_core::build_activity(&facts, &graph.agents);
    let touched = activity
        .events
        .iter()
        .find(|event| event.actor_pid == 11)
        .expect("the descendant's file access is still reported");
    assert_eq!(touched.agent_pid, 10, "attributed to the wrong agent");
}

#[test]
fn the_three_columns_are_filled_from_three_different_kinds_of_fact() {
    let facts = Stream::new(1)
        .seen("/bin/agent", 501, "testuser")
        .declares("~/work", Access::Write, true)
        .touched("~/work", Access::Write)
        .reachable("~/work", Access::Write, false)
        .build();

    let g = fold(&facts);
    let r = &g.agents[0].resources[0];

    assert_eq!(r.path, "~/work");
    assert_eq!(r.declared, Tri::Yes);
    assert_eq!(r.observed, Tri::Yes);
    assert_eq!(r.reachable, Tri::Yes);
    assert!(!r.is_drift());
    assert!(!r.is_latent_secret());
}

#[test]
fn touching_what_was_never_granted_is_drift() {
    let facts = Stream::new(1)
        .seen("/bin/agent", 501, "testuser")
        .declares("~/work", Access::Write, true)
        .touched("~/Projects", Access::Read)
        .build();

    let g = fold(&facts);
    let drift = g.agents[0].drift();

    assert_eq!(drift.len(), 1);
    assert_eq!(drift[0].path, "~/Projects");
    assert_eq!(drift[0].declared, Tri::No, "closed once a config was read");
    assert_eq!(drift[0].observed, Tri::Yes);
}

#[test]
fn an_untouched_credential_in_reach_is_still_a_finding() {
    let facts = Stream::new(1)
        .seen("/bin/agent", 501, "testuser")
        .declares("~/work", Access::Write, true)
        .reachable("~/.ssh/id_ed25519", Access::Read, true)
        .build();

    let g = fold(&facts);
    let secrets = g.agents[0].latent_secrets();

    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0].path, "~/.ssh/id_ed25519");
    assert!(secrets[0].sensitive);
    assert_eq!(secrets[0].observed, Tri::No);
    assert_eq!(secrets[0].reachable, Tri::Yes);
}

/// The finding, at the fold: a probe that only established the path resolves
/// must not close the reachable column. `SECRET_REACHABLE` is fifteen points
/// and `EXFILTRATION_PATH` twelve, and both used to fire on a successful stat.
#[test]
fn a_path_that_merely_resolves_does_not_become_a_reachable_secret() {
    let facts = Stream::new(1)
        .seen("/bin/agent", 501, "testuser")
        .declares("~/work", Access::Write, true)
        .reachable_by(
            "~/.ssh/id_ed25519",
            Access::Read,
            true,
            topgent_facts::Reachability::PathResolves,
        )
        .build();

    let g = fold(&facts);
    let r = &g.agents[0].resources[0];

    assert_eq!(
        r.reachable,
        Tri::Unknown,
        "traversal was reported as readability"
    );
    assert!(
        g.agents[0].latent_secrets().is_empty(),
        "a credential nobody showed was readable was scored as one"
    );
    // The resource is still in the report, and it says what was established.
    assert_eq!(
        r.reach_evidence,
        Some(topgent_facts::Reachability::PathResolves)
    );
    assert!(r.sensitive, "it is still known to be a credential");
}

/// Two probes, one path. The kernel's answer outranks traversal whichever
/// arrives first, because the fold is order-independent by construction.
#[test]
fn the_stronger_reachability_evidence_wins_in_either_order() {
    let weak = topgent_facts::Reachability::PathResolves;
    let strong = topgent_facts::Reachability::AccountReadable;
    for (first, second) in [(weak, strong), (strong, weak)] {
        let facts = Stream::new(1)
            .seen("/bin/agent", 501, "testuser")
            .reachable_by("~/.aws/credentials", Access::Read, true, first)
            .reachable_by("~/.aws/credentials", Access::Read, true, second)
            .build();
        let g = fold(&facts);
        let r = &g.agents[0].resources[0];
        assert_eq!(r.reach_evidence, Some(strong), "{first:?} then {second:?}");
        assert_eq!(r.reachable, Tri::Yes);
    }
}

#[test]
fn a_credential_that_was_touched_is_no_longer_latent() {
    let facts = Stream::new(1)
        .seen("/bin/agent", 501, "testuser")
        .declares("~/work", Access::Write, true)
        .reachable("~/.ssh/id_ed25519", Access::Read, true)
        .touched("~/.ssh/id_ed25519", Access::Read)
        .build();

    let g = fold(&facts);
    assert!(g.agents[0].latent_secrets().is_empty());
    assert_eq!(g.agents[0].drift().len(), 1, "it is drift instead");
}

#[test]
fn without_a_config_nothing_is_reported_as_denied() {
    // An agent nobody has read config for must not report every path as `No`.
    // That would read as reassurance we have not earned.
    let facts = Stream::new(1)
        .seen("/bin/agent", 501, "testuser")
        .reachable("~/.aws/credentials", Access::Read, true)
        .build();

    let g = fold(&facts);
    let r = &g.agents[0].resources[0];

    assert_eq!(r.declared, Tri::Unknown);
    assert_eq!(r.observed, Tri::Unknown);
    assert_eq!(r.reachable, Tri::Yes);
    assert!(!r.is_drift(), "unknown is never drift");
    assert!(r.is_latent_secret());
}

#[test]
fn a_denied_grant_records_no_access() {
    let facts = Stream::new(1)
        .seen("/bin/agent", 501, "testuser")
        .declares("~/.ssh", Access::Read, false)
        .build();

    let g = fold(&facts);
    let r = &g.agents[0].resources[0];

    assert_eq!(r.declared, Tri::No);
    assert_eq!(r.access, None, "a refusal grants nothing");
}

#[test]
fn access_widens_and_execute_outranks_everything() {
    let cases = [
        (vec![Access::Read], Some(Access::Read)),
        (vec![Access::Read, Access::Read], Some(Access::Read)),
        (vec![Access::Read, Access::Write], Some(Access::ReadWrite)),
        (vec![Access::Write, Access::Read], Some(Access::ReadWrite)),
        (vec![Access::Read, Access::Execute], Some(Access::Execute)),
        (vec![Access::Execute, Access::Read], Some(Access::Execute)),
        (
            vec![Access::ReadWrite, Access::Execute],
            Some(Access::Execute),
        ),
    ];

    for (accesses, want) in cases {
        let mut s = Stream::new(1).seen("/bin/agent", 501, "testuser");
        for a in &accesses {
            s = s.touched("~/p", *a);
        }
        let g = fold(&s.build());
        assert_eq!(g.agents[0].resources[0].access, want, "{accesses:?}");
    }
}

#[test]
fn evidence_is_deduplicated_and_sorted() {
    let facts = Stream::new(1)
        .seen("/bin/agent", 501, "testuser")
        .touched_via("~/p", Access::Read, "zebra probe")
        .touched_via("~/p", Access::Read, "alpha probe")
        .touched_via("~/p", Access::Read, "zebra probe")
        .build();

    let g = fold(&facts);
    assert_eq!(
        g.agents[0].resources[0].evidence,
        vec!["alpha probe".to_owned(), "zebra probe".to_owned()]
    );
}

#[test]
fn sockets_endpoints_and_connectors_are_collected_without_duplicates() {
    let facts = Stream::new(1)
        .seen("/bin/agent", 501, "testuser")
        .socket("api.anthropic.com", 443, Direction::Outbound)
        .socket("api.anthropic.com", 443, Direction::Outbound)
        .socket("api.anthropic.com", 443, Direction::Listening)
        .socket("github.com", 443, Direction::Outbound)
        .connector("filesystem", Access::ReadWrite)
        .connector("filesystem", Access::Execute)
        .connector("github", Access::Write)
        .build();

    let g = fold(&facts);
    let a = &g.agents[0];

    // Same host and port, two directions, two rows: listening is not connecting.
    assert_eq!(a.endpoints.len(), 3);
    assert_eq!(a.outbound_count(), 2);
    assert_eq!(a.endpoints[0].host, "api.anthropic.com");
    assert_eq!(a.endpoints[2].host, "github.com");

    assert_eq!(a.connectors.len(), 2);
    assert_eq!(a.connectors[0].name, "filesystem");
    assert_eq!(
        a.connectors[0].access,
        Access::Execute,
        "the later declaration wins"
    );
}

#[test]
fn agent_edges_are_kept_and_sorted_by_target() {
    let facts = Stream::new(66493)
        .seen("/bin/agent", 501, "testuser")
        .invokes(88317, "child-process")
        .invokes(71204, "mcp")
        .invokes(71204, "mcp")
        .build();

    let g = fold(&facts);
    let edges = &g.agents[0].invokes;

    assert_eq!(edges.len(), 2);
    assert_eq!(edges[0].target_pid, 71204);
    assert_eq!(edges[0].via, "mcp");
    assert_eq!(edges[1].target_pid, 88317);
}

#[test]
fn an_action_topgent_took_is_recorded_like_anything_else_it_saw() {
    let facts = Stream::new(1)
        .seen("/bin/agent", 501, "testuser")
        .action("kill", false)
        .action("kill", true)
        .build();

    let g = fold(&facts);
    assert_eq!(
        g.agents[0].actions,
        vec![("kill".to_owned(), false), ("kill".to_owned(), true)]
    );
}

#[test]
fn identity_is_delegated_when_permissions_come_from_a_persons_config() {
    let delegated = fold(
        &Stream::new(1)
            .seen("/bin/agent", 501, "testuser")
            .declares("~/work", Access::Write, true)
            .build(),
    );
    assert_eq!(delegated.agents[0].identity, IdentityKind::DelegatedHuman);

    let service = fold(&Stream::new(2).seen("/bin/ollama", 501, "testuser").build());
    assert_eq!(service.agents[0].identity, IdentityKind::ServiceAccount);

    // The operating system named no owner, which the fact contract carries as
    // uid zero. Previously this fixture had no process fact at all; the fold
    // now refuses to build an agent out of a family claim alone, because that
    // claim carries none of the executable and owner evidence a detection
    // normally comes with.
    let unknown = fold(
        &Stream::new(3)
            .seen_unrecognised("/bin/mystery", 0, "unknown")
            .family("mystery")
            .build(),
    );
    assert_eq!(unknown.agents[0].identity, IdentityKind::Unknown);
    assert_eq!(unknown.agents[0].uid, None);
}

#[test]
fn identity_labels_and_multipliers_are_ordered_by_how_much_they_amplify() {
    let cases = [
        (IdentityKind::DelegatedHuman, "delegated human", 100),
        (IdentityKind::Unknown, "unknown", 85),
        (IdentityKind::ServiceAccount, "service account", 75),
    ];
    for (kind, label, mult) in cases {
        assert_eq!(kind.label(), label);
        assert_eq!(kind.multiplier(), mult);
    }
    let order = topgent_core::risk::identity_order();
    assert!(order[0].multiplier() > order[1].multiplier());
    assert!(order[1].multiplier() > order[2].multiplier());
}

#[test]
fn the_strongest_signal_about_an_agent_is_the_one_reported() {
    use topgent_facts::Confidence;

    let facts = Stream::new(1)
        .confidence(Confidence::Possible)
        .seen("/bin/agent", 501, "testuser")
        .confidence(Confidence::Certain)
        .family("claude-code")
        .confidence(Confidence::Likely)
        .model("anthropic", "claude-opus-5")
        .build();

    let g = fold(&facts);
    assert_eq!(g.agents[0].discovery_confidence, Confidence::Certain);
}

#[test]
fn one_weak_observation_drags_down_the_confidence_of_its_whole_evidence_kind() {
    use topgent_facts::Confidence;

    // Four sockets read straight from the OS and one inferred from a hostname.
    // The network evidence is only as good as its weakest member, so the factor
    // built on it must not inherit the certainty of the other four.
    let facts = Stream::new(1)
        .seen("/bin/agent", 501, "testuser")
        .confidence(Confidence::Certain)
        .socket("a.example", 443, Direction::Outbound)
        .socket("b.example", 443, Direction::Outbound)
        .confidence(Confidence::Possible)
        .socket("c.example", 443, Direction::Outbound)
        .confidence(Confidence::Certain)
        .socket("d.example", 443, Direction::Outbound)
        .build();

    let g = fold(&facts);
    let a = &g.agents[0];

    assert_eq!(a.confidence_for("socket_open"), Confidence::Possible);
    assert_eq!(
        a.confidence_for("process_seen"),
        Confidence::Certain,
        "a weak socket does not taint an unrelated kind"
    );
    assert_eq!(
        a.confidence_for("never_emitted"),
        Confidence::Possible,
        "absence is the least certain answer, never the most"
    );
    assert_eq!(
        a.discovery_confidence,
        Confidence::Certain,
        "the agent is certainly there; one of its sockets is the doubtful part"
    );
}

#[test]
fn a_quiet_service_carries_no_findings_at_all() {
    let g = fold(&fixtures::quiet_service());
    let a = &g.agents[0];

    assert_eq!(a.identity, IdentityKind::ServiceAccount);
    assert!(a.resources.is_empty());
    assert!(a.drift().is_empty());
    assert!(a.latent_secrets().is_empty());
    assert_eq!(a.outbound_count(), 0, "it listens, it does not reach out");
    assert!(!a.can_execute());
    assert!(!a.can_write_broadly());
}

#[test]
fn an_agent_built_from_nothing_but_a_guess_says_so() {
    // A python process talking to a model endpoint is an agent, probably. The UI
    // has to be able to say "probably" rather than presenting it as established.
    let g = fold(
        &Stream::new(1)
            .confidence(topgent_facts::Confidence::Possible)
            .seen_unrecognised("/usr/bin/python3", 0, "unknown")
            .family("unclassified")
            .build(),
    );
    assert_eq!(
        g.agents[0].discovery_confidence,
        topgent_facts::Confidence::Possible
    );
    assert_eq!(g.agents[0].uid, None, "no owner was established");
    assert_eq!(g.agents[0].identity, IdentityKind::Unknown);
}

#[test]
fn an_empty_stream_produces_an_empty_graph() {
    let g = fold(&[]);
    assert_eq!(g, topgent_core::AgentGraph::default());
    assert!(g.by_pid(1).is_none());
}

#[test]
fn lookup_by_pid_finds_the_only_match() {
    let facts = fixtures::busy_agent();
    let g = fold(&facts);
    assert_eq!(g.by_pid(66493).map(|a| a.id.pid), Some(66493));
    assert!(g.by_pid(999).is_none());
}

#[test]
fn capability_predicates_read_the_right_columns() {
    let shell = fold(
        &Stream::new(1)
            .seen("/bin/agent", 501, "testuser")
            .declares("*", Access::Execute, true)
            .build(),
    );
    assert!(shell.agents[0].can_execute());
    assert!(!shell.agents[0].can_write_broadly());

    let via_connector = fold(
        &Stream::new(1)
            .seen("/bin/agent", 501, "testuser")
            .connector("shell", Access::Execute)
            .build(),
    );
    assert!(via_connector.agents[0].can_execute());

    let broad = fold(
        &Stream::new(1)
            .seen("/bin/agent", 501, "testuser")
            .declares("~/**", Access::Write, true)
            .build(),
    );
    assert!(broad.agents[0].can_write_broadly());
    assert!(!broad.agents[0].can_execute());

    // Execute that was observed but never granted is not a granted capability.
    let observed_only = fold(
        &Stream::new(1)
            .seen("/bin/agent", 501, "testuser")
            .declares("~/w", Access::Read, true)
            .touched("~/x", Access::Execute)
            .build(),
    );
    assert!(!observed_only.agents[0].can_execute());

    // A recursive glob that was refused grants nothing.
    let refused = fold(
        &Stream::new(1)
            .seen("/bin/agent", 501, "testuser")
            .declares("~/**", Access::Write, false)
            .build(),
    );
    assert!(!refused.agents[0].can_write_broadly());
}

#[test]
fn a_burst_of_outbound_connections_reads_as_scanning() {
    use topgent_facts::Direction;

    // A quiet agent: one endpoint, no scanning shape.
    let quiet = fold(
        &Stream::new(1)
            .seen("/bin/a", 501, "testuser")
            .socket("api.anthropic.com", 443, Direction::Outbound)
            .build(),
    );
    let q = &quiet.agents[0];
    assert_eq!(q.distinct_hosts(), 1);
    assert_eq!(q.max_ports_to_one_host(), 1);

    // Many hosts at once: the shape of scanning a network.
    let mut net = Stream::new(2).seen("/bin/a", 501, "testuser");
    for i in 0..20 {
        net = net.socket(&format!("10.0.0.{i}"), 22, Direction::Outbound);
    }
    let scan = fold(&net.build());
    assert_eq!(scan.agents[0].distinct_hosts(), 20);

    // Many ports to one host: the shape of scanning a host.
    let mut host = Stream::new(3).seen("/bin/a", 501, "testuser");
    for port in [22, 80, 443, 3306, 5432, 6379, 8080, 9200, 27017] {
        host = host.socket("example.internal", port, Direction::Outbound);
    }
    let ports = fold(&host.build());
    assert_eq!(ports.agents[0].max_ports_to_one_host(), 9);
    assert_eq!(ports.agents[0].distinct_hosts(), 1);
}

#[test]
fn the_graph_is_inspectable_for_debugging() {
    let g = fold(&fixtures::busy_agent());
    let shown = format!("{g:?}");
    assert!(shown.contains("66493"));
    assert!(shown.contains("DelegatedHuman"));
}

#[test]
fn a_connection_keeps_the_earliest_creation_time_any_collector_saw() {
    // Windows records when it made each connection. A later sweep of the same
    // live connection must not make it look younger, and a collector that has
    // no timestamp must not erase one from a collector that does: an age of
    // "unknown" and an age of "just now" are different claims.
    let facts = Stream::new(1)
        .seen("/bin/agent", 501, "testuser")
        .socket_opened_at("api.anthropic.com", 443, Direction::Outbound, 5_000)
        .socket_opened_at("api.anthropic.com", 443, Direction::Outbound, 9_000)
        .socket("api.anthropic.com", 443, Direction::Outbound)
        .socket("github.com", 443, Direction::Outbound)
        .build();

    let graph = fold(&facts);
    let agent = &graph.agents[0];
    let timed = agent
        .endpoints
        .iter()
        .find(|endpoint| endpoint.host == "api.anthropic.com")
        .expect("the timestamped endpoint survives the fold");
    assert_eq!(timed.opened_at, Some(topgent_facts::UnixMillis(5_000)));

    // An endpoint nobody timestamped stays honestly unknown rather than
    // borrowing a neighbour's time or defaulting to the epoch.
    let untimed = agent
        .endpoints
        .iter()
        .find(|endpoint| endpoint.host == "github.com")
        .expect("the untimed endpoint survives the fold");
    assert_eq!(untimed.opened_at, None);
}

#[test]
fn a_connection_keeps_the_largest_counter_any_collector_reported() {
    // Kernel counters only rise for the life of a connection, so the largest
    // reading is the current one. A collector that reports none must not erase
    // one from a collector that does, and a stale smaller reading must not
    // overwrite a newer larger one.
    let facts = Stream::new(1)
        .seen("/bin/agent", 501, "testuser")
        .socket_with_bytes("api.anthropic.com", 443, Direction::Outbound, 100, 200)
        .socket_with_bytes("api.anthropic.com", 443, Direction::Outbound, 90, 300)
        .socket("api.anthropic.com", 443, Direction::Outbound)
        .socket("github.com", 443, Direction::Outbound)
        .build();

    let graph = fold(&facts);
    let agent = &graph.agents[0];
    let counted = agent
        .endpoints
        .iter()
        .find(|endpoint| endpoint.host == "api.anthropic.com")
        .expect("the counted endpoint survives the fold");
    assert_eq!(
        counted.bytes.map(|bytes| (bytes.sent, bytes.received)),
        Some((100, 300))
    );

    // An endpoint nobody counted stays honestly uncounted rather than zero.
    let uncounted = agent
        .endpoints
        .iter()
        .find(|endpoint| endpoint.host == "github.com")
        .expect("the uncounted endpoint survives the fold");
    assert_eq!(uncounted.bytes, None);
}

/// Reachability names a credential `~/.aws/credentials` because that is what a
/// person reads. The filesystem sensor names the same file
/// `/home/testuser/.aws/credentials` because that is what the kernel saw. Keyed
/// as written they were two resources, so a credential stayed "never touched"
/// however often it was opened, and `CREDENTIAL_ACCESS` could not fire for
/// anything under a home directory. Found on a Linux lab host with auditd
/// live: the activity feed showed the read, the score never moved.
#[test]
fn a_credential_named_two_ways_is_one_resource() {
    let facts = Stream::new(4242)
        .seen("/usr/local/bin/claude", 501, "testuser")
        .family("claude-code")
        .reachable("~/.aws/credentials", Access::Read, true)
        .touched("/home/testuser/.aws/credentials", Access::Read)
        .build();

    let g = fold_with_home(&facts, Some("/home/testuser"));
    let agent = &g.agents[0];
    let creds: Vec<_> = agent
        .resources
        .iter()
        .filter(|r| r.path.contains(".aws/credentials"))
        .collect();

    assert_eq!(creds.len(), 1, "one file must not become two resources");
    assert_eq!(creds[0].reachable, Tri::Yes, "reach must survive the join");
    assert_eq!(
        creds[0].observed,
        Tri::Yes,
        "an observed read must land on the resource reachability named"
    );
    assert!(
        creds[0].sensitive,
        "it is still a credential after the join"
    );
}

/// The same join in the other direction, and for a path that is not under a
/// home directory, which must be left exactly as it arrived.
#[test]
fn paths_outside_home_are_keyed_as_written() {
    let facts = Stream::new(4243)
        .seen("/usr/local/bin/claude", 501, "testuser")
        .family("claude-code")
        .touched("/etc/shadow", Access::Read)
        .reachable("/etc/shadow", Access::Read, true)
        .build();

    let g = fold_with_home(&facts, Some("/home/testuser"));
    let hits: Vec<_> = g.agents[0]
        .resources
        .iter()
        .filter(|r| r.path == "/etc/shadow")
        .collect();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].observed, Tri::Yes);
}

/// The key a rule has to be written in, so a watchlist entry and the resource
/// it means agree. A rule typed as an absolute home path was accepted and then
/// matched nothing, because the graph keys that resource by its tilde form.
#[test]
fn a_home_path_keys_the_same_however_it_is_written() {
    let home = Some("/home/testuser");
    for written in ["/home/testuser/.ssh/id_rsa", "~/.ssh/id_rsa"] {
        assert_eq!(
            topgent_core::resource_key(written, home),
            "~/.ssh/id_rsa",
            "{written} must key the same as every other name for it"
        );
    }
    // Outside home, and with no home known, a path is left exactly as written.
    assert_eq!(
        topgent_core::resource_key("/etc/shadow", home),
        "/etc/shadow"
    );
    assert_eq!(
        topgent_core::resource_key("/home/testuser/x", None),
        "/home/testuser/x"
    );
    // A sibling directory that merely starts with the same characters is not
    // inside home.
    assert_eq!(
        topgent_core::resource_key("/home/testuser2/x", home),
        "/home/testuser2/x"
    );
}
