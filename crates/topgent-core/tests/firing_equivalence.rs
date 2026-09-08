//! The catalogue must decide exactly what the scorer used to decide.
//!
//! Moving a factor's gate from an `if` into a data file is only safe if the
//! two agree on every input. This is the proof: for each agent-level factor,
//! the condition in the catalogue is evaluated beside the predicate it
//! replaced, across a spread of agents, and the two must never differ.
//!
//! It is written against the predicates rather than against recorded output
//! because a golden file would pin the answer without saying why it is right.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use topgent_core::signals_for;
use topgent_facts::{Claim, Confidence, Fact, Provenance, Subject, UnixMillis};
use topgent_policy::{Policy, catalogue};

const OBSERVED: u64 = 1_756_000_000_000;

fn fact(pid: u32, claim: Claim, collector: &str) -> Fact {
    Fact::new(
        topgent_facts::SCHEMA_VERSION,
        Subject::Process {
            pid,
            started_at: UnixMillis(OBSERVED),
        },
        claim,
        Provenance {
            collector: collector.to_owned(),
            probe: "test".to_owned(),
            confidence: Confidence::Certain,
            observed_at: UnixMillis(OBSERVED),
        },
    )
    .expect("a well-formed fact")
}

/// One agent, built from whatever claims a case needs.
fn agent_from(pid: u32, extra: Vec<Claim>) -> topgent_core::Agent {
    let mut facts = vec![
        fact(
            pid,
            Claim::ProcessSeen {
                exe: "/usr/bin/claude".to_owned(),
                exe_path_known: true,
                uid: 501,
                user: "someone".to_owned(),
            },
            "process",
        ),
        fact(
            pid,
            Claim::AgentFamily {
                family: "claude-code".to_owned(),
            },
            "process",
        ),
    ];
    facts.extend(extra.into_iter().map(|claim| fact(pid, claim, "config")));
    let graph = topgent_core::fold(&facts);
    graph
        .agents
        .into_iter()
        .next()
        .expect("a recognised family makes one agent")
}

/// The agents the equivalence is checked across.
fn population() -> Vec<topgent_core::Agent> {
    vec![
        // Nothing declared, nothing observed.
        agent_from(10, Vec::new()),
        // Shell granted.
        agent_from(
            11,
            vec![Claim::PermissionDeclared {
                path: "*".to_owned(),
                access: topgent_facts::Access::Execute,
                granted: true,
            }],
        ),
        // A recursive write grant.
        agent_from(
            12,
            vec![Claim::PermissionDeclared {
                path: "/**".to_owned(),
                access: topgent_facts::Access::Write,
                granted: true,
            }],
        ),
        // A reachable credential and nothing else.
        agent_from(
            13,
            vec![Claim::ResourceReachable {
                path: "~/.ssh/id_rsa".to_owned(),
                access: topgent_facts::Access::Read,
                sensitive: true,
                evidence: topgent_facts::Reachability::AccountReadable,
            }],
        ),
        // Shell and a credential: the exfiltration pair.
        agent_from(
            14,
            vec![
                Claim::PermissionDeclared {
                    path: "*".to_owned(),
                    access: topgent_facts::Access::Execute,
                    granted: true,
                },
                Claim::ResourceReachable {
                    path: "~/.aws/credentials".to_owned(),
                    access: topgent_facts::Access::Read,
                    sensitive: true,
                    evidence: topgent_facts::Reachability::AccountReadable,
                },
            ],
        ),
        // Another agent it can invoke.
        agent_from(
            15,
            vec![Claim::InvokesAgent {
                target_pid: 99,
                via: "mcp".to_owned(),
            }],
        ),
    ]
}

#[test]
fn every_agent_level_condition_decides_what_the_predicate_decided() {
    let catalogue = catalogue::builtin().expect("the built-in catalogue loads");
    let policy = Policy::default();
    let th = &policy.thresholds;

    for agent in population() {
        let signals = signals_for(&agent);
        let fires = |code: &str| catalogue.fires(code, &signals, th);

        assert_eq!(
            fires("ARBITRARY_EXECUTION"),
            agent.can_execute(),
            "ARBITRARY_EXECUTION disagrees for pid {}",
            agent.id.pid
        );
        assert_eq!(
            fires("BROAD_WRITE"),
            agent.can_write_broadly(),
            "BROAD_WRITE disagrees for pid {}",
            agent.id.pid
        );
        assert_eq!(
            fires("UNRESTRICTED_NETWORK"),
            agent.outbound_count() >= th.network_spread,
            "UNRESTRICTED_NETWORK disagrees for pid {}",
            agent.id.pid
        );
        assert_eq!(
            fires("SECRET_REACHABLE"),
            !agent.latent_secrets().is_empty(),
            "SECRET_REACHABLE disagrees for pid {}",
            agent.id.pid
        );
        assert_eq!(
            fires("DECLARATION_DRIFT"),
            !agent.drift().is_empty(),
            "DECLARATION_DRIFT disagrees for pid {}",
            agent.id.pid
        );
        assert_eq!(
            fires("AGENT_CHAIN"),
            !agent.invokes.is_empty(),
            "AGENT_CHAIN disagrees for pid {}",
            agent.id.pid
        );
        assert_eq!(
            fires("EXFILTRATION_PATH"),
            agent.can_execute() && !agent.latent_secrets().is_empty(),
            "EXFILTRATION_PATH disagrees for pid {}",
            agent.id.pid
        );
        assert_eq!(
            fires("RECON_FANOUT"),
            agent.distinct_hosts() >= th.recon_hosts
                || agent.max_ports_to_one_host() >= th.recon_ports,
            "RECON_FANOUT disagrees for pid {}",
            agent.id.pid
        );
        assert_eq!(
            fires("PROCESS_EXPLOSION"),
            agent.children.len() >= th.process_children,
            "PROCESS_EXPLOSION disagrees for pid {}",
            agent.id.pid
        );
    }
}

#[test]
fn a_per_item_factor_never_fires_from_the_agent_level_gate() {
    // These decide per endpoint, per child or per resource. Asking the
    // agent-level gate about them must answer no, not guess.
    let catalogue = catalogue::builtin().expect("the built-in catalogue loads");
    let policy = Policy::default();
    for agent in population() {
        let signals = signals_for(&agent);
        for code in [
            "EXPOSED_LISTENER",
            "SUSPICIOUS_ENDPOINT",
            "PRIVATE_PEER",
            "METADATA_SERVICE",
            "OFFENSIVE_TOOL",
            "CREDENTIAL_ACCESS",
            "PERSISTENCE_WRITE",
            "SELF_TAMPERING",
            "WATCHLIST",
            "DISALLOWED_ASSET",
            "SANDBOX_ESCAPE",
        ] {
            assert!(
                !catalogue.fires(code, &signals, &policy.thresholds),
                "{code} answered the wrong question"
            );
        }
    }
}

#[test]
fn every_code_states_exactly_one_way_of_deciding() {
    // Three are possible and they answer different questions: `firing` decides
    // once for the agent, `per_item` walks a collection, `requires` is only a
    // reachability precondition for a factor still decided in Rust. A code with
    // two would have no rule for which wins. A code with none cannot be checked
    // for reachability at all, which is what these fields exist to make
    // possible.
    let catalogue = catalogue::builtin().expect("the built-in catalogue loads");
    for entry in &catalogue.factors {
        let ways = u8::from(entry.firing.is_some())
            + u8::from(entry.per_item.is_some())
            + u8::from(entry.requires.is_some());
        assert_eq!(ways, 1, "{} states {ways} ways of deciding", entry.code);
    }
}

#[test]
fn only_three_codes_are_still_decided_in_rust() {
    // The remainder of the decoupling, named rather than left to be discovered.
    // A watchlist match depends on rules the operator wrote, a disallowed asset
    // on dispositions they set, and a sandbox escape on a declaration compared
    // against behaviour. None reduces to a question about one item.
    let catalogue = catalogue::builtin().expect("the built-in catalogue loads");
    let mut left: Vec<&str> = catalogue
        .factors
        .iter()
        .filter(|entry| entry.requires.is_some())
        .map(|entry| entry.code.as_str())
        .collect();
    left.sort_unstable();
    assert_eq!(
        left,
        vec!["DISALLOWED_ASSET", "SANDBOX_ESCAPE", "WATCHLIST"],
        "the set of factors still decided in Rust changed"
    );
}
