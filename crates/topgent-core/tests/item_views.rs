//! The projection from an agent to the items a condition reads.
//!
//! If a flag is never set the factor that depends on it never fires, and a
//! factor that never fires looks exactly like a host with nothing wrong. So
//! the tests here are mostly about coverage: every flag a kind declares must
//! be reachable from some agent.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use topgent_facts::{Access, Claim, Confidence, Direction, Fact, MatchBasis, Protocol, Provenance};
use topgent_facts::{Reachability, Subject, UnixMillis};
use topgent_policy::ItemKind;

const OBSERVED: u64 = 1_756_000_000_000;
const PID: u32 = 4242;

fn fact(claim: Claim, collector: &str) -> Fact {
    Fact::new(
        topgent_facts::SCHEMA_VERSION,
        Subject::Process {
            pid: PID,
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

fn socket(host: &str, port: u16, direction: Direction) -> Claim {
    Claim::SocketOpen {
        protocol: Protocol::Tcp,
        host: host.to_owned(),
        port,
        direction,
        opened_at: None,
        bytes: None,
        basis: MatchBasis::ExactTuple,
    }
}

/// One agent carrying at least one item that sets every flag of every kind.
fn rich_agent() -> topgent_core::Agent {
    let facts = vec![
        fact(
            Claim::ProcessSeen {
                exe: "/usr/bin/claude".to_owned(),
                exe_path_known: true,
                uid: 501,
                user: "someone".to_owned(),
            },
            "process",
        ),
        fact(
            Claim::AgentFamily {
                family: "claude-code".to_owned(),
            },
            "process",
        ),
        // Endpoints: a loopback listener, a private outbound peer, a raw
        // address on an odd port, and a metadata service.
        fact(socket("127.0.0.1", 8080, Direction::Listening), "socket"),
        fact(socket("10.0.0.5", 4444, Direction::Outbound), "socket"),
        fact(socket("169.254.169.254", 80, Direction::Outbound), "socket"),
        // A connection that was only attempted and one that has already
        // closed: the two records a snapshot can never produce, and the reason
        // an agent working in milliseconds is visible at all.
        fact(
            Claim::ConnectionAttempt {
                host: "198.51.100.20".to_owned(),
                port: 4444,
                direction: Direction::Outbound,
                outcome: topgent_facts::ConnectionOutcome::Allowed,
            },
            "network_events",
        ),
        fact(
            Claim::SocketClosed {
                host: "203.0.113.10".to_owned(),
                port: 443,
                direction: Direction::Outbound,
                duration_ms: 12,
            },
            "network_events",
        ),
        // Traffic seen on the wire, which is the only record that says packets
        // moved and the only one available for a protocol no socket listing
        // reports.
        fact(
            Claim::TrafficObserved {
                protocol: topgent_facts::Protocol::Udp,
                host: "198.51.100.30".to_owned(),
                port: 53,
                direction: Direction::Outbound,
                packets: 12,
                first_seen: topgent_facts::UnixMillis(1_000),
                last_seen: topgent_facts::UnixMillis(2_000),
            },
            "capture",
        ),
        // A child that is known offensive tooling.
        fact(
            Claim::ChildProcessSeen {
                pid: 5150,
                name: "nmap".to_owned(),
                depth: 1,
            },
            "process",
        ),
        // Resources: observed, declared, reachable, sensitive, mutating,
        // a persistence location, and one of Topgent's own paths.
        fact(
            Claim::FileTouched {
                path: "~/.zshrc".to_owned(),
                access: Access::Write,
            },
            "filesystem",
        ),
        fact(
            Claim::ResourceReachable {
                path: "~/.aws/credentials".to_owned(),
                access: Access::Read,
                sensitive: true,
                evidence: Reachability::AccountReadable,
            },
            "reach",
        ),
        fact(
            Claim::PermissionDeclared {
                path: "/work/**".to_owned(),
                access: Access::Write,
                granted: true,
            },
            "config",
        ),
        fact(
            Claim::FileTouched {
                path: "/home/someone/.config/topgent/policy.json".to_owned(),
                access: Access::Write,
            },
            "filesystem",
        ),
    ];
    topgent_core::fold_with_home(&facts, None)
        .agents
        .into_iter()
        .next()
        .expect("a recognised family makes one agent")
}

#[test]
fn every_flag_a_kind_declares_is_reachable_from_some_item() {
    // A flag nothing can set is a factor nothing can fire.
    let agent = rich_agent();
    for kind in ItemKind::all() {
        let items = topgent_core::items_of(&agent, kind);
        assert!(
            !items.is_empty(),
            "{} projected nothing from an agent that has some",
            kind.as_str()
        );
        for flag in kind.flags() {
            assert!(
                items.iter().any(|item| item.has(*flag)),
                "no item sets {} on {}",
                flag.as_str(),
                kind.as_str()
            );
        }
    }
}

#[test]
fn every_item_names_the_kind_it_came_from() {
    let agent = rich_agent();
    for kind in ItemKind::all() {
        for item in topgent_core::items_of(&agent, kind) {
            assert_eq!(item.kind, Some(kind));
            assert!(
                !item.text.is_empty(),
                "an item with no text cannot be named"
            );
        }
    }
}

#[test]
fn an_item_never_carries_a_flag_from_another_kind() {
    let agent = rich_agent();
    for kind in ItemKind::all() {
        for item in topgent_core::items_of(&agent, kind) {
            for flag in &item.flags {
                assert!(
                    kind.flags().contains(flag),
                    "{} appeared on a {} item",
                    flag.as_str(),
                    kind.as_str()
                );
            }
        }
    }
}

#[test]
fn a_child_carries_its_executable_name_and_never_a_command_line() {
    // The fact vocabulary excludes arguments on purpose. This projection must
    // not be the place they come back.
    let agent = rich_agent();
    let children = topgent_core::items_of(&agent, ItemKind::Children);
    for item in &children {
        assert!(
            !item.text.contains(' '),
            "a child's text looks like a command line: {:?}",
            item.text
        );
    }
    assert!(children.iter().any(|item| item.text == "nmap"));
}

#[test]
fn the_projection_is_a_pure_function_of_the_agent() {
    let agent = rich_agent();
    for kind in ItemKind::all() {
        assert_eq!(
            topgent_core::items_of(&agent, kind),
            topgent_core::items_of(&agent, kind),
            "{} projected differently twice",
            kind.as_str()
        );
    }
}

#[test]
fn an_agent_with_nothing_projects_nothing_rather_than_an_empty_item() {
    let facts = vec![
        fact(
            Claim::ProcessSeen {
                exe: "/usr/bin/claude".to_owned(),
                exe_path_known: true,
                uid: 0,
                user: "root".to_owned(),
            },
            "process",
        ),
        fact(
            Claim::AgentFamily {
                family: "claude-code".to_owned(),
            },
            "process",
        ),
    ];
    let bare = topgent_core::fold_with_home(&facts, None)
        .agents
        .into_iter()
        .next()
        .expect("one agent");

    for kind in ItemKind::all() {
        assert!(
            topgent_core::items_of(&bare, kind).is_empty(),
            "{} invented an item",
            kind.as_str()
        );
    }
}
