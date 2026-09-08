//! What a drained capture is allowed to become.
//!
//! The projection from flows to facts is where a capture stops being a
//! measurement and starts being evidence about a named process, so the rules
//! about who a flow may be attributed to live here.

#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use topgent_collect::FixedClock;
use topgent_collect::capture::flows::{Drained, Key, Missed, Seen};
use topgent_collect::capture::live::facts_from;
use topgent_facts::{Claim, Direction, Protocol, Subject, UnixMillis};

/// The subject a flow from `pid` should end up on.
fn owner(pid: u32, started_at: u64) -> (u32, Subject) {
    (
        pid,
        Subject::Process {
            pid,
            started_at: UnixMillis(started_at),
        },
    )
}

fn flow(pid: u32, protocol: Protocol, port: u16, packets: u64) -> (Key, Seen) {
    (
        Key {
            pid,
            protocol,
            peer: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 30)),
            peer_port: port,
            direction: Direction::Outbound,
        },
        Seen {
            packets,
            first_seen: UnixMillis(1_000),
            last_seen: UnixMillis(2_000),
        },
    )
}

fn drained(flows: Vec<(Key, Seen)>) -> Drained {
    Drained {
        flows,
        missed: Missed::default(),
        scans: Vec::new(),
    }
}

#[test]
fn a_flow_becomes_a_fact_about_the_process_that_held_the_port() {
    let owners = BTreeMap::from([owner(42, 500)]);
    let facts = facts_from(
        &drained(vec![flow(42, Protocol::Udp, 53, 12)]),
        &owners,
        &FixedClock(9_000),
    );

    let fact = facts.first().expect("one fact");
    assert_eq!(
        *fact.subject(),
        Subject::Process {
            pid: 42,
            started_at: UnixMillis(500)
        }
    );
    let Claim::TrafficObserved {
        protocol,
        host,
        port,
        packets,
        first_seen,
        last_seen,
        ..
    } = fact.claim()
    else {
        panic!("a flow became something other than observed traffic");
    };
    assert_eq!(*protocol, Protocol::Udp);
    assert_eq!(host, "198.51.100.30");
    assert_eq!(*port, 53);
    assert_eq!(*packets, 12);
    assert_eq!(*first_seen, UnixMillis(1_000));
    assert_eq!(*last_seen, UnixMillis(2_000));
}

/// A flow with no agent above it belongs to nobody.
///
/// Pids are reused, and a flow attributed to a recycled pid would inherit the
/// previous occupant's findings. A process the sweep could not see, or one
/// with no recognised agent anywhere above it, has no subject and is dropped.
#[test]
fn a_flow_whose_process_is_gone_becomes_nothing() {
    let facts = facts_from(
        &drained(vec![flow(999, Protocol::Tcp, 443, 3)]),
        &BTreeMap::new(),
        &FixedClock(9_000),
    );
    assert!(facts.is_empty());
}

#[test]
fn each_flow_is_one_fact() {
    let owners = BTreeMap::from([owner(42, 500), owner(43, 600)]);
    let facts = facts_from(
        &drained(vec![
            flow(42, Protocol::Tcp, 443, 1),
            flow(43, Protocol::Tcp, 443, 1),
            flow(42, Protocol::Icmp, 0, 1),
        ]),
        &owners,
        &FixedClock(9_000),
    );
    assert_eq!(facts.len(), 3);
}

/// Every fact carries the collector that made it and the probe it came from.
#[test]
fn the_provenance_names_the_capture() {
    let owners = BTreeMap::from([owner(42, 500)]);
    let facts = facts_from(
        &drained(vec![flow(42, Protocol::Tcp, 443, 1)]),
        &owners,
        &FixedClock(9_000),
    );
    let fact = facts.first().expect("one fact");
    assert_eq!(fact.provenance().collector, "capture");
    assert!(fact.provenance().probe.contains("packet headers"));
    assert_eq!(fact.provenance().observed_at, UnixMillis(9_000));
}

/// A helper's traffic counts as its agent's.
///
/// The whole point of the owner map. An agent works through a shell it
/// spawned, and that shell holds the port; anchoring the flow to the shell
/// would produce a fact about a process with no family, which the fold
/// rejects, and the feature would report nothing at all for a real agent.
#[test]
fn a_helpers_traffic_is_attributed_to_the_agent_above_it() {
    let agent = Subject::Process {
        pid: 100,
        started_at: UnixMillis(1),
    };
    // The shell is pid 200; its owner is the agent.
    let owners = BTreeMap::from([(200, agent.clone())]);
    let facts = facts_from(
        &drained(vec![flow(200, Protocol::Udp, 9999, 7)]),
        &owners,
        &FixedClock(9_000),
    );
    let fact = facts.first().expect("one fact");
    assert_eq!(*fact.subject(), agent);
}
