//! What the capture accumulates, and what it refuses to.
//!
//! The accumulator sits between a wire nobody controls and a report somebody
//! reads, so both of its failure modes matter: growing without limit under
//! hostile traffic, and quietly losing evidence it was holding.

#![allow(clippy::panic, clippy::expect_used)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use topgent_collect::capture::flows::{Flows, Key, MAX_FLOWS, SCAN_PORTS};
use topgent_collect::capture::ports::{Owner, join, sole};
use topgent_collect::socket::LocalPort;

/// One row of a socket table, as the port map takes it.
fn held(port: u16, inode: u64, listening: bool) -> LocalPort {
    LocalPort {
        port,
        inode,
        listening,
    }
}
use topgent_facts::{Direction, Protocol, UnixMillis};

fn key(pid: u32, port: u16) -> Key {
    Key {
        pid,
        protocol: Protocol::Tcp,
        peer: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        peer_port: port,
        direction: Direction::Outbound,
    }
}

#[test]
fn packets_of_one_flow_fold_together() {
    let mut flows = Flows::new();
    for at in [10, 20, 30] {
        flows.record(key(1, 443), UnixMillis(at));
    }
    let drained = flows.drain();
    assert_eq!(drained.flows.len(), 1);
    let Some((_, seen)) = drained.flows.first() else {
        panic!("a recorded flow was not drained");
    };
    assert_eq!(seen.packets, 3);
    assert_eq!(seen.first_seen, UnixMillis(10));
    assert_eq!(seen.last_seen, UnixMillis(30));
}

/// Two processes talking to the same endpoint are two findings.
#[test]
fn the_process_is_part_of_the_flow() {
    let mut flows = Flows::new();
    flows.record(key(1, 443), UnixMillis(10));
    flows.record(key(2, 443), UnixMillis(10));
    assert_eq!(flows.len(), 2);
}

/// A clock that steps backwards must not produce a negative duration.
#[test]
fn last_seen_never_precedes_first_seen() {
    let mut flows = Flows::new();
    flows.record(key(1, 443), UnixMillis(500));
    flows.record(key(1, 443), UnixMillis(100));
    let drained = flows.drain();
    let Some((_, seen)) = drained.flows.first() else {
        panic!("a recorded flow was not drained");
    };
    assert!(seen.last_seen.0 >= seen.first_seen.0);
}

/// A scan across every port must not become an unbounded map.
#[test]
fn the_map_has_a_ceiling_and_says_when_it_is_reached() {
    let mut flows = Flows::new();
    for port in 0..u16::MAX {
        flows.record(key(1, port), UnixMillis(1));
    }
    assert_eq!(flows.len(), MAX_FLOWS);
    let drained = flows.drain();
    assert!(
        drained.missed.overflowed > 0,
        "flows were dropped and not counted"
    );
}

/// Nothing is evicted to make room.
///
/// An evicting cache would replace the evidence a report is about with
/// whatever arrived most recently, which under a scan is the scan itself.
#[test]
fn the_first_flows_are_the_ones_kept() {
    let mut flows = Flows::new();
    flows.record(key(1, 1), UnixMillis(1));
    for port in 1000..u16::MAX {
        flows.record(key(1, port), UnixMillis(2));
    }
    let drained = flows.drain();
    assert!(
        drained.flows.iter().any(|(held, _)| held.peer_port == 1),
        "the earliest flow was evicted"
    );
}

/// Draining is destructive, so a flow is never reported twice.
#[test]
fn draining_empties_the_accumulator() {
    let mut flows = Flows::new();
    flows.record(key(1, 443), UnixMillis(1));
    flows.frame();
    flows.unattributed();
    assert!(!flows.drain().flows.is_empty());
    let second = flows.drain();
    assert!(second.flows.is_empty());
    assert_eq!(second.missed.frames, 0);
    assert_eq!(second.missed.unattributed, 0);
}

/// Every frame is counted before anything decides not to keep it.
#[test]
fn what_was_not_kept_is_still_counted() {
    let mut flows = Flows::new();
    flows.frame();
    flows.frame();
    flows.not_modelled();
    flows.unattributed();
    let missed = flows.drain().missed;
    assert_eq!(missed.frames, 2);
    assert_eq!(missed.not_modelled, 1);
    assert_eq!(missed.unattributed, 1);
}

/// TCP 8080 and UDP 8080 can belong to different processes.
#[test]
fn the_port_map_keeps_the_protocols_apart() {
    let inodes = BTreeMap::from([(10, 100), (11, 200)]);
    let owners = join(
        &[
            (Protocol::Tcp, vec![held(8080, 10, false)]),
            (Protocol::Udp, vec![held(8080, 11, false)]),
        ],
        &inodes,
    );
    assert_eq!(owners.get(&(Protocol::Tcp, 8080)).map(|o| o.pid), Some(100));
    assert_eq!(owners.get(&(Protocol::Udp, 8080)).map(|o| o.pid), Some(200));
}

/// A socket whose inode names no process attributes to nobody.
#[test]
fn an_unowned_socket_owns_no_port() {
    let owners = join(
        &[(Protocol::Tcp, vec![held(8080, 99, false)])],
        &BTreeMap::new(),
    );
    assert!(owners.is_empty());
}

/// A port held through a fork is reported once, consistently.
#[test]
fn a_shared_port_reports_one_owner() {
    let inodes = BTreeMap::from([(10, 100), (11, 200)]);
    let owners = join(
        &[(
            Protocol::Tcp,
            vec![held(8080, 10, false), held(8080, 11, false)],
        )],
        &inodes,
    );
    assert_eq!(owners.get(&(Protocol::Tcp, 8080)).map(|o| o.pid), Some(100));
}

/// ICMP attribution is only made when it is not in doubt.
#[test]
fn icmp_is_attributed_only_to_a_sole_holder() {
    assert_eq!(sole(&[42]), Some(42));
    assert_eq!(sole(&[]), None);
    assert_eq!(sole(&[42, 43]), None);
}

/// A listening socket and a connected one are different flows.
///
/// The direction of a flow comes from here, because a packet cannot supply it:
/// a connection this host opened carries replies, and each reply looks inbound
/// on its own. Reading them that way turned every outbound connection into a
/// phantom listener, which is a scored finding.
#[test]
fn the_port_map_says_which_ports_are_listening() {
    let inodes = BTreeMap::from([(10, 100), (11, 200)]);
    let owners = join(
        &[(
            Protocol::Tcp,
            vec![held(8080, 10, true), held(52341, 11, false)],
        )],
        &inodes,
    );
    assert_eq!(
        owners.get(&(Protocol::Tcp, 8080)),
        Some(&Owner {
            pid: 100,
            listening: true
        })
    );
    assert_eq!(
        owners.get(&(Protocol::Tcp, 52341)),
        Some(&Owner {
            pid: 200,
            listening: false
        })
    );
}

/// A host touched on many ports is a scan, whoever sent it.
///
/// Counted before attribution, because a scan's connections are refused and a
/// refused connection leaves no socket to attribute through. Counting only
/// attributable packets would miss exactly the traffic this looks for.
#[test]
fn many_ports_on_one_host_is_a_scan() {
    let mut flows = Flows::new();
    let peer = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5));
    for port in 9000..9000 + u16::try_from(MAX_FLOWS.min(64)).unwrap_or(64) {
        flows.probe(peer, port, UnixMillis(port.into()));
    }
    let drained = flows.drain();
    let Some(scan) = drained.scans.first() else {
        panic!("a scan was not reported");
    };
    assert_eq!(scan.peer, peer);
    assert!(scan.ports >= SCAN_PORTS);
}

/// Ordinary traffic to a few ports is not a scan.
#[test]
fn a_handful_of_ports_is_not_a_scan() {
    let mut flows = Flows::new();
    let peer = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5));
    for port in [80, 443, 8080] {
        for _ in 0..50 {
            flows.probe(peer, port, UnixMillis(1));
        }
    }
    assert!(flows.drain().scans.is_empty());
}

/// The scan tracker is bounded like everything else here.
#[test]
fn the_scan_tracker_has_a_ceiling() {
    let mut flows = Flows::new();
    for host in 0..5000_u32 {
        let peer = IpAddr::V4(Ipv4Addr::from(host));
        for port in 0..u16::try_from(SCAN_PORTS).unwrap_or(20) {
            flows.probe(peer, port, UnixMillis(1));
        }
    }
    // Bounded, and every host it did keep is a real scan.
    let drained = flows.drain();
    assert!(drained.scans.len() <= 1024, "{}", drained.scans.len());
    assert!(drained.scans.iter().all(|scan| scan.ports >= SCAN_PORTS));
}

/// A helper's batch folds in without being replayed packet by packet.
///
/// The helper hands over an already-aggregated interval. Counting it back up
/// one packet at a time would be paying a million operations for a number the
/// other process had already worked out.
#[test]
fn an_absorbed_batch_adds_rather_than_replaces() {
    let mut first = Flows::new();
    first.record(key(1, 443), UnixMillis(10));
    first.record(key(1, 443), UnixMillis(20));
    first.frame();
    first.unattributed();
    let batch = first.drain();

    let mut second = Flows::new();
    second.record(key(1, 443), UnixMillis(5));
    second.frame();
    second.absorb(batch);

    let drained = second.drain();
    let Some((_, seen)) = drained.flows.first() else {
        panic!("the absorbed flow is missing");
    };
    assert_eq!(seen.packets, 3, "one held plus two absorbed");
    assert_eq!(seen.first_seen, UnixMillis(5), "the earliest is kept");
    assert_eq!(seen.last_seen, UnixMillis(20), "the latest is kept");
    assert_eq!(drained.missed.frames, 2);
    assert_eq!(drained.missed.unattributed, 1);
}

/// A scan reported by a helper survives the handoff.
#[test]
fn an_absorbed_scan_is_still_a_scan() {
    let mut helper = Flows::new();
    let peer = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
    for port in 0..u16::try_from(SCAN_PORTS).unwrap_or(20) + 5 {
        helper.probe(peer, port, UnixMillis(1));
    }
    let batch = helper.drain();
    assert!(!batch.scans.is_empty());

    let mut parent = Flows::new();
    parent.absorb(batch);
    let drained = parent.drain();
    let Some(scan) = drained.scans.first() else {
        panic!("the absorbed scan is missing");
    };
    assert_eq!(scan.peer, peer);
    assert!(scan.ports >= SCAN_PORTS);
}
