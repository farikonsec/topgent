//! What a captured frame is allowed to become.
//!
//! Frames are the most hostile input this tool will ever read: attacker-shaped
//! bytes, arriving continuously, parsed in-process. These tests are about the
//! boundaries rather than the happy path.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr};

use topgent_collect::capture::packet::{LinkKind, MAX_FRAME, Observed, parse};
use topgent_facts::{Direction, Protocol};

const HERE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const THERE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);

fn locals() -> Vec<IpAddr> {
    vec![IpAddr::V4(HERE), IpAddr::V4(Ipv4Addr::LOCALHOST)]
}

/// One frame, built the way the wire would carry it.
fn frame(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
) -> Vec<u8> {
    let builder = etherparse::PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [6, 5, 4, 3, 2, 1])
        .ipv4(source.octets(), destination.octets(), 64)
        .tcp(source_port, destination_port, 0, 1024);
    let mut out = Vec::new();
    builder.write(&mut out, &[]).expect("a well-formed frame");
    out
}

#[test]
fn an_outbound_packet_names_the_far_end_as_the_peer() {
    let observed = parse(
        &frame(HERE, THERE, 54321, 443),
        LinkKind::Ethernet,
        &locals(),
    )
    .expect("this host is one end");

    assert_eq!(
        observed,
        Observed {
            protocol: Protocol::Tcp,
            peer: IpAddr::V4(THERE),
            peer_port: 443,
            local_port: 54321,
            direction: Direction::Outbound,
        }
    );
}

#[test]
fn an_inbound_packet_names_the_far_end_as_the_peer_too() {
    // The peer is whichever end is not this host, and that follows from the
    // direction rather than being decided twice.
    let observed = parse(
        &frame(THERE, HERE, 443, 54321),
        LinkKind::Ethernet,
        &locals(),
    )
    .expect("this host is one end");

    assert_eq!(observed.peer, IpAddr::V4(THERE));
    assert_eq!(observed.peer_port, 443);
    assert_eq!(observed.local_port, 54321, "the end that names a process");
    assert_eq!(observed.direction, Direction::Listening);
}

#[test]
fn a_packet_between_two_other_machines_is_not_this_hosts_traffic() {
    // On a shared segment or a mirror port there is a great deal of it, and
    // attributing it to an agent here would be inventing evidence.
    let elsewhere = Ipv4Addr::new(198, 51, 100, 7);
    assert!(
        parse(
            &frame(elsewhere, THERE, 1, 2),
            LinkKind::Ethernet,
            &locals()
        )
        .is_none()
    );
}

#[test]
fn loopback_reads_as_outbound_rather_than_as_neither() {
    // Both ends are this host. Something here initiated it, so outbound is the
    // truthful read, and dropping it would lose every local connection.
    let observed = parse(
        &frame(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, 40000, 8080),
        LinkKind::Ethernet,
        &locals(),
    )
    .expect("loopback is this host's traffic");

    assert_eq!(observed.direction, Direction::Outbound);
    assert_eq!(observed.peer_port, 8080);
}

#[test]
fn udp_is_carried_with_its_ports() {
    let mut out = Vec::new();
    etherparse::PacketBuilder::ethernet2([1; 6], [2; 6])
        .ipv4(HERE.octets(), THERE.octets(), 64)
        .udp(5353, 53)
        .write(&mut out, &[])
        .expect("a well-formed frame");

    let observed = parse(&out, LinkKind::Ethernet, &locals()).expect("parsed");
    assert_eq!(observed.protocol, Protocol::Udp);
    assert_eq!(observed.peer_port, 53);
}

#[test]
fn icmp_has_no_ports_and_says_so_by_its_protocol() {
    // Zero is not a port. The protocol beside it is what tells a reader
    // whether zero means "none" or "unread".
    let mut out = Vec::new();
    etherparse::PacketBuilder::ethernet2([1; 6], [2; 6])
        .ipv4(HERE.octets(), THERE.octets(), 64)
        .icmpv4_echo_request(1, 1)
        .write(&mut out, &[])
        .expect("a well-formed frame");

    let observed = parse(&out, LinkKind::Ethernet, &locals()).expect("parsed");
    assert_eq!(observed.protocol, Protocol::Icmp);
    assert_eq!(observed.peer_port, 0);
    assert_eq!(observed.peer, IpAddr::V4(THERE));
}

#[test]
fn nothing_that_will_not_parse_becomes_a_finding() {
    for bad in [
        vec![],
        vec![0_u8; 3],
        vec![0xff_u8; 40],
        b"not a frame at all, just some bytes".to_vec(),
    ] {
        assert!(parse(&bad, LinkKind::Ethernet, &locals()).is_none());
        assert!(parse(&bad, LinkKind::Raw, &locals()).is_none());
    }
}

#[test]
fn an_absurdly_large_frame_is_refused_before_it_is_read() {
    // Cheaper than trusting a length field, and a handle configured for more
    // than this is configured wrong.
    let huge = vec![0_u8; MAX_FRAME + 1];
    assert!(parse(&huge, LinkKind::Ethernet, &locals()).is_none());
}

#[test]
fn a_frame_with_no_link_header_parses_from_the_ip_header() {
    // Loopback capture on some platforms hands over frames with no Ethernet
    // header at all.
    let mut out = Vec::new();
    etherparse::PacketBuilder::ipv4(HERE.octets(), THERE.octets(), 64)
        .tcp(1234, 80, 0, 1024)
        .write(&mut out, &[])
        .expect("a well-formed packet");

    assert!(parse(&out, LinkKind::Raw, &locals()).is_some());
    assert!(
        parse(&out, LinkKind::Ethernet, &locals()).is_none(),
        "read with the wrong link kind it must fail rather than misread"
    );
}

#[test]
fn a_packet_with_no_local_port_cannot_be_attributed_and_is_dropped() {
    // Port zero is carryable in a TCP header and there is no socket on it, so
    // nothing could ever tie such a packet to a process. The socket collector
    // applies the same rule to an unowned socket. Found by the fuzz target,
    // which reached it in twenty-five seconds.
    assert!(parse(&frame(HERE, THERE, 0, 443), LinkKind::Ethernet, &locals()).is_none());
    assert!(parse(&frame(THERE, HERE, 443, 0), LinkKind::Ethernet, &locals()).is_none());
}

#[test]
fn icmp_is_kept_even_though_it_has_no_ports() {
    // The rule above is about a port-bearing protocol with no port. ICMP has
    // none by design, and dropping it would lose the one protocol no socket
    // listing shows at all.
    let mut out = Vec::new();
    etherparse::PacketBuilder::ethernet2([1; 6], [2; 6])
        .ipv4(HERE.octets(), THERE.octets(), 64)
        .icmpv4_echo_request(7, 7)
        .write(&mut out, &[])
        .expect("a well-formed frame");

    assert!(parse(&out, LinkKind::Ethernet, &locals()).is_some());
}

#[test]
fn a_peer_on_this_machine_is_still_a_peer() {
    // An agent talking to a service on this host is real traffic and a real
    // finding: the lab's own listener and backdoor cases are both local.
    // Assuming otherwise was wrong, and the fuzz target proved it.
    let observed = parse(
        &frame(HERE, HERE, 40000, 4444),
        LinkKind::Ethernet,
        &locals(),
    )
    .expect("this host at both ends is still this host's traffic");

    assert_eq!(observed.peer, IpAddr::V4(HERE));
    assert_eq!(observed.peer_port, 4444);
}

#[test]
fn a_frame_truncated_by_the_capture_buffer_still_parses() {
    // Every frame the capture reads is truncated: the buffer holds headers
    // only, so an internet header declaring fifteen hundred bytes arrives with
    // a couple of hundred behind it. A strict parser calls that a length error
    // and refuses, which is correct about the frame and catastrophic about the
    // feature — the capture would have seen only packets small enough to fit,
    // which is roughly none of the ones worth seeing.
    let mut out = Vec::new();
    etherparse::PacketBuilder::ethernet2([1; 6], [2; 6])
        .ipv4(HERE.octets(), THERE.octets(), 64)
        .tcp(40000, 443, 0, 1024)
        .write(&mut out, &[7; 1400])
        .expect("a well-formed frame");
    out.truncate(topgent_collect::capture::wire::SNAP);

    let observed = parse(&out, LinkKind::Ethernet, &locals()).expect("a truncated frame is normal");
    assert_eq!(observed.peer, IpAddr::V4(THERE));
    assert_eq!(observed.peer_port, 443);
    assert_eq!(observed.local_port, 40000);
}
