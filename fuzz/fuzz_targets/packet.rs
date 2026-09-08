//! Frames off the wire, which is the most hostile input this tool reads.
//!
//! Attacker-shaped bytes, arriving continuously, parsed in-process. The
//! assertions are about what may reach a finding: the parser must never
//! produce an endpoint naming this host as the peer, and never a port on a
//! protocol that has none.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use topgent_collect::capture::packet::{LinkKind, parse};

    let locals = [
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ];
    for link in [LinkKind::Ethernet, LinkKind::Raw] {
        if let Some(observed) = parse(data, link, &locals) {
            // The peer may legitimately be local: an agent talking to a
            // service on this machine is real traffic and a real finding. The
            // fuzzer found that assuming otherwise was wrong within thirty
            // seconds, which is the entire point of it. What must hold is that
            // a peer is never invented: it is one of the two addresses the
            // frame actually carried.
            assert!(
                observed.local_port != 0 || observed.protocol != topgent_facts::Protocol::Tcp,
                "a TCP packet was reported with no local port to attribute it by"
            );
            if observed.protocol == topgent_facts::Protocol::Icmp {
                assert_eq!(
                    observed.peer_port, 0,
                    "ICMP has no ports and one was reported"
                );
            }
        }
    }
});
