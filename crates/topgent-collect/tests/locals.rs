//! What counts as one of this host's own addresses.
//!
//! Direction hangs off this set, so an address wrongly in it turns somebody
//! else's traffic into an agent's, and an address wrongly missing turns an
//! agent's inbound connection into a frame nobody claims.

#![allow(clippy::panic, clippy::expect_used)]

use std::net::{Ipv4Addr, Ipv6Addr};

use topgent_collect::capture::locals::{parse_fib_trie, parse_if_inet6};

/// A trimmed dump in the shape the kernel writes it.
const FIB_TRIE: &str = "Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        |-- 127.0.0.0
           /8 host LOCAL
        |-- 127.0.0.1
           /32 host LOCAL
     |-- 192.168.64.2
        /32 host LOCAL
Local:
     |-- 127.0.0.1
        /32 host LOCAL
";

#[test]
fn reads_the_host_addresses() {
    let found = parse_fib_trie(FIB_TRIE);
    assert!(found.contains(&Ipv4Addr::LOCALHOST));
    assert!(found.contains(&Ipv4Addr::new(192, 168, 64, 2)));
}

/// The loopback network appears with the same marker as an address.
///
/// `127.0.0.0/8 host LOCAL` is a route, not something this host answers on.
/// Admitting it would put a whole network in the set, and every packet to any
/// address in it would then read as this host's own.
#[test]
fn a_network_route_is_not_an_address() {
    assert!(!parse_fib_trie(FIB_TRIE).contains(&Ipv4Addr::new(127, 0, 0, 0)));
}

/// The file renders one address once per table it appears in.
#[test]
fn each_address_appears_once() {
    let found = parse_fib_trie(FIB_TRIE);
    let loopback = found
        .iter()
        .filter(|address| **address == Ipv4Addr::LOCALHOST)
        .count();
    assert_eq!(loopback, 1, "{found:?}");
}

/// A marker can only claim the line directly above it.
#[test]
fn a_marker_claims_only_the_line_above_it() {
    let text = "     |-- 10.0.0.1\n        /24 universe UNICAST\n        /32 host LOCAL\n";
    assert!(parse_fib_trie(text).is_empty());
}

#[test]
fn nonsense_produces_no_addresses() {
    for bad in [
        "",
        "|-- \n/32 host LOCAL",
        "|-- 999.1.1.1\n/32 host LOCAL",
        "|-- 192.168.1.1",
        "/32 host LOCAL",
    ] {
        assert!(
            parse_fib_trie(bad).is_empty(),
            "{bad:?} produced an address"
        );
    }
}

/// The interface file is network order throughout, unlike the socket tables.
///
/// Undoing a byte swap that was never applied yields an address that looks
/// plausible and is wrong, which is the failure worth a test of its own.
#[test]
fn reads_interface_addresses_in_network_order() {
    let text = "fe800000000000006893f4fffe616c01 02 40 20 80     eth0\n\
                00000000000000000000000000000001 01 80 10 80       lo\n";
    let found = parse_if_inet6(text);
    assert!(found.contains(&Ipv6Addr::LOCALHOST), "{found:?}");
    let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x6893, 0xf4ff, 0xfe61, 0x6c01);
    assert!(found.contains(&link_local), "{found:?}");
}

#[test]
fn a_field_of_the_wrong_shape_is_not_an_address() {
    for bad in [
        "0000000000000000000000000000001 01 80 10 80 lo",
        "000000000000000000000000000000012 01 80 10 80 lo",
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz 01 80 10 80 lo",
        "",
    ] {
        assert!(
            parse_if_inet6(bad).is_empty(),
            "{bad:?} produced an address"
        );
    }
}
