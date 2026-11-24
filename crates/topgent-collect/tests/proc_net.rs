//! Reading the kernel's socket tables without a subprocess in the middle.
//!
//! The addresses are hex words with per-word endianness, and getting that
//! wrong produces addresses that look plausible and are wrong, which is worse
//! than failing. Most of these tests are about that.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use topgent_collect::socket::{TableRow, attribute, parse_address, parse_table};
use topgent_facts::Direction;

/// Two rows in the kernel's own format: one established, one listening.
const TABLE: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 0100007F:C1AF 01 00000000:00000000 00:00000000 00000000  1000        0 54321 1 0000 10 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000 10 0 0 10 0
";

#[test]
fn an_established_row_reports_the_peer_and_a_listening_row_reports_the_bind() {
    // The distinction the `listeners` crate cannot make, because it keeps only
    // the local address. Every network factor Topgent has is a question about
    // the peer.
    let rows = parse_table(TABLE);
    assert_eq!(rows.len(), 2);

    let established = rows.first().expect("the first row");
    assert_eq!(established.host, "127.0.0.1");
    assert_eq!(
        established.port, 0xC1AF,
        "the peer's port, not the local one"
    );
    assert_eq!(established.direction, Direction::Outbound);
    assert_eq!(established.inode, 54321);

    let listening = rows.get(1).expect("the second row");
    assert_eq!(listening.host, "0.0.0.0");
    assert_eq!(listening.port, 22, "the bound port");
    assert_eq!(listening.direction, Direction::Listening);
}

#[test]
fn an_ipv4_address_is_decoded_little_endian() {
    // `0100007F` is 127.0.0.1, not 1.0.0.127. Reading it the other way round
    // gives an address that is syntactically fine and factually wrong.
    assert_eq!(
        parse_address("0100007F:1F90"),
        Some(("127.0.0.1".to_owned(), 8080))
    );
    assert_eq!(
        parse_address("0F02000A:0050"),
        Some(("10.0.2.15".to_owned(), 80))
    );
}

#[test]
fn an_ipv6_address_is_decoded_word_by_word() {
    // Four 32-bit words, each byte-reversed independently. All zeroes is the
    // unspecified address and is the simplest check that the shape is right.
    assert_eq!(
        parse_address("00000000000000000000000000000000:0050"),
        Some(("::".to_owned(), 80))
    );
}

#[test]
fn a_mapped_address_reports_as_the_ipv4_it_is() {
    // An IPv4 socket the kernel listed in the v6 table. Reporting
    // `::ffff:127.0.0.1` where every other source says `127.0.0.1` would split
    // one endpoint into two.
    let (host, port) = parse_address("0000000000000000FFFF00000100007F:0050").expect("it decodes");
    assert_eq!(host, "127.0.0.1");
    assert_eq!(port, 80);
}

#[test]
fn a_malformed_line_is_skipped_rather_than_guessed_at() {
    for bad in [
        "not a table at all",
        "   0: ZZZZZZZZ:1F90 0100007F:C1AF 01 x x x x 0 0 nope",
        "   0:",
        "",
    ] {
        let text = format!("header\n{bad}\n");
        assert!(parse_table(&text).is_empty(), "{bad:?} produced a row");
    }
}

#[test]
fn a_socket_nothing_owns_is_not_evidence_about_any_agent() {
    // Same rule the `ss` parser applies: an unattributed socket is dropped
    // rather than reported against a guess.
    let rows = vec![TableRow {
        host: "10.0.0.1".to_owned(),
        port: 443,
        direction: Direction::Outbound,
        inode: 99,
    }];
    assert!(attribute(rows, &std::collections::BTreeMap::new()).is_empty());
}

#[test]
fn an_attributed_row_claims_no_timing_and_no_counters() {
    // The table carries neither. Absent rather than zero: one means the source
    // does not say, the other would be a measurement nobody took.
    let mut owners = std::collections::BTreeMap::new();
    owners.insert(54321_u64, 4242_u32);
    let rows = attribute(parse_table(TABLE), &owners);

    assert_eq!(rows.len(), 1, "only the owned socket survives");
    let row = rows.first().expect("one row");
    assert_eq!(row.pid, 4242);
    assert_eq!(row.opened_at, None);
    assert_eq!(row.bytes, None);
}

#[test]
fn the_table_is_bounded() {
    // Reading an unbounded kernel table into memory is how a monitor becomes
    // the incident.
    let mut text = String::from("header\n");
    for i in 0..20_000 {
        use std::fmt::Write as _;
        let _ = writeln!(
            text,
            "  {i}: 0100007F:1F90 0100007F:C1AF 01 0:0 0:0 0 0 0 {i} 1"
        );
    }
    assert!(parse_table(&text).len() <= 8192);
}

/// A loopback server and its client, as the kernel lists them: the listener on
/// 8080, the connection it accepted, and the client's own end.
const ACCEPTED: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 100 1 0000 10 0 0 10 0
   1: 0100007F:1F90 0100007F:C350 01 00000000:00000000 00:00000000 00000000  1000        0 101 1 0000 10 0 0 10 0
   2: 0100007F:C350 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 102 1 0000 10 0 0 10 0
";

#[test]
fn a_connection_accepted_on_a_listening_port_is_inbound() {
    // Every established row used to be outbound. A dev server with twenty
    // browser tabs open then looked like an agent reaching twenty hosts.
    let rows = parse_table(ACCEPTED);
    assert_eq!(rows.len(), 3);
    let accepted = rows.iter().find(|row| row.inode == 101).expect("accepted");
    assert_eq!(accepted.direction, Direction::Inbound);
    assert_eq!(
        (accepted.host.as_str(), accepted.port),
        ("127.0.0.1", 0xC350)
    );
    let client = rows.iter().find(|row| row.inode == 102).expect("client");
    assert_eq!(client.direction, Direction::Outbound);
    assert_eq!(client.port, 8080);
}

#[test]
fn a_listener_on_one_address_does_not_claim_connections_on_another() {
    // Listening on 127.0.0.1:8080 says nothing about a socket whose local end
    // is 10.0.0.5:8080.
    let text = "\
header
   0: 0100007F:1F90 00000000:0000 0A 0:0 0:0 0 1000 0 200 1
   1: 0500000A:1F90 0100000A:01BB 01 0:0 0:0 0 1000 0 201 1
";
    let rows = parse_table(text);
    let other = rows.iter().find(|row| row.inode == 201).expect("row");
    assert_eq!(other.direction, Direction::Outbound);
}
