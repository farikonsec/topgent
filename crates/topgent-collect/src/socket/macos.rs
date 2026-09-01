//! Reading `lsof -i -n -P`.
//!
//! The NAME column is column 8 and not the last token. Taking the last token
//! picks up `(LISTEN)` or `(ESTABLISHED)` instead of the endpoint, which is how
//! this parser silently returned nothing the first time it met a real machine.

use super::row::SocketRow;
use topgent_facts::Direction;
use topgent_facts::Protocol;

/// Parse `lsof -i -n -P` output.
///
/// Split out so the parser can be tested against captured output without
/// running anything. Every line the parser does not understand is skipped: a
/// malformed row must never abort the sweep.
#[must_use]
pub fn parse_lsof(out: &str) -> Vec<SocketRow> {
    let mut rows = Vec::new();
    for line in out.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME [STATE]
        // NAME is column 8. Taking the last token instead picks up `(LISTEN)`
        // or `(ESTABLISHED)`, which is how this parser silently returned nothing
        // the first time it ran against a real machine.
        let (Some(pid), Some(node), Some(name)) = (cols.get(1), cols.get(7), cols.get(8)) else {
            continue;
        };
        let Ok(pid) = pid.parse::<u32>() else {
            continue;
        };
        // Every protocol, not only TCP. Dropping the rest meant a process that
        // resolved a name over UDP and pinged the result over ICMP produced no
        // evidence at all, while this collector reported itself available.
        let protocol = Protocol::parse(node);

        // `addr:port->peer:port` when connected, `addr:port` when bound, and
        // `*:*` when the platform states neither. macOS gives ICMP the last
        // form: the socket is real and its destination is not observable here.
        let (endpoint, direction) = match name.split_once("->") {
            Some((_local, peer)) => (peer, Direction::Outbound),
            None => (*name, Direction::Listening),
        };

        let (host, port) = match endpoint.rsplit_once(':') {
            Some((host, port)) => (host.trim_matches(['[', ']']), port.parse::<u16>().ok()),
            None => (endpoint, None),
        };
        // A row with no address at all is still evidence. An AI agent holding
        // a raw ICMP socket can reach any host on the network, and recording
        // nothing because the peer is unreadable is the failure this collector
        // exists to avoid.
        let host = if host.is_empty() { "*" } else { host }.to_owned();
        if host == "*" && port.is_none() && protocol == Protocol::Tcp {
            continue;
        }

        rows.push(SocketRow {
            protocol,
            opened_at: None,
            bytes: None,
            pid,
            host,
            port: port.unwrap_or(0),
            direction,
        });
    }
    rows
}

#[cfg(test)]
mod tests {
    // Test code asserts and indexes; production code does neither.
    #![allow(clippy::indexing_slicing, clippy::panic, clippy::expect_used)]

    use super::*;

    // Captured from a real `lsof -i -n -P`, with addresses altered.
    const SAMPLE: &str = "\
COMMAND     PID  USER   FD   TYPE             DEVICE SIZE/OFF   NODE NAME
rapportd   1025 testuser   10u  IPv4 0xeeb65baf1127b455      0t0    TCP *:57119 (LISTEN)
rapportd   1025 testuser   17u  IPv6 0x11e601d1fd375909      0t0    TCP [fe80::1]:57119->[fe80::2]:55258 (ESTABLISHED)
node      65776 testuser   24u  IPv4 0x493742d50d374dd       0t0    TCP 192.168.1.5:52001->203.0.113.20:443 (ESTABLISHED)
ollama      998 testuser    8u  IPv4 0xa61b1e2b58b23562      0t0    TCP 127.0.0.1:11434 (LISTEN)
rapportd   1025 testuser   18u  IPv6 0x130e27a62e26c23e      0t0    UDP *:3722
ping      47261 testuser    3u  IPv4 0xf40ab2a4ac940dd1      0t0   ICMP *:*
garbage line with too few columns
";

    #[test]
    fn a_ping_is_recorded_even_though_macos_will_not_say_where_it_went() {
        let rows = parse_lsof(SAMPLE);
        let icmp: Vec<&SocketRow> = rows
            .iter()
            .filter(|r| r.protocol == Protocol::Icmp)
            .collect();
        assert_eq!(icmp.len(), 1, "the ICMP socket was dropped: {rows:#?}");
        assert_eq!(icmp[0].pid, 47261);
        // The peer is `*` because the platform states none, and the protocol
        // is what says so. An agent holding a raw ICMP socket can reach any
        // host on the network, and that is worth recording without a
        // destination.
        assert_eq!(icmp[0].host, "*");
        assert!(!icmp[0].protocol.peer_observable());
    }

    #[test]
    fn a_udp_socket_is_recorded_with_the_port_it_is_bound_to() {
        let rows = parse_lsof(SAMPLE);
        let udp: Vec<&SocketRow> = rows
            .iter()
            .filter(|r| r.protocol == Protocol::Udp)
            .collect();
        assert_eq!(udp.len(), 1, "the UDP socket was dropped: {rows:#?}");
        assert_eq!(udp[0].port, 3722);
        assert!(
            udp[0].protocol.peer_observable(),
            "UDP can name a peer when connected"
        );
    }

    #[test]
    fn the_parser_reads_the_name_column_not_the_connection_state() {
        let rows = parse_lsof(SAMPLE);

        // Four TCP rows, one UDP, one ICMP. Only the malformed line is
        // skipped. Dropping every non-TCP row is how a ping to a host on the
        // other side of the world produced no evidence at all.
        assert_eq!(rows.len(), 6, "{rows:#?}");

        assert_eq!(rows[0].pid, 1025);
        assert_eq!(rows[0].host, "*");
        assert_eq!(rows[0].port, 57119);
        assert_eq!(rows[0].direction, Direction::Listening);

        assert_eq!(rows[1].host, "fe80::2");
        assert_eq!(rows[1].direction, Direction::Outbound);

        assert_eq!(rows[3].pid, 998);
        assert_eq!(rows[3].host, "127.0.0.1");
        assert_eq!(rows[3].port, 11434);
        assert_eq!(rows[3].direction, Direction::Listening);
    }

    #[test]
    fn nothing_a_hostile_process_can_print_makes_the_parser_fail() {
        for junk in [
            "",
            "header only\n",
            "h\nx y z\n",
            "h\ncmd notanumber u u u u u u 1.2.3.4:80\n",
            "h\ncmd 1 u u u u u u noport\n",
            "h\ncmd 1 u u u u u u 1.2.3.4:99999\n",
            &format!("h\ncmd 1 u u u u u u {}:80\n", "a".repeat(10_000)),
        ] {
            let _ = parse_lsof(junk);
        }
    }
}
