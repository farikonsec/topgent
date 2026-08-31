//! Reading `ss -H -t -a -n -p -i`.
//!
//! Linux shows unowned system sockets to ordinary users without process
//! metadata. Those rows are ignored: a socket Topgent cannot attribute to a pid
//! is not evidence about any agent.
//!
//! `-i` adds the kernel's own counters on an indented continuation line, which
//! is the only truthful source of how much a connection has carried. Counting
//! how often a snapshot saw an endpoint counts sweeps, not traffic.

use super::row::SocketRow;
use topgent_facts::ByteCounters;
use topgent_facts::Direction;
use topgent_facts::Protocol;

/// Parse Linux `ss -H -t -a -n -p` output.
///
/// Linux exposes unowned system sockets without process metadata to ordinary
/// users. Those rows are deliberately ignored: Topgent only reports a socket
/// when `ss` attributes it to a pid that can in turn be tied to an agent.
#[must_use]
pub fn parse_ss(out: &str) -> Vec<SocketRow> {
    let mut rows: Vec<SocketRow> = Vec::new();
    // `ss -i` prints each socket's kernel counters on the following indented
    // line, so a continuation belongs to the rows the previous line produced.
    let mut previous = 0_usize..0_usize;
    for line in out.lines() {
        if line.starts_with([' ', '\t']) {
            if let Some(bytes) = tcp_info_bytes(line) {
                for row in rows.get_mut(previous.clone()).unwrap_or_default() {
                    row.bytes = Some(bytes);
                }
            }
            continue;
        }
        let started = rows.len();
        let cols: Vec<&str> = line.split_whitespace().collect();
        let (Some(state), Some(local), Some(peer)) = (cols.first(), cols.get(3), cols.get(4))
        else {
            continue;
        };
        let (endpoint, direction) = if state.eq_ignore_ascii_case("LISTEN") {
            (*local, Direction::Listening)
        } else if state.eq_ignore_ascii_case("ESTAB") {
            (*peer, Direction::Outbound)
        } else {
            continue;
        };
        let Some((host, port)) = endpoint.rsplit_once(':') else {
            continue;
        };
        let Ok(port) = port.parse::<u16>() else {
            continue;
        };
        let host = host.trim_matches(['[', ']']).to_owned();
        if host.is_empty() {
            continue;
        }

        // A row can name more than one owning process. Parse only decimal
        // digits immediately following a literal `pid=` marker; everything
        // else printed by a process or kernel is inert input data.
        let owners = cols.get(5..).unwrap_or_default().join(" ");
        let mut rest = owners.as_str();
        while let Some((_, after)) = rest.split_once("pid=") {
            let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
            if let Ok(pid) = digits.parse::<u32>() {
                rows.push(SocketRow {
                    // The invocation this parses is a TCP listing. UDP and
                    // ICMP on Linux come from `network_events`, which reads
                    // the audit log and names the destination, and the sensor
                    // states that boundary rather than implying coverage here.
                    protocol: Protocol::Tcp,
                    opened_at: None,
                    bytes: None,
                    pid,
                    host: host.clone(),
                    port,
                    direction,
                });
            }
            rest = after.get(digits.len()..).unwrap_or_default();
        }
        previous = started..rows.len();
    }
    rows
}

/// The kernel's cumulative byte counters from one `ss -i` continuation line.
///
/// Both directions must be present: a connection with only one of them counted
/// is a reading Topgent cannot state, and half a fact is not a smaller fact.
#[must_use]
pub fn tcp_info_bytes(line: &str) -> Option<ByteCounters> {
    if line.len() > 8_192 {
        return None;
    }
    let field = |name: &str| {
        line.split_whitespace()
            .filter(|token| token.len() <= 40)
            .find_map(|token| token.strip_prefix(name)?.parse::<u64>().ok())
    };
    // `bytes_sent` is what this host handed to the kernel and `bytes_acked` is
    // what the peer confirmed. Sent is the honest answer to how much an agent
    // pushed: a peer that never acknowledges has still been sent the data.
    Some(ByteCounters {
        sent: field("bytes_sent:").or_else(|| field("bytes_acked:"))?,
        received: field("bytes_received:")?,
    })
}

#[cfg(test)]
mod tests {
    // Test code asserts and indexes; production code does neither.
    #![allow(clippy::indexing_slicing, clippy::panic, clippy::expect_used)]

    use super::*;

    const SS_SAMPLE: &str = "\
LISTEN 0 511 127.0.0.1:4173 0.0.0.0:* users:((\"node\",pid=3745,fd=21))
LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
ESTAB 0 0 192.168.1.10:33306 203.0.113.7:443 users:((\"aider\",pid=2721,fd=53))
ESTAB 0 0 [fd00::2]:33307 [2606:4700::1]:443 users:((\"opencode\",pid=4000,fd=7),(\"helper\",pid=4001,fd=8))
TIME-WAIT 0 0 127.0.0.1:1 127.0.0.1:2 users:((\"old\",pid=9,fd=1))
";

    #[test]
    fn linux_ss_parser_keeps_only_pid_attributed_live_tcp_rows() {
        let rows = parse_ss(SS_SAMPLE);
        assert_eq!(rows.len(), 4, "{rows:#?}");
        assert_eq!(rows[0].pid, 3745);
        assert_eq!(rows[0].host, "127.0.0.1");
        assert_eq!(rows[0].port, 4173);
        assert_eq!(rows[0].direction, Direction::Listening);
        assert_eq!(rows[1].pid, 2721);
        assert_eq!(rows[1].host, "203.0.113.7");
        assert_eq!(rows[1].direction, Direction::Outbound);
        assert_eq!(rows[2].host, "2606:4700::1");
        assert_eq!(rows[3].pid, 4001);
    }

    #[test]
    fn the_kernels_own_counters_are_read_from_the_socket_they_belong_to() {
        // Taken verbatim from `ss -H -t -a -n -p -i` on Kali 6.19.14. The
        // counters arrive on the line after the socket they describe.
        let out = concat!(
            "ESTAB 0 0 192.168.1.10:22 192.168.1.1:60969 users:((\"sshd\",pid=700,fd=4))\n",
            "\t cubic wscale:6,9 rto:204 rtt:0.587/0.306 mss:1448 bytes_sent:4213 ",
            "bytes_acked:4213 bytes_received:4410 segs_out:20 segs_in:29\n",
            "LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=701,fd=3))\n",
        );
        let rows = parse_ss(out);
        assert_eq!(rows.len(), 2);
        let counted = rows
            .iter()
            .find(|row| row.pid == 700)
            .expect("the established socket is parsed");
        assert_eq!(
            counted.bytes,
            Some(topgent_facts::ByteCounters {
                sent: 4_213,
                received: 4_410
            })
        );
        // A socket the kernel printed no counters for keeps none. Counting how
        // often a sweep saw it would be counting sweeps, not traffic.
        assert_eq!(
            rows.iter()
                .find(|row| row.pid == 701)
                .and_then(|row| row.bytes),
            None
        );
    }

    #[test]
    fn counters_attach_to_the_socket_above_them_and_to_nothing_else() {
        // A continuation belongs to the socket it follows. Attaching it to
        // whatever was parsed last across a whole listing would put one
        // connection's traffic on another agent's endpoint.
        let out = concat!(
            "ESTAB 0 0 10.0.0.1:1 10.0.0.2:443 users:((\"a\",pid=10,fd=4))\n",
            "\t bytes_sent:100 bytes_received:200\n",
            "ESTAB 0 0 10.0.0.1:2 10.0.0.3:443 users:((\"b\",pid=11,fd=4))\n",
            "\t bytes_sent:300 bytes_received:400\n",
        );
        let rows = parse_ss(out);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0].bytes.map(|b| (b.sent, b.received)),
            Some((100, 200))
        );
        assert_eq!(
            rows[1].bytes.map(|b| (b.sent, b.received)),
            Some((300, 400))
        );

        // A continuation before any socket has nothing to attach to.
        assert!(parse_ss("\t bytes_sent:1 bytes_received:2\n").is_empty());
    }

    #[test]
    fn half_a_reading_is_not_a_smaller_reading() {
        // Both directions or nothing: a connection with only one side counted
        // is a number Topgent cannot state, and reporting the other as zero
        // would invent the missing half.
        assert_eq!(tcp_info_bytes(" bytes_sent:10"), None);
        assert_eq!(tcp_info_bytes(" bytes_received:10"), None);
        assert_eq!(tcp_info_bytes(" rtt:0.5 mss:1448"), None);
        assert_eq!(tcp_info_bytes(""), None);

        // Where the kernel reports only what the peer confirmed, that is used.
        assert_eq!(
            tcp_info_bytes(" bytes_acked:70 bytes_received:80"),
            Some(topgent_facts::ByteCounters {
                sent: 70,
                received: 80
            })
        );
        // Sent outranks acked: a peer that never acknowledges has still been
        // sent the data, and how much an agent pushed is the question.
        assert_eq!(
            tcp_info_bytes(" bytes_sent:90 bytes_acked:70 bytes_received:80")
                .map(|bytes| bytes.sent),
            Some(90)
        );
    }

    #[test]
    fn nothing_a_hostile_counter_line_contains_becomes_a_number() {
        for bad in [
            " bytes_sent:-5 bytes_received:10",
            " bytes_sent:notanumber bytes_received:10",
            " bytes_sent:99999999999999999999999999 bytes_received:10",
            " prefix_bytes_sent:10 bytes_received:20",
        ] {
            assert_eq!(tcp_info_bytes(bad), None, "took a number from: {bad}");
        }
        // A line long enough to be an attack is not walked.
        let flood = format!(" bytes_sent:1 bytes_received:2{}", "x".repeat(9_000));
        assert_eq!(tcp_info_bytes(&flood), None);
    }
}
