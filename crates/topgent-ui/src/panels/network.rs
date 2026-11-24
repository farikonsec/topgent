//! The Network panel: every endpoint an agent was seen using.
//!
//! Separate because its wording rules (what an unstated protocol or an
//! accepted connection does and does not establish) are read and changed on
//! their own.

use crate::Message;
use crate::report::Report;
use crate::table::{self, Tables};
use crate::theme::Style;
use iced::Element;

pub(super) fn view<'a>(
    report: &'a Report,
    selected: Option<u32>,
    t: &'a Tables,
    s: Style,
) -> Element<'a, Message> {
    let rows = report
        .network
        .iter()
        .filter(|e| selected.is_none_or(|pid| e.agent_pid == pid))
        .map(|e| {
            // A peer the platform cannot expose says so, rather than showing a
            // wildcard that reads like a bug. A raw ICMP socket is real and
            // alarming; its destination simply is not observable here.
            let host = if e.peer_observable {
                e.dns_name.clone().unwrap_or_else(|| e.host.clone())
            } else {
                "destination not observable here".to_owned()
            };
            let (protocol, _) = protocol_label(&e.protocol);
            table::Row::new(vec![
                // Which agent's process held the socket: the question the
                // host-wide table is read to answer.
                table::Cell::new(agent_label(report, e)),
                table::Cell::new(format!("{host}:{}", e.port)),
                table::Cell::new(e.direction.clone()),
                table::Cell::tinted(e.verdict.clone(), verdict_colour(&e.verdict, s)),
                table::Cell::new(if e.currently_observed {
                    "visible now"
                } else {
                    "not in latest sweep"
                }),
                // The flag never appears without the code beside it. A glyph
                // is not a fact and must not be the only carrier of one.
                // An address the table does not cover reads faint, so a row
                // whose ownership is genuinely unknown is not mistaken for one
                // that was looked up and found uninteresting.
                if e.owner_known {
                    table::Cell::new(e.country.clone())
                } else {
                    table::Cell::tinted(e.country.clone(), s.palette.faint)
                },
                if e.owner_known {
                    table::Cell::new(e.network_owner.clone())
                } else {
                    table::Cell::tinted(e.network_owner.clone(), s.palette.faint)
                },
                table::Cell::new(e.observations.to_string()),
                e.packets.map_or_else(
                    || table::Cell::tinted("-".to_owned(), s.palette.faint),
                    |packets| table::Cell::new(packets.to_string()),
                ),
                e.bytes.map_or_else(
                    || table::Cell::tinted("-".to_owned(), s.palette.faint),
                    |bytes| table::Cell::new(bytes.to_string()),
                ),
            ])
            .detailed(vec![
                ("agent".to_owned(), agent_label(report, e)),
                (
                    "protocol".to_owned(),
                    format!("{protocol} — {}", protocol_meaning(&e.protocol)),
                ),
                ("address".to_owned(), e.host.clone()),
                ("name".to_owned(), e.dns_name.clone().unwrap_or_default()),
                ("country".to_owned(), e.country.clone()),
                ("network".to_owned(), e.network_owner.clone()),
                ("port".to_owned(), e.port.to_string()),
                ("direction".to_owned(), direction_meaning(&e.direction)),
                ("verdict".to_owned(), e.verdict.clone()),
                (
                    "peer observable".to_owned(),
                    if e.peer_observable {
                        "yes".to_owned()
                    } else {
                        "no, this platform does not expose it".to_owned()
                    },
                ),
                (
                    "observations".to_owned(),
                    format!("{} snapshot sweeps", e.observations),
                ),
                (
                    "packets".to_owned(),
                    e.packets.map_or_else(
                        || "no capture saw this endpoint".to_owned(),
                        |packets| packets.to_string(),
                    ),
                ),
                (
                    "bytes".to_owned(),
                    e.bytes.map_or_else(
                        || "no byte counter was available".to_owned(),
                        |bytes| bytes.to_string(),
                    ),
                ),
                (
                    "seen now".to_owned(),
                    if e.currently_observed {
                        "yes"
                    } else {
                        "not in the last sweep"
                    }
                    .to_owned(),
                ),
            ])
        })
        .collect();
    table::view(
        table::Id::Network,
        &NETWORK,
        rows,
        &table::state_of(t, table::Id::Network),
        "No endpoints recorded for this agent.",
        s,
    )
}

/// Which agent's process held the socket, with the model it runs on.
fn agent_label(report: &Report, e: &crate::report::Endpoint) -> String {
    format!(
        "{} ({})",
        report.run_name(e.agent_pid, e.agent_started_at, &e.agent_family),
        e.agent_pid
    )
}

pub(super) static NETWORK: [table::Column2; 10] = [
    table::Column2::text("AGENT", 3),
    table::Column2::text("ENDPOINT", 4).mono(),
    table::Column2::text("DIRECTION", 3),
    table::Column2::text("VERDICT", 3),
    table::Column2::text("STATE", 3),
    table::Column2::text("COUNTRY", 2),
    table::Column2::text("NETWORK", 3),
    table::Column2::text("OBS", 2).number().mono(),
    table::Column2::text("PACKETS", 2).number().mono(),
    table::Column2::text("BYTES", 2).number().mono(),
];

/// The protocol as the table shows it, and whether a sensor actually stated it.
///
/// `unstated` is not a protocol. It reads faint and in words, so a row whose
/// protocol nobody observed is not mistaken for one that was.
fn protocol_label(protocol: &str) -> (String, bool) {
    match protocol {
        "unstated" | "" => ("not stated".to_owned(), false),
        other => (other.to_ascii_uppercase(), true),
    }
}

/// What the protocol cell means, for the expanded row.
fn protocol_meaning(protocol: &str) -> String {
    match protocol {
        "unstated" | "" => "unknown: TCP or UDP not recorded".to_owned(),
        other => other.to_ascii_uppercase(),
    }
}

/// What the direction means, for the expanded row.
fn direction_meaning(direction: &str) -> String {
    match direction {
        "outbound" => "outbound: this agent connected to the peer".to_owned(),
        "listening" => "listening: this agent is waiting for connections".to_owned(),
        "inbound" => "inbound: a peer connected to this agent's listening port".to_owned(),
        other => other.to_owned(),
    }
}

fn verdict_colour(verdict: &str, s: Style) -> iced::Color {
    match verdict {
        "metadata_service" | "suspicious_endpoint" => s.palette.critical,
        "exposed_listener" => s.palette.high,
        "private_peer" => s.palette.medium,
        _ => s.palette.muted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_protocol_nobody_stated_reads_as_not_stated_and_faint() {
        assert_eq!(protocol_label("unstated"), ("not stated".to_owned(), false));
        assert_eq!(protocol_label(""), ("not stated".to_owned(), false));
        assert_eq!(protocol_label("tcp"), ("TCP".to_owned(), true));
        assert!(protocol_meaning("unstated").contains("TCP or UDP not recorded"));
    }

    #[test]
    fn an_accepted_connection_says_the_peer_came_to_the_agent() {
        assert!(direction_meaning("inbound").contains("listening port"));
        assert!(direction_meaning("outbound").contains("this agent connected"));
        // An unknown word from a newer report is shown as it is, not guessed.
        assert_eq!(direction_meaning("sideways"), "sideways");
    }

    #[test]
    fn every_verdict_that_matters_is_coloured_apart_from_the_ordinary_one() {
        let s = Style::default();
        let ordinary = verdict_colour("observed", s);
        for verdict in [
            "metadata_service",
            "suspicious_endpoint",
            "exposed_listener",
            "private_peer",
        ] {
            assert_ne!(
                verdict_colour(verdict, s),
                ordinary,
                "{verdict} looks ordinary"
            );
        }
    }
}
