//! Reading the Windows TCP table.
//!
//! Two sources, deliberately. `Get-NetTCPConnection` carries a per-connection
//! creation time — the only platform that records one — and is preferred.
//! `netstat -ano -p tcp` is the fallback, so a sweep never loses sockets over a
//! missing age. Both are readable by a standard user, so this stays Tier 0.

#[cfg(any(windows, test, fuzzing))]
use super::row::SocketRow;
#[cfg(windows)]
use crate::CollectError;
#[cfg(any(windows, test, fuzzing))]
use topgent_facts::Direction;
#[cfg(any(windows, test, fuzzing))]
use topgent_facts::UnixMillis;

/// Largest number of rows accepted from the Windows TCP table in one sweep.
#[cfg(any(windows, test, fuzzing))]
pub const MAX_WINDOWS_TCP_ROWS: usize = 512;

/// Furthest ahead of the sweep a creation timestamp may sit and still be kept.
///
/// Clocks move. A connection created slightly in the future is a skew; one
/// created far in the future is a record Topgent cannot vouch for, and an age
/// computed from it would be nonsense.
#[cfg(any(windows, test, fuzzing))]
pub const MAX_WINDOWS_CLOCK_SKEW_MS: u64 = 60_000;

/// Parse the structured Windows TCP table.
///
/// Windows records when it created each connection, which is the only truthful
/// source of a connection's age: the difference between two socket snapshots
/// says how long Topgent has been watching, not how long the connection has
/// existed. Rows are accepted only with an exact owner pid and a usable
/// endpoint; a missing, zero, or implausibly future timestamp yields `None`
/// rather than a guess.
///
/// `now` is the sweep clock, used only to reject timestamps from the future.
#[cfg(any(windows, test, fuzzing))]
#[must_use]
pub fn parse_windows_tcp_connections(out: &str, now: UnixMillis) -> Vec<SocketRow> {
    let mut rows = Vec::new();
    for line in out.lines() {
        if rows.len() >= MAX_WINDOWS_TCP_ROWS {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(pid) = value
            .get("pid")
            .and_then(serde_json::Value::as_u64)
            .and_then(|pid| u32::try_from(pid).ok())
        else {
            continue;
        };
        if pid == 0 {
            continue;
        }
        let state = value.get("state").and_then(serde_json::Value::as_str);
        let (direction, host_key, port_key) = match state {
            Some(state) if state.eq_ignore_ascii_case("listen") => {
                (Direction::Listening, "local", "localPort")
            }
            Some(state) if state.eq_ignore_ascii_case("established") => {
                (Direction::Outbound, "host", "port")
            }
            _ => continue,
        };
        let Some(host) = value.get(host_key).and_then(serde_json::Value::as_str) else {
            continue;
        };
        let host = host.trim().trim_matches(['[', ']']).to_owned();
        if host.is_empty() {
            continue;
        }
        let Some(port) = value
            .get(port_key)
            .and_then(serde_json::Value::as_u64)
            .and_then(|port| u16::try_from(port).ok())
        else {
            continue;
        };
        if port == 0 {
            continue;
        }
        let opened_at = value
            .get("created")
            .and_then(serde_json::Value::as_u64)
            .filter(|created| *created > 0)
            .filter(|created| *created <= now.0.saturating_add(MAX_WINDOWS_CLOCK_SKEW_MS))
            .map(UnixMillis);
        rows.push(SocketRow {
            // `Get-NetTCPConnection` is TCP by name. UDP and ICMP would need a
            // second cmdlet and neither reports a peer for an unconnected
            // socket, so the sensor states that boundary instead.
            protocol: topgent_facts::Protocol::Tcp,
            pid,
            host,
            port,
            direction,
            opened_at,
            bytes: None,
        });
    }
    rows
}

/// Parse Windows `netstat -ano -p tcp` output.
///
/// Only TCP listeners and established connections with an explicit owner PID
/// are admitted. Localized headings, malformed rows and transient lifecycle
/// states are ignored rather than guessed.
#[cfg(any(windows, test, fuzzing))]
#[must_use]
pub fn parse_windows_netstat(out: &str) -> Vec<SocketRow> {
    let mut rows = Vec::new();
    for line in out.lines() {
        let columns = line.split_whitespace().collect::<Vec<_>>();
        let [protocol, local, peer, state, pid] = columns.as_slice() else {
            continue;
        };
        // Every protocol netstat names, not only TCP. A UDP row has no state
        // column, so it is treated as bound rather than skipped.
        let parsed = topgent_facts::Protocol::parse(protocol);
        let direction = if state.eq_ignore_ascii_case("LISTENING") {
            Direction::Listening
        } else if state.eq_ignore_ascii_case("ESTABLISHED") {
            Direction::Outbound
        } else if parsed == topgent_facts::Protocol::Udp {
            Direction::Listening
        } else {
            continue;
        };
        let endpoint = if direction == Direction::Listening {
            *local
        } else {
            *peer
        };
        let Some((host, port)) = endpoint.rsplit_once(':') else {
            continue;
        };
        let (Ok(port), Ok(pid)) = (port.parse::<u16>(), pid.parse::<u32>()) else {
            continue;
        };
        let host = host.trim_matches(['[', ']']).to_owned();
        if host.is_empty() || pid == 0 {
            continue;
        }
        rows.push(SocketRow {
            protocol: parsed,
            opened_at: None,
            bytes: None,
            pid,
            host,
            port,
            direction,
        });
    }
    rows
}

/// Read the Windows TCP table with per-connection creation timestamps.
///
/// Fixed script, no interpolation, bounded output. Verified readable by a
/// non-administrator account, so this stays a Tier 0 probe.
#[cfg(windows)]
pub(super) fn read_windows_tcp_connections() -> Result<String, CollectError> {
    const SCRIPT: &str = r"$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); Get-NetTCPConnection -ErrorAction Stop | Where-Object {$_.State -eq 'Listen' -or $_.State -eq 'Established'} | Select-Object -First 512 | ForEach-Object {[pscustomobject]@{pid=$_.OwningProcess; state=[string]$_.State; local=[string]$_.LocalAddress; localPort=$_.LocalPort; host=[string]$_.RemoteAddress; port=$_.RemotePort; created=$(if ($_.CreationTime) {([DateTimeOffset]$_.CreationTime).ToUnixTimeMilliseconds()} else {$null})} | ConvertTo-Json -Compress}";
    let output = crate::tool::POWERSHELL
        .command()?
        .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
        .output()
        .map_err(|error| CollectError::Unavailable {
            what: format!("powershell.exe: {error}"),
        })?;
    if !output.status.success() {
        return Err(CollectError::Denied {
            what: "Get-NetTCPConnection was refused".to_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    // Test code asserts and indexes; production code does neither.
    #![allow(clippy::indexing_slicing, clippy::panic, clippy::expect_used)]

    use super::*;
    use topgent_facts::UnixMillis;

    const NOW: UnixMillis = UnixMillis(1_787_756_900_000);

    const WINDOWS_NETSTAT_SAMPLE: &str = "\
  Proto  Local Address          Foreign Address        State           PID\n\
  TCP    0.0.0.0:22             0.0.0.0:0              LISTENING       612\n\
  TCP    172.31.0.25:53144      203.0.113.10:443       ESTABLISHED     4242\n\
  TCP    [::]:8080              [::]:0                 LISTENING       5000\n\
  TCP    [::1]:53145            [2001:db8::20]:8443    ESTABLISHED     4242\n\
  TCP    172.31.0.25:53146      203.0.113.11:443       TIME_WAIT       0\n\
  UDP    0.0.0.0:53             *:*                                    700\n\
  TCP    malformed              row                     LISTENING       nope\n";

    #[test]
    fn windows_netstat_keeps_only_pid_owned_listeners_and_established_peers() {
        assert_eq!(
            parse_windows_netstat(WINDOWS_NETSTAT_SAMPLE),
            [
                super::SocketRow {
                    protocol: topgent_facts::Protocol::Tcp,
                    opened_at: None,
                    bytes: None,
                    pid: 612,
                    host: "0.0.0.0".to_owned(),
                    port: 22,
                    direction: Direction::Listening,
                },
                super::SocketRow {
                    protocol: topgent_facts::Protocol::Tcp,
                    opened_at: None,
                    bytes: None,
                    pid: 4242,
                    host: "203.0.113.10".to_owned(),
                    port: 443,
                    direction: Direction::Outbound,
                },
                super::SocketRow {
                    protocol: topgent_facts::Protocol::Tcp,
                    opened_at: None,
                    bytes: None,
                    pid: 5000,
                    host: "::".to_owned(),
                    port: 8080,
                    direction: Direction::Listening,
                },
                super::SocketRow {
                    protocol: topgent_facts::Protocol::Tcp,
                    opened_at: None,
                    bytes: None,
                    pid: 4242,
                    host: "2001:db8::20".to_owned(),
                    port: 8443,
                    direction: Direction::Outbound,
                },
            ]
        );
    }

    fn row(json: &str) -> Option<super::SocketRow> {
        parse_windows_tcp_connections(json, NOW).into_iter().next()
    }

    #[test]
    fn the_windows_tcp_table_carries_the_creation_time_windows_records() {
        // netstat cannot print this. It is the only truthful source of a
        // connection's age: the gap between two sweeps measures how long
        // Topgent has been watching, not how long the connection has existed.
        let out = concat!(
            r#"{"pid":2964,"state":"Established","local":"172.31.0.25","localPort":54950,"host":"52.123.242.66","port":443,"created":1787756827000}"#,
            "\n",
            r#"{"pid":1408,"state":"Listen","local":"0.0.0.0","localPort":22,"host":"0.0.0.0","port":0,"created":1787700000000}"#,
        );
        let rows = parse_windows_tcp_connections(out, NOW);
        assert_eq!(rows.len(), 2);

        assert_eq!(rows[0].pid, 2964);
        assert_eq!(rows[0].direction, Direction::Outbound);
        assert_eq!(rows[0].host, "52.123.242.66");
        assert_eq!(rows[0].port, 443);
        assert_eq!(rows[0].opened_at, Some(UnixMillis(1_787_756_827_000)));

        // A listener is described by what it bound, not by a peer it has none of.
        assert_eq!(rows[1].direction, Direction::Listening);
        assert_eq!(rows[1].host, "0.0.0.0");
        assert_eq!(rows[1].port, 22);
        assert_eq!(rows[1].opened_at, Some(UnixMillis(1_787_700_000_000)));
    }

    #[test]
    fn an_unusable_creation_time_becomes_no_time_rather_than_a_guess() {
        let with = |created: &str| {
            format!(
                r#"{{"pid":10,"state":"Established","host":"10.0.0.1","port":443,"created":{created}}}"#
            )
        };
        // Absent, null, zero and non-numeric all mean the same thing: unknown.
        assert_eq!(
            row(r#"{"pid":10,"state":"Established","host":"10.0.0.1","port":443}"#)
                .and_then(|r| r.opened_at),
            None
        );
        assert_eq!(row(&with("null")).and_then(|r| r.opened_at), None);
        assert_eq!(row(&with("0")).and_then(|r| r.opened_at), None);
        assert_eq!(row(&with(r#""yesterday""#)).and_then(|r| r.opened_at), None);

        // Clocks move, so a small step into the future is skew and is kept.
        let skewed = NOW.0 + MAX_WINDOWS_CLOCK_SKEW_MS;
        assert_eq!(
            row(&with(&skewed.to_string())).and_then(|r| r.opened_at),
            Some(UnixMillis(skewed))
        );
        // Beyond that it is a record Topgent cannot vouch for, and an age
        // computed from it would be nonsense.
        let absurd = NOW.0 + MAX_WINDOWS_CLOCK_SKEW_MS + 1;
        assert_eq!(
            row(&with(&absurd.to_string())).and_then(|r| r.opened_at),
            None
        );

        // The row itself survives: losing the age must not lose the socket.
        assert!(row(&with("0")).is_some());
    }

    #[test]
    fn nothing_a_hostile_or_broken_row_contains_makes_the_tcp_parser_fail() {
        for bad in [
            "",
            "not json",
            "{",
            r#"{"pid":0,"state":"Established","host":"10.0.0.1","port":443}"#,
            r#"{"pid":10,"state":"Established","host":"10.0.0.1","port":0}"#,
            r#"{"pid":10,"state":"Established","host":"","port":443}"#,
            r#"{"pid":10,"state":"TimeWait","host":"10.0.0.1","port":443}"#,
            r#"{"pid":10,"host":"10.0.0.1","port":443}"#,
            r#"{"pid":10,"state":"Established","host":"10.0.0.1","port":70000}"#,
            r#"{"pid":99999999999,"state":"Established","host":"10.0.0.1","port":443}"#,
            r#"{"pid":10,"state":"Established","host":"10.0.0.1
{"pid":11}","port":443}"#,
        ] {
            let rows = parse_windows_tcp_connections(bad, NOW);
            assert!(
                rows.iter()
                    .all(|row| row.pid != 0 && row.port != 0 && !row.host.is_empty()),
                "admitted an unusable row from: {bad}"
            );
        }
        // A row that cannot be understood is skipped, and the next one is not.
        let mixed = concat!(
            "not json\n",
            r#"{"pid":10,"state":"Established","host":"10.0.0.1","port":443,"created":1787756827000}"#,
        );
        assert_eq!(parse_windows_tcp_connections(mixed, NOW).len(), 1);
    }

    #[test]
    fn the_tcp_table_is_bounded_however_many_rows_the_host_offers() {
        let line = r#"{"pid":10,"state":"Established","host":"10.0.0.1","port":443}"#;
        let flood = std::iter::repeat_n(line, MAX_WINDOWS_TCP_ROWS + 250)
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            parse_windows_tcp_connections(&flood, NOW).len(),
            MAX_WINDOWS_TCP_ROWS
        );
    }

    #[test]
    fn ipv6_brackets_are_stripped_from_the_endpoint() {
        let out = r#"{"pid":10,"state":"Established","host":"[2606:4700::1111]","port":443}"#;
        assert_eq!(row(out).map(|r| r.host), Some("2606:4700::1111".to_owned()));
    }
}
