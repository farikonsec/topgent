//! PID-attributed operating-system connection events.
//!
//! The audit rules this needs, which an operator installs once. Without them
//! the log holds nothing to read and the sensor says so rather than reporting
//! an empty result as coverage:
//!
//! ```text
//! -a always,exit -F arch=b64 -S connect,sendto,sendmsg -F success=1 -k topgent
//! -a always,exit -F arch=b64 -S close -F success=1 -k topgent
//! ```
//!
//! `sendto` and `sendmsg` are what make a raw socket visible. A ping calls
//! `connect` never, so with `connect` alone this collector sees nothing of it,
//! which is how a ten-minute ping to a host on the other side of the world went
//! entirely unrecorded.
//!
//! This optional collector reads a bounded Audit-log tail. It joins successful
//! `connect` syscalls to their exact `SOCKADDR` record and optionally correlates
//! a later successful `close` for the same PID/file descriptor. Only recent
//! lifecycle edges whose PID still identifies the same process are admitted.

#[cfg(target_os = "linux")]
use crate::emit;
use crate::{Clock, CollectError, Collector};
#[cfg(any(target_os = "linux", windows, test, fuzzing))]
use std::collections::BTreeMap;
#[cfg(any(target_os = "linux", test, fuzzing))]
use std::collections::BTreeSet;
#[cfg(any(windows, test))]
use topgent_facts::ConnectionOutcome;
use topgent_facts::Fact;
#[cfg(any(target_os = "linux", windows))]
use topgent_facts::{Claim, Confidence, Direction, Provenance, SCHEMA_VERSION, UnixMillis};

const ID: &str = "network_events";
#[cfg(target_os = "linux")]
const PROBE: &str = "Linux Audit connect/close events (bounded, PID/FD-attributed)";
#[cfg(windows)]
const PROBE: &str = "Windows Filtering Platform 5156/5157 attempts (bounded, PID-attributed)";
#[cfg(target_os = "linux")]
const MAX_AUDIT_BYTES: u64 = 1_048_576;
#[cfg(any(target_os = "linux", test, fuzzing))]
const EVENT_WINDOW_MS: u64 = 5_000;
#[cfg(any(windows, test))]
const WINDOWS_EVENT_WINDOW_MS: u64 = 30_000;

/// A read-only Linux Audit connection-event collector.
#[derive(Debug, Clone)]
pub struct NetworkEventCollector {
    /// Audit log path. The default is `/var/log/audit/audit.log`.
    pub audit_log: std::path::PathBuf,
}

impl Default for NetworkEventCollector {
    fn default() -> Self {
        Self {
            audit_log: "/var/log/audit/audit.log".into(),
        }
    }
}

impl Collector for NetworkEventCollector {
    fn id(&self) -> &'static str {
        ID
    }

    /// Windows has no connection close in the Security log.
    ///
    /// Probed on Windows Server 2025 build 26100: the Filtering Platform
    /// catalogue 5150-5160 covers packet drops, listen, bind, permit and block
    /// decisions, and audit-mode allows. None of them is a teardown, so a
    /// completed-lifecycle duration cannot be observed at this tier. The only
    /// source is the `Microsoft-Windows-Kernel-Network` kernel provider
    /// (`TCPv4` close is event 13, `TCPv6` is event 29), which is a Tier 2
    /// privileged sensor and is not installed. A socket that stops appearing
    /// between two sweeps is not evidence that it closed: Topgent may simply
    /// have missed it, so nothing here is inferred from disappearance.
    #[cfg(windows)]
    fn boundary(&self) -> Option<&'static str> {
        Some(
            "Linux: `connect`, `sendto`, and `sendmsg`, which covers a raw socket that \
             calls `connect` never, provided the audit rules include them. Without those \
             rules there is nothing to read and a ping is attributed by nothing. Windows: \
             `connect` only, and the Security log records no connection close, so \
             completed-connection duration is unavailable without the optional privileged \
             kernel network sensor. Open connections still carry the creation time Windows \
             records for them.",
        )
    }

    fn collect(&self, clock: &dyn Clock) -> Result<Vec<Fact>, CollectError> {
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            let _ = clock;
            Err(CollectError::Unavailable {
                what: "PID-attributed Linux Audit connection events are Linux-only".to_owned(),
            })
        }
        #[cfg(windows)]
        {
            let text = read_windows_filtering_events()?;
            let processes = crate::process::snapshot()
                .into_iter()
                .map(|process| (process.pid, (process.started_at.0, process.subject())))
                .collect::<BTreeMap<_, _>>();
            let now = clock.now().0;
            Ok(parse_windows_filtering_events(&text)
                .into_iter()
                .filter_map(|event| {
                    let (started_at, subject) = processes.get(&event.pid)?;
                    if !attempt_matches_process(&event, *started_at, now) {
                        return None;
                    }
                    emit_at(
                        subject.clone(),
                        Claim::ConnectionAttempt {
                            host: event.host,
                            port: event.port,
                            direction: Direction::Outbound,
                            outcome: event.outcome,
                        },
                        event.observed_at,
                    )
                })
                .collect())
        }
        #[cfg(target_os = "linux")]
        {
            let text = read_bounded_tail(&self.audit_log)?;
            let processes = crate::process::snapshot()
                .into_iter()
                .map(|process| (process.pid, (process.started_at.0, process.subject())))
                .collect::<BTreeMap<_, _>>();
            let live_sockets = current_outbound_sockets();
            let now = clock.now().0;
            Ok(parse_audit_connections(&text)
                .into_iter()
                .filter_map(|event| {
                    let (started_at, subject) = processes.get(&event.pid)?;
                    if !event_matches_process(&event, *started_at, now) {
                        return Some(Vec::new());
                    }
                    if !event_is_confirmed(&event, &live_sockets) {
                        return Some(Vec::new());
                    }
                    if let Some(closed_at) = event.closed_at {
                        return Some(
                            emit_at(
                                subject.clone(),
                                Claim::SocketClosed {
                                    host: event.host,
                                    port: event.port,
                                    direction: Direction::Outbound,
                                    duration_ms: closed_at.saturating_sub(event.observed_at),
                                },
                                closed_at,
                            )
                            .into_iter()
                            .collect(),
                        );
                    }
                    Some(
                        emit(
                            ID,
                            PROBE,
                            Confidence::Certain,
                            clock,
                            subject.clone(),
                            Claim::SocketOpen {
                                protocol: topgent_facts::Protocol::Tcp,
                                bytes: None,
                                host: event.host,
                                port: event.port,
                                direction: Direction::Outbound,
                                // The connect record carries when the syscall
                                // happened, which the fact's own timestamp
                                // already states; it is not a socket creation
                                // time the kernel keeps for the connection.
                                opened_at: None,
                            },
                        )
                        .into_iter()
                        .collect(),
                    )
                })
                .flatten()
                .collect())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(any(windows, test))]
struct AttemptEvent {
    pid: u32,
    observed_at: u64,
    host: String,
    port: u16,
    outcome: ConnectionOutcome,
}

#[derive(Debug, serde::Deserialize)]
#[cfg(any(windows, test))]
struct WindowsFilteringRecord {
    #[serde(rename = "at")]
    observed_at: u64,
    pid: String,
    event: u16,
    direction: String,
    protocol: String,
    host: String,
    port: String,
}

#[cfg(any(windows, test))]
fn parse_windows_filtering_events(text: &str) -> Vec<AttemptEvent> {
    text.lines()
        .take(256)
        .filter(|line| line.len() <= 8_192)
        .filter_map(|line| serde_json::from_str::<WindowsFilteringRecord>(line).ok())
        .filter(|record| matches!(record.direction.as_str(), "%%14593" | "Outbound"))
        .filter(|record| matches!(record.protocol.as_str(), "6" | "TCP"))
        .filter_map(|record| {
            let pid = parse_windows_number(&record.pid).and_then(|value| value.try_into().ok())?;
            let port =
                parse_windows_number(&record.port).and_then(|value| value.try_into().ok())?;
            if pid == 0 || port == 0 {
                return None;
            }
            let host = record.host.parse::<std::net::IpAddr>().ok()?.to_string();
            let outcome = match record.event {
                5156 => ConnectionOutcome::Allowed,
                5157 => ConnectionOutcome::Blocked,
                _ => return None,
            };
            Some(AttemptEvent {
                pid,
                observed_at: record.observed_at,
                host,
                port,
                outcome,
            })
        })
        .collect()
}

/// Read a number Windows may have written as decimal or as hex.
///
/// Event data fields arrive as strings, and the same field is decimal in one
/// provider and `0x`-prefixed in another, so every Windows collector reads
/// them through here rather than each guessing.
#[cfg(any(windows, test))]
pub(crate) fn parse_windows_number(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() || value.len() > 18 {
        return None;
    }
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()
    } else {
        value.parse().ok()
    }
}

#[cfg(any(windows, test))]
fn attempt_matches_process(event: &AttemptEvent, started_at: u64, now: u64) -> bool {
    event.observed_at >= started_at
        && event.observed_at <= now
        && event.observed_at >= now.saturating_sub(WINDOWS_EVENT_WINDOW_MS)
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(any(target_os = "linux", test, fuzzing))]
/// One connection or datagram read from the audit log.
///
/// Public so a fuzz target can reach the parser that builds it. Nothing else
/// outside this module constructs one.
pub struct ConnectionEvent {
    pid: u32,
    fd: u32,
    observed_at: u64,
    host: String,
    port: u16,
    pending: bool,
    closed_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg(any(target_os = "linux", test, fuzzing))]
enum AuditOperation {
    #[default]
    Other,
    Connect,
    /// A datagram sent to a named address.
    ///
    /// Separate from `Connect` because it is not a connection. A raw socket
    /// calls `connect` never and `sendto` once per datagram, which is why a
    /// ping was attributed by no sensor at all; and a datagram has no lifetime,
    /// so it must never be paired with a `close` and given a duration.
    Send,
    Close,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg(any(target_os = "linux", test, fuzzing))]
enum AuditResult {
    #[default]
    Failed,
    Success,
    Pending,
}

#[derive(Default)]
#[cfg(any(target_os = "linux", test, fuzzing))]
struct PartialEvent {
    pid: Option<u32>,
    observed_at: Option<u64>,
    result: AuditResult,
    operation: AuditOperation,
    fd: Option<u32>,
    endpoint: Option<(String, u16)>,
}

#[cfg(any(target_os = "linux", windows))]
fn emit_at(subject: topgent_facts::Subject, claim: Claim, observed_at: u64) -> Option<Fact> {
    Fact::new(
        SCHEMA_VERSION,
        subject,
        claim,
        Provenance {
            collector: ID.to_owned(),
            probe: PROBE.to_owned(),
            confidence: Confidence::Certain,
            observed_at: UnixMillis(observed_at),
        },
    )
    .ok()
}

#[cfg(windows)]
fn read_windows_filtering_events() -> Result<String, CollectError> {
    const SCRIPT: &str = r"$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); try {$events=Get-WinEvent -FilterHashtable @{LogName='Security';Id=5156,5157;StartTime=(Get-Date).AddSeconds(-30)} -MaxEvents 256} catch {if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {exit 0}; throw}; $events | ForEach-Object {$xml=[xml]$_.ToXml(); $data=@{}; foreach($item in $xml.Event.EventData.Data){$data[[string]$item.Name]=[string]$item.'#text'}; [pscustomobject]@{at=([DateTimeOffset]$_.TimeCreated).ToUnixTimeMilliseconds(); pid=$data.ProcessID; event=$_.Id; direction=$data.Direction; protocol=$data.Protocol; host=$data.DestAddress; port=$data.DestPort} | ConvertTo-Json -Compress}";
    let output = crate::tool::POWERSHELL
        .command()?
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            SCRIPT,
        ])
        .output()
        .map_err(|error| CollectError::Unavailable {
            what: format!("Windows PowerShell event reader is unavailable: {error}"),
        })?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        let normalized = detail.to_ascii_lowercase();
        return Err(
            if normalized.contains("access is denied") || normalized.contains("unauthorized") {
                CollectError::Denied {
                    what: "Windows Security event log requires permission".to_owned(),
                }
            } else {
                CollectError::Unreadable {
                    what: format!(
                        "Windows Filtering Platform event query failed: {}",
                        detail.trim()
                    ),
                }
            },
        );
    }
    String::from_utf8(output.stdout).map_err(|error| CollectError::Unreadable {
        what: format!("Windows Filtering Platform output was not UTF-8: {error}"),
    })
}

#[cfg(any(target_os = "linux", test, fuzzing))]
fn event_matches_process(event: &ConnectionEvent, started_at: u64, now: u64) -> bool {
    let latest = event.closed_at.unwrap_or(event.observed_at);
    event.observed_at >= started_at
        && latest >= event.observed_at
        && latest <= now
        && latest >= now.saturating_sub(EVENT_WINDOW_MS)
}

#[cfg(any(target_os = "linux", test, fuzzing))]
fn event_is_confirmed(event: &ConnectionEvent, live: &BTreeSet<(u32, String, u16)>) -> bool {
    !event.pending || live.contains(&(event.pid, event.host.clone(), event.port))
}

#[cfg(any(target_os = "linux", test, fuzzing))]
/// Read connections and datagrams out of an audit-log tail.
///
/// Public for the same reason: this is the parser that reads a log any process
/// able to write to it can shape, so it is the one most worth fuzzing.
#[must_use]
pub fn parse_audit_connections(text: &str) -> Vec<ConnectionEvent> {
    let mut groups = BTreeMap::<String, PartialEvent>::new();
    for line in text.lines() {
        let Some(id) = audit_id(line) else { continue };
        let event = groups.entry(id.to_owned()).or_default();
        event.observed_at = audit_time_ms(id);
        if line.starts_with("type=SYSCALL ") {
            event.result = if field(line, "exit") == Some("-115") {
                AuditResult::Pending
            } else if field(line, "success") == Some("yes") {
                AuditResult::Success
            } else {
                AuditResult::Failed
            };
            // Numbers as well as names, because auditd prints the number
            // unless it was built with the syscall table. The two architectures
            // this ships for number them differently: x86-64 first, aarch64
            // second.
            event.operation = match field(line, "syscall") {
                Some("connect" | "42" | "203") => AuditOperation::Connect,
                Some("sendto" | "44" | "206" | "sendmsg" | "46" | "211") => AuditOperation::Send,
                Some("close" | "3" | "57") => AuditOperation::Close,
                _ => AuditOperation::Other,
            };
            event.pid = field(line, "pid").and_then(|value| value.parse().ok());
            event.fd = field(line, "a0").and_then(parse_fd);
        } else if line.starts_with("type=SOCKADDR ") {
            event.endpoint = field(line, "saddr").and_then(parse_sockaddr);
        }
    }
    let mut syscalls = groups
        .into_values()
        .filter(|event| event.observed_at.is_some() && event.pid.is_some() && event.fd.is_some())
        .collect::<Vec<_>>();
    syscalls.sort_by_key(|event| event.observed_at);
    let mut connections = Vec::<ConnectionEvent>::new();
    let mut open = BTreeMap::<(u32, u32), usize>::new();
    for event in syscalls {
        let pid = event.pid.unwrap_or(0);
        let fd = event.fd.unwrap_or(0);
        let observed_at = event.observed_at.unwrap_or(0);
        if event.operation == AuditOperation::Connect && event.result != AuditResult::Failed {
            let Some((host, port)) = event.endpoint else {
                continue;
            };
            connections.push(ConnectionEvent {
                pid,
                fd,
                observed_at,
                host,
                port,
                pending: event.result == AuditResult::Pending,
                closed_at: None,
            });
            open.insert((pid, fd), connections.len() - 1);
        } else if event.operation == AuditOperation::Send && event.result == AuditResult::Success {
            // A datagram, and the address it named. `sendto` on a connected
            // socket passes no address and produces no SOCKADDR record, which
            // is exactly the case the connect above already covers.
            let Some((host, port)) = event.endpoint else {
                continue;
            };
            // One row per destination, not one per datagram. A ping sends
            // once a second for as long as it runs, and a sensor that records
            // each one has become a packet log.
            if connections
                .iter()
                .any(|c| c.pid == pid && c.host == host && c.port == port)
            {
                continue;
            }
            // Deliberately not entered into `open`: a datagram has no
            // lifetime, so a later `close` on the same descriptor must not
            // give it a duration it never had.
            connections.push(ConnectionEvent {
                pid,
                fd,
                observed_at,
                host,
                port,
                pending: false,
                closed_at: None,
            });
        } else if event.operation == AuditOperation::Close
            && event.result == AuditResult::Success
            && let Some(index) = open.remove(&(pid, fd))
            && let Some(connection) = connections.get_mut(index)
            && observed_at >= connection.observed_at
        {
            connection.closed_at = Some(observed_at);
        }
    }
    connections
}

#[cfg(any(target_os = "linux", test, fuzzing))]
fn parse_fd(value: &str) -> Option<u32> {
    if value.is_empty() || value.len() > 8 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(value, 16).ok()
}

#[cfg(target_os = "linux")]
fn current_outbound_sockets() -> BTreeSet<(u32, String, u16)> {
    crate::tool::SS
        .command()
        .ok()
        .and_then(|mut ss| ss.args(["-H", "-t", "-a", "-n", "-p"]).output().ok())
        .map(|output| {
            crate::socket::parse_ss(&String::from_utf8_lossy(&output.stdout))
                .into_iter()
                .filter(|row| row.direction == Direction::Outbound)
                .map(|row| (row.pid, row.host, row.port))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(any(target_os = "linux", test, fuzzing))]
/// Decode the hex `saddr` field of an audit record into an address and port.
///
/// Length-prefixed binary decoded from text is the classic shape for an
/// out-of-bounds read, which is why it is public and fuzzed separately.
#[must_use]
pub fn parse_sockaddr(hex: &str) -> Option<(String, u16)> {
    // Enriched audit logs append an ASCII record separator and a decoded
    // `SADDR={...}` rendering to the raw hex field. Consume only the leading
    // kernel-provided hex value.
    let hex = hex.get(
        ..hex
            .find(|character: char| !character.is_ascii_hexdigit())
            .unwrap_or(hex.len()),
    )?;
    if hex.is_empty() || hex.len() > 256 || hex.len() % 2 != 0 {
        return None;
    }
    let bytes = hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
        })
        .collect::<Option<Vec<_>>>()?;
    let family = u16::from_ne_bytes([*bytes.first()?, *bytes.get(1)?]);
    let port = u16::from_be_bytes([*bytes.get(2)?, *bytes.get(3)?]);
    if port == 0 {
        return None;
    }
    match family {
        2 if bytes.len() >= 8 => {
            let address = <[u8; 4]>::try_from(bytes.get(4..8)?).ok()?;
            Some((std::net::Ipv4Addr::from(address).to_string(), port))
        }
        10 if bytes.len() >= 24 => {
            let address = <[u8; 16]>::try_from(bytes.get(8..24)?).ok()?;
            Some((std::net::Ipv6Addr::from(address).to_string(), port))
        }
        _ => None,
    }
}

#[cfg(any(target_os = "linux", test, fuzzing))]
fn audit_id(line: &str) -> Option<&str> {
    line.split_once("msg=audit(")?
        .1
        .split_once("): ")
        .map(|(id, _)| id)
}

#[cfg(any(target_os = "linux", test, fuzzing))]
fn audit_time_ms(id: &str) -> Option<u64> {
    let timestamp = id.split_once(':')?.0;
    let (seconds, fraction) = timestamp.split_once('.').unwrap_or((timestamp, "0"));
    let seconds = seconds.parse::<u64>().ok()?;
    let mut milliseconds = fraction.chars().take(3).collect::<String>();
    while milliseconds.len() < 3 {
        milliseconds.push('0');
    }
    Some(
        seconds
            .saturating_mul(1_000)
            .saturating_add(milliseconds.parse::<u64>().ok()?),
    )
}

#[cfg(any(target_os = "linux", test, fuzzing))]
fn field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    line.split_ascii_whitespace()
        .find_map(|part| part.strip_prefix(name)?.strip_prefix('='))
}

#[cfg(target_os = "linux")]
fn read_bounded_tail(path: &std::path::Path) -> Result<String, CollectError> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::PermissionDenied => CollectError::Denied {
            what: format!("cannot read {}", path.display()),
        },
        std::io::ErrorKind::NotFound => CollectError::Unavailable {
            what: format!("{} is absent; Linux Audit is not installed", path.display()),
        },
        _ => CollectError::Unreadable {
            what: format!("{}: {error}", path.display()),
        },
    })?;
    let length = file.metadata().map_or(0, |metadata| metadata.len());
    file.seek(SeekFrom::Start(length.saturating_sub(MAX_AUDIT_BYTES)))
        .map_err(|error| CollectError::Unreadable {
            what: error.to_string(),
        })?;
    let mut text = String::new();
    file.take(MAX_AUDIT_BYTES)
        .read_to_string(&mut text)
        .map_err(|error| CollectError::Unreadable {
            what: error.to_string(),
        })?;
    Ok(text)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]

    use super::{
        AttemptEvent, ConnectionEvent, attempt_matches_process, event_is_confirmed,
        event_matches_process, parse_audit_connections, parse_sockaddr,
        parse_windows_filtering_events,
    };
    use std::collections::BTreeSet;
    use topgent_facts::ConnectionOutcome;

    #[test]
    fn windows_filtering_events_preserve_allowed_and_blocked_attempt_truth() {
        let fixture = concat!(
            r#"{"at":1700000000100,"pid":"0x2bc","event":5156,"direction":"%%14593","protocol":"6","host":"192.0.2.10","port":"443"}"#,
            "\n",
            r#"{"at":1700000000200,"pid":"701","event":5157,"direction":"Outbound","protocol":"TCP","host":"2001:db8::53","port":"22"}"#,
            "\n",
        );
        assert_eq!(
            parse_windows_filtering_events(fixture),
            vec![
                AttemptEvent {
                    pid: 700,
                    observed_at: 1_700_000_000_100,
                    host: "192.0.2.10".into(),
                    port: 443,
                    outcome: ConnectionOutcome::Allowed
                },
                AttemptEvent {
                    pid: 701,
                    observed_at: 1_700_000_000_200,
                    host: "2001:db8::53".into(),
                    port: 22,
                    outcome: ConnectionOutcome::Blocked
                },
            ]
        );
    }

    #[test]
    fn windows_filtering_events_reject_non_tcp_inbound_unknown_and_hostile_rows() {
        let fixture = concat!(
            r#"{"at":1,"pid":"7","event":5156,"direction":"%%14592","protocol":"6","host":"192.0.2.1","port":"443"}"#,
            "\n",
            r#"{"at":2,"pid":"7","event":5156,"direction":"%%14593","protocol":"17","host":"192.0.2.1","port":"53"}"#,
            "\n",
            r#"{"at":3,"pid":"7","event":9999,"direction":"%%14593","protocol":"6","host":"192.0.2.1","port":"443"}"#,
            "\n",
            r#"{"at":4,"pid":"0","event":5156,"direction":"%%14593","protocol":"6","host":"not-an-ip","port":"0"}"#,
            "\n",
            "not-json\n",
        );
        assert!(parse_windows_filtering_events(fixture).is_empty());
    }

    #[test]
    fn windows_attempt_window_rejects_stale_future_and_recycled_pid_records() {
        let event = AttemptEvent {
            pid: 7,
            observed_at: 10_000,
            host: "127.0.0.1".into(),
            port: 443,
            outcome: ConnectionOutcome::Allowed,
        };
        assert!(attempt_matches_process(&event, 9_000, 12_000));
        assert!(!attempt_matches_process(&event, 10_001, 12_000));
        assert!(!attempt_matches_process(&event, 9_000, 40_001));
        assert!(!attempt_matches_process(&event, 9_000, 9_999));
    }

    /// A ping calls `connect` never and `sendto` once per datagram. Before
    /// this, no sensor Topgent had attributed one to a process at all.
    #[test]
    fn a_datagram_names_its_destination_and_the_process_that_sent_it() {
        let text = concat!(
            "type=SYSCALL msg=audit(1700000000.100:41): syscall=44 success=yes pid=700 a0=3\n",
            "type=SOCKADDR msg=audit(1700000000.100:41): saddr=02000050CB00716E0000000000000000\n",
        );
        let events = parse_audit_connections(text);
        assert_eq!(events.len(), 1, "the datagram was dropped: {events:?}");
        assert_eq!(events[0].pid, 700);
        assert_eq!(events[0].host, "203.0.113.110");
        assert!(!events[0].pending, "a datagram is never pending");
    }

    /// A ping sends once a second. Recording each one would make this a packet
    /// log, and the destination is the same every time.
    #[test]
    fn repeated_datagrams_to_one_destination_are_recorded_once() {
        let mut text = String::new();
        for n in 0..20u64 {
            let (at, id) = (1_700_000_000 + n, 100 + n);
            text.push_str(&format!(
                "type=SYSCALL msg=audit({at}.100:{id}): syscall=44 success=yes pid=700 a0=3\n"
            ));
            text.push_str(&format!(
                "type=SOCKADDR msg=audit({at}.100:{id}): saddr=02000050CB00716E0000000000000000\n"
            ));
        }
        let events = parse_audit_connections(&text);
        assert_eq!(
            events.len(),
            1,
            "one destination, twenty datagrams: {events:?}"
        );
    }

    /// A datagram has no lifetime. Pairing one with a later `close` on the
    /// same descriptor would give it a duration it never had.
    #[test]
    fn a_close_does_not_give_a_datagram_a_duration() {
        let text = concat!(
            "type=SYSCALL msg=audit(1700000000.100:41): syscall=44 success=yes pid=700 a0=3\n",
            "type=SOCKADDR msg=audit(1700000000.100:41): saddr=02000050CB00716E0000000000000000\n",
            "type=SYSCALL msg=audit(1700000009.100:42): syscall=3 success=yes pid=700 a0=3\n",
        );
        let events = parse_audit_connections(text);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].closed_at, None, "a datagram was given a duration");
    }

    /// A refused send is not a destination reached.
    #[test]
    fn a_failed_datagram_is_not_recorded_as_one_that_arrived() {
        let text = concat!(
            "type=SYSCALL msg=audit(1700000000.100:41): syscall=44 success=no pid=700 a0=3\n",
            "type=SOCKADDR msg=audit(1700000000.100:41): saddr=02000050CB00716E0000000000000000\n",
        );
        assert!(parse_audit_connections(text).is_empty());
    }

    #[test]
    fn joins_only_successful_connect_syscalls_to_exact_sockaddr_records() {
        let fixture = concat!(
            "type=SYSCALL msg=audit(1700000000.100:41): syscall=42 success=yes pid=700 a0=d\n",
            "type=SOCKADDR msg=audit(1700000000.100:41): saddr=020001BBC000020A0000000000000000\n",
            "type=SYSCALL msg=audit(1700000000.200:42): syscall=42 success=no pid=700 a0=e\n",
            "type=SOCKADDR msg=audit(1700000000.200:42): saddr=02000035080808080000000000000000\n",
            "type=SYSCALL msg=audit(1700000000.300:43): syscall=257 success=yes pid=700 a0=f\n",
            "type=SOCKADDR msg=audit(1700000000.300:43): saddr=020001BB7F0000010000000000000000\n",
        );
        assert_eq!(
            parse_audit_connections(fixture),
            vec![ConnectionEvent {
                pid: 700,
                fd: 13,
                observed_at: 1_700_000_000_100,
                host: "192.0.2.10".into(),
                port: 443,
                pending: false,
                closed_at: None,
            }]
        );
    }

    #[test]
    fn correlates_only_a_later_successful_close_for_the_same_pid_and_fd() {
        let fixture = concat!(
            "type=SYSCALL msg=audit(1700000000.100:41): syscall=connect success=yes pid=700 a0=d\n",
            "type=SOCKADDR msg=audit(1700000000.100:41): saddr=020001BBC000020A0000000000000000\n",
            "type=SYSCALL msg=audit(1700000000.150:42): syscall=close success=yes pid=701 a0=d\n",
            "type=SYSCALL msg=audit(1700000000.175:43): syscall=close success=no pid=700 a0=d\n",
            "type=SYSCALL msg=audit(1700000000.350:44): syscall=close success=yes pid=700 a0=e\n",
            "type=SYSCALL msg=audit(1700000000.600:45): syscall=3 success=yes pid=700 a0=d\n",
        );
        assert_eq!(
            parse_audit_connections(fixture),
            vec![ConnectionEvent {
                pid: 700,
                fd: 13,
                observed_at: 1_700_000_000_100,
                host: "192.0.2.10".into(),
                port: 443,
                pending: false,
                closed_at: Some(1_700_000_000_600),
            }]
        );
    }

    #[test]
    fn malformed_or_missing_descriptors_cannot_create_lifecycle_evidence() {
        let fixture = concat!(
            "type=SYSCALL msg=audit(1700000000.100:41): syscall=connect success=yes pid=700\n",
            "type=SOCKADDR msg=audit(1700000000.100:41): saddr=020001BBC000020A0000000000000000\n",
            "type=SYSCALL msg=audit(1700000000.200:42): syscall=connect success=yes pid=700 a0=nothex\n",
            "type=SOCKADDR msg=audit(1700000000.200:42): saddr=020001BBC000020A0000000000000000\n",
            "type=SYSCALL msg=audit(1700000000.300:43): syscall=close success=yes pid=700 a0=fffffffff\n",
        );
        assert!(parse_audit_connections(fixture).is_empty());
    }

    #[test]
    fn sockaddr_parser_handles_ipv4_ipv6_and_rejects_local_or_malformed_families() {
        assert_eq!(
            parse_sockaddr("02000035080808080000000000000000"),
            Some(("8.8.8.8".into(), 53))
        );
        assert_eq!(
            parse_sockaddr("0A0001BB0000000020010DB8000000000000000000000001"),
            Some(("2001:db8::1".into(), 443))
        );
        assert_eq!(parse_sockaddr("01000000"), None);
        assert_eq!(parse_sockaddr("not-hex"), None);
        assert_eq!(
            parse_sockaddr("0200B26E7F0000010000000000000000\u{1d}SADDR={"),
            Some(("127.0.0.1".into(), 45678))
        );
    }

    #[test]
    fn event_window_rejects_stale_future_and_recycled_pid_records() {
        let event = ConnectionEvent {
            pid: 7,
            fd: 3,
            observed_at: 10_000,
            host: "127.0.0.1".into(),
            port: 4173,
            pending: false,
            closed_at: None,
        };
        assert!(event_matches_process(&event, 9_000, 12_000));
        assert!(!event_matches_process(&event, 10_001, 12_000));
        assert!(!event_matches_process(&event, 9_000, 15_001));
        assert!(!event_matches_process(&event, 9_000, 9_999));

        let recently_closed = ConnectionEvent {
            observed_at: 1_000,
            closed_at: Some(20_000),
            ..event
        };
        assert!(event_matches_process(&recently_closed, 500, 20_100));
        assert!(!event_matches_process(&recently_closed, 1_001, 20_100));
    }

    #[test]
    fn nonblocking_connect_requires_a_matching_live_socket() {
        let event = ConnectionEvent {
            pid: 7,
            fd: 3,
            observed_at: 10_000,
            host: "127.0.0.1".into(),
            port: 4173,
            pending: true,
            closed_at: None,
        };
        assert!(!event_is_confirmed(&event, &BTreeSet::new()));
        assert!(event_is_confirmed(
            &event,
            &BTreeSet::from([(7, "127.0.0.1".into(), 4173)])
        ));
        assert!(!event_is_confirmed(
            &event,
            &BTreeSet::from([(8, "127.0.0.1".into(), 4173)])
        ));
    }
}
