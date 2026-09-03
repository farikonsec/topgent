//! PID-attributed name-resolution events.
//!
//! The two platforms give very different things, and the collector reports
//! exactly what each one gives rather than levelling them to the weaker.
//!
//! On Linux, Audit exposes the destination of `sendto` and `connect` but no
//! safe query-name field, so only the fact that a live process contacted a
//! resolver on port 53 is reported. It never invents a hostname.
//!
//! On Windows the DNS client's operational log does name the query, and some
//! of its records name the process that asked. Only those records are used.
//! The log is off by default and Topgent never turns it on.

#[cfg(any(target_os = "linux", windows))]
use crate::emit;
use crate::{Clock, CollectError, Collector};
#[cfg(any(target_os = "linux", windows, test))]
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use topgent_facts::Direction;
#[cfg(any(windows, test))]
use topgent_facts::DnsOutcome;
use topgent_facts::Fact;
#[cfg(any(target_os = "linux", windows))]
use topgent_facts::{Claim, Confidence};

const ID: &str = "dns_events";
#[cfg(target_os = "linux")]
const PROBE: &str = "Linux Audit DNS resolver contacts (metadata-only, PID-attributed)";
#[cfg(target_os = "linux")]
const MAX_AUDIT_BYTES: u64 = 1_048_576;
#[cfg(any(target_os = "linux", test))]
const EVENT_WINDOW_MS: u64 = 5_000;
#[cfg(windows)]
const PROBE: &str = "Windows DNS-Client operational log, records naming the client process";
/// Event Log delivery is asynchronous, so the accepted window is wider here
/// than the Audit one, exactly as the Filtering Platform collector does.
#[cfg(any(windows, test))]
const WINDOWS_EVENT_WINDOW_MS: u64 = 30_000;
/// Largest number of resolver records read from one sweep.
#[cfg(any(windows, test))]
pub const MAX_WINDOWS_DNS_RECORDS: usize = 256;
/// The line the reader prints when the operational log is switched off.
#[cfg(any(windows, test))]
const WINDOWS_LOG_DISABLED: &str = "#disabled";

/// A read-only Linux Audit DNS resolver-contact collector.
#[derive(Debug, Clone)]
pub struct DnsEventCollector {
    /// Audit log path. The default is `/var/log/audit/audit.log`.
    pub audit_log: std::path::PathBuf,
}

impl Default for DnsEventCollector {
    fn default() -> Self {
        Self {
            audit_log: "/var/log/audit/audit.log".into(),
        }
    }
}

impl Collector for DnsEventCollector {
    fn id(&self) -> &'static str {
        ID
    }

    /// Windows names the query but not always the asker.
    ///
    /// The operational log's completion record, event 3008, carries the name
    /// and the status and no client process id at all. Its own
    /// `Execution ProcessID` is the DNS cache service, so using it would
    /// attribute every lookup on the machine to one system process. Only the
    /// records that carry an explicit client id are used, and the rest are
    /// left unattributed rather than pinned on the resolver.
    #[cfg(windows)]
    fn boundary(&self) -> Option<&'static str> {
        Some(
            "Only resolver records that name the requesting process. Windows writes some \
             lookups without a client process id, and those are not attributed to any agent \
             rather than being attributed to the DNS cache service that logged them.",
        )
    }

    fn collect(&self, clock: &dyn Clock) -> Result<Vec<Fact>, CollectError> {
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            let _ = clock;
            Err(CollectError::Unavailable {
                what: "no PID-attributed name-resolution sensor exists on this platform".to_owned(),
            })
        }
        #[cfg(windows)]
        {
            let text = read_windows_dns_events()?;
            if text.lines().any(|line| line.trim() == WINDOWS_LOG_DISABLED) {
                return Err(CollectError::Denied {
                    what: "the Windows DNS-Client operational log is switched off; enable \
                           Microsoft-Windows-DNS-Client/Operational in Event Viewer to attribute \
                           name lookups to agents. Topgent does not enable it."
                        .to_owned(),
                });
            }
            let processes = crate::process::snapshot()
                .into_iter()
                .map(|process| (process.pid, (process.started_at.0, process.subject())))
                .collect::<BTreeMap<_, _>>();
            let now = clock.now().0;
            Ok(parse_windows_dns_events(&text)
                .into_iter()
                .filter_map(|event| {
                    let (started_at, subject) = processes.get(&event.pid)?;
                    if !windows_event_matches_process(&event, *started_at, now) {
                        return None;
                    }
                    emit(
                        ID,
                        PROBE,
                        Confidence::Certain,
                        clock,
                        subject.clone(),
                        Claim::DnsQueryObserved {
                            name: event.name,
                            query_type: event.query_type,
                            outcome: event.outcome,
                        },
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
            let now = clock.now().0;
            Ok(parse_dns_contacts(&text)
                .into_iter()
                .filter_map(|event| {
                    let (started_at, subject) = processes.get(&event.pid)?;
                    if !event_matches_process(&event, *started_at, now) {
                        return None;
                    }
                    emit(
                        ID,
                        PROBE,
                        Confidence::Likely,
                        clock,
                        subject.clone(),
                        Claim::SocketOpen {
                            protocol: topgent_facts::Protocol::Tcp,
                            bytes: None,
                            host: event.resolver,
                            port: 53,
                            direction: Direction::Outbound,
                            // Audit records the contact, not when the socket
                            // to the resolver was created.
                            opened_at: None,
                            // The audit record names the process the kernel attributed
                            // the syscall to, as it happened. Nothing was searched and
                            // no key was relaxed.
                            basis: topgent_facts::MatchBasis::KernelEvent,
                        },
                    )
                })
                .collect())
        }
    }
}

/// One resolver record that names the process which asked.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(any(windows, test))]
pub struct WindowsDnsQuery {
    /// The process the record says made the request.
    pub pid: u32,
    /// When the record was written.
    pub observed_at: u64,
    /// The name that was looked up.
    pub name: String,
    /// Numeric DNS record type.
    pub query_type: u16,
    /// What the resolver said.
    pub outcome: DnsOutcome,
}

/// Windows status codes that mean the resolver answered with nothing.
///
/// `9003` is a name that does not exist and `9501` is a name with no record of
/// the requested type. Both are answers, not failures, and calling them
/// failures would make an ordinary IPv6 probe on an IPv4-only name look like a
/// broken resolver.
#[cfg(any(windows, test))]
const WINDOWS_DNS_NOT_FOUND: [u32; 2] = [9003, 9501];

/// Read one numeric event-data field, however Windows wrote it.
///
/// Event data arrives as strings, sometimes decimal and sometimes `0x` hex, and
/// a serializer may render a plain number instead. All three are the same fact.
#[cfg(any(windows, test))]
fn windows_field(value: &serde_json::Value, key: &str) -> Option<u64> {
    match value.get(key)? {
        serde_json::Value::Number(number) => number.as_u64(),
        serde_json::Value::String(text) => crate::network_event::parse_windows_number(text),
        _ => None,
    }
}

#[cfg(any(windows, test))]
fn windows_outcome(status: u32) -> DnsOutcome {
    if status == 0 {
        DnsOutcome::Answered
    } else if WINDOWS_DNS_NOT_FOUND.contains(&status) {
        DnsOutcome::NotFound
    } else {
        DnsOutcome::Failed
    }
}

#[cfg(any(windows, test))]
fn windows_event_matches_process(event: &WindowsDnsQuery, started_at: u64, now: u64) -> bool {
    event.observed_at >= started_at
        && event.observed_at <= now
        && event.observed_at >= now.saturating_sub(WINDOWS_EVENT_WINDOW_MS)
}

/// Parse resolver records that name the requesting process.
///
/// Only records carrying an explicit client process id are admitted. The
/// record's own `Execution ProcessID` is the DNS cache service, not the
/// program that asked, so a record without a client id is dropped rather than
/// attributed to whatever wrote it. Names are bounded and taken verbatim; no
/// address, blob or handle from the record is retained.
#[cfg(any(windows, test))]
#[must_use]
pub fn parse_windows_dns_events(out: &str) -> Vec<WindowsDnsQuery> {
    let mut events = Vec::new();
    for line in out.lines() {
        if events.len() >= MAX_WINDOWS_DNS_RECORDS {
            break;
        }
        let line = line.trim();
        if line.is_empty() || line == WINDOWS_LOG_DISABLED {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(pid) = windows_field(&value, "pid").and_then(|pid| u32::try_from(pid).ok()) else {
            continue;
        };
        if pid == 0 {
            continue;
        }
        let Some(observed_at) = value.get("at").and_then(serde_json::Value::as_u64) else {
            continue;
        };
        let Some(name) = value.get("name").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let name = name.trim().trim_end_matches('.');
        if name.is_empty() || name.len() > 253 || name.contains(char::is_whitespace) {
            continue;
        }
        let Some(query_type) =
            windows_field(&value, "type").and_then(|kind| u16::try_from(kind).ok())
        else {
            continue;
        };
        let Some(status) =
            windows_field(&value, "status").and_then(|status| u32::try_from(status).ok())
        else {
            continue;
        };
        events.push(WindowsDnsQuery {
            pid,
            observed_at,
            name: name.to_owned(),
            query_type,
            outcome: windows_outcome(status),
        });
    }
    events
}

/// Read recent resolver records, or report that the log is switched off.
///
/// Event 3020 is the query response, and it is the record that carries both
/// the name and the client process id. Fixed script, no interpolation, bounded
/// output. Topgent never enables the log.
#[cfg(windows)]
fn read_windows_dns_events() -> Result<String, CollectError> {
    const SCRIPT: &str = r"$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $log='Microsoft-Windows-DNS-Client/Operational'; if (-not (Get-WinEvent -ListLog $log -ErrorAction SilentlyContinue).IsEnabled) {Write-Output '#disabled'; exit 0}; try {$events=Get-WinEvent -FilterHashtable @{LogName=$log;Id=3020;StartTime=(Get-Date).AddSeconds(-30)} -MaxEvents 256} catch {if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {exit 0}; throw}; $events | ForEach-Object {$xml=[xml]$_.ToXml(); $data=@{}; foreach($item in $xml.Event.EventData.Data){$data[[string]$item.Name]=[string]$item.'#text'}; [pscustomobject]@{at=([DateTimeOffset]$_.TimeCreated).ToUnixTimeMilliseconds(); pid=$data.ClientPID; name=$data.QueryName; type=$data.QueryType; status=$data.Status} | ConvertTo-Json -Compress}";
    let output = crate::tool::POWERSHELL
        .command()?
        .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
        .output()
        .map_err(|error| CollectError::Unavailable {
            what: format!("powershell.exe: {error}"),
        })?;
    if !output.status.success() {
        return Err(CollectError::Unreadable {
            what: "the Windows DNS-Client operational log could not be read".to_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(any(target_os = "linux", test))]
struct DnsContact {
    pid: u32,
    observed_at: u64,
    resolver: String,
}

#[derive(Default)]
#[cfg(any(target_os = "linux", test))]
struct PartialEvent {
    pid: Option<u32>,
    observed_at: Option<u64>,
    success: bool,
    dns_transport: bool,
    endpoint: Option<(String, u16)>,
}

#[cfg(any(target_os = "linux", test))]
fn event_matches_process(event: &DnsContact, started_at: u64, now: u64) -> bool {
    event.observed_at >= started_at
        && event.observed_at <= now
        && event.observed_at >= now.saturating_sub(EVENT_WINDOW_MS)
}

#[cfg(any(target_os = "linux", test))]
fn parse_dns_contacts(text: &str) -> Vec<DnsContact> {
    let mut groups = BTreeMap::<String, PartialEvent>::new();
    for line in text.lines() {
        let Some(id) = audit_id(line) else { continue };
        let event = groups.entry(id.to_owned()).or_default();
        event.observed_at = audit_time_ms(id);
        if line.starts_with("type=SYSCALL ") {
            event.success = field(line, "success") == Some("yes");
            event.dns_transport = matches!(
                field(line, "syscall"),
                Some("sendto" | "connect" | "44" | "42" | "206" | "203")
            );
            event.pid = field(line, "pid").and_then(|value| value.parse().ok());
        } else if line.starts_with("type=SOCKADDR ") {
            event.endpoint = field(line, "saddr").and_then(parse_sockaddr);
        }
    }
    groups
        .into_values()
        .filter(|event| event.success && event.dns_transport)
        .filter_map(|event| {
            let (resolver, port) = event.endpoint?;
            (port == 53).then_some(DnsContact {
                pid: event.pid?,
                observed_at: event.observed_at?,
                resolver,
            })
        })
        .collect()
}

#[cfg(any(target_os = "linux", test))]
fn parse_sockaddr(value: &str) -> Option<(String, u16)> {
    let end = value
        .find(|character: char| !character.is_ascii_hexdigit())
        .unwrap_or(value.len());
    let hex = value.get(..end)?;
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

#[cfg(any(target_os = "linux", test))]
fn audit_id(line: &str) -> Option<&str> {
    line.split_once("msg=audit(")?
        .1
        .split_once("): ")
        .map(|(id, _)| id)
}

#[cfg(any(target_os = "linux", test))]
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

#[cfg(any(target_os = "linux", test))]
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
        DnsContact, MAX_WINDOWS_DNS_RECORDS, WINDOWS_EVENT_WINDOW_MS, WindowsDnsQuery,
        event_matches_process, parse_dns_contacts, parse_windows_dns_events,
        windows_event_matches_process,
    };
    use topgent_facts::DnsOutcome;

    #[test]
    fn exact_join_accepts_successful_ipv4_and_ipv6_port_53_contacts_only() {
        let fixture = concat!(
            "type=SYSCALL msg=audit(1700000000.100:41): syscall=206 success=yes exit=32 pid=700\n",
            "type=SOCKADDR msg=audit(1700000000.100:41): saddr=02000035080808080000000000000000\u{1d}SADDR={\n",
            "type=SYSCALL msg=audit(1700000000.200:42): syscall=203 success=yes exit=0 pid=701\n",
            "type=SOCKADDR msg=audit(1700000000.200:42): saddr=0A0000350000000020010DB8000000000000000000000053\n",
            "type=SYSCALL msg=audit(1700000000.300:43): syscall=206 success=yes exit=32 pid=700\n",
            "type=SOCKADDR msg=audit(1700000000.300:43): saddr=020001BBC000020A0000000000000000\n",
            "type=SYSCALL msg=audit(1700000000.400:44): syscall=206 success=no exit=-1 pid=700\n",
            "type=SOCKADDR msg=audit(1700000000.400:44): saddr=02000035010101010000000000000000\n",
        );
        assert_eq!(
            parse_dns_contacts(fixture),
            vec![
                DnsContact {
                    pid: 700,
                    observed_at: 1_700_000_000_100,
                    resolver: "8.8.8.8".into()
                },
                DnsContact {
                    pid: 701,
                    observed_at: 1_700_000_000_200,
                    resolver: "2001:db8::53".into()
                },
            ]
        );
    }

    #[test]
    fn malformed_unix_unrelated_and_mismatched_records_are_rejected() {
        let fixture = concat!(
            "type=SYSCALL msg=audit(1700000000.100:41): syscall=257 success=yes pid=700\n",
            "type=SOCKADDR msg=audit(1700000000.100:41): saddr=02000035080808080000000000000000\n",
            "type=SYSCALL msg=audit(1700000000.200:42): syscall=206 success=yes pid=700\n",
            "type=SOCKADDR msg=audit(1700000000.201:43): saddr=02000035080808080000000000000000\n",
            "type=SYSCALL msg=audit(1700000000.300:44): syscall=206 success=yes pid=700\n",
            "type=SOCKADDR msg=audit(1700000000.300:44): saddr=01002F72756E2F6E7363642F736F636B6574\n",
        );
        assert!(parse_dns_contacts(fixture).is_empty());
    }

    #[test]
    fn event_window_rejects_stale_future_and_recycled_pid_records() {
        let event = DnsContact {
            pid: 7,
            observed_at: 10_000,
            resolver: "127.0.0.53".into(),
        };
        assert!(event_matches_process(&event, 9_000, 12_000));
        assert!(!event_matches_process(&event, 10_001, 12_000));
        assert!(!event_matches_process(&event, 9_000, 15_001));
        assert!(!event_matches_process(&event, 9_000, 9_999));
    }

    /// The shape PowerShell produces from event 3020: every field a string.
    fn record(pid: &str, name: &str, kind: &str, status: &str, at: u64) -> String {
        format!(
            r#"{{"at":{at},"pid":"{pid}","name":"{name}","type":"{kind}","status":"{status}"}}"#
        )
    }

    #[test]
    fn a_resolver_record_naming_the_client_becomes_one_attributed_lookup() {
        // Event 3020 is the only response record that carries both the queried
        // name and the process that asked for it.
        let out = [
            record("1484", "api.anthropic.com", "1", "0", 1_787_760_000_000),
            record(
                "1484",
                "topgent-b2-canary.example.com.",
                "28",
                "9501",
                1_787_760_001_000,
            ),
            record("2000", "nowhere.invalid", "1", "9003", 1_787_760_002_000),
            record("2000", "broken.invalid", "1", "12345", 1_787_760_003_000),
        ]
        .join("\n");
        let events = parse_windows_dns_events(&out);
        assert_eq!(events.len(), 4);

        assert_eq!(events[0].pid, 1484);
        assert_eq!(events[0].name, "api.anthropic.com");
        assert_eq!(events[0].query_type, 1);
        assert_eq!(events[0].outcome, DnsOutcome::Answered);

        // A trailing root dot is the same name, and 9501 is an answer of "no
        // record of that type", not a failure: an IPv6 probe on an IPv4-only
        // name must not look like a broken resolver.
        assert_eq!(events[1].name, "topgent-b2-canary.example.com");
        assert_eq!(events[1].query_type, 28);
        assert_eq!(events[1].outcome, DnsOutcome::NotFound);

        // A name that does not exist is also an answer.
        assert_eq!(events[2].outcome, DnsOutcome::NotFound);
        // Anything else is a lookup that did not complete.
        assert_eq!(events[3].outcome, DnsOutcome::Failed);
    }

    #[test]
    fn a_lookup_windows_does_not_attribute_is_left_unattributed() {
        // Event 3008 carries the name and the status and no client id at all,
        // and the record's own process is the DNS cache service. Guessing from
        // that would attribute every lookup on the machine to one process.
        for unattributed in [
            r#"{"at":1,"name":"api.anthropic.com","type":"1","status":"0"}"#,
            r#"{"at":1,"pid":"","name":"api.anthropic.com","type":"1","status":"0"}"#,
            r#"{"at":1,"pid":"0","name":"api.anthropic.com","type":"1","status":"0"}"#,
            r#"{"at":1,"pid":"not a pid","name":"api.anthropic.com","type":"1","status":"0"}"#,
        ] {
            assert!(
                parse_windows_dns_events(unattributed).is_empty(),
                "attributed a lookup with no client process: {unattributed}"
            );
        }
    }

    #[test]
    fn nothing_a_hostile_or_broken_resolver_record_contains_survives() {
        let long_name = "a".repeat(254);
        for bad in [
            String::from("not json"),
            String::from("{"),
            record("10", "", "1", "0", 1),
            record("10", "has a space", "1", "0", 1),
            format!(r#"{{"at":1,"pid":"10","name":"{long_name}","type":"1","status":"0"}}"#),
            String::from(r#"{"at":1,"pid":"10","name":"x.example","status":"0"}"#),
            String::from(r#"{"at":1,"pid":"10","name":"x.example","type":"1"}"#),
            String::from(r#"{"pid":"10","name":"x.example","type":"1","status":"0"}"#),
            String::from(r#"{"at":1,"pid":"10","name":"x.example","type":"99999","status":"0"}"#),
        ] {
            assert!(
                parse_windows_dns_events(&bad).is_empty(),
                "admitted an unusable record: {bad}"
            );
        }

        // A hex-written field is the same fact as a decimal one, and a broken
        // line does not stop the next.
        let mixed = format!(
            "not json\n{}",
            r#"{"at":1,"pid":"0x5cc","name":"x.example","type":"0x1","status":"0"}"#
        );
        let events = parse_windows_dns_events(&mixed);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].pid, 1_484);
        assert_eq!(events[0].query_type, 1);
    }

    #[test]
    fn resolver_records_are_bounded_however_many_the_log_holds() {
        let flood = std::iter::repeat_n(
            record("10", "x.example", "1", "0", 1),
            MAX_WINDOWS_DNS_RECORDS + 100,
        )
        .collect::<Vec<_>>()
        .join("\n");
        assert_eq!(
            parse_windows_dns_events(&flood).len(),
            MAX_WINDOWS_DNS_RECORDS
        );
    }

    #[test]
    fn a_lookup_is_admitted_only_for_the_exact_run_that_was_alive_for_it() {
        let now = 1_787_760_000_000_u64;
        let query = |at: u64| WindowsDnsQuery {
            pid: 10,
            observed_at: at,
            name: "x.example".to_owned(),
            query_type: 1,
            outcome: DnsOutcome::Answered,
        };
        let started = now - 10_000;

        assert!(windows_event_matches_process(
            &query(now - 1_000),
            started,
            now
        ));
        // A record older than the delivery window is stale.
        assert!(!windows_event_matches_process(
            &query(now - WINDOWS_EVENT_WINDOW_MS - 1),
            started,
            now
        ));
        // A record from the future cannot describe anything that has happened.
        assert!(!windows_event_matches_process(
            &query(now + 1),
            started,
            now
        ));
        // A record from before this process existed belongs to whatever held
        // the pid before it, which is the pid-reuse trap.
        assert!(!windows_event_matches_process(
            &query(started - 1),
            started,
            now
        ));
        // The boundaries themselves are inside.
        assert!(windows_event_matches_process(&query(started), started, now));
        assert!(windows_event_matches_process(&query(now), started, now));
    }
}
