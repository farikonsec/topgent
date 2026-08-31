//! PID-attributed operating-system filesystem events.
//!
//! Topgent reads a bounded local audit-log tail and never launches or configures
//! an elevated helper. A successful syscall and path must share one audit ID,
//! and the PID must still resolve to a live process identity.

#[cfg(target_os = "linux")]
use crate::emit;
use crate::{Clock, CollectError, Collector};
#[cfg(any(target_os = "linux", windows, test))]
use std::collections::BTreeMap;
#[cfg(any(target_os = "linux", windows, test))]
use topgent_facts::Access;
use topgent_facts::Fact;
#[cfg(any(target_os = "linux", windows))]
use topgent_facts::{Claim, Confidence};

const ID: &str = "filesystem_events";
#[cfg(target_os = "linux")]
const PROBE: &str = "Linux Audit log (bounded, PID-attributed)";
#[cfg(windows)]
const PROBE: &str = "Windows Security 4663 events (bounded, PID-attributed)";
#[cfg(target_os = "linux")]
const MAX_AUDIT_BYTES: u64 = 1_048_576;
#[cfg(any(target_os = "linux", windows, test))]
const EVENT_WINDOW_MS: u64 = 5_000;

/// A read-only operating-system filesystem-event collector.
#[derive(Debug, Clone)]
pub struct FilesystemEventCollector {
    /// Audit log path. The default is `/var/log/audit/audit.log`.
    pub audit_log: std::path::PathBuf,
}

impl Default for FilesystemEventCollector {
    fn default() -> Self {
        Self {
            audit_log: "/var/log/audit/audit.log".into(),
        }
    }
}

impl Collector for FilesystemEventCollector {
    fn id(&self) -> &'static str {
        ID
    }

    fn collect(&self, clock: &dyn Clock) -> Result<Vec<Fact>, CollectError> {
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            let _ = clock;
            Err(CollectError::Unavailable {
                what: "PID-attributed Linux Audit events are Linux-only".to_owned(),
            })
        }
        #[cfg(windows)]
        {
            let text = read_windows_security_events()?;
            let processes = crate::process::snapshot()
                .into_iter()
                .map(|process| (process.pid, (process.started_at.0, process.subject())))
                .collect::<BTreeMap<_, _>>();
            let now = clock.now().0;
            Ok(parse_windows_security_events(&text)
                .into_iter()
                .filter_map(|event| {
                    let (started_at, subject) = processes.get(&event.pid)?;
                    if !event_matches_process(&event, *started_at, now) {
                        return None;
                    }
                    emit_at(
                        subject.clone(),
                        Claim::FileTouched {
                            path: event.path,
                            access: event.access,
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
            let now = clock.now().0;
            Ok(parse_audit_events(&text)
                .into_iter()
                .filter_map(|event| {
                    let (started_at, subject) = processes.get(&event.pid)?;
                    if !event_matches_process(&event, *started_at, now) {
                        return None;
                    }
                    emit(
                        ID,
                        PROBE,
                        Confidence::Certain,
                        clock,
                        subject.clone(),
                        Claim::FileTouched {
                            path: event.path,
                            access: event.access,
                        },
                    )
                })
                .collect())
        }
    }
}

#[cfg(windows)]
fn emit_at(subject: topgent_facts::Subject, claim: Claim, observed_at: u64) -> Option<Fact> {
    use topgent_facts::{Provenance, SCHEMA_VERSION, UnixMillis};
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

#[cfg(any(target_os = "linux", windows, test))]
fn event_matches_process(event: &AuditEvent, started_at: u64, now: u64) -> bool {
    event.observed_at >= started_at
        && event.observed_at <= now
        && event.observed_at >= now.saturating_sub(EVENT_WINDOW_MS)
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(any(target_os = "linux", windows, test))]
struct AuditEvent {
    pid: u32,
    observed_at: u64,
    path: String,
    access: Access,
}

#[derive(Debug, serde::Deserialize)]
#[cfg(any(windows, test))]
struct WindowsSecurityRecord {
    #[serde(rename = "at")]
    observed_at: u64,
    pid: String,
    #[serde(rename = "mask")]
    access_mask: String,
    #[serde(rename = "path")]
    path: String,
    #[serde(rename = "type")]
    object_type: String,
}

#[cfg(any(windows, test))]
fn parse_windows_security_events(text: &str) -> Vec<AuditEvent> {
    text.lines()
        .take(128)
        .filter(|line| line.len() <= 16_384)
        .filter_map(|line| serde_json::from_str::<WindowsSecurityRecord>(line).ok())
        .filter(|record| record.object_type.eq_ignore_ascii_case("file"))
        .filter(|record| safe_windows_path(&record.path))
        .filter_map(|record| {
            let pid = parse_windows_number(&record.pid).and_then(|value| value.try_into().ok())?;
            let mask = parse_windows_number(&record.access_mask)?;
            Some(AuditEvent {
                pid,
                observed_at: record.observed_at,
                path: record.path,
                access: windows_access(mask)?,
            })
        })
        .collect()
}

#[cfg(any(windows, test))]
fn parse_windows_number(value: &str) -> Option<u64> {
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
fn windows_access(mask: u64) -> Option<Access> {
    let reads = mask & (0x1 | 0x8 | 0x80) != 0;
    let writes = mask & (0x2 | 0x4 | 0x10 | 0x100 | 0x10000) != 0;
    if mask & 0x20 != 0 && !reads && !writes {
        Some(Access::Execute)
    } else if reads && writes {
        Some(Access::ReadWrite)
    } else if writes {
        Some(Access::Write)
    } else if reads {
        Some(Access::Read)
    } else {
        None
    }
}

#[cfg(any(windows, test))]
fn safe_windows_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    let drive_absolute = matches!(
        (bytes.first(), bytes.get(1), bytes.get(2)),
        (Some(drive), Some(b':'), Some(b'\\' | b'/')) if drive.is_ascii_alphabetic()
    );
    let unc = path.starts_with("\\\\") && path.len() > 2;
    (drive_absolute || unc) && path.len() <= 4_096 && !path.chars().any(char::is_control)
}

#[cfg(windows)]
fn read_windows_security_events() -> Result<String, CollectError> {
    const SCRIPT: &str = r"$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); try {$events=Get-WinEvent -FilterHashtable @{LogName='Security';Id=4663;StartTime=(Get-Date).AddSeconds(-5)} -MaxEvents 128} catch {if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {exit 0}; throw}; $events | ForEach-Object { $xml=[xml]$_.ToXml(); $data=@{}; foreach($item in $xml.Event.EventData.Data){$data[[string]$item.Name]=[string]$item.'#text'}; [pscustomobject]@{at=([DateTimeOffset]$_.TimeCreated).ToUnixTimeMilliseconds(); pid=$data.ProcessId; mask=$data.AccessMask; path=$data.ObjectName; type=$data.ObjectType} | ConvertTo-Json -Compress }";
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
        return Err(classify_windows_query_error(&detail));
    }
    String::from_utf8(output.stdout).map_err(|error| CollectError::Unreadable {
        what: format!("Windows Security event output was not UTF-8: {error}"),
    })
}

#[cfg(any(windows, test))]
fn classify_windows_query_error(detail: &str) -> CollectError {
    let normalized = detail.to_ascii_lowercase();
    if normalized.contains("access is denied") || normalized.contains("unauthorized") {
        CollectError::Denied {
            what: "Windows Security event log requires permission".to_owned(),
        }
    } else {
        CollectError::Unreadable {
            what: format!("Windows Security event query failed: {}", detail.trim()),
        }
    }
}

#[derive(Default)]
#[cfg(any(target_os = "linux", test))]
struct PartialEvent {
    pid: Option<u32>,
    observed_at: Option<u64>,
    access: Option<Access>,
    success: bool,
    paths: Vec<String>,
}

#[cfg(any(target_os = "linux", test))]
fn parse_audit_events(text: &str) -> Vec<AuditEvent> {
    let mut groups = BTreeMap::<String, PartialEvent>::new();
    for line in text.lines() {
        let Some(id) = audit_id(line) else { continue };
        let event = groups.entry(id.to_owned()).or_default();
        event.observed_at = audit_time_ms(id);
        if line.starts_with("type=SYSCALL ") {
            event.success = field(line, "success") == Some("yes");
            event.pid = field(line, "pid").and_then(|value| value.parse().ok());
            event.access = syscall_access(line);
        } else if line.starts_with("type=PATH ")
            && let Some(path) = quoted_field(line, "name")
            && safe_path(&path)
        {
            event.paths.push(path);
        }
    }
    groups
        .into_values()
        .filter(|event| event.success)
        .flat_map(|event| {
            event.paths.into_iter().filter_map(move |path| {
                Some(AuditEvent {
                    pid: event.pid?,
                    observed_at: event.observed_at?,
                    path,
                    access: event.access?,
                })
            })
        })
        .collect()
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

#[cfg(any(target_os = "linux", test))]
fn quoted_field(line: &str, name: &str) -> Option<String> {
    let marker = format!("{name}=\"");
    let rest = line.split_once(&marker)?.1;
    Some(rest[..rest.find('"')?].replace("\\x20", " "))
}

#[cfg(any(target_os = "linux", test))]
fn syscall_access(line: &str) -> Option<Access> {
    let syscall = field(line, "syscall")?;
    if matches!(syscall, "execve" | "59" | "221") {
        return Some(Access::Execute);
    }
    if matches!(
        syscall,
        "unlink"
            | "unlinkat"
            | "rename"
            | "renameat"
            | "truncate"
            | "87"
            | "263"
            | "82"
            | "264"
            | "76"
    ) {
        return Some(Access::Write);
    }
    if !matches!(syscall, "open" | "openat" | "2" | "56" | "257") {
        return None;
    }
    let flags = if matches!(syscall, "open" | "2") {
        field(line, "a1")?
    } else {
        field(line, "a2")?
    };
    let flags = u64::from_str_radix(flags.trim_start_matches("0x"), 16).ok()?;
    Some(
        if flags.trailing_zeros() >= 2 && flags & (0x40 | 0x200) == 0 {
            Access::Read
        } else if flags & 3 == 2 {
            Access::ReadWrite
        } else {
            Access::Write
        },
    )
}

#[cfg(any(target_os = "linux", test))]
fn safe_path(path: &str) -> bool {
    path.starts_with('/') && path.len() <= 4_096 && !path.chars().any(char::is_control)
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
    use super::{
        AuditEvent, classify_windows_query_error, event_matches_process, parse_audit_events,
        parse_windows_security_events,
    };
    use crate::CollectError;
    use topgent_facts::Access;

    #[test]
    fn windows_security_records_map_exact_pid_path_and_access_masks() {
        let fixture = concat!(
            r#"{"at":1700000000100,"pid":"0x2bc","mask":"0x1","path":"C:\\Users\\test\\.ssh\\id_ed25519","type":"File"}"#,
            "\n",
            r#"{"at":1700000000200,"pid":"700","mask":"0x10006","path":"C:\\Users\\test\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\agent.cmd","type":"File"}"#,
            "\n",
            r#"{"at":1700000000300,"pid":"701","mask":"0x20","path":"\\\\server\\share\\tool.exe","type":"File"}"#,
        );
        assert_eq!(
            parse_windows_security_events(fixture),
            vec![
                AuditEvent { pid: 700, observed_at: 1_700_000_000_100, path: r"C:\Users\test\.ssh\id_ed25519".into(), access: Access::Read },
                AuditEvent { pid: 700, observed_at: 1_700_000_000_200, path: r"C:\Users\test\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\agent.cmd".into(), access: Access::Write },
                AuditEvent { pid: 701, observed_at: 1_700_000_000_300, path: r"\\server\share\tool.exe".into(), access: Access::Execute },
            ]
        );
    }

    #[test]
    fn windows_security_records_reject_hostile_or_unattributable_input() {
        let fixture = concat!(
            r#"{"at":1,"pid":"0","mask":"0x1","path":"relative.txt","type":"File"}"#,
            "\n",
            r#"{"at":2,"pid":"7","mask":"0x40000","path":"C:\\safe.txt","type":"File"}"#,
            "\n",
            r#"{"at":3,"pid":"7","mask":"0x1","path":"C:\\bad\tname","type":"File"}"#,
            "\n",
            r#"{"at":4,"pid":"7","mask":"0x1","path":"C:\\safe.txt","type":"Key"}"#,
            "\n",
            "not-json\n",
        );
        assert!(parse_windows_security_events(fixture).is_empty());
    }

    #[test]
    fn windows_security_query_errors_preserve_permission_vs_operational_health() {
        assert!(matches!(
            classify_windows_query_error("Access is denied"),
            CollectError::Denied { .. }
        ));
        assert!(matches!(
            classify_windows_query_error("RPC server unavailable"),
            CollectError::Unreadable { .. }
        ));
    }

    #[test]
    fn audit_records_require_matching_success_pid_path_and_known_syscall() {
        let fixture = concat!(
            "type=SYSCALL msg=audit(1700000000.100:41): syscall=257 success=yes a2=0 pid=700\n",
            "type=PATH msg=audit(1700000000.100:41): name=\"/Users/test/.ssh/id_ed25519\"\n",
            "type=SYSCALL msg=audit(1700000000.200:42): syscall=257 success=yes a2=241 pid=700\n",
            "type=PATH msg=audit(1700000000.200:42): name=\"/Users/test/Library/LaunchAgents/evil.plist\"\n",
            "type=SYSCALL msg=audit(1700000000.300:43): syscall=257 success=no a2=0 pid=700\n",
            "type=PATH msg=audit(1700000000.300:43): name=\"/denied\"\n",
        );
        assert_eq!(
            parse_audit_events(fixture),
            vec![
                AuditEvent {
                    pid: 700,
                    observed_at: 1_700_000_000_100,
                    path: "/Users/test/.ssh/id_ed25519".into(),
                    access: Access::Read
                },
                AuditEvent {
                    pid: 700,
                    observed_at: 1_700_000_000_200,
                    path: "/Users/test/Library/LaunchAgents/evil.plist".into(),
                    access: Access::Write
                },
            ]
        );
    }

    #[test]
    fn parser_handles_exec_mutation_spaces_and_malformed_input() {
        let fixture = concat!(
            "garbage\n",
            "type=SYSCALL msg=audit(1.0:1): syscall=59 success=yes pid=9\n",
            "type=PATH msg=audit(1.0:1): name=\"/tmp/tool\\x20name\"\n",
            "type=SYSCALL msg=audit(1.0:2): syscall=87 success=yes pid=9\n",
            "type=PATH msg=audit(1.0:2): name=\"/tmp/old\"\n",
        );
        let events = parse_audit_events(fixture);
        assert_eq!(
            events,
            vec![
                AuditEvent {
                    pid: 9,
                    observed_at: 1_000,
                    path: "/tmp/tool name".into(),
                    access: Access::Execute
                },
                AuditEvent {
                    pid: 9,
                    observed_at: 1_000,
                    path: "/tmp/old".into(),
                    access: Access::Write
                },
            ]
        );
    }

    #[test]
    fn event_window_rejects_stale_future_and_recycled_pid_records() {
        let event = AuditEvent {
            pid: 9,
            observed_at: 10_000,
            path: "/tmp/x".into(),
            access: Access::Write,
        };
        assert!(event_matches_process(&event, 9_000, 12_000));
        assert!(!event_matches_process(&event, 10_001, 12_000));
        assert!(!event_matches_process(&event, 9_000, 15_001));
        assert!(!event_matches_process(&event, 9_000, 9_999));
    }
}
