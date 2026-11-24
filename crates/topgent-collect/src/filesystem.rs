//! PID-attributed operating-system filesystem events.
//!
//! Topgent reads a bounded local audit-log tail and never launches or configures
//! an elevated helper. A successful syscall and path must share one audit ID,
//! and the PID must still resolve to a live process identity.

#[cfg(any(target_os = "linux", test))]
use crate::audit::record::{audit_id, audit_time_ms, field, quoted_field};
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

    /// Two limits measured on a Kali guest, 2026-09-02, both permanent under
    /// the current privilege model.
    ///
    /// The kernel counts audit events it dropped, and reading that counter
    /// needs `CAP_AUDIT_CONTROL`: `auditctl -s` answers "You must be root".
    /// Topgent is unprivileged, so it reports no loss accounting at all rather
    /// than a zero it cannot stand behind. By `docs/NORMATIVE-CLAIMS.md` §3.7 a
    /// collector without loss accounting can never claim completeness, and this
    /// one never will.
    ///
    /// The second is subtler and was found by a read that produced nothing. An
    /// audit record names the process that made the syscall. When an agent
    /// reads a file through a short-lived child, `cat` or similar, the record
    /// names the child, and by the time a sweep resolves that pid the child is
    /// gone. The read is real and invisible. Reads the agent performs itself
    /// are attributed correctly.
    fn boundary(&self) -> Option<&'static str> {
        Some(
            "Audit actions are joined to retained process history at event time, including exited children. \
             Read/write describe successful opens or related syscalls, not transferred bytes. Only configured Audit rules and a bounded log tail are read; \
             upstream loss is unmeasured and completeness is not claimed.",
        )
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
            let events = parse_audit_events(&text);
            hand_over(&events, &text, clock.now().0);
            crate::observed::publish_syscalls(&text, clock.now().0);
            let processes = crate::process::snapshot()
                .into_iter()
                .map(|process| (process.pid, (process.started_at.0, process.subject())))
                .collect::<BTreeMap<_, _>>();
            let now = clock.now().0;
            Ok(events
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

/// Every record, attributable or not, for the report to resolve against
/// process history: this sweep's lookup only finds processes still running.
#[cfg(target_os = "linux")]
fn hand_over(events: &[AuditEvent], text: &str, now: u64) {
    use crate::observed::{ActionKind, ObservedAction, Stream, lineage_offset, publish};
    let offset = lineage_offset();
    let programs = crate::audit::exec::programs(text);
    publish(
        Stream::File,
        events
            .iter()
            .map(|event| {
                ObservedAction::new(
                    &event.record,
                    event.pid,
                    event.observed_at,
                    offset,
                    ActionKind::File {
                        path: event.path.clone(),
                        access: event.access,
                    },
                )
            })
            .map(|mut action| {
                action.program = programs.get(&action.record).cloned();
                action
            })
            .collect(),
        now,
    );
    publish(
        Stream::Exec,
        crate::audit::exec::parse(text)
            .into_iter()
            .map(|exec| {
                ObservedAction::new(
                    &exec.record,
                    exec.pid,
                    exec.at,
                    offset,
                    ActionKind::Exec {
                        program: exec.program,
                    },
                )
            })
            .map(|mut action| {
                action.program = programs.get(&action.record).cloned();
                action
            })
            .collect(),
        now,
    );
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
    /// The record id, `seconds.millis:serial`; empty where the source has none.
    record: String,
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
                record: String::new(),
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
    /// Whether a relative name was resolved against the working directory.
    /// Only `AT_FDCWD` says so; any other descriptor is a directory the log
    /// does not name.
    from_cwd: bool,
    cwd: Option<String>,
    parents: Vec<String>,
    names: Vec<String>,
}

#[cfg(any(target_os = "linux", test))]
impl PartialEvent {
    /// Every file the syscall acted on, as an absolute path.
    ///
    /// The kernel writes a `PARENT` record for the directory it looked a name
    /// up in and a separate record for the name itself, often exactly as the
    /// program passed it. The parent is not the file acted on: reporting it
    /// turned `rm b.txt` into a write to the directory, and dropped `b.txt`
    /// for being relative. A relative name is placed under its own parent
    /// record, in order, or under the working directory when the call named
    /// that; with neither, it is not placed anywhere.
    fn targets(self) -> Vec<String> {
        let Self {
            from_cwd,
            cwd,
            parents,
            names,
            ..
        } = self;
        names
            .into_iter()
            .enumerate()
            .filter_map(|(index, name)| {
                if name.starts_with('/') {
                    return Some(name);
                }
                let base = parents
                    .get(index)
                    .or_else(|| parents.first())
                    .filter(|parent| parent.starts_with('/'))
                    .or_else(|| cwd.as_ref().filter(|_| from_cwd))?;
                Some(format!("{}/{name}", base.trim_end_matches('/')))
            })
            .filter(|path| safe_path(path))
            .collect()
    }
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
            event.from_cwd = relative_to_cwd(line);
        } else if line.starts_with("type=CWD ") {
            event.cwd = quoted_field(line, "cwd").filter(|cwd| safe_path(cwd));
        } else if line.starts_with("type=PATH ")
            && let Some(name) = quoted_field(line, "name")
            && !name.is_empty()
            && name.len() <= 4_096
            && !name.chars().any(char::is_control)
        {
            if field(line, "nametype") == Some("PARENT") {
                event.parents.push(name);
            } else {
                event.names.push(name);
            }
        }
    }
    groups
        .into_iter()
        .filter(|(_, event)| event.success)
        .flat_map(|(record, event)| {
            let (pid, observed_at, access) = (event.pid, event.observed_at, event.access);
            event.targets().into_iter().filter_map(move |path| {
                Some(AuditEvent {
                    record: record.clone(),
                    pid: pid?,
                    observed_at: observed_at?,
                    path,
                    access: access?,
                })
            })
        })
        .collect()
}

/// Whether a relative name in this call is relative to the working directory.
///
/// The calls without a directory argument always are. An `*at` call is only
/// when its first argument is `AT_FDCWD`, -100, which audit prints as a 32- or
/// 64-bit register. Any other descriptor names a directory the log does not.
#[cfg(any(target_os = "linux", test))]
fn relative_to_cwd(line: &str) -> bool {
    use crate::audit::Syscall;
    match crate::audit::syscall(line) {
        Some(
            Syscall::Open | Syscall::Execve | Syscall::Rename | Syscall::Unlink | Syscall::Truncate,
        ) => true,
        Some(
            Syscall::Openat
            | Syscall::Execveat
            | Syscall::Unlinkat
            | Syscall::Renameat
            | Syscall::Renameat2,
        ) => {
            matches!(field(line, "a0"), Some("ffffff9c" | "ffffffffffffff9c"))
        }
        _ => false,
    }
}

#[cfg(any(target_os = "linux", test))]
fn syscall_access(line: &str) -> Option<Access> {
    use crate::audit::Syscall;
    let syscall = crate::audit::syscall(line)?;
    let flags = match syscall {
        Syscall::Execve | Syscall::Execveat => return Some(Access::Execute),
        Syscall::Unlink
        | Syscall::Unlinkat
        | Syscall::Rename
        | Syscall::Renameat
        | Syscall::Renameat2
        | Syscall::Truncate => return Some(Access::Write),
        Syscall::Open => field(line, "a1")?,
        Syscall::Openat => field(line, "a2")?,
        Syscall::Close | Syscall::Connect | Syscall::Sendto | Syscall::Sendmsg => return None,
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
                AuditEvent { record: String::new(), pid: 700, observed_at: 1_700_000_000_100, path: r"C:\Users\test\.ssh\id_ed25519".into(), access: Access::Read },
                AuditEvent { record: String::new(), pid: 700, observed_at: 1_700_000_000_200, path: r"C:\Users\test\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\agent.cmd".into(), access: Access::Write },
                AuditEvent { record: String::new(), pid: 701, observed_at: 1_700_000_000_300, path: r"\\server\share\tool.exe".into(), access: Access::Execute },
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
            "type=SYSCALL msg=audit(1700000000.100:41): arch=c000003e syscall=257 success=yes a2=0 pid=700\n",
            "type=PATH msg=audit(1700000000.100:41): name=\"/Users/test/.ssh/id_ed25519\"\n",
            "type=SYSCALL msg=audit(1700000000.200:42): arch=c000003e syscall=257 success=yes a2=241 pid=700\n",
            "type=PATH msg=audit(1700000000.200:42): name=\"/Users/test/Library/LaunchAgents/evil.plist\"\n",
            "type=SYSCALL msg=audit(1700000000.300:43): arch=c000003e syscall=257 success=no a2=0 pid=700\n",
            "type=PATH msg=audit(1700000000.300:43): name=\"/denied\"\n",
        );
        assert_eq!(
            parse_audit_events(fixture),
            vec![
                AuditEvent {
                    record: "1700000000.100:41".into(),
                    pid: 700,
                    observed_at: 1_700_000_000_100,
                    path: "/Users/test/.ssh/id_ed25519".into(),
                    access: Access::Read
                },
                AuditEvent {
                    record: "1700000000.200:42".into(),
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
            "type=SYSCALL msg=audit(1.0:1): arch=c000003e syscall=59 success=yes pid=9\n",
            "type=PATH msg=audit(1.0:1): name=\"/tmp/tool\\x20name\"\n",
            "type=SYSCALL msg=audit(1.0:2): arch=c000003e syscall=87 success=yes pid=9\n",
            "type=PATH msg=audit(1.0:2): name=\"/tmp/old\"\n",
        );
        let events = parse_audit_events(fixture);
        assert_eq!(
            events,
            vec![
                AuditEvent {
                    record: "1.0:1".into(),
                    pid: 9,
                    observed_at: 1_000,
                    path: "/tmp/tool name".into(),
                    access: Access::Execute
                },
                AuditEvent {
                    record: "1.0:2".into(),
                    pid: 9,
                    observed_at: 1_000,
                    path: "/tmp/old".into(),
                    access: Access::Write
                },
            ]
        );
    }

    /// `rm b.txt` on the Kali aarch64 lab, trimmed of fields the parser does
    /// not read. aarch64 numbers `unlinkat` 35; the kernel records the resolved
    /// parent directory and the name exactly as the program passed it.
    const KALI_RM: &str = concat!(
        "type=SYSCALL msg=audit(1790152037.611:89): arch=c00000b7 syscall=35 success=yes exit=0 a0=ffffff9c a1=aaaae121e3f0 a2=0 pid=73360 comm=\"rm\" exe=\"/usr/bin/rm\" key=\"s2probe\"\n",
        "type=CWD msg=audit(1790152037.611:89): cwd=\"/tmp/s2probe.a2Ot\"\n",
        "type=PATH msg=audit(1790152037.611:89): item=0 name=\"/tmp/s2probe.a2Ot\" nametype=PARENT\n",
        "type=PATH msg=audit(1790152037.611:89): item=1 name=\"b.txt\" nametype=DELETE\n",
    );

    /// `mv a.txt b.txt` on the same lab: `renameat2`, 276, two parents and the
    /// two names.
    const KALI_MV: &str = concat!(
        "type=SYSCALL msg=audit(1790152037.611:77): arch=c00000b7 syscall=276 success=yes exit=0 a0=ffffffffffffff9c a1=fffff6d16d85 a2=ffffffffffffff9c pid=73358 comm=\"mv\" exe=\"/usr/bin/mv\" key=\"s2probe\"\n",
        "type=CWD msg=audit(1790152037.611:77): cwd=\"/tmp/s2probe.a2Ot\"\n",
        "type=PATH msg=audit(1790152037.611:77): item=0 name=\"/tmp/s2probe.a2Ot\" nametype=PARENT\n",
        "type=PATH msg=audit(1790152037.611:77): item=1 name=\"/tmp/s2probe.a2Ot\" nametype=PARENT\n",
        "type=PATH msg=audit(1790152037.611:77): item=2 name=\"a.txt\" nametype=DELETE\n",
        "type=PATH msg=audit(1790152037.611:77): item=3 name=\"b.txt\" nametype=CREATE\n",
    );

    fn paths(events: &[AuditEvent]) -> Vec<(&str, Access)> {
        events
            .iter()
            .map(|event| (event.path.as_str(), event.access))
            .collect()
    }

    /// The delete names the file, not a write to the directory holding it.
    #[test]
    fn an_aarch64_delete_names_the_deleted_file() {
        assert_eq!(
            paths(&parse_audit_events(KALI_RM)),
            vec![("/tmp/s2probe.a2Ot/b.txt", Access::Write)]
        );
    }

    #[test]
    fn an_aarch64_rename_names_both_files_and_neither_directory() {
        let events = parse_audit_events(KALI_MV);
        let mut seen = paths(&events);
        seen.sort_unstable();
        assert_eq!(
            seen,
            vec![
                ("/tmp/s2probe.a2Ot/a.txt", Access::Write),
                ("/tmp/s2probe.a2Ot/b.txt", Access::Write),
            ]
        );
    }

    /// aarch64 `fsync` is 82, which is `rename` on x86-64; x86-64 `clone` is
    /// 56, which is `openat` on aarch64. Neither touches a file's contents.
    #[test]
    fn a_syscall_number_is_read_for_the_architecture_that_recorded_it() {
        let fixture = concat!(
            "type=SYSCALL msg=audit(1.0:1): arch=c00000b7 syscall=82 success=yes pid=9\n",
            "type=PATH msg=audit(1.0:1): item=0 name=\"/home/u/.bashrc\" nametype=NORMAL\n",
            "type=SYSCALL msg=audit(1.0:2): arch=c000003e syscall=56 success=yes a2=0 pid=9\n",
            "type=PATH msg=audit(1.0:2): item=0 name=\"/home/u/.ssh/id_rsa\" nametype=NORMAL\n",
            "type=SYSCALL msg=audit(1.0:3): arch=c00000b7 syscall=56 success=yes a2=0 pid=9\n",
            "type=PATH msg=audit(1.0:3): item=0 name=\"/home/u/.ssh/id_ed25519\" nametype=NORMAL\n",
        );
        assert_eq!(
            paths(&parse_audit_events(fixture)),
            vec![("/home/u/.ssh/id_ed25519", Access::Read)]
        );
    }

    /// A name relative to a directory descriptor, with no parent record to
    /// resolve it against, cannot be placed anywhere, so it is not guessed.
    #[test]
    fn a_relative_name_without_a_known_directory_is_not_guessed() {
        let fixture = concat!(
            "type=SYSCALL msg=audit(1.0:1): arch=c00000b7 syscall=56 success=yes a0=5 a2=0 pid=9\n",
            "type=CWD msg=audit(1.0:1): cwd=\"/home/u\"\n",
            "type=PATH msg=audit(1.0:1): item=0 name=\"id_rsa\" nametype=NORMAL\n",
        );
        assert!(parse_audit_events(fixture).is_empty());
        // The same name opened relative to the working directory is placed.
        let cwd = fixture.replace("a0=5", "a0=ffffff9c");
        assert_eq!(
            paths(&parse_audit_events(&cwd)),
            vec![("/home/u/id_rsa", Access::Read)]
        );
    }

    #[test]
    fn event_window_rejects_stale_future_and_recycled_pid_records() {
        let event = AuditEvent {
            record: String::new(),
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
