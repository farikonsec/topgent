//! The helper's line format.
//!
//! Separate from the accounting because it is the trust boundary: every line
//! is parsed as hostile, bounded and checked before anything else sees it.

use serde_json::Value;
use topgent_facts::UnixMillis;

use crate::audit::names::named;
use crate::audit_syscalls::{AuditPath, CallSource, SyscallEvent, socket_address};

/// Longest line read from the helper. A `sys` line carries two paths of up
/// to 511 bytes each, which in the worst case of all-replacement characters
/// is about 3,100 bytes of UTF-8, plus an address; an `exec` line up to
/// 12,000 bytes of arguments.
const MAX_LINE: usize = 16_384;
/// Longest syscall path kept.
const MAX_CALL_PATH: usize = 1_024;
/// Longest socket address kept, as hex: `sizeof(struct sockaddr_storage)`.
const MAX_SADDR_HEX: usize = 256;
/// Most ancestors kept with a syscall.
const MAX_ANCESTORS: usize = 16;
/// Most exec arguments kept, and the longest one.
const MAX_ARGS: usize = 64;
const MAX_ARG: usize = 4_096;
/// Longest process name kept.
const MAX_NAME: usize = 64;
/// Longest program path kept.
const MAX_PATH: usize = 1_024;
/// Longest note kept from a health line.
const MAX_NOTE: usize = 300;

/// What happened to a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleKind {
    /// It was created by `parent`.
    Fork {
        /// The process that created it.
        parent: u32,
    },
    /// It replaced its program.
    Exec,
    /// The kernel renamed it, as `exec` does with the new program's name.
    Rename,
    /// It ended.
    Exit {
        /// Its exit status, when the sensor's source reports one. The eBPF
        /// source does not; the process connector does.
        code: Option<u32>,
    },
}

/// One lifecycle event, as the helper reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleEvent {
    /// What happened.
    pub kind: LifecycleKind,
    /// The process.
    pub pid: u32,
    /// Its kernel start time, when the helper could read it.
    pub started_at: Option<UnixMillis>,
    /// Its name, when readable.
    pub name: Option<String>,
    /// Its program's file name, without the path.
    pub program: Option<String>,
    /// Its program's full path, as handed to exec, when the sensor read it
    /// in the kernel at the moment of the exec (the eBPF source). Always
    /// absolute; a relative path is not kept.
    pub path: Option<String>,
    /// The pid namespace the kernel placed it in at the moment of the event,
    /// when that was the host's (the eBPF source). Absent is not a claim of
    /// a container: it means the sensor did not establish it.
    pub pid_namespace: Option<u64>,
    /// The real user id it ran as, when the sensor read it in the kernel
    /// (the eBPF source).
    pub uid: Option<u32>,
    /// The container it ran in, by its full id, when the sensor named one
    /// from the event's own cgroup (the eBPF source). Absent is no claim
    /// either way.
    pub container: Option<String>,
    /// For an exec, its arguments, when the sensor read all of them (the
    /// eBPF source). Kept in memory for rule evaluation only, as Audit's
    /// are: nothing that stores or reports an event may keep them.
    pub argv: Option<Vec<String>>,
    /// For an exec, the audit login id, when the eBPF source read it.
    pub loginuid: Option<u32>,
    /// Whether the process had a controlling terminal when observed.
    pub tty: Option<bool>,
    /// For an exec, the working directory it ran in, when the eBPF source
    /// walked it whole. Absolute, as the process saw it from its own root.
    pub cwd: Option<String>,
    /// When it happened.
    pub at: UnixMillis,
}

/// The helper's own account of what it could not deliver.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HelperHealth {
    /// Which run of the helper this is.
    pub session: String,
    /// Messages the kernel numbered and the socket never delivered.
    pub lost: u64,
    /// Times the socket reported its buffer full.
    pub overflows: u64,
    /// When the helper wrote it, by its own wall clock.
    pub at: u64,
    /// Where its events come from: `ebpf` or `connector` (the kernel's
    /// process connector). `None` from a helper that does not say.
    pub source: Option<String>,
    /// Why the helper is not using eBPF, when it is not.
    pub note: Option<String>,
    /// How many rule syscalls the helper is tracing: `Some(0)` or `None`
    /// means it delivers none, and the Audit log stays their source.
    pub syscalls: Option<u64>,
    /// Syscalls its source dropped since it started.
    pub syscalls_lost: Option<u64>,
}

/// One syscall the helper saw, as a behaviour-rule event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensorCall {
    /// The call. Its `at` is in the start-time base, as every helper line
    /// is, and its `record` is empty until it is handed over.
    pub event: SyscallEvent,
    /// The helper's own number for it, in order within its session.
    pub seq: u64,
}

/// One line from the helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// A lifecycle event.
    Event(LifecycleEvent),
    /// A health report.
    Health(HelperHealth),
    /// A syscall a behaviour rule may read.
    Syscall(Box<SensorCall>),
}

fn text(value: &Value, name: &str) -> Option<String> {
    let raw = value.get(name)?.as_str()?;
    let clean: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME)
        .collect();
    let base = clean.rsplit('/').next().unwrap_or(&clean).to_owned();
    (!base.is_empty()).then_some(base)
}

/// A full program path: absolute, bounded, no control characters.
fn path(value: &Value, name: &str) -> Option<String> {
    let raw = value.get(name)?.as_str()?;
    if !raw.starts_with('/') || raw.chars().count() > MAX_PATH || raw.chars().any(char::is_control)
    {
        return None;
    }
    Some(raw.to_owned())
}

/// Free text for a person to read: bounded, control characters removed.
fn note(value: &Value, name: &str) -> Option<String> {
    let clean: String = value
        .get(name)?
        .as_str()?
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_NOTE)
        .collect();
    (!clean.trim().is_empty()).then_some(clean)
}

/// A path a syscall named: absolute or relative (the probe cannot read the
/// working directory), bounded, no control characters.
fn call_path(value: &Value, name: &str) -> Option<String> {
    let raw = value.get(name)?.as_str()?;
    if raw.is_empty() || raw.chars().count() > MAX_CALL_PATH || raw.chars().any(char::is_control) {
        return None;
    }
    Some(raw.to_owned())
}

/// The kinds Audit's `PATH` records give the paths of each call, so the
/// rules read a sensor call exactly as they read an Audit one.
fn nametypes(call: &str) -> (&'static str, &'static str) {
    match call {
        "unlink" | "unlinkat" | "rmdir" => ("DELETE", ""),
        "mkdir" | "mkdirat" => ("CREATE", ""),
        c if c.starts_with("rename") => ("DELETE", "CREATE"),
        c if c.starts_with("link") => ("NORMAL", "CREATE"),
        // The link made, then what it points to: no Audit PATH kind names
        // a target, so it has its own, which no reader takes for a file.
        c if c.starts_with("symlink") => ("CREATE", "TARGET"),
        _ => ("NORMAL", ""),
    }
}

/// `AT_FDCWD` as the low 32 bits of a register: a directory argument meaning
/// "the working directory".
const AT_FDCWD: u64 = 0xffff_ff9c;

/// Whether a call's path (`which` 0) or second path (1) is looked up from
/// the working directory when relative: always for the calls with no
/// directory argument, and for the `*at` calls when that argument is
/// `AT_FDCWD`. A symbolic link's target is text, never looked up.
fn under_cwd(call: &str, which: usize, args: &[Option<u64>; 4]) -> bool {
    let dirfd = match (call, which) {
        ("symlink" | "symlinkat", 1) => return false,
        ("symlinkat", 0) => 1,
        ("renameat" | "renameat2" | "linkat", 1) => 2,
        (c, _) if c.ends_with("at") || c == "openat2" => 0,
        _ => return true,
    };
    args.get(dirfd)
        .copied()
        .flatten()
        .is_some_and(|fd| fd & 0xffff_ffff == AT_FDCWD)
}

/// A path under `base` unless it is already absolute, as Audit's are placed
/// under their `CWD` record.
fn absolute(name: &str, base: Option<&str>) -> String {
    match base {
        Some(base) if !name.starts_with('/') => {
            format!("{}/{name}", base.trim_end_matches('/'))
        }
        _ => name.to_owned(),
    }
}

/// A call's ancestors: `[[pid, name], …]`, nearest first. An entry that is
/// not a pid with a name or null ends the list there: a chain with a gap in
/// it would put the wrong process in the gap.
fn ancestors(value: &Value) -> Vec<(u32, Option<String>)> {
    let Some(list) = value.get("anc").and_then(Value::as_array) else {
        return Vec::new();
    };
    list.iter()
        .take(MAX_ANCESTORS)
        .map_while(|entry| {
            let pair = entry.as_array()?;
            let pid = u32::try_from(pair.first()?.as_u64()?)
                .ok()
                .filter(|p| *p > 0)?;
            let name = pair.get(1).and_then(Value::as_str).map(|n| {
                n.chars()
                    .filter(|c| !c.is_control())
                    .take(MAX_NAME)
                    .collect()
            });
            Some((pid, name))
        })
        .collect()
}

/// A `sys` line: one call, read as hostile as every other line.
fn syscall(value: &Value, at: UnixMillis) -> Option<SensorCall> {
    let call = named(value.get("call")?.as_str()?)?;
    let ret = value.get("ret")?.as_i64()?;
    let mut args = [None; 4];
    if let Some(given) = value.get("args").and_then(Value::as_array) {
        for (slot, arg) in args.iter_mut().zip(given) {
            *slot = arg.as_u64();
        }
    }
    let (first, second) = nametypes(call);
    // Sent only with a call that had a relative path.
    let cwd = path(value, "cwd");
    let paths = [("path", first, 0), ("path2", second, 1)]
        .into_iter()
        .filter(|(_, kind, _)| !kind.is_empty())
        .filter_map(|(key, kind, which)| {
            let raw = call_path(value, key)?;
            let base = cwd.as_deref().filter(|_| under_cwd(call, which, &args));
            Some(AuditPath {
                name: absolute(&raw, base),
                raw,
                nametype: kind.to_owned(),
            })
        })
        .collect();
    let sockaddr = value
        .get("saddr")
        .and_then(Value::as_str)
        .filter(|hex| hex.len() <= MAX_SADDR_HEX)
        .and_then(socket_address);
    Some(SensorCall {
        event: SyscallEvent {
            source: CallSource::Ebpf,
            record: String::new(),
            at: at.0,
            pid: pid(value, "pid")?,
            ppid: pid(value, "ppid"),
            syscall: call,
            // As Audit's `success`: a negative result is a failure, and so
            // is `EINPROGRESS`, which the rules test for by value.
            success: ret >= 0,
            exit: Some(ret),
            args,
            uid: value
                .get("uid")
                .and_then(Value::as_u64)
                .and_then(|uid| u32::try_from(uid).ok()),
            auid: value
                .get("auid")
                .and_then(Value::as_u64)
                .and_then(|uid| u32::try_from(uid).ok()),
            tty: value
                .get("tty")
                .and_then(Value::as_u64)
                .map(|tty| if tty == 0 { "0" } else { "1" }.to_owned()),
            comm: text(value, "name"),
            exe: None,
            cwd,
            paths,
            sockaddr,
            argv: Vec::new(),
            pid_namespace: value
                .get("pidns")
                .and_then(Value::as_u64)
                .filter(|ns| *ns > 0),
            socket: value
                .get("sock")
                .and_then(Value::as_array)
                .and_then(|kind| {
                    let byte = |i: usize| u8::try_from(kind.get(i)?.as_u64()?).ok();
                    Some((byte(0)?, byte(1)?, byte(2)?))
                }),
            capabilities: value.get("cap").and_then(Value::as_array).and_then(|c| {
                // Two u64 as decimal strings; a JSON number loses the top bits.
                let word = |i: usize| c.get(i)?.as_str()?.parse::<u64>().ok();
                Some((word(0)?, word(1)?))
            }),
            ancestors: ancestors(value),
            container: container(value),
        },
        seq: value.get("seq")?.as_u64()?,
    })
}

/// A full container id, exactly 64 hex digits, or none.
fn container(value: &Value) -> Option<String> {
    value
        .get("ctr")
        .and_then(Value::as_str)
        .filter(|id| crate::container::valid_container_id(id))
        .map(str::to_ascii_lowercase)
}

/// Exec arguments: every one a string within bounds, or none at all. A list
/// with one bad entry is not trimmed into a different command line.
fn argv(value: &Value) -> Option<Vec<String>> {
    let list = value.get("argv")?.as_array()?;
    if list.len() > MAX_ARGS {
        return None;
    }
    list.iter()
        .map(|arg| {
            arg.as_str()
                .filter(|a| a.chars().count() <= MAX_ARG)
                .map(str::to_owned)
        })
        .collect()
}

fn pid(value: &Value, name: &str) -> Option<u32> {
    u32::try_from(value.get(name)?.as_u64()?)
        .ok()
        .filter(|pid| *pid > 0)
}

/// Reads one helper line, or nothing if it is not one this build understands.
#[must_use]
pub fn parse_line(line: &str) -> Option<Line> {
    if line.len() > MAX_LINE {
        return None;
    }
    let value: Value = serde_json::from_str(line).ok()?;
    let at = UnixMillis(value.get("at")?.as_u64()?);
    let kind = match value.get("e")?.as_str()? {
        "health" => {
            return Some(Line::Health(HelperHealth {
                session: text(&value, "session")?,
                lost: value.get("lost")?.as_u64()?,
                overflows: value.get("overflows")?.as_u64()?,
                at: at.0,
                source: value
                    .get("source")
                    .and_then(Value::as_str)
                    .filter(|source| matches!(*source, "ebpf" | "connector"))
                    .map(str::to_owned),
                note: note(&value, "note"),
                syscalls: value.get("syscalls").and_then(Value::as_u64),
                syscalls_lost: value.get("sys_lost").and_then(Value::as_u64),
            }));
        }
        "sys" => return syscall(&value, at).map(|call| Line::Syscall(Box::new(call))),
        "fork" => LifecycleKind::Fork {
            parent: pid(&value, "ppid")?,
        },
        "exec" => LifecycleKind::Exec,
        "comm" => LifecycleKind::Rename,
        // A code, when present, must be a real one: a line that sends a
        // malformed code is refused, not read as "no code".
        "exit" => LifecycleKind::Exit {
            code: match value.get("code") {
                None => None,
                Some(code) => Some(u32::try_from(code.as_u64()?).ok()?),
            },
        },
        _ => return None,
    };
    Some(Line::Event(LifecycleEvent {
        kind,
        pid: pid(&value, "pid")?,
        started_at: value.get("start").and_then(Value::as_u64).map(UnixMillis),
        name: text(&value, "name"),
        program: text(&value, "program"),
        path: path(&value, "path"),
        pid_namespace: value
            .get("pidns")
            .and_then(Value::as_u64)
            .filter(|ns| *ns > 0),
        uid: value
            .get("uid")
            .and_then(Value::as_u64)
            .and_then(|uid| u32::try_from(uid).ok()),
        container: container(&value),
        argv: argv(&value).filter(|_| matches!(kind, LifecycleKind::Exec)),
        loginuid: matches!(kind, LifecycleKind::Exec)
            .then(|| value.get("auid").and_then(Value::as_u64))
            .flatten()
            .and_then(|uid| u32::try_from(uid).ok()),
        tty: matches!(kind, LifecycleKind::Exec)
            .then(|| value.get("tty").and_then(Value::as_u64))
            .flatten()
            .map(|tty| tty != 0),
        cwd: path(&value, "cwd").filter(|_| matches!(kind, LifecycleKind::Exec)),
        at,
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::indexing_slicing)]

    use super::{LifecycleKind, Line, parse_line};
    use topgent_facts::UnixMillis;

    #[test]
    fn each_line_kind_is_read_with_its_fields() {
        let fork = parse_line(
            r#"{"e":"fork","pid":201,"ppid":100,"start":1790000000010,"name":"sh","at":1790000000011}"#,
        );
        let Some(Line::Event(fork)) = fork else {
            unreachable!("{fork:?}")
        };
        assert_eq!(fork.kind, LifecycleKind::Fork { parent: 100 });
        assert_eq!(fork.started_at, Some(UnixMillis(1_790_000_000_010)));
        assert_eq!(fork.name.as_deref(), Some("sh"));

        let exec =
            parse_line(r#"{"e":"exec","pid":201,"name":"cat","program":"/usr/bin/cat","at":2}"#);
        assert!(
            matches!(
                exec,
                Some(Line::Event(ref e)) if e.kind == LifecycleKind::Exec
                    && e.program.as_deref() == Some("cat")
            ),
            "a path is cut to its file name: {exec:?}"
        );

        let rename = parse_line(r#"{"e":"comm","pid":201,"name":"cat","at":2}"#);
        assert!(matches!(
            rename,
            Some(Line::Event(ref e)) if e.kind == LifecycleKind::Rename
                && e.name.as_deref() == Some("cat")
        ));

        let exit = parse_line(r#"{"e":"exit","pid":201,"code":256,"at":3}"#);
        assert!(matches!(
            exit,
            Some(Line::Event(ref e)) if e.kind == LifecycleKind::Exit { code: Some(256) }
                && e.started_at.is_none()
        ));

        let health = parse_line(r#"{"e":"health","session":"s1","lost":3,"overflows":1,"at":4}"#);
        assert!(matches!(
            health,
            Some(Line::Health(ref h)) if h.lost == 3 && h.overflows == 1 && h.source.is_none()
        ));
    }

    #[test]
    fn the_ebpf_source_adds_a_full_path_and_may_omit_the_exit_code() {
        let exec = parse_line(
            r#"{"e":"exec","pid":7,"name":"nmap","program":"nmap","path":"/usr/bin/nmap","at":1}"#,
        );
        assert!(
            matches!(
                exec,
                Some(Line::Event(ref e)) if e.path.as_deref() == Some("/usr/bin/nmap")
                    && e.program.as_deref() == Some("nmap")
            ),
            "{exec:?}"
        );
        for kept_out in [r#""./run.sh""#, r#""/tmp/a\u0007b""#] {
            let line = format!(r#"{{"e":"exec","pid":7,"path":{kept_out},"at":1}}"#);
            assert!(
                matches!(parse_line(&line), Some(Line::Event(ref e)) if e.path.is_none()),
                "{line}"
            );
        }
        let placed = parse_line(r#"{"e":"exec","pid":7,"pidns":4026531836,"at":1}"#);
        assert!(matches!(
            placed,
            Some(Line::Event(ref e)) if e.pid_namespace == Some(4_026_531_836)
        ));
        for odd in ["0", "-1", r#""host""#] {
            let line = format!(r#"{{"e":"exec","pid":7,"pidns":{odd},"at":1}}"#);
            assert!(
                matches!(parse_line(&line), Some(Line::Event(ref e)) if e.pid_namespace.is_none()),
                "{line}"
            );
        }
        let exit = parse_line(r#"{"e":"exit","pid":7,"at":2}"#);
        assert!(matches!(
            exit,
            Some(Line::Event(ref e)) if e.kind == LifecycleKind::Exit { code: None }
        ));
        assert!(
            parse_line(r#"{"e":"exit","pid":7,"code":"zero","at":2}"#).is_none(),
            "a malformed code is refused, not read as no code"
        );
    }

    #[test]
    fn health_says_which_kernel_source_and_why() {
        let ebpf = parse_line(
            r#"{"e":"health","session":"s","lost":0,"overflows":0,"at":1,"source":"ebpf"}"#,
        );
        assert!(matches!(
            ebpf,
            Some(Line::Health(ref h)) if h.source.as_deref() == Some("ebpf") && h.note.is_none()
        ));
        let fallback = parse_line(
            r#"{"e":"health","session":"s","lost":0,"overflows":0,"at":1,"source":"connector","note":"this build of Topgent carries no eBPF probe"}"#,
        );
        assert!(matches!(
            fallback,
            Some(Line::Health(ref h)) if h.source.as_deref() == Some("connector")
                && h.note.as_deref() == Some("this build of Topgent carries no eBPF probe")
        ));
        let unknown = parse_line(
            r#"{"e":"health","session":"s","lost":0,"overflows":0,"at":1,"source":"magic"}"#,
        );
        assert!(
            matches!(unknown, Some(Line::Health(ref h)) if h.source.is_none()),
            "an unknown source is not repeated"
        );
    }

    fn call(line: &str) -> crate::process_events::SensorCall {
        match parse_line(line) {
            Some(Line::Syscall(call)) => *call,
            other => unreachable!("{line}: {other:?}"),
        }
    }

    #[test]
    fn a_sensor_syscall_reads_as_the_audit_event_the_rules_know() {
        let open = call(
            r#"{"e":"sys","call":"openat","pid":7,"uid":0,"ret":3,"args":[18446744073709551516,1,0,0],"path":"/etc/shadow","name":"cat","seq":4,"at":1000}"#,
        );
        let event = &open.event;
        assert_eq!(event.syscall, "openat");
        assert_eq!((event.pid, event.exit, event.success), (7, Some(3), true));
        assert_eq!(event.args[2], Some(0), "flags of zero are O_RDONLY, kept");
        assert_eq!(event.paths.len(), 1);
        assert_eq!(event.paths[0].name, "/etc/shadow");
        assert_eq!(event.paths[0].nametype, "NORMAL");
        assert_eq!(event.comm.as_deref(), Some("cat"));
        assert_eq!(event.source.as_str(), "ebpf");
        assert_eq!((event.auid, event.cwd.as_deref()), (None, None));
        assert_eq!(open.seq, 4);

        let rename = call(
            r#"{"e":"sys","call":"renameat2","pid":7,"ret":0,"path":"/tmp/a","path2":"/tmp/.b","seq":5,"at":1}"#,
        );
        let kinds: Vec<_> = rename
            .event
            .paths
            .iter()
            .map(|p| p.nametype.as_str())
            .collect();
        assert_eq!(
            kinds,
            ["DELETE", "CREATE"],
            "old then new, as Audit has them"
        );

        let failed = call(
            r#"{"e":"sys","call":"connect","pid":7,"ret":-115,"saddr":"02001f907f000001","seq":6,"at":1}"#,
        );
        assert!(
            !failed.event.success,
            "EINPROGRESS is not success, as in Audit"
        );
        let peer = failed.event.sockaddr.expect("an address");
        assert_eq!(
            (peer.family, peer.host.as_str(), peer.port),
            (2, "127.0.0.1", 8080)
        );

        let relative = call(
            r#"{"e":"sys","call":"openat","pid":7,"ret":3,"path":"notes.txt","seq":7,"at":1}"#,
        );
        assert_eq!(
            relative.event.paths[0].name, "notes.txt",
            "kept relative, not guessed"
        );

        let placed = call(
            r#"{"e":"sys","call":"openat","pid":7,"ret":3,"args":[18446744073709551516,0,0,0],"path":"notes.txt","cwd":"/home/user/a b","seq":7,"at":1}"#,
        );
        assert_eq!(placed.event.paths[0].name, "/home/user/a b/notes.txt");
        assert_eq!(placed.event.paths[0].raw, "notes.txt");
        assert_eq!(placed.event.cwd.as_deref(), Some("/home/user/a b"));
        let from_fd = call(
            r#"{"e":"sys","call":"openat","pid":7,"ret":3,"args":[5,0,0,0],"path":"notes.txt","cwd":"/home/user","seq":7,"at":1}"#,
        );
        assert_eq!(
            from_fd.event.paths[0].name, "notes.txt",
            "relative to a directory descriptor, not the working directory"
        );
        let link = call(
            r#"{"e":"sys","call":"symlink","pid":7,"ret":0,"args":[0,0,0,0],"path":"l","path2":"../t","cwd":"/tmp","seq":7,"at":1}"#,
        );
        let names: Vec<_> = link.event.paths.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            ["/tmp/l", "../t"],
            "a link's target stays as written"
        );

        let udp =
            call(r#"{"e":"sys","call":"connect","pid":7,"ret":0,"sock":[2,2,0],"seq":8,"at":1}"#);
        assert_eq!(udp.event.socket, Some((2, 2, 0)));
        let odd =
            call(r#"{"e":"sys","call":"connect","pid":7,"ret":0,"sock":[2,300,0],"seq":9,"at":1}"#);
        assert_eq!(odd.event.socket, None, "a kind out of range is not guessed");
    }

    #[test]
    fn hostile_sensor_syscalls_are_refused_or_trimmed() {
        for line in [
            r#"{"e":"sys","call":"reboot","pid":7,"ret":0,"seq":1,"at":1}"#,
            r#"{"e":"sys","call":"openat","pid":7,"seq":1,"at":1}"#,
            r#"{"e":"sys","call":"openat","pid":0,"ret":0,"seq":1,"at":1}"#,
            r#"{"e":"sys","call":"openat","pid":7,"ret":0,"at":1}"#,
        ] {
            assert!(parse_line(line).is_none(), "{line}");
        }
        let odd = call(
            r#"{"e":"sys","call":"openat","pid":7,"ret":0,"path":"/tmp/a\u001bb","saddr":"zz","seq":1,"at":1}"#,
        );
        assert!(
            odd.event.paths.is_empty(),
            "a control character drops the path"
        );
        assert!(odd.event.sockaddr.is_none(), "an address that is not hex");
        let long = call(&format!(
            r#"{{"e":"sys","call":"openat","pid":7,"ret":0,"path":"/{}","seq":1,"at":1}}"#,
            "a".repeat(2_000)
        ));
        assert!(long.event.paths.is_empty(), "an oversized path");
    }

    #[test]
    fn a_container_is_named_only_by_a_full_id() {
        let id = "AB".repeat(32);
        let ctr = |value: &str| match parse_line(&format!(
            r#"{{"e":"exec","pid":7,"ctr":{value},"at":1}}"#
        )) {
            Some(Line::Event(event)) => event.container,
            other => unreachable!("{other:?}"),
        };
        assert_eq!(ctr(&format!(r#""{id}""#)), Some(id.to_ascii_lowercase()));
        assert_eq!(
            ctr(r#""abcdef012345""#),
            None,
            "a short id is not a full one"
        );
        assert_eq!(ctr(&format!(r#""{}zz""#, "a".repeat(62))), None);
        let call = call(&format!(
            r#"{{"e":"sys","call":"openat","pid":7,"ret":3,"ctr":"{id}","seq":1,"at":1}}"#
        ));
        assert_eq!(call.event.container, Some(id.to_ascii_lowercase()));
    }

    #[test]
    fn exec_arguments_are_kept_whole_or_not_at_all() {
        let argv = |line: &str| match parse_line(line) {
            Some(Line::Event(event)) => event.argv,
            other => unreachable!("{line}: {other:?}"),
        };
        assert_eq!(
            argv(r#"{"e":"exec","pid":7,"argv":["cat","/etc/shadow"],"at":1}"#),
            Some(vec!["cat".to_owned(), "/etc/shadow".to_owned()])
        );
        assert_eq!(
            argv(r#"{"e":"exec","pid":7,"argv":["cat",5],"at":1}"#),
            None
        );
        assert_eq!(argv(r#"{"e":"exec","pid":7,"argv":"cat","at":1}"#), None);
        let many = format!(
            r#"{{"e":"exec","pid":7,"argv":[{}],"at":1}}"#,
            vec!["\"a\""; 65].join(",")
        );
        assert_eq!(argv(&many), None, "more than 64");
        assert_eq!(
            argv(r#"{"e":"exit","pid":7,"argv":["cat"],"at":1}"#),
            None,
            "only an exec has arguments"
        );
    }

    #[test]
    fn a_calls_ancestry_stops_at_the_first_entry_it_cannot_trust() {
        let anc = |list: &str| {
            call(&format!(
                r#"{{"e":"sys","call":"openat","pid":7,"ret":3,"anc":{list},"seq":1,"at":1}}"#
            ))
            .event
            .ancestors
        };
        assert_eq!(
            anc(r#"[[6,"sudo"],[5,null],[1,"systemd"]]"#),
            [
                (6, Some("sudo".to_owned())),
                (5, None),
                (1, Some("systemd".to_owned()))
            ]
        );
        assert_eq!(
            anc(r#"[[6,"sudo"],["x","sh"],[1,"systemd"]]"#),
            [(6, Some("sudo".to_owned()))]
        );
        assert_eq!(anc(r#"[[0,"swapper"]]"#), []);
        assert_eq!(anc(r#""sudo""#), []);
        let long: Vec<String> = (2..40).map(|p| format!(r#"[{p},"sh"]"#)).collect();
        assert_eq!(anc(&format!("[{}]", long.join(","))).len(), 16, "bounded");
    }

    #[test]
    fn health_says_how_many_syscalls_the_helper_traces() {
        let health = parse_line(
            r#"{"e":"health","session":"s","lost":0,"overflows":0,"at":1,"source":"ebpf","syscalls":29,"sys_lost":2}"#,
        );
        assert!(matches!(
            health,
            Some(Line::Health(ref h)) if h.syscalls == Some(29) && h.syscalls_lost == Some(2)
        ));
    }

    #[test]
    fn hostile_lines_are_refused() {
        for line in [
            "not json",
            r#"{"e":"fork","pid":0,"ppid":1,"at":1}"#,
            r#"{"e":"fork","pid":5000000000,"ppid":1,"at":1}"#,
            r#"{"e":"fork","pid":5,"at":1}"#,
            r#"{"e":"teleport","pid":5,"at":1}"#,
            r#"{"e":"exit","pid":5,"code":1}"#,
        ] {
            assert!(parse_line(line).is_none(), "{line}");
        }
        let long = format!(
            r#"{{"e":"exec","pid":5,"at":1,"name":"{}"}}"#,
            "x".repeat(17_000)
        );
        assert!(parse_line(&long).is_none(), "an oversized line");
        let control = parse_line(r#"{"e":"exec","pid":5,"at":1,"name":"a\u001b[31mb"}"#);
        assert!(
            matches!(
                control,
                Some(Line::Event(ref e)) if e.name.as_deref() == Some("a[31mb")
            ),
            "control characters are stripped: {control:?}"
        );
    }
}
