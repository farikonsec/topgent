//! The preferred source: Topgent's own eBPF probe.
//!
//! Everything a line says is read in the kernel at the moment of the event:
//! the creator of a new process, the name, the full path handed to exec. None
//! of it depends on `/proc` still holding the process, so a process that
//! lives for a millisecond is described as fully as one that lives for a day.
//! Only the start time, which is the key every process is filed under, is
//! still read from `/proc`, so that events and sweeps file a process under
//! the same key.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};
use topgent_collect::process::boot_seconds;
use topgent_ebpf::{
    ArgvRecord, CwdRecord, Kind, Namespace, Probe, ProcessEvent, SocketKind, SyscallRecord, text,
};

use crate::cgroups::Cgroups;
use crate::clock::{event_ms, now_ms};
use crate::line::{Happened, Known, add, ancestry, describe, forget};
use crate::output::Output;

/// How long to wait between drains of the ring buffer. The buffer holds
/// about 3,400 events, so this keeps up with over 150,000 a second.
const POLL: Duration = Duration::from_millis(20);

pub(crate) fn run(mut probe: Probe) -> ExitCode {
    let boot = boot_seconds();
    let host = probe.host_pid_namespace();
    let mut out = Output::new("ebpf", None);
    let traced = u64::try_from(probe.traced().len()).unwrap_or(0);
    // Topgent's own calls are not reported: it reads credentials and
    // configuration to inventory them, which are the very reads the rules
    // flag. Only these two processes; anything they start is reported.
    let own = [std::process::id(), std::os::unix::process::parent_id()];
    let mut known: HashMap<u32, Known> = HashMap::new();
    let mut events = Vec::new();
    let mut calls = Vec::new();
    let mut seq = 0_u64;
    // Each exec's arguments, which arrive just ahead of it, until it comes.
    let mut argv_records = Vec::new();
    let mut arguments: HashMap<u32, Vec<String>> = HashMap::new();
    let mut cwds = Cwds::default();
    // Processes that ended this poll, forgotten only after its calls are
    // written: a process's last calls are drained with its exit.
    let mut ended = Vec::new();
    let mut cgroups = Cgroups::default();
    // Events of a kind this build does not know: a build fault, counted as
    // lost rather than dropped silently.
    let mut unknown = 0_u64;
    loop {
        // Syscalls are drained first and written last. A call drained now
        // was made after everything its process did before it, and all of
        // that is in the event buffer by the time it is drained next, so
        // every call's line follows its process's fork and exec.
        probe.drain_syscalls(&mut calls);
        probe.drain(&mut events);
        probe.take_argv(&mut argv_records);
        for record in argv_records.drain(..) {
            remember_argv(&mut arguments, &record);
        }
        cwds.take(&mut probe);
        for event in events.drain(..) {
            let exec_cwd = cwds.for_event(&event);
            let argv = match event.kind() {
                Some(Kind::Exec) => arguments.remove(&event.pid),
                Some(Kind::Exit) => {
                    arguments.remove(&event.pid);
                    ended.push(event.pid);
                    None
                }
                _ => None,
            };
            let Some(happened) = happened(&event, host, argv) else {
                unknown = unknown.saturating_add(1);
                continue;
            };
            // The probe stamps events on the boot clock, which is already
            // the base process start times use.
            let at = boot.map_or_else(now_ms, |boot| event_ms(boot, event.boot_ns, 0));
            let mut line = describe(happened, &mut known, boot, at);
            if matches!(event.kind(), Some(Kind::Exec)) {
                // The uid the new program runs as, read in the kernel.
                add(&mut line, "uid", event.uid);
                if let Some(cwd) = exec_cwd {
                    add(&mut line, "cwd", cwd);
                }
            }
            if matches!(event.kind(), Some(Kind::Spawn | Kind::Exec))
                && let Some(id) = cgroups.container(event.cgroup)
            {
                add(&mut line, "ctr", id);
            }
            if !out.event(&line) {
                return ExitCode::SUCCESS;
            }
        }
        for record in calls.drain(..) {
            if own.contains(&record.pid) {
                continue;
            }
            let Some(call) = probe.syscall_name(record.call) else {
                unknown = unknown.saturating_add(1);
                continue;
            };
            seq = seq.saturating_add(1);
            let at = boot.map_or_else(now_ms, |boot| event_ms(boot, record.boot_ns, 0));
            let mut line = syscall_line(&record, call, host, seq, at);
            if let Some(cwd) = cwds.for_call(&record) {
                add(&mut line, "cwd", cwd);
            }
            place(&mut line, &record, &mut cgroups, &mut known);
            if !out.event(&line) {
                return ExitCode::SUCCESS;
            }
        }
        for pid in ended.drain(..) {
            forget(&mut known, pid);
        }
        let (lost, syscalls_lost) = match (probe.lost(), probe.syscalls_lost()) {
            (Ok(lost), Ok(syscalls_lost)) => (lost, syscalls_lost),
            (Err(why), _) | (_, Err(why)) => {
                // Loss that cannot be measured must not read as none.
                eprintln!("the eBPF loss counter could not be read: {why}");
                return ExitCode::from(4);
            }
        };
        out.syscalls(traced, syscalls_lost);
        let lost = lost
            .saturating_add(probe.malformed())
            .saturating_add(unknown);
        if !out.health(lost, 0) || !out.flush() {
            return ExitCode::SUCCESS;
        }
        thread::sleep(POLL);
    }
}

/// Where a call's process is: its container, when its cgroup names one, and
/// its ancestors, nearest first, with its parent on its own.
fn place(
    line: &mut Value,
    record: &SyscallRecord,
    cgroups: &mut Cgroups,
    known: &mut HashMap<u32, Known>,
) {
    if let Some(id) = cgroups.container(record.cgroup) {
        add(line, "ctr", id);
    }
    let ancestors = ancestry(known, record.pid);
    if let Some((ppid, _)) = ancestors.first() {
        add(line, "ppid", *ppid);
    }
    add(
        line,
        "anc",
        ancestors
            .into_iter()
            .map(|(pid, name)| json!([pid, name]))
            .collect::<Vec<_>>(),
    );
}

/// What a probe event says, in the sensor's terms. `host` is the pid
/// namespace the probe compared with; an event the kernel placed in it is
/// written with it, and any other answer is left unsaid rather than guessed.
fn happened(
    event: &ProcessEvent,
    host: Option<u64>,
    argv: Option<Vec<String>>,
) -> Option<Happened> {
    let name = lossy(&event.comm);
    let pid_namespace = host.filter(|_| event.namespace() == Namespace::Host);
    Some(match event.kind()? {
        Kind::Spawn => Happened::Fork {
            parent: event.creator,
            child: event.pid,
            name,
            pid_namespace,
        },
        Kind::Exec => {
            let path = lossy(&event.filename);
            Happened::Exec {
                pid: event.pid,
                name,
                program: path
                    .as_deref()
                    .and_then(|path| path.rsplit('/').next())
                    .filter(|file| !file.is_empty())
                    .map(str::to_owned),
                path,
                pid_namespace,
                argv,
                loginuid: event.login_uid(),
                tty: event.has_tty(),
            }
        }
        Kind::Exit => Happened::Exit {
            pid: event.pid,
            code: None,
        },
    })
}

/// Most working directories waiting for their exec or call. A directory
/// whose call was lost in the kernel is never taken, so past this the
/// waiting ones are dropped, to be read again with the next.
const MAX_WAITING_CWD: usize = 4_096;

/// A working directory as a path, when the probe walked it whole.
fn cwd(record: &CwdRecord) -> Option<String> {
    let parts: Vec<String> = record
        .components()?
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    let path = format!("/{}", parts.join("/"));
    (!path.chars().any(char::is_control)).then_some(path)
}

/// Working directories waiting for what they go with: an exec, by pid,
/// or a call with a relative path, by thread and time.
#[derive(Default)]
struct Cwds {
    records: Vec<CwdRecord>,
    execs: HashMap<u32, String>,
    calls: HashMap<(u32, u64), String>,
}

impl Cwds {
    /// Takes what the last drains found.
    fn take(&mut self, probe: &mut Probe) {
        probe.take_cwds(&mut self.records);
        for record in self.records.drain(..) {
            remember(&mut self.execs, record.pid, cwd(&record));
        }
        probe.take_call_cwds(&mut self.records);
        for record in self.records.drain(..) {
            remember(&mut self.calls, (record.tid, record.boot_ns), cwd(&record));
        }
    }

    /// An exec's working directory; an exit forgets any left waiting.
    fn for_event(&mut self, event: &ProcessEvent) -> Option<String> {
        match event.kind() {
            Some(Kind::Exec) => self.execs.remove(&event.pid),
            Some(Kind::Exit) => {
                self.execs.remove(&event.pid);
                None
            }
            _ => None,
        }
    }

    /// A call's working directory, sent with it when it had a relative path.
    fn for_call(&mut self, record: &SyscallRecord) -> Option<String> {
        self.calls.remove(&(record.tid, record.boot_ns))
    }
}

/// Keeps a working directory for what it goes with, or forgets an older one
/// when this one was not read whole.
fn remember<K: std::hash::Hash + Eq>(
    waiting: &mut HashMap<K, String>,
    key: K,
    cwd: Option<String>,
) {
    let Some(cwd) = cwd else {
        waiting.remove(&key);
        return;
    };
    if waiting.len() >= MAX_WAITING_CWD {
        waiting.clear();
    }
    waiting.insert(key, cwd);
}

/// Most processes whose exec arguments wait for their exec.
const MAX_WAITING_ARGV: usize = 4_096;

/// Keeps a process's latest exec arguments, when they were read whole, for
/// the exec that follows. A failed `execve` leaves arguments that the next
/// one replaces, since every `execve` sends its own first.
fn remember_argv(arguments: &mut HashMap<u32, Vec<String>>, record: &ArgvRecord) {
    let Some(argv) = record.argv() else {
        arguments.remove(&record.pid);
        return;
    };
    if arguments.len() >= MAX_WAITING_ARGV && !arguments.contains_key(&record.pid) {
        return;
    }
    let argv = argv
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect();
    arguments.insert(record.pid, argv);
}

/// One syscall as a `sys` line. A path is written only when the probe read
/// it whole and it has no control character; an address as hex, as Audit
/// writes `saddr`.
fn syscall_line(record: &SyscallRecord, call: &str, host: Option<u64>, seq: u64, at: u64) -> Value {
    let [a0, a1, a2, a3, ..] = record.args;
    let mut line = json!({"e": "sys", "call": call, "pid": record.pid, "uid": record.uid,
                          "ret": record.ret, "args": [a0, a1, a2, a3],
                          "name": lossy(&record.comm), "seq": seq, "at": at});
    for (key, path) in [("path", record.path()), ("path2", record.path2())] {
        if let Some(path) = path
            .map(String::from_utf8_lossy)
            .filter(|p| !p.chars().any(char::is_control))
        {
            add(&mut line, key, path.into_owned());
        }
    }
    if let Some(addr) = record.addr() {
        let hex = addr.iter().fold(String::new(), |mut hex, b| {
            let _ = write!(hex, "{b:02x}");
            hex
        });
        add(&mut line, "saddr", hex);
    }
    if let Some(namespace) = host.filter(|_| record.namespace() == Namespace::Host) {
        add(&mut line, "pidns", namespace);
    }
    if let Some(socket) = SocketKind::unpack(record.socket) {
        add(
            &mut line,
            "sock",
            json!([socket.domain, socket.kind, socket.protocol]),
        );
    }
    if let Some((effective, permitted)) = record.capabilities() {
        // As two decimal strings: JSON numbers lose the top bits of a u64.
        add(
            &mut line,
            "cap",
            json!([effective.to_string(), permitted.to_string()]),
        );
    }
    if let Some(auid) = record.login_uid() {
        add(&mut line, "auid", auid);
    }
    if let Some(tty) = record.has_tty() {
        add(&mut line, "tty", u8::from(tty));
    }
    line
}

/// A NUL-padded field as text, or `None` when empty.
fn lossy(field: &[u8]) -> Option<String> {
    let bytes = text(field);
    (!bytes.is_empty()).then(|| String::from_utf8_lossy(bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use topgent_collect::process_events::{Line, parse_line};
    use topgent_ebpf::{Kind, Namespace, ProcessEvent, SyscallRecord};

    use super::{happened, syscall_line};
    use crate::line::Happened;

    /// What the writer says about a syscall, the collector reads back.
    #[test]
    fn a_syscall_line_reads_back_as_the_same_call() {
        let mut record = SyscallRecord {
            pid: 7,
            uid: 1000,
            ret: -2,
            args: [0xffff_ff9c, 0x1000, 0, 0, 0, 0],
            pid_namespace: Namespace::Host as u32,
            comm: padded(b"cat"),
            path: padded(b"/etc/shadow"),
            path_read: 12,
            ..SyscallRecord::EMPTY
        };
        record.path2 = padded(b"/tmp/a\x1bb");
        record.path2_read = 9;
        let line = syscall_line(&record, "renameat", HOST, 3, 1_000).to_string();
        let Some(Line::Syscall(call)) = parse_line(&line) else {
            unreachable!("{line}")
        };
        let event = &call.event;
        assert_eq!(
            (event.syscall, event.pid, event.exit),
            ("renameat", 7, Some(-2))
        );
        assert_eq!(
            event.args,
            [Some(0xffff_ff9c), Some(0x1000), Some(0), Some(0)]
        );
        assert_eq!(event.uid, Some(1000));
        assert_eq!(event.comm.as_deref(), Some("cat"));
        let names: Vec<_> = event.paths.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            ["/etc/shadow"],
            "a new name with a control character is not written"
        );
        assert_eq!(call.seq, 3);
        assert!(!line.contains("saddr"), "no address, none written");
    }

    #[test]
    fn a_working_directory_is_a_path_only_when_walked_whole() {
        let mut record = topgent_ebpf::CwdRecord::EMPTY;
        record.names[0][..3].copy_from_slice(b"a b");
        record.lens[0] = 4;
        record.names[1][..3].copy_from_slice(b"tmp");
        record.lens[1] = 4;
        record.count = 2;
        record.complete = 1;
        assert_eq!(super::cwd(&record).as_deref(), Some("/tmp/a b"));
        record.complete = 0;
        assert_eq!(super::cwd(&record), None);
        let root = topgent_ebpf::CwdRecord {
            complete: 1,
            ..topgent_ebpf::CwdRecord::EMPTY
        };
        assert_eq!(super::cwd(&root).as_deref(), Some("/"));
    }

    const HOST: Option<u64> = Some(4_026_531_836);

    fn padded<const N: usize>(text: &[u8]) -> [u8; N] {
        let mut out = [0; N];
        for (slot, byte) in out.iter_mut().zip(text) {
            *slot = *byte;
        }
        out
    }

    #[test]
    fn a_spawn_names_its_creator_as_the_parent() {
        let event = ProcessEvent {
            kind: Kind::Spawn as u32,
            pid: 20,
            creator: 10,
            pid_namespace: Namespace::Host as u32,
            comm: padded(b"codex"),
            ..ProcessEvent::EMPTY
        };
        assert!(matches!(
            happened(&event, HOST, None),
            Some(Happened::Fork { parent: 10, child: 20, name: Some(ref name), pid_namespace: HOST })
                if name == "codex"
        ));
    }

    #[test]
    fn an_exec_keeps_its_full_path_and_derives_the_file_name() {
        let event = ProcessEvent {
            kind: Kind::Exec as u32,
            pid: 20,
            comm: padded(b"nmap"),
            filename: padded(b"/usr/bin/nmap"),
            ..ProcessEvent::EMPTY
        };
        assert!(matches!(
            happened(&event, HOST, None),
            Some(Happened::Exec { pid: 20, ref program, ref path, .. })
                if program.as_deref() == Some("nmap") && path.as_deref() == Some("/usr/bin/nmap")
        ));
    }

    #[test]
    fn an_exit_has_no_code_and_an_unknown_kind_is_not_guessed() {
        let exit = ProcessEvent {
            kind: Kind::Exit as u32,
            pid: 20,
            ..ProcessEvent::EMPTY
        };
        assert!(matches!(
            happened(&exit, HOST, None),
            Some(Happened::Exit {
                pid: 20,
                code: None
            })
        ));
        let odd = ProcessEvent {
            kind: 99,
            ..ProcessEvent::EMPTY
        };
        assert!(happened(&odd, HOST, None).is_none());
    }

    /// Only a kernel answer of "host" is written; "other" and "unknown" are
    /// left unsaid, so a container is never filed as the host.
    #[test]
    fn only_a_confirmed_host_namespace_is_written() {
        for (answer, written) in [
            (Namespace::Host, HOST),
            (Namespace::Other, None),
            (Namespace::Unknown, None),
        ] {
            let event = ProcessEvent {
                kind: Kind::Exec as u32,
                pid: 20,
                pid_namespace: answer as u32,
                filename: padded(b"/usr/bin/nmap"),
                ..ProcessEvent::EMPTY
            };
            assert!(
                matches!(happened(&event, HOST, None), Some(Happened::Exec { pid_namespace, .. }) if pid_namespace == written),
                "{answer:?}"
            );
        }
        let event = ProcessEvent {
            kind: Kind::Exec as u32,
            pid_namespace: Namespace::Host as u32,
            ..ProcessEvent::EMPTY
        };
        assert!(
            matches!(
                happened(&event, None, None),
                Some(Happened::Exec {
                    pid_namespace: None,
                    ..
                })
            ),
            "no host namespace read, nothing written"
        );
    }
}
