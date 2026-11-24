//! Reading every syscall the behaviour rules react to, from real Audit records.
//!
//! `fixtures/audit-aarch64-syscalls.log` was captured on the Kali aarch64 lab
//! with one lab-owned rule loaded: ordinary file, link, rename, chmod,
//! connect, setuid, ptrace, bpf, userfaultfd, unshare and dup calls made by
//! the lab's own programs.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::BTreeSet;
use std::fmt::Write as _;

use topgent_collect::audit_syscalls::{SyscallEvent, parse};

const KALI: &str = include_str!("fixtures/audit-aarch64-syscalls.log");

fn events() -> Vec<SyscallEvent> {
    parse(KALI)
}

fn first(name: &str) -> SyscallEvent {
    events()
        .into_iter()
        .find(|e| e.syscall == name)
        .unwrap_or_else(|| panic!("no {name} in the fixture"))
}

#[test]
fn every_captured_syscall_is_named_for_its_architecture() {
    let names: BTreeSet<&str> = events().iter().map(|e| e.syscall).collect();
    for expected in [
        "openat",
        "execve",
        "socket",
        "connect",
        "linkat",
        "symlinkat",
        "mkdirat",
        "renameat2",
        "fchmodat",
        "unlinkat",
        "setuid",
        "dup3",
        "ptrace",
        "bpf",
        "userfaultfd",
        "unshare",
    ] {
        assert!(
            names.contains(expected),
            "{expected} missing from {names:?}"
        );
    }
}

#[test]
fn an_exec_keeps_its_program_arguments_and_identity() {
    let cat = events()
        .into_iter()
        .find(|e| e.syscall == "execve" && e.exe.as_deref() == Some("/usr/bin/cat"))
        .expect("cat's exec");
    assert!(cat.success);
    assert_eq!(cat.argv, ["cat", "/etc/hostname"]);
    assert_eq!(cat.uid, Some(1000));
    assert_eq!(cat.auid, Some(1000));
    assert_eq!(cat.tty, None, "tty=(none) is no terminal");
    assert_eq!(cat.comm.as_deref(), Some("cat"));
    assert!(cat.ppid.is_some());
}

#[test]
fn a_refused_connect_keeps_its_address_and_error() {
    let connect = first("connect");
    assert!(!connect.success);
    assert_eq!(connect.exit, Some(-111));
    let peer = connect.sockaddr.expect("address");
    assert_eq!(
        (peer.host.as_str(), peer.port, peer.family),
        ("127.0.0.1", 9, 2)
    );
}

#[test]
fn file_calls_keep_their_paths_resolved_against_the_working_directory() {
    let rename = first("renameat2");
    let names: Vec<&str> = rename.paths.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"/tmp/s7cap/hl"), "{names:?}");
    assert!(names.contains(&"/tmp/s7cap/hl2"), "{names:?}");
    assert_eq!(rename.cwd.as_deref(), Some("/tmp/s7cap"));
    let chmod = first("fchmodat");
    assert!(chmod.paths.iter().any(|p| p.name == "/tmp/s7cap/f"));
    assert_eq!(chmod.args[2], Some(0o600), "the mode argument");
}

#[test]
fn calls_with_no_path_keep_their_arguments() {
    let ptrace = first("ptrace");
    assert_eq!(ptrace.args[0], Some(0), "PTRACE_TRACEME");
    let setuid = first("setuid");
    assert_eq!(setuid.args[0], Some(1000));
    let bpf = first("bpf");
    assert!(!bpf.success, "an unprivileged bpf call is refused");
}

/// The same call recorded on x86-64 is numbered differently.
#[test]
fn x86_64_numbers_name_the_same_calls() {
    let line = "type=SYSCALL msg=audit(1700000000.100:41): arch=c000003e syscall=101 success=yes exit=0 a0=0 a1=0 a2=0 a3=0 ppid=1 pid=7 auid=1000 uid=1000 tty=pts0 comm=\"x\" exe=\"/usr/bin/x\"\n";
    let events = parse(line);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].syscall, "ptrace");
    assert_eq!(events[0].tty.as_deref(), Some("pts0"));
}

/// Arguments hex-encoded by Audit (they held a space) are decoded, and a
/// hostile record cannot make the reader keep unbounded arguments.
#[test]
fn arguments_are_decoded_and_bounded() {
    let text = "type=SYSCALL msg=audit(1.000:9): arch=c00000b7 syscall=221 success=yes exit=0 a0=0 a1=0 a2=0 a3=0 ppid=1 pid=7 uid=1000 comm=\"sh\" exe=\"/usr/bin/dash\"\n\
                type=EXECVE msg=audit(1.000:9): argc=3 a0=\"sh\" a1=\"-c\" a2=6C73202D6C\n";
    assert_eq!(parse(text)[0].argv, ["sh", "-c", "ls -l"]);
    let mut hostile = String::from(
        "type=SYSCALL msg=audit(1.000:9): arch=c00000b7 syscall=221 success=yes exit=0 pid=7 uid=1 comm=\"x\" exe=\"/x\"\ntype=EXECVE msg=audit(1.000:9): argc=100000",
    );
    for i in 0..500 {
        let _ = write!(hostile, " a{i}=\"{}\"", "y".repeat(10_000));
    }
    let event = &parse(&hostile)[0];
    assert!(event.argv.len() <= 64);
    assert!(event.argv.iter().all(|a| a.len() <= 4_096));
}

#[test]
fn records_for_other_syscalls_and_garbage_are_ignored() {
    let text = "garbage\ntype=SYSCALL msg=audit(1.000:9): arch=c00000b7 syscall=63 success=yes exit=0 pid=7\n";
    assert!(
        parse(text).is_empty(),
        "read(63) is not a call the rules use"
    );
}

/// An `*at` call names a path relative to a directory descriptor, which Audit
/// records as a PARENT record. The name goes under that directory, not under
/// the working directory, and the name as passed is kept too.
#[test]
fn a_relative_name_goes_under_its_parent_record_before_the_working_directory() {
    let text = "type=SYSCALL msg=audit(1.000:9): arch=c00000b7 syscall=35 success=yes exit=0 a0=5 a1=0 a2=0 a3=0 ppid=1 pid=7 uid=1000 comm=\"rm\" exe=\"/usr/bin/rm\"\n\
                type=CWD msg=audit(1.000:9): cwd=\"/home/u\"\n\
                type=PATH msg=audit(1.000:9): item=0 name=\"/var/log/app/\" nametype=PARENT\n\
                type=PATH msg=audit(1.000:9): item=1 name=\"old.log\" nametype=DELETE\n";
    let event = &parse(text)[0];
    let deleted = event
        .paths
        .iter()
        .find(|p| p.nametype == "DELETE")
        .expect("deleted");
    assert_eq!(deleted.name, "/var/log/app/old.log");
    assert_eq!(deleted.raw, "old.log");
}
