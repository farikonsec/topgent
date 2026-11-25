//! E4 step 1: the rule syscalls this test makes each arrive with their
//! arguments, result and paths, and a read-only open under `/proc/` does not,
//! nor a receive with no IPv4 or IPv6 sender.
//!
//! Needs root, like `load.rs`; see there for how to run it. Every call here
//! is benign: files under a fresh directory in `/tmp`, a loopback listener,
//! and a `ptrace(PTRACE_TRACEME)` by a child that then exits.

#![cfg(all(target_os = "linux", feature = "probe"))]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::indexing_slicing
)]

use std::{
    fs,
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream, UdpSocket},
    os::unix::{fs::OpenOptionsExt as _, net::UnixDatagram},
    process::Command,
    thread,
    time::{Duration, Instant},
};

use topgent_ebpf::{
    ArgvRecord, CwdRecord, Kind, Namespace, Probe, SocketKind, SyscallRecord, text,
};

/// A record, with its call's name.
struct Call {
    name: &'static str,
    record: SyscallRecord,
}

impl Call {
    fn path(&self) -> Option<&str> {
        std::str::from_utf8(self.record.path()?).ok()
    }

    fn path2(&self) -> Option<&str> {
        std::str::from_utf8(self.record.path2()?).ok()
    }
}

/// Everything the probe reported for `pids`, until `done` holds or 5 s pass.
fn collect(probe: &mut Probe, pids: &[u32], done: impl Fn(&[Call]) -> bool) -> Vec<Call> {
    let mut calls = Vec::new();
    let mut records = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        probe.drain_syscalls(&mut records);
        for record in records.drain(..) {
            if pids.contains(&record.pid) {
                let name = probe.syscall_name(record.call).expect("a traced call");
                calls.push(Call { name, record });
            }
        }
        if done(&calls) || Instant::now() > deadline {
            return calls;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn find<'a>(calls: &'a [Call], names: &[&str], path: &str) -> Option<&'a Call> {
    calls
        .iter()
        .find(|c| names.contains(&c.name) && c.path() == Some(path))
}

/// The loopback TCP connect with its address, and both connects with the
/// kind of socket they used.
fn check_connects(calls: &[Call], port: u16) {
    let connect = calls
        .iter()
        .find(|c| {
            c.name == "connect" && c.record.addr_read >= 8 && c.record.addr[4..8] == [127, 0, 0, 1]
        })
        .expect("the loopback connect, with its address");
    let addr = &connect.record.addr;
    assert_eq!(u16::from_ne_bytes([addr[0], addr[1]]), 2, "AF_INET");
    assert_eq!(u16::from_be_bytes([addr[2], addr[3]]), port);
    assert_eq!(&addr[4..8], &[127, 0, 0, 1]);

    let kind = |c: &Call| SocketKind::unpack(c.record.socket).map(|k| (k.domain, k.kind));
    assert_eq!(
        kind(connect),
        Some((2, 1)),
        "the TCP connect knows its socket"
    );
    let udp_connect = calls
        .iter()
        .find(|c| c.name == "connect" && c.record.addr[4..8] == [192, 0, 2, 1])
        .expect("the UDP connect");
    assert_eq!(
        kind(udp_connect),
        Some((2, 2)),
        "the UDP connect knows its socket"
    );
}

#[test]
#[ignore = "needs root: loads a program into the running kernel"]
fn each_rule_syscall_arrives_with_its_arguments_result_and_paths() {
    let mut probe = topgent_ebpf::load().expect("the probe loads");
    println!("traced: {}", probe.traced().join(" "));
    for (name, why) in probe.untraced() {
        println!("untraced: {name}: {why}");
    }
    let me = std::process::id();
    let dir = format!("/tmp/topgent-e4-{me}");
    fs::create_dir_all(&dir).expect("a scratch directory");
    let (made, moved, missing) = (
        format!("{dir}/made"),
        format!("{dir}/moved"),
        format!("{dir}/missing"),
    );

    // A read, a failed read, a create for writing, a rename, an unlink.
    let mut text = String::new();
    fs::File::open("/etc/hostname")
        .expect("open /etc/hostname")
        .read_to_string(&mut text)
        .expect("read it");
    assert!(fs::File::open(&missing).is_err());
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&made)
        .expect("create a file");
    fs::rename(&made, &moved).expect("rename it");
    fs::remove_file(&moved).expect("unlink it");
    // Read-only under /proc: dropped in the kernel.
    fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
    // A loopback connect.
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
    let port = listener.local_addr().expect("its address").port();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    // A UDP connect only records the peer: nothing is sent. The address is
    // TEST-NET-1, reserved for documentation.
    let udp = UdpSocket::bind("0.0.0.0:0").expect("a UDP socket");
    udp.connect("192.0.2.1:9").expect("a UDP connect");
    let sender = receive_three_ways(&listener, &mut stream);
    // PTRACE_TRACEME (request 0), made by a child: nothing is traced.
    let tracer = Command::new("python3")
        .args(["-c", "import ctypes; ctypes.CDLL(None).ptrace(0, 0, 0, 0)"])
        .spawn()
        .expect("python3 runs");
    let child = tracer.id();
    let status = tracer.wait_with_output().expect("it exits").status;
    assert!(status.success());
    fs::remove_dir(&dir).expect("remove the scratch directory");

    let calls = collect(&mut probe, &[me, child], |calls| {
        calls.iter().any(|c| c.name == "ptrace") && calls.iter().any(|c| c.name == "connect")
    });
    let lost = probe.syscalls_lost().expect("the lost counter reads");
    println!(
        "calls {} · lost {lost} · malformed {}",
        calls.len(),
        probe.malformed()
    );
    for call in &calls {
        println!(
            "  {:<9} ret {:>4} args {:x?} path {:?} path2 {:?} addr {}",
            call.name,
            call.record.ret,
            &call.record.args[..4],
            call.path(),
            call.path2(),
            call.record.addr_read,
        );
    }
    assert_eq!(probe.malformed(), 0);

    let open = ["open", "openat"];
    let read = find(&calls, &open, "/etc/hostname").expect("the read");
    assert!(read.record.ret >= 0, "a descriptor");
    assert_eq!(read.record.namespace(), Namespace::Host);

    let failed = find(&calls, &open, &missing).expect("the failed open");
    assert_eq!(failed.record.ret, -2, "ENOENT");

    let created = find(&calls, &open, &made).expect("the create");
    let flags_at = usize::from(created.name == "openat") + 1;
    let flags = created.record.args[flags_at];
    assert_eq!(flags & 0o3, 1, "O_WRONLY: {flags:o}");
    assert_ne!(flags & 0o100, 0, "O_CREAT: {flags:o}");

    let renamed = find(&calls, &["rename", "renameat", "renameat2"], &made).expect("the rename");
    assert_eq!(renamed.path2(), Some(moved.as_str()));
    assert_eq!(renamed.record.ret, 0);

    assert!(
        find(&calls, &["unlink", "unlinkat"], &moved).is_some(),
        "the unlink"
    );

    check_dropped_opens(&calls);

    check_connects(&calls, port);
    check_receives(&calls, sender);

    let ptrace = calls
        .iter()
        .find(|c| c.name == "ptrace" && c.record.pid == child)
        .expect("the child's ptrace");
    assert_eq!(ptrace.record.args[0], 0, "PTRACE_TRACEME");
    assert_eq!(ptrace.record.ret, 0);
    check_credentials(ptrace);
}

/// Read-only opens under `/proc/` and of the linker cache (which the
/// `python3` child makes) are dropped in the kernel.
fn check_dropped_opens(calls: &[Call]) {
    assert!(
        !calls
            .iter()
            .any(|c| c.path().is_some_and(|p| p.starts_with("/proc/"))),
        "a read-only open under /proc/ is dropped in the kernel"
    );
    assert!(
        !calls.iter().any(|c| c.path() == Some("/etc/ld.so.cache")),
        "a read-only open of the linker cache is dropped in the kernel"
    );
}

/// Three receives: a UDP datagram from a named sender, which is kept, and
/// one on a stream and one on a local socket, dropped in the kernel.
/// Returns the datagram sender's port.
fn receive_three_ways(listener: &TcpListener, stream: &mut TcpStream) -> u16 {
    let inbox = UdpSocket::bind("127.0.0.1:0").expect("a UDP receiver");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("a UDP sender");
    sender
        .send_to(b"x", inbox.local_addr().expect("its address"))
        .expect("send a datagram");
    let mut byte = [0_u8; 1];
    let (_, from) = inbox.recv_from(&mut byte).expect("receive it");
    let mut accepted = listener.accept().expect("accept the connect").0;
    accepted.write_all(b"x").expect("write on the stream");
    stream.read_exact(&mut byte).expect("read on the stream");
    let (local, peer) = UnixDatagram::pair().expect("a local pair");
    local.send(b"x").expect("send locally");
    peer.recv(&mut byte).expect("receive locally");
    from.port()
}

/// Only the datagram with a named IPv4 sender was reported of the three
/// receives (E9).
fn check_receives(calls: &[Call], sender: u16) {
    let receives: Vec<&Call> = calls
        .iter()
        .filter(|c| c.name == "recvfrom" || c.name == "recvmsg")
        .collect();
    assert_eq!(receives.len(), 1, "one receive kept of three");
    let addr = &receives[0].record.addr;
    assert_eq!(u16::from_ne_bytes([addr[0], addr[1]]), 2, "AF_INET");
    assert_eq!(u16::from_be_bytes([addr[2], addr[3]]), sender);
}

/// Credentials from BTF (E8): this test runs as root, so its own calls carry
/// a full effective set (`CAP_SYS_ADMIN` is bit 21), and a login id, since it
/// was started over ssh then sudo.
fn check_credentials(call: &Call) {
    let (effective, _permitted) = call
        .record
        .capabilities()
        .expect("the caller's capabilities were read");
    assert_ne!(
        effective & (1 << 21),
        0,
        "root has CAP_SYS_ADMIN: {effective:#x}"
    );
    // A login uid exists only inside a login session (ssh, a console). A CI
    // runner's sudo has none, and the kernel then reports it as unset.
    let in_session =
        fs::read_to_string("/proc/self/loginuid").is_ok_and(|id| id.trim() != "4294967295");
    if in_session {
        assert!(call.record.login_uid().is_some(), "the login uid was read");
    }
}

#[test]
#[ignore = "needs root: loads a program into the running kernel"]
fn exec_arguments_arrive_whole_and_ahead_of_their_exec() {
    let mut probe = topgent_ebpf::load().expect("the probe loads");
    assert!(probe.reads_argv(), "this kernel has the execve tracepoints");
    let long = "x".repeat(300);
    let many: Vec<String> = (0..20).map(|i| i.to_string()).collect();
    let short = Command::new("/bin/echo")
        .args(["one", "two words"])
        .output()
        .expect("echo runs");
    assert!(short.status.success());
    let cut = Command::new("/bin/echo")
        .arg(&long)
        .output()
        .expect("echo runs");
    assert!(cut.status.success());
    let over = Command::new("/bin/echo")
        .args(&many)
        .output()
        .expect("echo runs");
    assert!(over.status.success());
    // Read at exec from the new program's memory (E10), the arguments of a
    // command `sudo` runs arrive too; at `execve` entry they were not
    // resident and a BPF read cannot fault them in.
    let via_sudo = Command::new("sudo")
        .args(["-n", "/bin/echo", "via", "sudo"])
        .output()
        .expect("sudo runs");
    assert!(via_sudo.status.success());
    thread::sleep(Duration::from_millis(200));

    // Arguments, then the exec, per pid, in the order they were drained.
    let mut events = Vec::new();
    let mut argv = Vec::new();
    let mut order: Vec<(u32, &str, Option<Vec<String>>)> = Vec::new();
    probe.drain(&mut events);
    probe.take_argv(&mut argv);
    let all: Vec<ArgvRecord> = argv;
    for record in &all {
        let list = record.argv().map(|each| {
            each.map(|a| String::from_utf8_lossy(a).into_owned())
                .collect::<Vec<_>>()
        });
        order.push((record.pid, "argv", list));
    }
    let execs: Vec<u32> = events
        .iter()
        .filter(|e| e.kind() == Some(Kind::Exec) && text(&e.filename) == b"/bin/echo")
        .map(|e| e.pid)
        .collect();
    assert_eq!(execs.len(), 4, "four echo execs");
    let of = |pid: u32| {
        order
            .iter()
            .rfind(|(p, ..)| *p == pid)
            .and_then(|(_, _, args)| args.clone())
    };
    assert_eq!(
        of(execs[0]),
        Some(vec![
            "/bin/echo".to_owned(),
            "one".to_owned(),
            "two words".to_owned()
        ])
    );
    assert_eq!(of(execs[1]), None, "an argument longer than the slot");
    assert_eq!(of(execs[2]), None, "more arguments than are read");
    assert_eq!(
        of(execs[3]),
        Some(vec![
            "/bin/echo".to_owned(),
            "via".to_owned(),
            "sudo".to_owned()
        ]),
        "a command run by sudo"
    );
    println!(
        "argv records {} · execs {execs:?} · malformed {}",
        all.len(),
        probe.malformed()
    );
    assert_eq!(probe.malformed(), 0);
}

/// A working directory as the record gives it, when whole.
fn cwd_of(record: &CwdRecord) -> Option<String> {
    let parts: Vec<String> = record
        .components()?
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    Some(format!("/{}", parts.join("/")))
}

#[test]
#[ignore = "needs root: loads a program into the running kernel"]
fn the_working_directory_arrives_with_an_exec_and_a_relative_call() {
    let mut probe = topgent_ebpf::load().expect("the probe loads");
    assert!(probe.reads_cwd(), "this kernel's BTF has every offset");
    // Under /tmp, its own mount on the lab VM, so the walk crosses one.
    let dir = format!("/tmp/topgent-e11-{}/a b", std::process::id());
    fs::create_dir_all(&dir).expect("a scratch directory");
    fs::write(format!("{dir}/rel"), "x").expect("a file to read");
    let cat = Command::new("/bin/cat")
        .arg("rel")
        .current_dir(&dir)
        .output()
        .expect("cat runs");
    assert!(cat.status.success());
    // The same relative name, looked up from a directory descriptor.
    let by_fd = Command::new("python3")
        .args([
            "-c",
            "import os; d = os.open('.', os.O_RDONLY); os.open('rel', os.O_RDONLY, dir_fd=d)",
        ])
        .current_dir(&dir)
        .spawn()
        .expect("python3 runs");
    let by_fd_pid = by_fd.id();
    assert!(by_fd.wait_with_output().expect("it exits").status.success());
    let root = Command::new("/bin/true")
        .current_dir("/")
        .spawn()
        .expect("true runs");
    let root_pid = root.id();
    root.wait_with_output().expect("it exits");
    thread::sleep(Duration::from_millis(200));

    let mut events = Vec::new();
    let mut calls = Vec::new();
    let mut cwds = Vec::new();
    probe.drain(&mut events);
    probe.drain_syscalls(&mut calls);
    probe.take_cwds(&mut cwds);
    let mut call_cwds = Vec::new();
    probe.take_call_cwds(&mut call_cwds);
    fs::remove_dir_all(dir.trim_end_matches("/a b")).expect("remove the scratch directory");
    assert_eq!(probe.malformed(), 0);

    let exec = events
        .iter()
        .find(|e| e.kind() == Some(Kind::Exec) && text(&e.filename) == b"/bin/cat")
        .expect("the cat exec");
    let at_exec = cwds
        .iter()
        .rfind(|c| c.pid == exec.pid && c.boot_ns <= exec.boot_ns)
        .expect("a working directory ahead of the exec");
    assert_eq!(cwd_of(at_exec).as_deref(), Some(dir.as_str()));

    // The syscall buffer is drained on its own schedule and can trail the
    // exec buffer on a busy host, so keep draining for up to two seconds.
    let mut found = None;
    for _ in 0..20 {
        found = calls.iter().position(|c| {
            c.pid == exec.pid
                && probe
                    .syscall_name(c.call)
                    .is_some_and(|n| n.starts_with("open"))
                && c.path() == Some(&b"rel"[..])
        });
        if found.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
        probe.drain_syscalls(&mut calls);
        probe.take_call_cwds(&mut call_cwds);
    }
    let Some(open) = found.and_then(|i| calls.get(i)) else {
        let mine: Vec<_> = calls
            .iter()
            .filter(|c| c.pid == exec.pid)
            .map(|c| (probe.syscall_name(c.call), c.path()))
            .collect();
        panic!("cat's relative open; cat's calls: {mine:?}");
    };
    let with_call = call_cwds
        .iter()
        .find(|c| c.tid == open.tid && c.boot_ns == open.boot_ns)
        .expect("a working directory with the call, by thread and time");
    assert_eq!(cwd_of(with_call).as_deref(), Some(dir.as_str()));

    let at_root = cwds
        .iter()
        .find(|c| c.pid == root_pid)
        .expect("the root exec's working directory");
    assert_eq!(cwd_of(at_root).as_deref(), Some("/"));
    let from_fd = calls
        .iter()
        .find(|c| c.pid == by_fd_pid && c.path() == Some(&b"rel"[..]))
        .expect("the open relative to a directory descriptor");
    assert!(
        !call_cwds
            .iter()
            .any(|c| c.tid == from_fd.tid && c.boot_ns == from_fd.boot_ns),
        "no working directory with a call that looks up from a descriptor"
    );
    println!(
        "cwd records: {} with execs, {} with calls · malformed {}",
        cwds.len(),
        call_cwds.len(),
        probe.malformed()
    );
}
