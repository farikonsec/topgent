//! `evt.*` and `fd.*`: what the call was, its result, and what it touched.

use topgent_behaviour::event::Field;
use topgent_collect::audit_syscalls::{AuditPath, SyscallEvent};

use super::event::{Happening, RuleEvent, flag, known, value};
use super::names;

/// `O_CREAT`, the same on every architecture Topgent reads.
const O_CREAT: u64 = 0o100;

pub(super) fn field(event: &RuleEvent<'_>, name: &str) -> Field {
    match event.happening {
        Happening::Syscall(call) => from_call(&call.event, name, event.ctx.users),
        Happening::Exec(exec) => match name {
            "evt.type" => value("execve"),
            // Only ever compared with zero, in a placeholder that must stay
            // false: any real event has a positive number.
            "evt.num" => value(exec.at.0.max(1).to_string()),
            "evt.rawres" => value("0"),
            "evt.res" => value("SUCCESS"),
            "evt.is_open_read" | "evt.is_open_write" | "evt.is_open_exec" => flag(false),
            // The path handed to exec, when the sensor read it in the
            // kernel (the eBPF source). The process connector names the
            // program only, so there it stays unknown.
            "evt.arg.filename" => known(exec.path.clone()),
            // An exec has no file descriptor and no other arguments.
            _ => Field::Absent,
        },
    }
}

fn is_open(call: &SyscallEvent) -> bool {
    matches!(call.syscall, "open" | "openat" | "openat2" | "creat")
}

fn is_network(call: &SyscallEvent) -> bool {
    matches!(
        call.syscall,
        "connect" | "accept" | "accept4" | "sendto" | "sendmsg" | "recvfrom" | "recvmsg"
    )
}

/// The open call's flags: `open` passes them second, `openat` third, `creat`
/// implies them. `openat2` passes a structure Audit does not unpack.
fn open_flags(call: &SyscallEvent) -> Option<u64> {
    match call.syscall {
        "open" => call.args[1],
        "openat" => call.args[2],
        "creat" => Some(0o1101),
        _ => None,
    }
}

/// The mode argument of the calls that take one, when they take one.
fn mode(call: &SyscallEvent) -> Option<u64> {
    match call.syscall {
        "chmod" | "fchmod" | "mkdir" => call.args[1],
        "fchmodat" | "mkdirat" => call.args[2],
        "open" => open_flags(call)
            .filter(|f| f & O_CREAT != 0)
            .and(call.args[2]),
        "openat" => open_flags(call)
            .filter(|f| f & O_CREAT != 0)
            .and(call.args[3]),
        _ => None,
    }
}

/// The path the call acted on: the first that is not only a parent directory.
fn primary(call: &SyscallEvent) -> Option<&AuditPath> {
    call.paths
        .iter()
        .find(|p| p.nametype != "PARENT")
        .or_else(|| call.paths.first())
}

fn of_type<'a>(call: &'a SyscallEvent, kinds: &[&str]) -> Option<&'a AuditPath> {
    call.paths
        .iter()
        .find(|p| kinds.contains(&p.nametype.as_str()))
}

/// `/a/./b/../c` as `/a/c`, without touching the file system. `None` for a
/// path still relative: which directory it is under was not recorded (one
/// relative to a directory descriptor, whose path neither source keeps),
/// and reading it as if it were under `/` would put `7` at `/7`.
fn normalise(path: &str) -> Option<String> {
    if !path.starts_with('/') {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    Some(format!("/{}", parts.join("/")))
}

fn from_call(
    call: &SyscallEvent,
    name: &str,
    users: &std::collections::BTreeMap<u32, String>,
) -> Field {
    if name.starts_with("evt.arg.") {
        argument(call, name, users)
    } else if name.starts_with("fd.") {
        descriptor(call, name)
    } else {
        outcome(call, name)
    }
}

/// `evt.type`, the result, and what an open asked for.
fn outcome(call: &SyscallEvent, name: &str) -> Field {
    let flags = open_flags(call).filter(|_| is_open(call));
    match name {
        "evt.type" => value(call.syscall),
        "evt.num" => known(topgent_collect::observed::serial(&call.record).map(|n| n.to_string())),
        "evt.rawres" => known(call.exit.map(|exit| exit.to_string())),
        "evt.res" => known(call.exit.map(names::result)),
        "evt.is_open_read" | "evt.is_open_write" | "evt.is_open_exec" if !is_open(call) => {
            flag(false)
        }
        // An open whose flags Audit did not unpack (`openat2`).
        "evt.is_open_read" | "evt.is_open_write" | "evt.is_open_exec" if flags.is_none() => {
            Field::Unknown
        }
        "evt.is_open_read" => flag(flags.is_some_and(|f| f & 0o3 != 1)),
        "evt.is_open_write" => flag(flags.is_some_and(|f| f & 0o3 != 0)),
        "evt.is_open_exec" => match (flags, mode(call)) {
            (Some(f), Some(mode)) => flag(f & O_CREAT != 0 && mode & 0o111 != 0),
            // Created, but with a mode Audit did not record: cannot tell.
            (Some(f), None) if f & O_CREAT != 0 => Field::Unknown,
            _ => flag(false),
        },
        _ => Field::Unknown,
    }
}

/// `evt.arg.*`: the call's arguments, named as the rules read them.
fn argument(
    call: &SyscallEvent,
    name: &str,
    users: &std::collections::BTreeMap<u32, String>,
) -> Field {
    let syscall = call.syscall;
    let first = call.args[0];
    match name {
        "evt.arg.flags" if is_open(call) => {
            open_flags(call).map_or(Field::Unknown, |f| value(names::open_flags(f)))
        }
        "evt.arg.mode" => mode(call).map_or(Field::Absent, |m| value(names::mode(m))),
        "evt.arg.name" if matches!(syscall, "open" | "openat" | "openat2" | "unlinkat") => {
            path_value(primary(call))
        }
        "evt.arg.path" if matches!(syscall, "mkdir" | "mkdirat" | "rmdir" | "unlink") => {
            path_value(primary(call))
        }
        "evt.arg.filename" if matches!(syscall, "chmod" | "fchmodat" | "execve" | "execveat") => {
            path_value(primary(call))
        }
        "evt.arg.oldpath" if syscall.starts_with("rename") => {
            path_value(of_type(call, &["DELETE"]))
        }
        "evt.arg.oldpath" if syscall.starts_with("link") => path_value(of_type(call, &["NORMAL"])),
        "evt.arg.newpath" if syscall.starts_with("rename") || syscall.starts_with("link") => {
            path_value(of_type(call, &["CREATE"]))
        }
        "evt.arg.target" if syscall.starts_with("symlink") => {
            path_value(of_type(call, &["TARGET"]))
        }
        "evt.arg.request" if syscall == "ptrace" => known(first.map(names::ptrace_request)),
        // The rules name accounts (`nobody`, `_apt`), as the uid is printed.
        "evt.arg.uid" if syscall == "setuid" => known(first.map(|uid| {
            u32::try_from(uid)
                .ok()
                .and_then(|uid| users.get(&uid).cloned())
                .unwrap_or_else(|| uid.to_string())
        })),
        "evt.arg.cmd" if syscall == "bpf" => known(first.map(|cmd| cmd.to_string())),
        "evt.arg.domain" if syscall == "socket" => known(first.map(names::socket_domain)),
        // Not an argument this call has.
        _ => Field::Absent,
    }
}

/// `fd.*`: the file an open named, or the peer a network call named.
fn descriptor(call: &SyscallEvent, name: &str) -> Field {
    // Only an open gives the process a file descriptor; an exec, unlink or
    // rename names its paths as arguments, not as `fd.name`.
    let path = primary(call).filter(|_| is_open(call));
    let peer = call.sockaddr.as_ref().filter(|_| is_network(call));
    let inet = peer.filter(|p| p.family != 1);
    match name {
        "fd.name" => path.map_or(Field::Absent, |p| known(normalise(&p.name))),
        "fd.nameraw" => path.map_or(Field::Absent, |p| value(p.name.clone())),
        "fd.directory" => path.map_or(Field::Absent, |p| {
            known(normalise(&p.name).map(|full| match full.rsplit_once('/') {
                Some(("", _)) | None => "/".to_owned(),
                Some((dir, _)) => dir.to_owned(),
            }))
        }),
        // The last component is the same wherever a relative path is.
        "fd.filename" => path.map_or(Field::Absent, |p| {
            value(p.name.rsplit('/').next().unwrap_or("").to_owned())
        }),
        "fd.typechar" | "fd.type" => {
            let kind = match (path, peer) {
                (Some(_), _) => ("f", "file"),
                (None, Some(p)) if p.family == 2 => ("4", "ipv4"),
                (None, Some(p)) if p.family == 10 => ("6", "ipv6"),
                (None, Some(_)) => ("u", "unix"),
                (None, None) => return Field::Absent,
            };
            value(if name == "fd.typechar" {
                kind.0
            } else {
                kind.1
            })
        }
        "fd.num" if is_open(call) => known(call.exit.map(|exit| exit.max(-1).to_string())),
        "fd.num" if is_network(call) => known(call.args[0].map(|fd| fd.to_string())),
        "fd.sip" | "fd.ip" | "fd.net" | "fd.snet" | "fd.rnet" => {
            inet.map_or(Field::Absent, |p| value(p.host.clone()))
        }
        "fd.cip" | "fd.cnet" if is_inbound(call) => {
            inet.map_or(Field::Absent, |p| value(p.host.clone()))
        }
        "fd.cip.name" if is_inbound(call) => Field::Absent,
        "fd.name_changed"
            if matches!(call.syscall, "sendto" | "sendmsg" | "recvfrom" | "recvmsg") =>
        {
            flag(peer.is_some())
        }
        "fd.name_changed" if is_network(call) => flag(false),
        "fd.sport" | "fd.port" => inet.map_or(Field::Absent, |p| value(p.port.to_string())),
        "fd.sockfamily" => peer.map_or(Field::Absent, |p| {
            value(if p.family == 1 { "unix" } else { "ip" })
        }),
        // Known only when the eBPF probe saw the socket made; Audit never
        // says, and a socket from before the probe loaded stays unknown.
        "fd.l4proto" if is_network(call) || call.syscall == "listen" => {
            known(call.socket.and_then(l4proto))
        }
        "fd.connected" if peer.is_some() && call.syscall == "connect" => flag(call.success),
        "fd.connected" if peer.is_some() => Field::Unknown,
        _ => Field::Absent,
    }
}

fn is_inbound(call: &SyscallEvent) -> bool {
    matches!(
        call.syscall,
        "accept" | "accept4" | "listen" | "recvfrom" | "recvmsg"
    )
}

/// `fd.l4proto` for an internet socket, as the rules name it: the protocol
/// asked for, else the type's default. `None` for any other family, or a
/// type or protocol the rules have no name for.
fn l4proto((domain, kind, protocol): (u8, u8, u8)) -> Option<String> {
    const AF_INET: u8 = 2;
    const AF_INET6: u8 = 10;
    if domain != AF_INET && domain != AF_INET6 {
        return None;
    }
    let name = match (kind, protocol) {
        (_, 6) | (1, 0) => "tcp",
        (_, 17) | (2, 0) => "udp",
        (_, 1 | 58) => "icmp",
        (3, _) => "raw",
        _ => return None,
    };
    Some(name.to_owned())
}

fn path_value(path: Option<&AuditPath>) -> Field {
    path.map_or(Field::Absent, |p| known(normalise(&p.name)))
}

#[cfg(test)]
mod tests {
    use super::normalise;

    #[test]
    fn paths_are_normalised_lexically() {
        assert_eq!(normalise("/a/./b/../c").as_deref(), Some("/a/c"));
        assert_eq!(
            normalise("/tmp/x/../../etc/shadow").as_deref(),
            Some("/etc/shadow")
        );
        assert_eq!(normalise("/").as_deref(), Some("/"));
    }

    #[test]
    fn a_socket_is_named_by_its_protocol_else_its_type() {
        use super::l4proto;
        assert_eq!(l4proto((2, 1, 0)).as_deref(), Some("tcp"));
        assert_eq!(l4proto((10, 2, 0)).as_deref(), Some("udp"));
        assert_eq!(l4proto((2, 2, 1)).as_deref(), Some("icmp"), "a ping socket");
        assert_eq!(l4proto((2, 3, 255)).as_deref(), Some("raw"));
        assert_eq!(
            l4proto((1, 1, 0)),
            None,
            "a local socket has no layer-4 protocol"
        );
        assert_eq!(l4proto((2, 5, 0)), None, "SOCK_SEQPACKET has no name here");
    }

    /// Found in the E4 lab: `runc` opened `7` and "Write below root" fired
    /// on `/7`.
    #[test]
    fn a_relative_path_is_never_read_as_under_the_root() {
        assert_eq!(normalise("7"), None);
        assert_eq!(normalise("./etc/shadow"), None);
    }
}
