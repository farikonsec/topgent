//! Every syscall the behaviour rules react to, as the Audit log recorded it.
//!
//! The file, exec and connect readers each keep the slice of a record their
//! own finding needs. The behaviour rules need more of the same record: the
//! call's arguments and result, who made it (uid, login uid, terminal), where
//! (working directory), what it touched (paths, peer address), and for an
//! exec, the arguments. This reads all of it, for forty-one calls.
//!
//! Exec arguments are read so rules can be evaluated on them, and are kept in
//! memory only: nothing that stores or reports an event may keep `argv`.
//!
//! Everything is bounded: arguments, paths and text lengths, whatever the log
//! claims.

use std::collections::BTreeMap;

use super::Arch;
use super::names::{named, numbered};
use super::record::{audit_id, audit_time_ms, field};

/// Most exec arguments kept.
const MAX_ARGS: usize = 64;
/// Longest text value kept: one argument, one path.
const MAX_TEXT: usize = 4_096;
/// Most paths kept for one call.
const MAX_PATHS: usize = 8;

/// A path a call named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditPath {
    /// Absolute where the record allows: a relative name is placed under its
    /// call's PARENT record when that is absolute, else under the working
    /// directory.
    pub name: String,
    /// The name as the program passed it.
    pub raw: String,
    /// `NORMAL`, `PARENT`, `CREATE`, `DELETE`, as Audit wrote it.
    pub nametype: String,
}

/// The address a network call named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketAddress {
    /// Address family: 2 IPv4, 10 IPv6, 1 local.
    pub family: u16,
    /// Address literal, or the socket path for a local socket.
    pub host: String,
    /// Port, 0 where the family has none.
    pub port: u16,
}

/// Which kernel facility recorded a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallSource {
    /// The Linux Audit log.
    Audit,
    /// Topgent's own eBPF probe, through `topgent-sensor`.
    Ebpf,
}

impl CallSource {
    /// Stable report label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Audit => "audit",
            Self::Ebpf => "ebpf",
        }
    }
}

/// One call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallEvent {
    /// Which kernel facility recorded it.
    pub source: CallSource,
    /// The record id, `seconds.millis:serial`.
    pub record: String,
    /// When, by the wall clock.
    pub at: u64,
    /// The process.
    pub pid: u32,
    /// Its parent, as the record gave it.
    pub ppid: Option<u32>,
    /// The call, by name.
    pub syscall: &'static str,
    /// Whether it succeeded.
    pub success: bool,
    /// Its return value: a descriptor, zero, or a negated error number.
    pub exit: Option<i64>,
    /// The first four arguments.
    pub args: [Option<u64>; 4],
    /// Real user id.
    pub uid: Option<u32>,
    /// Login user id: the account that logged in, unchanged by `su`.
    pub auid: Option<u32>,
    /// Controlling terminal, `None` for none.
    pub tty: Option<String>,
    /// The process name.
    pub comm: Option<String>,
    /// The program's path.
    pub exe: Option<String>,
    /// Working directory, where the record carried one.
    pub cwd: Option<String>,
    /// Paths the call named.
    pub paths: Vec<AuditPath>,
    /// The address a network call named.
    pub sockaddr: Option<SocketAddress>,
    /// An exec's arguments. In memory only.
    pub argv: Vec<String>,
    /// The pid namespace the kernel placed the caller in, when that was the
    /// host's (the eBPF source). Audit does not say.
    pub pid_namespace: Option<u64>,
    /// The kind of socket a network call used, as `socket(domain, type,
    /// protocol)` made it, when the eBPF probe saw it made. Audit does not
    /// record it.
    pub socket: Option<(u8, u8, u8)>,
    /// The container the caller ran in, by its full id, when the eBPF probe
    /// named it from the call's own cgroup. Audit does not say.
    pub container: Option<String>,
    /// The caller's ancestors at the moment of the call, nearest first, as
    /// `(pid, name)` (the eBPF source). Audit names only the parent, in
    /// `ppid`.
    pub ancestors: Vec<(u32, Option<String>)>,
    /// The caller's effective and permitted capability sets, read from its
    /// credentials (the eBPF source). Audit does not record them.
    pub capabilities: Option<(u64, u64)>,
}

/// Every rule-relevant call in `text`, in record order.
#[must_use]
pub fn parse(text: &str) -> Vec<SyscallEvent> {
    let mut order: Vec<&str> = Vec::new();
    let mut groups: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for line in text.lines() {
        let Some(id) = audit_id(line) else { continue };
        let group = groups.entry(id).or_default();
        if group.is_empty() {
            order.push(id);
        }
        group.push(line);
    }
    order
        .into_iter()
        .filter_map(|id| event(id, groups.get(id)?))
        .collect()
}

fn event(id: &str, lines: &[&str]) -> Option<SyscallEvent> {
    let call = lines.iter().find(|l| l.starts_with("type=SYSCALL "))?;
    let raw = field(call, "syscall")?;
    let syscall = match raw.parse::<u32>() {
        Ok(number) => numbered(Arch::of(call)?, number)?,
        Err(_) => named(raw)?,
    };
    let cwd = lines
        .iter()
        .find(|l| l.starts_with("type=CWD "))
        .and_then(|l| text(l, "cwd"));
    let named: Vec<(String, String)> = lines
        .iter()
        .filter(|l| l.starts_with("type=PATH "))
        .filter_map(|l| {
            Some((
                text(l, "name")?,
                field(l, "nametype").unwrap_or("").to_owned(),
            ))
        })
        .take(MAX_PATHS)
        .collect();
    // A directory descriptor's path, when the call used one, is the PARENT.
    let parent = named
        .iter()
        .find(|(name, kind)| kind == "PARENT" && name.starts_with('/'))
        .map(|(name, _)| name.clone());
    let paths = named
        .into_iter()
        .map(|(raw, nametype)| AuditPath {
            name: absolute(&raw, parent.as_deref().or(cwd.as_deref())),
            raw,
            nametype,
        })
        .collect();
    let sockaddr = lines
        .iter()
        .find(|l| l.starts_with("type=SOCKADDR "))
        .and_then(|l| field(l, "saddr"))
        .and_then(socket_address);
    let argv = lines
        .iter()
        .find(|l| l.starts_with("type=EXECVE "))
        .map(|l| arguments(l))
        .unwrap_or_default();
    Some(SyscallEvent {
        source: CallSource::Audit,
        record: id.to_owned(),
        at: audit_time_ms(id)?,
        pid: number(call, "pid")?,
        ppid: number(call, "ppid"),
        syscall,
        success: field(call, "success") == Some("yes"),
        exit: field(call, "exit").and_then(|v| v.parse().ok()),
        args: ["a0", "a1", "a2", "a3"].map(|a| field(call, a).and_then(hex_number)),
        uid: number(call, "uid"),
        auid: number(call, "auid").filter(|auid| *auid != u32::MAX),
        tty: field(call, "tty").filter(|t| *t != "(none)").map(bounded),
        comm: text(call, "comm"),
        exe: text(call, "exe"),
        cwd,
        paths,
        sockaddr,
        argv,
        pid_namespace: None,
        socket: None,
        container: None,
        ancestors: Vec::new(),
        capabilities: None,
    })
}

fn number(line: &str, name: &str) -> Option<u32> {
    field(line, name)?.parse().ok()
}

fn hex_number(value: &str) -> Option<u64> {
    u64::from_str_radix(value, 16).ok()
}

fn bounded(text: &str) -> String {
    text.chars().take(MAX_TEXT).collect()
}

/// A text field: quoted, or hex when it held a space or anything unprintable.
/// `(null)` and `(none)` are no value.
fn text(line: &str, name: &str) -> Option<String> {
    let marker = format!(" {name}=");
    let rest = line.split_once(&marker)?.1;
    decode(rest)
}

fn decode(rest: &str) -> Option<String> {
    if let Some(quoted) = rest.strip_prefix('"') {
        return Some(bounded(&quoted[..quoted.find('"')?]));
    }
    let token = rest.split_whitespace().next()?;
    if matches!(token, "(null)" | "(none)") {
        return None;
    }
    if token.len() % 2 == 0 && token.len() <= MAX_TEXT * 2 {
        let bytes: Option<Vec<u8>> = (0..token.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(token.get(at..at + 2)?, 16).ok())
            .collect();
        if let Some(bytes) = bytes {
            return Some(bounded(&String::from_utf8_lossy(&bytes)));
        }
    }
    Some(bounded(token))
}

/// An exec's arguments. A long one is split into `aN[0]`, `aN[1]`… chunks.
fn arguments(line: &str) -> Vec<String> {
    let argc: usize = field(line, "argc")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
        .min(MAX_ARGS);
    (0..argc)
        .map(|index| {
            text(line, &format!("a{index}")).unwrap_or_else(|| {
                let mut joined = String::new();
                for chunk in 0..64 {
                    match text(line, &format!("a{index}[{chunk}]")) {
                        Some(part) if joined.len() < MAX_TEXT => joined.push_str(&part),
                        _ => break,
                    }
                }
                bounded(&joined)
            })
        })
        .collect()
}

/// A path under `base` unless it is already absolute.
fn absolute(name: &str, base: Option<&str>) -> String {
    if name.starts_with('/') {
        return name.to_owned();
    }
    match base {
        Some(base) => bounded(&format!("{}/{name}", base.trim_end_matches('/'))),
        None => name.to_owned(),
    }
}

/// `saddr`: the kernel's `sockaddr`, hex. Family is little-endian, the port
/// big-endian.
pub(crate) fn socket_address(hex: &str) -> Option<SocketAddress> {
    let bytes: Vec<u8> = (0..hex.len().min(512))
        .step_by(2)
        .map(|at| u8::from_str_radix(hex.get(at..at + 2)?, 16).ok())
        .collect::<Option<_>>()?;
    let family = u16::from_le_bytes([*bytes.first()?, *bytes.get(1)?]);
    let port = || Some(u16::from_be_bytes([*bytes.get(2)?, *bytes.get(3)?]));
    match family {
        2 => {
            let octets: [u8; 4] = bytes.get(4..8)?.try_into().ok()?;
            Some(SocketAddress {
                family,
                host: std::net::Ipv4Addr::from(octets).to_string(),
                port: port()?,
            })
        }
        10 => {
            let octets: [u8; 16] = bytes.get(8..24)?.try_into().ok()?;
            Some(SocketAddress {
                family,
                host: std::net::Ipv6Addr::from(octets).to_string(),
                port: port()?,
            })
        }
        1 => {
            let path: Vec<u8> = bytes
                .get(2..)?
                .iter()
                .copied()
                .take_while(|b| *b != 0)
                .collect();
            Some(SocketAddress {
                family,
                host: bounded(&String::from_utf8_lossy(&path)),
                port: 0,
            })
        }
        _ => None,
    }
}
