//! Which process holds which local port.
//!
//! # Why attribution is a join and not a read
//!
//! A packet carries no process id. It never has, on any operating system, and
//! no capture tool gets one out of the wire. What a packet carries is a local
//! port, and what the kernel keeps is a table saying who holds that port; the
//! owning process is the join of the two. Sniffnet is often credited with fast
//! per-process attribution and does exactly this, and so does `ss -p`.
//!
//! # What that costs, stated rather than discovered
//!
//! The join is a snapshot. A short-lived socket that closed before the map was
//! rebuilt has no owner in it, and the flow it carried is dropped rather than
//! attributed to whichever process later took the port. Reusing a port is
//! normal, and pinning one agent's traffic on another because the numbers line
//! up would be inventing evidence.
//!
//! # Both protocols, keyed apart
//!
//! TCP 8080 and UDP 8080 are different sockets and can belong to different
//! processes, so the key carries the protocol. Collapsing them was never worth
//! the smaller map.

use std::collections::BTreeMap;

use topgent_facts::Protocol;

/// The tables read, and what each one carries.
///
/// UDP is the reason this list is not the socket collector's. That collector
/// reports TCP and says so in its own boundary text; a captured UDP flow has
/// no owner at all without these two.
#[cfg(target_os = "linux")]
const TABLES: &[(&str, Protocol)] = &[
    ("/proc/net/tcp", Protocol::Tcp),
    ("/proc/net/tcp6", Protocol::Tcp),
    ("/proc/net/udp", Protocol::Udp),
    ("/proc/net/udp6", Protocol::Udp),
];

/// What is known about the process holding one local port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owner {
    /// The process, or the agent above it once the map is joined.
    pub pid: u32,
    /// Whether the socket is waiting to be called rather than calling out.
    ///
    /// This is what decides a flow's direction, because a packet cannot. A
    /// connection this host opened carries replies from the peer, and reading
    /// each packet's own direction splits one conversation into an outbound
    /// flow and an inbound one. The inbound half then reads as a listener,
    /// which is a scored finding, so every ordinary outbound connection an
    /// agent made would have produced one.
    pub listening: bool,
}

/// Who holds each local port, by protocol.
pub type Owners = BTreeMap<(Protocol, u16), Owner>;

/// Builds the port map from a set of already-read tables.
///
/// Split from the reading so the join itself is testable on every platform
/// rather than only on the one that has a `/proc`.
#[must_use]
pub fn join(
    tables: &[(Protocol, Vec<crate::socket::LocalPort>)],
    inodes: &BTreeMap<u64, u32>,
) -> Owners {
    let mut owners = Owners::new();
    for (protocol, rows) in tables {
        for row in rows {
            let Some(pid) = inodes.get(&row.inode) else {
                continue;
            };
            // First writer wins, matching the inode map's own rule. A port
            // held through a fork belongs to both processes, and picking
            // either consistently beats reporting the flow twice.
            owners.entry((*protocol, row.port)).or_insert(Owner {
                pid: *pid,
                listening: row.listening,
            });
        }
    }
    owners
}

/// Reads every socket table and joins it to the processes holding them.
///
/// Returns an empty map where `/proc` cannot be read, which a caller treats as
/// "nothing can be attributed this cycle" and not as "nothing is running".
#[cfg(target_os = "linux")]
#[must_use]
pub fn owners() -> Owners {
    let mut tables = Vec::new();
    for (path, protocol) in TABLES {
        if let Ok(text) = std::fs::read_to_string(path) {
            tables.push((*protocol, crate::socket::parse_local_ports(&text)));
        }
    }
    if tables.is_empty() {
        return Owners::new();
    }
    join(&tables, &crate::socket::inode_owners())
}

/// The tables holding sockets that can send and receive ICMP.
///
/// Two kinds. A raw socket is the privileged form and the one worth watching;
/// the datagram form is what an ordinary `ping` uses on a modern kernel, and
/// it belongs here too or a ping is captured and attributed to nobody.
#[cfg(target_os = "linux")]
const ICMP_TABLES: &[&str] = &[
    "/proc/net/raw",
    "/proc/net/raw6",
    "/proc/net/icmp",
    "/proc/net/icmp6",
];

/// Decides who an ICMP flow belongs to, when that can be decided at all.
///
/// ICMP carries no port, so the join the rest of this module makes is not
/// available: there is no number on the packet to look up. What there is, is
/// the set of processes holding a socket that could have sent it, and when
/// that set has exactly one member the answer is not in doubt.
///
/// When it has more than one, this returns nothing and the flow is reported as
/// unattributed. Picking the likeliest of several would be a guess printed as
/// an observation, which is the one thing this tool does not do.
#[must_use]
pub fn icmp_holder() -> Option<u32> {
    sole(&icmp_pids())
}

/// The single element of a set, or nothing.
#[must_use]
pub fn sole(pids: &[u32]) -> Option<u32> {
    match pids {
        [only] => Some(*only),
        _ => None,
    }
}

/// Every process holding a socket that could carry ICMP.
#[cfg(target_os = "linux")]
#[must_use]
fn icmp_pids() -> Vec<u32> {
    let mut inodes = Vec::new();
    for path in ICMP_TABLES {
        if let Ok(text) = std::fs::read_to_string(path) {
            inodes.extend(crate::socket::parse_inodes(&text));
        }
    }
    if inodes.is_empty() {
        return Vec::new();
    }
    let holders = crate::socket::inode_owners();
    let mut pids: Vec<u32> = inodes
        .iter()
        .filter_map(|inode| holders.get(inode).copied())
        .collect();
    pids.sort_unstable();
    pids.dedup();
    pids
}

/// The same join, through the only listing macOS offers.
///
/// There is no `/proc` here, so the socket table comes from `lsof` with fixed
/// arguments and nothing interpolated. It is the same tool and the same
/// invocation the socket collector already uses, so this adds no new command
/// to the crate, only a second reading of one it already runs.
///
/// The cost is a subprocess per refresh rather than four file reads. That is
/// why the refresh is bounded by a floor in the capture loop: without one, a
/// port scan would be a request to spawn `lsof` once per packet.
#[cfg(target_os = "macos")]
#[must_use]
pub fn owners() -> Owners {
    let mut owners = Owners::new();
    for (protocol, port, pid, listening) in lsof_rows() {
        owners
            .entry((protocol, port))
            .or_insert(Owner { pid, listening });
    }
    owners
}

/// Every socket `lsof` will name for this account.
///
/// An empty result is "nothing could be listed", which a caller treats as
/// "nothing can be attributed this cycle" and never as "nothing is running".
#[cfg(target_os = "macos")]
#[must_use]
fn lsof_rows() -> Vec<(Protocol, u16, u32, bool)> {
    let Ok(mut command) = crate::tool::LSOF.command() else {
        return Vec::new();
    };
    let Ok(out) = command.args(["-i", "-n", "-P"]).output() else {
        return Vec::new();
    };
    crate::socket::parse_lsof_local(&String::from_utf8_lossy(&out.stdout))
}

/// See the macOS note. ICMP has no port, so the sole-holder rule applies here
/// too, over the raw sockets `lsof` names.
#[cfg(target_os = "macos")]
#[must_use]
fn icmp_pids() -> Vec<u32> {
    let mut pids: Vec<u32> = lsof_rows()
        .into_iter()
        .filter(|(protocol, _, _, _)| *protocol == Protocol::Icmp)
        .map(|(_, _, pid, _)| pid)
        .collect();
    pids.sort_unstable();
    pids.dedup();
    pids
}

/// The same join, through the only listing Windows offers.
///
/// `netstat -ano` names the local endpoint, the state, and the owning process
/// id. It is the same tool and the same fixed arguments the socket collector
/// already runs, read a second way.
#[cfg(windows)]
#[must_use]
pub fn owners() -> Owners {
    let mut owners = Owners::new();
    for (protocol, port, pid, listening) in netstat_rows() {
        owners
            .entry((protocol, port))
            .or_insert(Owner { pid, listening });
    }
    owners
}

/// Every socket `netstat` will name.
#[cfg(windows)]
#[must_use]
fn netstat_rows() -> Vec<(Protocol, u16, u32, bool)> {
    let Ok(mut command) = crate::tool::NETSTAT.command() else {
        return Vec::new();
    };
    let Ok(out) = command.args(["-a", "-n", "-o"]).output() else {
        return Vec::new();
    };
    crate::socket::parse_windows_netstat_local(&String::from_utf8_lossy(&out.stdout))
}

/// Windows names no ICMP socket in `netstat`, so there is nothing to hold the
/// sole-holder rule against and ICMP stays unattributed here.
#[cfg(windows)]
#[must_use]
fn icmp_pids() -> Vec<u32> {
    Vec::new()
}

/// See the Linux note. No other platform reaches the capture loop.
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
#[must_use]
pub fn owners() -> Owners {
    Owners::new()
}

/// See the Linux note. No other platform reaches the capture loop.
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
#[must_use]
fn icmp_pids() -> Vec<u32> {
    Vec::new()
}
