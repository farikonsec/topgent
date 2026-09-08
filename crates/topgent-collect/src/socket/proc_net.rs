//! The kernel's own socket tables, read directly.
//!
//! # Why this exists
//!
//! The Linux socket collector ran `ss` and parsed its output. That single
//! choice is the reason three things exist: an output parser per platform, a
//! sensor that reports `permission_required` when a tool prints nothing
//! useful, and the binary-attestation subsystem, built because `PATH` is
//! writable by the very agents being watched. A file read has no `PATH` to
//! poison, no output format that can change under a distribution upgrade, and
//! no binary to attest.
//!
//! # Why not the `listeners` crate
//!
//! It was the obvious candidate and it does not fit, which was worth finding
//! out before depending on it. Its parser reads `/proc/net/tcp` with no state
//! filter, so despite the name it does return established sockets. But it
//! keeps only `local_addr`: the remote address is parsed past and discarded.
//! Sniffnet can live with that because it already holds the packet and only
//! needs a pid for the local port. Topgent cannot: every network factor it has
//! is about where an agent connected *to*. `SUSPICIOUS_ENDPOINT`,
//! `PRIVATE_PEER`, `METADATA_SERVICE` and `RECON_FANOUT` are all questions
//! about the peer, and a source that throws the peer away answers none of
//! them.
//!
//! # What this reads
//!
//! `/proc/net/tcp` and `/proc/net/tcp6`, which give local address, remote
//! address, connection state and the socket inode. The inode is then matched
//! against `/proc/<pid>/fd/*`, where a socket file descriptor is a symlink
//! reading `socket:[12345]`. That is the same route `ss` takes; this simply
//! takes it without a subprocess in the middle.
//!
//! Byte counters are not here. They come from `tcp_info`, which the table does
//! not carry, so a row from this source leaves them `None` — which means "this
//! source does not count", never zero.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::row::SocketRow;
use topgent_facts::{Direction, Protocol};

/// The state value `/proc/net/tcp` uses for a listening socket.
const TCP_LISTEN: u8 = 0x0A;

/// Most rows read from one table.
///
/// A host with more sockets than this has something wrong with it, and reading
/// an unbounded table into memory is how a monitor becomes the incident.
const MAX_ROWS: usize = 8192;

/// Most process directories walked when mapping inodes to pids.
///
/// The parsers below are tested and fuzzed on every platform; only the two
/// functions that touch `/proc` are Linux-only, and they are gated rather than
/// left to warn everywhere else.
#[cfg(target_os = "linux")]
const MAX_PROCS: usize = 4096;

/// One row of a kernel socket table, before a pid is attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableRow {
    /// Peer address, or the bind address when listening.
    pub host: String,
    /// Peer port, or the bound port when listening.
    pub port: u16,
    /// Which way it goes.
    pub direction: Direction,
    /// The socket inode, which is what ties a row to a process.
    pub inode: u64,
}

/// Parses one `/proc/net/tcp` or `/proc/net/tcp6` table.
///
/// The input is a kernel-owned file, but it is parsed as though it were not:
/// every field is checked, a malformed line is skipped rather than guessed at,
/// and the row count is bounded.
#[must_use]
pub fn parse_table(text: &str) -> Vec<TableRow> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        if out.len() >= MAX_ROWS {
            break;
        }
        if let Some(row) = parse_line(line) {
            out.push(row);
        }
    }
    out
}

fn parse_line(line: &str) -> Option<TableRow> {
    let mut fields = line.split_whitespace();
    // sl, local_address, rem_address, st, ... , inode
    let _sl = fields.next()?;
    let local = fields.next()?;
    let remote = fields.next()?;
    let state = u8::from_str_radix(fields.next()?, 16).ok()?;
    let inode = fields.nth(5)?.parse::<u64>().ok()?;

    // Both addresses are decoded even though only one is reported. A line
    // whose local address will not parse is a line this code did not fully
    // understand, and half-reading a kernel table is how a wrong endpoint
    // reaches a report looking exactly like a right one.
    parse_address(local)?;
    parse_address(remote)?;

    let listening = state == TCP_LISTEN;
    // A listening socket has no peer, and the kernel writes zeros there. The
    // bind address is the truthful thing to report for it.
    let (address, direction) = if listening {
        (local, Direction::Listening)
    } else {
        (remote, Direction::Outbound)
    };
    let (host, port) = parse_address(address)?;
    Some(TableRow {
        host,
        port,
        direction,
        inode,
    })
}

/// Every local port in one `/proc/net` socket table, with the inode holding it.
///
/// Deliberately separate from [`parse_table`], which reads the peer end and
/// applies TCP state semantics. Those semantics do not hold for `/proc/net/udp`,
/// where the state column means something else entirely, and a port map that
/// quietly read a UDP row as a listening TCP socket would attribute packets to
/// the wrong process rather than to none.
///
/// This is what ties a captured packet to a process: the packet names a local
/// port, this names who holds it. It is the same join the operating system's
/// own tools make, and the same one Sniffnet makes, because a packet carries
/// no process id and never has.
#[must_use]
pub fn parse_local_ports(text: &str) -> Vec<LocalPort> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        if out.len() >= MAX_ROWS {
            break;
        }
        if let Some(row) = parse_local_port(line) {
            out.push(row);
        }
    }
    out
}

/// One local port, who holds it, and whether it is waiting to be called.
///
/// The last part is what decides a flow's direction. A packet on its own
/// cannot say: a connection this host opened carries replies from the peer,
/// and reading each packet's own direction turns one outgoing connection into
/// an outgoing flow and an incoming one. That is not a cosmetic double count.
/// An inbound flow reads as a listener, and a listener is a scored finding, so
/// every ordinary outbound connection would have produced one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalPort {
    /// The port this host holds.
    pub port: u16,
    /// The socket inode, which is what ties it to a process.
    pub inode: u64,
    /// Whether the socket is listening rather than connected outward.
    pub listening: bool,
}

fn parse_local_port(line: &str) -> Option<LocalPort> {
    let (port, inode, listening) = parse_local(line)?;
    // A socket bound to port zero holds no port anything could be attributed
    // through, so it is not a row this map has any use for.
    if port == 0 {
        return None;
    }
    Some(LocalPort {
        port,
        inode,
        listening,
    })
}

/// Every socket inode in one `/proc/net` table, whatever its local port.
///
/// `/proc/net/raw` and `/proc/net/icmp` put a protocol number or a message id
/// in the column the others use for a port, so a port is not a useful key
/// there and the inode alone is what the caller wants.
#[must_use]
pub fn parse_inodes(text: &str) -> Vec<u64> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        if out.len() >= MAX_ROWS {
            break;
        }
        if let Some((_, inode, _)) = parse_local(line) {
            out.push(inode);
        }
    }
    out
}

/// The local port and the inode from one row of any `/proc/net` socket table.
///
/// All of them share a column layout, which is why one reader serves the port
/// map, the raw-socket lookup, and anything else that needs to know who holds
/// what.
fn parse_local(line: &str) -> Option<(u16, u64, bool)> {
    let mut fields = line.split_whitespace();
    let _sl = fields.next()?;
    let (_, port) = parse_address(fields.next()?)?;
    let _remote = fields.next()?;
    let listening = u8::from_str_radix(fields.next()?, 16).ok()? == TCP_LISTEN;
    // tx_rx_queue, tr_tm_when, retrnsmt, uid, timeout, inode
    let inode = fields.nth(5)?.parse::<u64>().ok()?;
    Some((port, inode, listening))
}

/// Decodes the kernel's hex address form.
///
/// IPv4 is a little-endian 32-bit word; IPv6 is four such words, each of which
/// is byte-reversed independently. Getting that wrong produces addresses that
/// look plausible and are wrong, which is worse than failing.
#[must_use]
pub fn parse_address(field: &str) -> Option<(String, u16)> {
    let (address, port) = field.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    match address.len() {
        8 => {
            let raw = u32::from_str_radix(address, 16).ok()?;
            Some((Ipv4Addr::from(raw.to_be()).to_string(), port))
        }
        32 => {
            let mut octets = [0_u8; 16];
            for word in 0..4 {
                let start = word * 8;
                let hex = address.get(start..start + 8)?;
                let raw = u32::from_str_radix(hex, 16).ok()?;
                let bytes = raw.to_le_bytes();
                for (index, byte) in bytes.iter().enumerate() {
                    *octets.get_mut(word * 4 + index)? = *byte;
                }
            }
            let v6 = Ipv6Addr::from(octets);
            // A mapped address is an IPv4 socket the kernel happened to list in
            // the v6 table. Reporting `::ffff:10.0.0.1` where every other
            // source says `10.0.0.1` would split one endpoint into two.
            Some((
                v6.to_ipv4_mapped()
                    .map_or_else(|| IpAddr::V6(v6).to_string(), |v4| v4.to_string()),
                port,
            ))
        }
        _ => None,
    }
}

/// Maps socket inodes to the processes holding them.
///
/// A socket file descriptor is a symlink reading `socket:[12345]`. Walking
/// every process's descriptors is what `ss -p` does; a descriptor belonging to
/// another user is simply unreadable, and that is an ordinary answer rather
/// than a failure.
#[cfg(target_os = "linux")]
#[must_use]
pub fn inode_owners() -> BTreeMap<u64, u32> {
    let mut owners = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return owners;
    };
    for entry in entries.flatten().take(MAX_PROCS) {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            if let Some(inode) = target
                .to_str()
                .and_then(|link| link.strip_prefix("socket:["))
                .and_then(|rest| rest.strip_suffix(']'))
                .and_then(|digits| digits.parse::<u64>().ok())
            {
                // First writer wins. Two processes sharing one socket through
                // a fork is real, and picking either consistently beats
                // reporting the endpoint twice.
                owners.entry(inode).or_insert(pid);
            }
        }
    }
    owners
}

/// Joins parsed tables to their owning processes.
#[must_use]
pub fn attribute(rows: Vec<TableRow>, owners: &BTreeMap<u64, u32>) -> Vec<SocketRow> {
    rows.into_iter()
        .filter_map(|row| {
            // A socket Topgent cannot attribute to a pid is not evidence about
            // any agent, which is the same rule the `ss` parser applies.
            let pid = *owners.get(&row.inode)?;
            Some(SocketRow {
                protocol: Protocol::Tcp,
                pid,
                host: row.host,
                port: row.port,
                direction: row.direction,
                // The table carries no creation time and no counters. Absent
                // rather than zero: one means the source does not say, the
                // other would be a measurement nobody took.
                opened_at: None,
                bytes: None,
            })
        })
        .collect()
}

/// Every TCP socket this host holds, attributed to processes.
///
/// Returns an empty vector when `/proc` is not readable, which a caller treats
/// as "this source said nothing" and falls back rather than reporting a host
/// with no sockets.
#[cfg(target_os = "linux")]
#[must_use]
pub fn snapshot() -> Vec<SocketRow> {
    let mut rows = Vec::new();
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(text) = std::fs::read_to_string(table) {
            rows.extend(parse_table(&text));
        }
    }
    if rows.is_empty() {
        return Vec::new();
    }
    attribute(rows, &inode_owners())
}
