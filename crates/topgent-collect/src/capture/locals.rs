//! Which addresses belong to this host.
//!
//! # Why this exists
//!
//! A captured frame has two ends and says nothing about which of them is here.
//! Direction is decided by looking one of them up in this set, never guessed
//! from a port number: "the low port is the server" is a convention, and an
//! agent opening a listener on 61234 breaks it in exactly the case worth
//! catching.
//!
//! # Where it comes from
//!
//! Two kernel files, read and parsed as though they were hostile input even
//! though the kernel wrote them.
//!
//! `/proc/net/fib_trie` holds every local IPv4 address as an indented line
//! followed by a line marking it a host route. Only `/32` counts: the loopback
//! entry also appears as `/8 host LOCAL`, which is the subnet and not an
//! address this host answers on.
//!
//! `/proc/net/if_inet6` holds every local IPv6 address, one per line, as
//! thirty-two hex characters.
//!
//! Neither is the whole truth on a host whose addresses change mid-capture,
//! which is why the set is rebuilt each time flows are drained rather than
//! read once at startup.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Most addresses read from either file.
///
/// A host with more than this has a routing table nobody should be parsing
/// into memory, and the loop that reads it is not the place to find that out.
const MAX_ADDRESSES: usize = 512;

/// The marker `/proc/net/fib_trie` writes beside a local host address.
const HOST_ROUTE: &str = "/32 host LOCAL";

/// The prefix `/proc/net/fib_trie` writes before every leaf address.
const LEAF: &str = "|-- ";

/// Every local IPv4 address named in a `/proc/net/fib_trie` dump.
///
/// The file is a tree rendering, so an address appears once per table it is
/// in. Duplicates are dropped here rather than left for the caller.
#[must_use]
pub fn parse_fib_trie(text: &str) -> Vec<Ipv4Addr> {
    let mut out: Vec<Ipv4Addr> = Vec::new();
    let mut previous: Option<Ipv4Addr> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.contains(HOST_ROUTE) {
            if let Some(address) = previous.take()
                && out.len() < MAX_ADDRESSES
                && !out.contains(&address)
            {
                out.push(address);
            }
            continue;
        }
        // A leaf line names an address; anything else clears the pending one,
        // so a marker can only ever claim the line directly above it.
        previous = trimmed
            .strip_prefix(LEAF)
            .and_then(|rest| rest.trim().parse::<Ipv4Addr>().ok());
    }
    out
}

/// Every local IPv6 address named in a `/proc/net/if_inet6` dump.
#[must_use]
pub fn parse_if_inet6(text: &str) -> Vec<Ipv6Addr> {
    let mut out: Vec<Ipv6Addr> = Vec::new();
    for line in text.lines() {
        if out.len() >= MAX_ADDRESSES {
            break;
        }
        let Some(field) = line.split_whitespace().next() else {
            continue;
        };
        if let Some(address) = parse_hex_v6(field)
            && !out.contains(&address)
        {
            out.push(address);
        }
    }
    out
}

/// Decodes the thirty-two-character hex form `/proc/net/if_inet6` uses.
///
/// Unlike the socket tables, this one is written in network order throughout,
/// so there is no word-reversal to undo. Reading it as though there were
/// produces addresses that look plausible and are wrong.
fn parse_hex_v6(field: &str) -> Option<Ipv6Addr> {
    if field.len() != 32 || !field.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut groups = [0u16; 8];
    for (index, group) in groups.iter_mut().enumerate() {
        let start = index * 4;
        let text = field.get(start..start + 4)?;
        *group = u16::from_str_radix(text, 16).ok()?;
    }
    Some(Ipv6Addr::from(groups))
}

/// Every address this host answers on, as far as the kernel will say.
///
/// Returns an empty vector where neither file can be read, which a caller
/// treats as "direction cannot be decided" and drops the frame, rather than
/// reporting every packet as outbound.
#[cfg(target_os = "linux")]
#[must_use]
pub fn addresses() -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    if let Ok(text) = std::fs::read_to_string("/proc/net/fib_trie") {
        out.extend(parse_fib_trie(&text).into_iter().map(IpAddr::V4));
    }
    if let Ok(text) = std::fs::read_to_string("/proc/net/if_inet6") {
        out.extend(parse_if_inet6(&text).into_iter().map(IpAddr::V6));
    }
    out
}

/// The same set, from the only listing macOS offers without unsafe code.
///
/// There is no `fib_trie` here and no `getifaddrs` this crate may call, so the
/// addresses come from the local end of every socket the machine holds. That
/// is complete for any address traffic is actually flowing on, which is the
/// only kind a capture has to decide the direction of, plus the loopback
/// addresses, which are always this host whether a socket names them or not.
#[cfg(target_os = "macos")]
#[must_use]
pub fn addresses() -> Vec<IpAddr> {
    let mut out = vec![
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ];
    let Ok(mut command) = crate::tool::LSOF.command() else {
        return out;
    };
    let Ok(listing) = command.args(["-i", "-n", "-P"]).output() else {
        return out;
    };
    for address in parse_lsof_addresses(&String::from_utf8_lossy(&listing.stdout)) {
        if out.len() < MAX_ADDRESSES && !out.contains(&address) {
            out.push(address);
        }
    }
    out
}

/// Every local address named in an `lsof -i -n -P` listing.
///
/// The wildcard is not an address: a socket bound to every interface names
/// none of them, and admitting `*` would put a host in the set that no packet
/// can carry.
#[must_use]
pub fn parse_lsof_addresses(out: &str) -> Vec<IpAddr> {
    let mut found = Vec::new();
    for line in out.lines().skip(1) {
        let Some(name) = line.split_whitespace().nth(8) else {
            continue;
        };
        let local = name.split_once("->").map_or(name, |(local, _)| local);
        let Some((host, _)) = local.rsplit_once(':') else {
            continue;
        };
        let host = host.trim_matches(['[', ']']);
        if let Ok(address) = host.parse::<IpAddr>()
            && found.len() < MAX_ADDRESSES
            && !found.contains(&address)
        {
            found.push(address);
        }
    }
    found
}

/// The same set, from the listing Windows offers.
#[cfg(windows)]
#[must_use]
pub fn addresses() -> Vec<IpAddr> {
    let mut out = vec![
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ];
    let Ok(mut command) = crate::tool::NETSTAT.command() else {
        return out;
    };
    let Ok(listing) = command.args(["-a", "-n", "-o"]).output() else {
        return out;
    };
    let text = String::from_utf8_lossy(&listing.stdout);
    for address in crate::socket::parse_windows_netstat_addresses(&text) {
        if out.len() < MAX_ADDRESSES && !out.contains(&address) {
            out.push(address);
        }
    }
    out
}

/// See the Linux note. No other platform reaches the capture loop.
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
#[must_use]
pub fn addresses() -> Vec<IpAddr> {
    Vec::new()
}
