//! One frame off the wire, reduced to the four things a finding needs.
//!
//! # What is kept
//!
//! Protocol, peer address, peer port, direction. Nothing else. There is no
//! field on [`Observed`] that can hold a payload, which is how the promise in
//! the consent dialog is kept: not by remembering to discard the body, but by
//! having nowhere to put it.
//!
//! # What is borrowed and what is not
//!
//! The shape of this layer follows Sniffnet: parse headers, reduce to an
//! address pair, and let something else do attribution. The parsing itself is
//! `etherparse`, which is what Sniffnet uses too, and for the same reason —
//! walking IPv6 extension headers by hand in a security tool is how a monitor
//! becomes the vulnerability. None of their code is here; the vocabulary,
//! the direction rule and the bounds are this project's.
//!
//! # Direction
//!
//! Decided by which end is one of this host's own addresses, never guessed
//! from a port number. A packet with neither end local is not this host's
//! traffic and is dropped: on a shared segment it belongs to somebody else,
//! and attributing it here would be inventing evidence.

use std::net::IpAddr;

use topgent_facts::{Direction, Protocol};

/// Longest frame this reads.
///
/// Jumbo frames exist; a capture handle configured for more than this is
/// configured wrong, and refusing is cheaper than trusting a length field.
pub const MAX_FRAME: usize = 65_536;

/// What one packet says, and nothing more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    /// Which protocol carried it.
    pub protocol: Protocol,
    /// The other end. Never this host.
    pub peer: IpAddr,
    /// The other end's port, or zero where the protocol has none.
    ///
    /// Zero is not a port. ICMP has no ports at all, and the protocol beside
    /// it is what says whether zero means "none" or "unread".
    pub peer_port: u16,
    /// This host's port, which is what ties the packet to a process.
    pub local_port: u16,
    /// Which way it went.
    pub direction: Direction,
}

/// What the capture handle put at the front of each frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    /// An Ethernet header.
    Ethernet,
    /// No link header: the frame starts at the IP header.
    Raw,
    /// Four bytes naming an address family, then the IP header.
    ///
    /// What a loopback interface hands over on the BSDs, macOS included. The
    /// four bytes are read past rather than parsed: they say IPv4 or IPv6, and
    /// the internet header says the same thing one byte later in a form this
    /// already reads. Two sources for one fact is a way for them to disagree.
    Null,
}

/// The address-family header a loopback frame carries.
const NULL_HEADER: usize = 4;

/// Reduces one frame to what a finding needs, or nothing.
///
/// Returns `None` for every frame this host is not one end of, every protocol
/// this build does not model, and every frame that will not parse. All three
/// are ordinary and none is an error: a capture sees a great deal that is not
/// evidence about anything.
#[must_use]
pub fn parse(frame: &[u8], link: LinkKind, locals: &[IpAddr]) -> Option<Observed> {
    if frame.is_empty() || frame.len() > MAX_FRAME {
        return None;
    }
    // Lax parsing, because every frame this reads is truncated by design. The
    // capture buffer holds headers only, so an internet header that declares a
    // fifteen-hundred-byte packet is followed by two hundred and forty-two
    // bytes of slice, and a strict parser calls that a length error and
    // refuses. It refuses *correctly* — the frame really is short — but the
    // effect is a capture that sees only packets small enough to fit, which is
    // roughly none of the ones worth seeing. The lax reader is built for
    // exactly this and stops at the last header it can read in full.
    let headers = match link {
        LinkKind::Ethernet => etherparse::LaxPacketHeaders::from_ethernet(frame).ok()?,
        LinkKind::Raw => etherparse::LaxPacketHeaders::from_ip(frame).ok()?,
        LinkKind::Null => etherparse::LaxPacketHeaders::from_ip(frame.get(NULL_HEADER..)?).ok()?,
    };
    let (source, destination) = addresses(headers.net.as_ref()?)?;
    let direction = direction_of(source, destination, locals)?;
    let (protocol, source_port, destination_port) = transport(headers.transport.as_ref());

    // The peer is whichever end is not this host, which follows from the
    // direction rather than being decided again.
    let (peer, peer_port, local_port) = match direction {
        Direction::Outbound => (destination, destination_port, source_port),
        Direction::Listening => (source, source_port, destination_port),
    };
    // A packet on a port-bearing protocol with no local port cannot be tied to
    // any process: there is no socket on port zero for the inode map to find.
    // The socket collector applies the same rule and says so — a socket
    // Topgent cannot attribute is not evidence about any agent — and a crafted
    // frame carrying port zero would otherwise become an unattributable
    // endpoint in somebody's report. Found by the fuzz target.
    if local_port == 0 && matches!(protocol, Protocol::Tcp | Protocol::Udp) {
        return None;
    }
    Some(Observed {
        protocol,
        peer,
        peer_port,
        local_port,
        direction,
    })
}

/// The two addresses, whichever internet protocol carried them.
fn addresses(net: &etherparse::NetHeaders) -> Option<(IpAddr, IpAddr)> {
    match net {
        etherparse::NetHeaders::Ipv4(header, _) => Some((
            IpAddr::from(header.source),
            IpAddr::from(header.destination),
        )),
        etherparse::NetHeaders::Ipv6(header, _) => Some((
            IpAddr::from(header.source),
            IpAddr::from(header.destination),
        )),
        // ARP names no internet peer, so there is no endpoint to report and
        // nothing to attribute it to.
        etherparse::NetHeaders::Arp(_) => None,
    }
}

/// Which way the packet went, or `None` when this host is neither end.
///
/// A packet with no local end is somebody else's traffic. On a shared segment
/// or a mirror port there is plenty of it, and reporting it as an agent's
/// would be inventing evidence.
fn direction_of(source: IpAddr, destination: IpAddr, locals: &[IpAddr]) -> Option<Direction> {
    let from_here = locals.contains(&source);
    let to_here = locals.contains(&destination);
    match (from_here, to_here) {
        // This host at both ends. Real traffic, and the peer is legitimately
        // local: an agent connecting to a service on 127.0.0.1, or to a
        // listener bound on this machine's own LAN address. Dropping it would
        // lose exactly the findings the lab exercises, so it is kept and read
        // as outbound, because something here initiated it.
        (true, _) => Some(Direction::Outbound),
        (false, true) => Some(Direction::Listening),
        (false, false) => None,
    }
}

/// The protocol and its ports, where it has them.
fn transport(transport: Option<&etherparse::TransportHeader>) -> (Protocol, u16, u16) {
    match transport {
        Some(etherparse::TransportHeader::Tcp(header)) => {
            (Protocol::Tcp, header.source_port, header.destination_port)
        }
        Some(etherparse::TransportHeader::Udp(header)) => {
            (Protocol::Udp, header.source_port, header.destination_port)
        }
        Some(etherparse::TransportHeader::Icmpv4(_) | etherparse::TransportHeader::Icmpv6(_)) => {
            // No ports exist. Zero here means "this protocol has none", which
            // is why `Observed` carries the protocol beside the number.
            (Protocol::Icmp, 0, 0)
        }
        // Something this build does not model, or a header it could not read.
        // The addresses are still true, so the packet is reported with the
        // protocol saying it was not identified.
        _ => (Protocol::Other, 0, 0),
    }
}
