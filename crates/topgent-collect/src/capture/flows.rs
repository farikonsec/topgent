//! What a capture accumulates between two sweeps.
//!
//! # Why anything is accumulated at all
//!
//! A sweep is a snapshot and a capture is a stream, so the two do not meet
//! without something in between. This is that something: packets fold into
//! flows as they arrive, and a sweep takes whatever has built up since the
//! last one. A port scan that lasted forty milliseconds is in there; the
//! socket table it came and went between never saw it.
//!
//! # Why it is bounded
//!
//! A monitor that grows without limit under traffic it does not control is a
//! denial-of-service vector wearing a security tool's name, and a scan of
//! sixty-five thousand ports is a perfectly ordinary way to trigger it. The
//! map has a ceiling. Once it is reached, new flows are counted and dropped
//! rather than admitted, and the count is reported: "there were more than this
//! and we stopped counting them" is a finding, and silently forgetting them is
//! not.
//!
//! Nothing is evicted to make room. An evicting cache would quietly replace
//! the evidence a report is about with whatever arrived most recently.

use std::collections::BTreeMap;
use std::net::IpAddr;

use topgent_facts::{Direction, Protocol, UnixMillis};

/// Most distinct flows held between two sweeps.
///
/// Chosen to be far above what an ordinary host produces in a sweep interval
/// and far below what would matter to the machine.
pub const MAX_FLOWS: usize = 4096;

/// One conversation, as far as a capture can tell.
///
/// The process id is part of the key rather than a field beside it: two
/// processes talking to the same endpoint are two findings, and merging them
/// would attribute one agent's traffic to another.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    /// The process holding the local port, from the socket table.
    pub pid: u32,
    /// Which protocol carried it.
    pub protocol: Protocol,
    /// The other end.
    pub peer: IpAddr,
    /// The other end's port, or zero where the protocol has none.
    pub peer_port: u16,
    /// Which way it went.
    pub direction: Direction,
}

/// How much of one flow was seen, and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seen {
    /// Packets counted. Not bytes: a truncated read cannot measure a payload
    /// it deliberately never received.
    pub packets: u64,
    /// When the first packet of this flow arrived.
    pub first_seen: UnixMillis,
    /// When the most recent one did.
    pub last_seen: UnixMillis,
}

/// What could not be turned into a flow, and why.
///
/// Every one of these is an ordinary outcome of watching a wire, and every one
/// of them is a hole in coverage. Counting them is what lets a report say how
/// complete it is instead of implying it is complete.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Missed {
    /// Frames read off the wire.
    pub frames: u64,
    /// Frames that named no endpoint this build models: ARP, and anything
    /// neither end of which is this host.
    pub not_modelled: u64,
    /// Frames whose local port belonged to no process the socket table knew
    /// about, usually because the socket had already closed.
    pub unattributed: u64,
    /// Flows refused because the map was full.
    pub overflowed: u64,
}

/// How many distinct ports on one host make a scan.
///
/// A browser opens a handful of ports on a server. A scan opens hundreds.
/// Twenty is well above ordinary behaviour and well below what any scanner
/// does, which is where a threshold detector wants to sit. Snort and Zeek
/// count the same way: distinct destination ports per host in a window.
pub const SCAN_PORTS: usize = 20;

/// Most hosts tracked for scanning at once.
const MAX_PROBED: usize = 1024;

/// Most ports remembered per host.
///
/// Past this the answer is already "a scan", and counting further is paying
/// memory for a conclusion that will not change.
const MAX_PORTS_PER_HOST: usize = 256;

/// One host being probed, and how widely.
#[derive(Debug, Clone)]
struct Probed {
    ports: std::collections::BTreeSet<u16>,
    packets: u64,
    first_seen: UnixMillis,
    last_seen: UnixMillis,
}

/// A host that was probed across enough ports to call it a scan.
///
/// Reported about the host on the other end, not about a process, because a
/// scan's connections are refused and refused connections leave no socket for
/// any snapshot to attribute. The traffic is real and its source is not
/// knowable at this tier. Saying so is the finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scan {
    /// The host that was probed.
    pub peer: IpAddr,
    /// How many distinct ports were touched.
    pub ports: usize,
    /// Packets seen towards it.
    pub packets: u64,
    /// When the first was seen.
    pub first_seen: UnixMillis,
    /// When the last was seen.
    pub last_seen: UnixMillis,
}

/// The accumulator itself.
#[derive(Debug, Default)]
pub struct Flows {
    seen: BTreeMap<Key, Seen>,
    probed: BTreeMap<IpAddr, Probed>,
    /// Scans handed over already decided, by a helper that did the counting.
    carried: BTreeMap<IpAddr, Scan>,
    missed: Missed,
}

/// One sweep's worth of capture, taken away from the accumulator.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Drained {
    /// Every flow held, in key order.
    pub flows: Vec<(Key, Seen)>,
    /// What was seen and not kept, over the same interval.
    pub missed: Missed,
    /// Hosts probed across enough ports to call it a scan.
    pub scans: Vec<Scan>,
}

impl Flows {
    /// A new, empty accumulator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Counts a frame that was read, whatever becomes of it.
    pub const fn frame(&mut self) {
        self.missed.frames = self.missed.frames.saturating_add(1);
    }

    /// Counts a frame this build names no endpoint for.
    pub const fn not_modelled(&mut self) {
        self.missed.not_modelled = self.missed.not_modelled.saturating_add(1);
    }

    /// Counts a frame whose local port no process was holding.
    pub const fn unattributed(&mut self) {
        self.missed.unattributed = self.missed.unattributed.saturating_add(1);
    }

    /// Notes one packet towards a host, whoever sent it.
    ///
    /// Called before attribution and regardless of it, which is the point. A
    /// scan's connections are refused, so they leave no socket and cannot be
    /// tied to a process; counting only attributed packets would miss exactly
    /// the traffic this is looking for.
    pub fn probe(&mut self, peer: IpAddr, port: u16, at: UnixMillis) {
        if self.probed.len() >= MAX_PROBED && !self.probed.contains_key(&peer) {
            return;
        }
        let entry = self.probed.entry(peer).or_insert(Probed {
            ports: std::collections::BTreeSet::new(),
            packets: 0,
            first_seen: at,
            last_seen: at,
        });
        entry.packets = entry.packets.saturating_add(1);
        entry.last_seen = UnixMillis(at.0.max(entry.last_seen.0));
        if entry.ports.len() < MAX_PORTS_PER_HOST {
            entry.ports.insert(port);
        }
    }

    /// Folds one attributed packet in.
    pub fn record(&mut self, key: Key, at: UnixMillis) {
        if let Some(seen) = self.seen.get_mut(&key) {
            seen.packets = seen.packets.saturating_add(1);
            // Clocks can go backwards, and a last-seen earlier than a
            // first-seen would render as a negative duration in a report.
            seen.last_seen = UnixMillis(at.0.max(seen.last_seen.0));
            return;
        }
        if self.seen.len() >= MAX_FLOWS {
            self.missed.overflowed = self.missed.overflowed.saturating_add(1);
            return;
        }
        self.seen.insert(
            key,
            Seen {
                packets: 1,
                first_seen: at,
                last_seen: at,
            },
        );
    }

    /// How many distinct flows are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether nothing has been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Folds a whole interval in at once.
    ///
    /// What the helper hands over is already aggregated, so replaying it
    /// packet by packet would be counting a number back up from itself. The
    /// counts are added directly.
    ///
    /// Scans are the one lossy part. The wire form carries how many distinct
    /// ports were touched and not which ones, so two intervals covering the
    /// same host cannot be unioned: the larger count is kept and the packets
    /// are summed. That understates a scan spread across intervals and never
    /// overstates one, which is the right direction for a finding.
    pub fn absorb(&mut self, other: Drained) {
        for (key, seen) in other.flows {
            if let Some(held) = self.seen.get_mut(&key) {
                held.packets = held.packets.saturating_add(seen.packets);
                held.first_seen = UnixMillis(held.first_seen.0.min(seen.first_seen.0));
                held.last_seen = UnixMillis(held.last_seen.0.max(seen.last_seen.0));
            } else if self.seen.len() >= MAX_FLOWS {
                self.missed.overflowed = self.missed.overflowed.saturating_add(1);
            } else {
                self.seen.insert(key, seen);
            }
        }
        self.missed.frames = self.missed.frames.saturating_add(other.missed.frames);
        self.missed.not_modelled = self
            .missed
            .not_modelled
            .saturating_add(other.missed.not_modelled);
        self.missed.unattributed = self
            .missed
            .unattributed
            .saturating_add(other.missed.unattributed);
        self.missed.overflowed = self
            .missed
            .overflowed
            .saturating_add(other.missed.overflowed);
        for scan in other.scans {
            let entry = self.carried.entry(scan.peer).or_insert_with(|| Scan {
                peer: scan.peer,
                ports: 0,
                packets: 0,
                first_seen: scan.first_seen,
                last_seen: scan.last_seen,
            });
            entry.ports = entry.ports.max(scan.ports);
            entry.packets = entry.packets.saturating_add(scan.packets);
            entry.first_seen = UnixMillis(entry.first_seen.0.min(scan.first_seen.0));
            entry.last_seen = UnixMillis(entry.last_seen.0.max(scan.last_seen.0));
        }
    }

    /// Takes everything held and resets the counters.
    ///
    /// Draining is destructive on purpose. A sweep reports the interval since
    /// the last one, so a flow reported twice would read as traffic that
    /// happened twice.
    pub fn drain(&mut self) -> Drained {
        let flows = std::mem::take(&mut self.seen).into_iter().collect();
        let missed = std::mem::take(&mut self.missed);
        let mut scans: Vec<Scan> = std::mem::take(&mut self.probed)
            .into_iter()
            .filter(|(_, probed)| probed.ports.len() >= SCAN_PORTS)
            .map(|(peer, probed)| Scan {
                peer,
                ports: probed.ports.len(),
                packets: probed.packets,
                first_seen: probed.first_seen,
                last_seen: probed.last_seen,
            })
            .collect();
        scans.extend(std::mem::take(&mut self.carried).into_values());
        Drained {
            flows,
            missed,
            scans,
        }
    }
}
