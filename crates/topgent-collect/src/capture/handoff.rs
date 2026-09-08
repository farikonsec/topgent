//! What one process tells another about a capture.
//!
//! # Why there are two processes
//!
//! Capturing needs a privilege. The window does not. Wireshark settled this
//! years ago: the capability goes on `dumpcap`, a small program that does
//! nothing but read frames, and the interface reads what it writes. The
//! interface is the large, complicated, frequently changed program, and it is
//! the one that must never hold a raw socket.
//!
//! Topgent does the same. `topgent-capture` holds the capability and reads the
//! wire; everything else reads its output. That is why this file exists: two
//! processes need a format, and a format has to be written down.
//!
//! # Why a wire form rather than the internal types
//!
//! The accumulator's types belong to the accumulator. Serialising them
//! directly would make every field of an internal structure part of a
//! compatibility contract with a separately built binary, which is how a
//! refactor becomes a version mismatch. The types here are the contract, and
//! they are deliberately dull: numbers and strings, each with a stable
//! spelling that already exists in the vocabulary.
//!
//! # Trust
//!
//! The helper is Topgent's own binary and its output is still checked. A
//! version this build does not know is refused rather than guessed at, an
//! address that will not parse drops its row, and the batch size is bounded.
//! A privileged process is exactly the wrong thing to extend blind faith to.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use topgent_facts::{Direction, Protocol, UnixMillis};

use super::flows::{Drained, Key, Missed, Scan, Seen};

/// The format version this build writes and accepts.
pub const HANDOFF_VERSION: u32 = 1;

/// Most rows accepted from one batch.
///
/// The accumulator is already bounded, so a larger batch than this did not
/// come from a healthy helper.
const MAX_ROWS: usize = 8192;

/// One conversation, as it crosses the process boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireFlow {
    /// The process holding the local port.
    pub pid: u32,
    /// Protocol, in the vocabulary's own spelling.
    pub protocol: String,
    /// The other end.
    pub peer: String,
    /// The other end's port.
    pub peer_port: u16,
    /// `outbound` or `listening`.
    pub direction: String,
    /// Packets counted.
    pub packets: u64,
    /// When the first arrived.
    pub first_seen: u64,
    /// When the last did.
    pub last_seen: u64,
}

/// A host probed widely enough to call it a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireScan {
    /// The host probed.
    pub peer: String,
    /// Distinct ports touched.
    pub ports: usize,
    /// Packets towards it.
    pub packets: u64,
    /// When the first arrived.
    pub first_seen: u64,
    /// When the last did.
    pub last_seen: u64,
}

/// What was seen and not kept.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct WireMissed {
    /// Frames read.
    pub frames: u64,
    /// Frames naming no endpoint this build models.
    pub not_modelled: u64,
    /// Frames whose local port belonged to no process.
    pub unattributed: u64,
    /// Flows refused because the map was full.
    pub overflowed: u64,
}

/// One interval's worth of capture, as one line of the helper's output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Batch {
    /// Format version, checked rather than assumed.
    pub version: u32,
    /// Flows in the interval.
    pub flows: Vec<WireFlow>,
    /// What was seen and not kept.
    pub missed: WireMissed,
    /// Hosts probed widely.
    pub scans: Vec<WireScan>,
}

/// Puts a drained accumulator into the wire form.
#[must_use]
pub fn to_wire(drained: &Drained) -> Batch {
    Batch {
        version: HANDOFF_VERSION,
        flows: drained
            .flows
            .iter()
            .map(|(key, seen)| WireFlow {
                pid: key.pid,
                protocol: key.protocol.as_str().to_owned(),
                peer: key.peer.to_string(),
                peer_port: key.peer_port,
                direction: direction_str(key.direction).to_owned(),
                packets: seen.packets,
                first_seen: seen.first_seen.0,
                last_seen: seen.last_seen.0,
            })
            .collect(),
        missed: WireMissed {
            frames: drained.missed.frames,
            not_modelled: drained.missed.not_modelled,
            unattributed: drained.missed.unattributed,
            overflowed: drained.missed.overflowed,
        },
        scans: drained
            .scans
            .iter()
            .map(|scan| WireScan {
                peer: scan.peer.to_string(),
                ports: scan.ports,
                packets: scan.packets,
                first_seen: scan.first_seen.0,
                last_seen: scan.last_seen.0,
            })
            .collect(),
    }
}

/// Reads a batch back, refusing what it does not understand.
///
/// Returns nothing for a version this build does not speak. A row whose
/// address or protocol will not parse is dropped and the rest is kept: one
/// malformed row must not cost an interval of evidence, and a guessed one must
/// never reach a report.
#[must_use]
pub fn from_wire(batch: &Batch) -> Option<Drained> {
    if batch.version != HANDOFF_VERSION {
        return None;
    }
    let flows = batch
        .flows
        .iter()
        .take(MAX_ROWS)
        .filter_map(|flow| {
            let peer = flow.peer.parse::<IpAddr>().ok()?;
            let protocol = Protocol::parse(&flow.protocol);
            let direction = direction_of(&flow.direction)?;
            Some((
                Key {
                    pid: flow.pid,
                    protocol,
                    peer,
                    peer_port: flow.peer_port,
                    direction,
                },
                Seen {
                    packets: flow.packets,
                    first_seen: UnixMillis(flow.first_seen),
                    last_seen: UnixMillis(flow.last_seen),
                },
            ))
        })
        .collect();
    let scans = batch
        .scans
        .iter()
        .take(MAX_ROWS)
        .filter_map(|scan| {
            Some(Scan {
                peer: scan.peer.parse::<IpAddr>().ok()?,
                ports: scan.ports,
                packets: scan.packets,
                first_seen: UnixMillis(scan.first_seen),
                last_seen: UnixMillis(scan.last_seen),
            })
        })
        .collect();
    Some(Drained {
        flows,
        missed: Missed {
            frames: batch.missed.frames,
            not_modelled: batch.missed.not_modelled,
            unattributed: batch.missed.unattributed,
            overflowed: batch.missed.overflowed,
        },
        scans,
    })
}

/// The stable spelling of a direction.
const fn direction_str(direction: Direction) -> &'static str {
    match direction {
        Direction::Outbound => "outbound",
        Direction::Listening => "listening",
    }
}

/// The direction a spelling names, or nothing.
fn direction_of(text: &str) -> Option<Direction> {
    match text {
        "outbound" => Some(Direction::Outbound),
        "listening" => Some(Direction::Listening),
        _ => None,
    }
}
