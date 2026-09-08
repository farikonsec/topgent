//! The capture itself: one thread, one socket, one accumulator.
//!
//! # The shape, and why it is this shape
//!
//! A capture has to keep up with a wire it does not control, and a sweep runs
//! whenever a person asks for one. Those are different clocks, so they are
//! kept apart: a thread reads frames as fast as they arrive and folds them
//! into a bounded map, and a sweep takes whatever is in the map. Nothing in
//! the reading path waits on anything in the reporting path. This is how every
//! capture tool is built, Sniffnet included, for the same reason — a reader
//! that blocks on a consumer is a reader that drops packets.
//!
//! # Attribution happens here, not at the sweep
//!
//! The socket table is a snapshot, and a socket that opened and closed between
//! two sweeps is not in the one a sweep would read. So the port map is rebuilt
//! inside the loop: on a schedule, and again whenever a packet names a local
//! port the current map does not know, subject to its own floor so that a scan
//! across sixty thousand unknown ports cannot turn into sixty thousand walks
//! of `/proc`.
//!
//! That still misses sockets shorter-lived than the floor. It is a real gap
//! and it is reported as one: those frames are counted as unattributed rather
//! than pinned on whichever process happened to hold the port next.
//!
//! # Stopping
//!
//! The thread checks a flag between reads and the read has a timeout, so a
//! stop is honoured within that timeout. Dropping the session stops it; there
//! is no path that leaves the thread running after the handle is gone.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};

use super::flows::{Drained, Flows, Key};
use super::packet;
use super::ports::{self, Owners};
use super::{locals, wire};
use crate::{Clock, CollectError, SystemClock};
use topgent_facts::{Direction, Protocol};

/// How often the port map and address set are rebuilt regardless of traffic.
const REFRESH_MS: u128 = 1_000;

/// The shortest gap between two rebuilds triggered by an unknown port.
///
/// Without this, a port scan is a request to walk every process's file
/// descriptors once per packet, and the monitor becomes the load.
const REFRESH_FLOOR_MS: u128 = 100;

/// A running capture.
///
/// Holding one is what makes the capability actually used, as opposed to
/// merely granted. Dropping one stops the thread.
#[derive(Debug)]
pub struct Session {
    flows: Arc<Mutex<Flows>>,
    stop: Arc<AtomicBool>,
    ended: Arc<Mutex<Option<String>>>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Session {
    /// Opens the socket and starts reading.
    ///
    /// The socket is opened on the calling thread so a refusal is returned to
    /// the caller rather than disappearing into a thread nobody is watching.
    ///
    /// # Errors
    ///
    /// [`CollectError::Denied`] where the capability has not been granted, or
    /// has been granted and this process not yet restarted. Every other
    /// failure is [`CollectError::Unavailable`] carrying what went wrong.
    pub fn start() -> Result<Self, CollectError> {
        let wires = wire::open_all()?;
        let flows = Arc::new(Mutex::new(Flows::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let ended = Arc::new(Mutex::new(None));
        let mut threads = Vec::with_capacity(wires.len());
        for (index, wire) in wires.into_iter().enumerate() {
            let thread = std::thread::Builder::new()
                .name(format!("topgent-capture-{index}"))
                .spawn({
                    let flows = Arc::clone(&flows);
                    let stop = Arc::clone(&stop);
                    let ended = Arc::clone(&ended);
                    let mut wire = wire;
                    move || run(&mut wire, &flows, &stop, &ended, &SystemClock)
                })
                .map_err(|error| CollectError::Unavailable {
                    what: format!("the capture thread could not be started: {error}"),
                })?;
            threads.push(thread);
        }
        Ok(Self {
            flows,
            stop,
            ended: Arc::clone(&ended),
            threads,
        })
    }

    /// Takes everything captured since the last drain.
    #[must_use]
    pub fn drain(&self) -> Drained {
        let mut guard = self.flows.lock().unwrap_or_else(PoisonError::into_inner);
        guard.drain()
    }

    /// Why the capture stopped, if it has.
    ///
    /// `None` while it is still reading. A session that died is not the same
    /// as a session that saw nothing, and a report that showed the two alike
    /// would be claiming coverage it lost.
    #[must_use]
    pub fn ended(&self) -> Option<String> {
        self.ended
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in std::mem::take(&mut self.threads) {
            // The read timeout bounds each wait. A join that hung would hang
            // whatever dropped the session, which in the interface is the
            // thread drawing the window.
            drop(thread.join());
        }
    }
}

/// The read loop.
///
/// Split out and given every collaborator as an argument so the loop's
/// behaviour is a function of its inputs and not of the machine it runs on.
fn run(
    wire: &mut wire::Wire,
    flows: &Mutex<Flows>,
    stop: &AtomicBool,
    ended: &Mutex<Option<String>>,
    clock: &dyn Clock,
) {
    let mut buffer = [0_u8; wire::SNAP];
    // Asked once. A handle's link type is fixed for its life, and asking per
    // frame would be a question with a constant answer in the hot path.
    let link = wire.link();
    let mut owners: Owners = ports::owners();
    let mut icmp = ports::icmp_holder();
    let mut addresses = locals::addresses();
    let mut refreshed = std::time::Instant::now();

    while !stop.load(Ordering::Relaxed) {
        if refreshed.elapsed().as_millis() >= REFRESH_MS {
            owners = ports::owners();
            icmp = ports::icmp_holder();
            addresses = locals::addresses();
            refreshed = std::time::Instant::now();
        }
        let read = match wire.read(&mut buffer) {
            wire::Frame::Idle => continue,
            // One interface going away is not the capture ending. The reason
            // is recorded so a report can say a source was lost, and the other
            // threads carry on reading the interfaces that still work.
            wire::Frame::Ended { detail } => {
                *ended.lock().unwrap_or_else(PoisonError::into_inner) = Some(detail);
                return;
            }
            wire::Frame::Read(read) => read,
        };
        let Some(frame) = buffer.get(..read) else {
            continue;
        };
        // Every frame is counted before anything can decide not to keep it, so
        // the ratio of kept to seen is a real number rather than a count of
        // successes with no denominator.
        let Some(observed) = ({
            let mut guard = flows.lock().unwrap_or_else(PoisonError::into_inner);
            guard.frame();
            let observed = packet::parse(frame, link, &addresses);
            if observed.is_none() {
                guard.not_modelled();
            }
            observed
        }) else {
            continue;
        };

        // Counted before attribution and regardless of it. A scan's
        // connections are refused, so they leave no socket and cannot be tied
        // to a process; counting only what could be attributed would miss
        // exactly the traffic this is looking for.
        if matches!(observed.protocol, Protocol::Tcp | Protocol::Udp) {
            flows.lock().unwrap_or_else(PoisonError::into_inner).probe(
                observed.peer,
                observed.peer_port,
                clock.now(),
            );
        }

        // An unknown port is the one case worth paying for a rebuild: it is
        // what a socket opened since the last refresh looks like, which is
        // exactly the short-lived traffic a snapshot collector cannot see.
        let mut pid = owner_of(&owners, icmp, observed.protocol, observed.local_port);
        if pid.is_none() && refreshed.elapsed().as_millis() >= REFRESH_FLOOR_MS {
            owners = ports::owners();
            icmp = ports::icmp_holder();
            addresses = locals::addresses();
            refreshed = std::time::Instant::now();
            pid = owner_of(&owners, icmp, observed.protocol, observed.local_port);
        }
        let mut guard = flows.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(owner) = pid else {
            guard.unattributed();
            continue;
        };
        // The socket decides the direction, not the packet. A connection this
        // host opened carries replies from the peer, and each reply looks
        // inbound on its own: the same conversation would become an outbound
        // flow and a listening one, and the listening half is a scored
        // finding. Every ordinary outbound connection would have produced a
        // phantom listener. Seen on macOS against real agent traffic, where
        // every endpoint appeared twice.
        //
        // ICMP has no socket to ask, so its packet direction stands.
        let direction = match observed.protocol {
            Protocol::Tcp | Protocol::Udp => {
                if owner.listening {
                    Direction::Listening
                } else {
                    Direction::Outbound
                }
            }
            _ => observed.direction,
        };
        guard.record(
            Key {
                pid: owner.pid,
                protocol: observed.protocol,
                peer: observed.peer,
                peer_port: observed.peer_port,
                direction,
            },
            clock.now(),
        );
    }
}

/// Who a flow belongs to, by whichever route the protocol allows.
///
/// A port-bearing protocol is a lookup. ICMP has no port and so no lookup, and
/// falls back to the sole holder of an ICMP-capable socket when there is
/// exactly one; where there is not, the flow stays unattributed rather than
/// being pinned on the likeliest candidate.
fn owner_of(
    owners: &Owners,
    icmp: Option<u32>,
    protocol: Protocol,
    local_port: u16,
) -> Option<super::ports::Owner> {
    match protocol {
        Protocol::Tcp | Protocol::Udp => owners.get(&(protocol, local_port)).copied(),
        // A raw socket is not a listener in any sense the socket table states,
        // so the packet's own direction stands.
        Protocol::Icmp => icmp.map(|pid| super::ports::Owner {
            pid,
            listening: false,
        }),
        _ => None,
    }
}
