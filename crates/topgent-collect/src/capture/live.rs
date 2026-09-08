//! The one capture this process runs, and the collector that reports it.
//!
//! # Why a singleton
//!
//! One process, one packet socket. A second would read the same frames twice
//! and count everything double, and a session per sweep would mean a capture
//! that only exists while a sweep is running, which is precisely backwards:
//! the whole point is to see what happens *between* sweeps.
//!
//! So the session outlives every sweep, and a sweep takes what has built up.
//! Starting it is attempted once. If the capability is absent the answer is
//! kept and the collector reports it every sweep, rather than re-asking the
//! kernel a question whose answer cannot change without a restart.
//!
//! # What a sweep gets
//!
//! Flows, attributed to processes, since the last sweep. Each becomes a
//! [`Claim::TrafficObserved`] against the process that held the port, and the
//! counters that could not be turned into flows become the collector's own
//! health rather than disappearing.

use std::sync::OnceLock;

use topgent_facts::{Claim, Confidence, Fact, Subject};

use super::flows::Drained;
use super::helper;
use super::session::Session;
use crate::{Clock, CollectError, Collector, emit};

/// Stable collector identity.
const ID: &str = "capture";

/// What the provenance line says this came from.
const PROBE: &str = "packet headers off the wire, attributed through the socket table";

/// What a healthy capture still cannot supply.
const BOUNDARY: &str = "Headers only: the read buffer holds the front of each frame and the \
                        kernel discards the rest, so no payload, no content, and no byte \
                        volume. Attribution is a join on the local port, so a socket shorter \
                        lived than the port map's refresh is counted and not attributed, and \
                        ICMP is attributed only where exactly one process holds an \
                        ICMP-capable socket. Capture sees nothing that happened before it \
                        started.";

/// Where the frames come from.
///
/// Two ways, and the first is preferred wherever it is available. Reading the
/// wire in a separate program is how Wireshark has done it for years: the
/// capability goes on a small binary that does nothing else, and the large
/// program reads what it writes. Running the capture inside this process is
/// the fallback for a build with no helper beside it.
#[derive(Debug)]
pub enum Source {
    /// A separate program holds the capability and hands batches over.
    Helper(helper::Helper),
    /// This process holds the capability and reads the wire itself.
    InProcess(Session),
}

impl Source {
    /// Takes everything captured since the last drain.
    #[must_use]
    pub fn drain(&self) -> Drained {
        match self {
            Self::Helper(helper) => helper.drain(),
            Self::InProcess(session) => session.drain(),
        }
    }

    /// Why the capture stopped, if it has.
    #[must_use]
    pub fn ended(&self) -> Option<String> {
        match self {
            Self::Helper(helper) => helper.ended(),
            Self::InProcess(session) => session.ended(),
        }
    }
}

/// The process-wide capture, started at most once.
fn cell() -> &'static OnceLock<Result<Source, CollectError>> {
    static SESSION: OnceLock<OnceLock<Result<Source, CollectError>>> = OnceLock::new();
    SESSION.get_or_init(OnceLock::new)
}

/// Starts the capture if it has not been started, and reports what happened.
///
/// Safe to call on every sweep: the first call decides, and every later one
/// returns that decision.
///
/// The helper is tried first and only where it exists. Falling back rather
/// than failing matters: a build run from a source tree has no helper beside
/// it, and refusing to capture there would make the feature untestable in the
/// place it is most often changed.
pub fn ensure() -> &'static Result<Source, CollectError> {
    cell().get_or_init(|| match helper::Helper::start() {
        Ok(helper) => Ok(Source::Helper(helper)),
        Err(_) => Session::start().map(Source::InProcess),
    })
}

/// Whether packets are being read right now.
///
/// Asked by the interface, which must never say a capture is running when it
/// is not. A session that died answers `false` here, the same as one that
/// never started.
#[must_use]
pub fn running() -> bool {
    matches!(cell().get(), Some(Ok(session)) if session.ended().is_none())
}

/// One line describing the capture as it actually is.
#[must_use]
pub fn status() -> String {
    match cell().get() {
        None => "not started".to_owned(),
        Some(Err(error)) => format!("not running: {error}"),
        Some(Ok(session)) => session.ended().map_or_else(
            || "running".to_owned(),
            |detail| format!("stopped: {detail}"),
        ),
    }
}

/// Reports the traffic a running capture has accumulated.
///
/// Holds the last drain's shortfall so the sweep can report it. A capture that
/// silently stopped keeping flows would show as a healthy sensor with less to
/// say, which is the failure mode this whole crate is built to avoid.
#[derive(Debug, Default)]
pub struct CaptureCollector {
    lost: std::sync::Mutex<Option<u64>>,
    seen: std::sync::Mutex<Option<super::flows::Missed>>,
    started_here: std::sync::Mutex<bool>,
}

/// Hosts the last drain saw being scanned.
///
/// Held module-wide rather than on the collector, because a scan is a finding
/// about the host and not about any agent, so it has no fact to travel in and
/// the report reads it from here. A scan's connections are refused; refused
/// connections leave no socket; a socket is what attribution needs. The
/// traffic is real and its source is not knowable at this tier.
fn scans() -> &'static std::sync::Mutex<Vec<super::flows::Scan>> {
    static SCANS: OnceLock<std::sync::Mutex<Vec<super::flows::Scan>>> = OnceLock::new();
    SCANS.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

/// What the last sweep saw being scanned.
#[must_use]
pub fn recent_scans() -> Vec<super::flows::Scan> {
    scans()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

impl Collector for CaptureCollector {
    fn id(&self) -> &'static str {
        ID
    }

    fn boundary(&self) -> Option<&'static str> {
        Some(BOUNDARY)
    }

    /// What the last drain saw beyond what it could turn into facts.
    ///
    /// A capture that read three hundred frames and attributed forty of them
    /// is not a quiet capture, and a fact count of zero would say it was. The
    /// difference matters most in exactly the case the capability is sold on:
    /// a scan of refused ports leaves no socket for any snapshot to find, at
    /// any refresh rate, so most of its frames arrive with no owner. The
    /// number is reported rather than the shortfall being hidden.
    fn detail(&self) -> Option<String> {
        // A capture that began with this sweep has read nothing yet, and
        // saying "0 frames" would read as a quiet wire rather than as a sensor
        // that has not started listening. A one-shot run only ever sees this.
        if *self
            .started_here
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            return Some(
                "started with this sweep; a capture reports the traffic between two sweeps, \
                 so the first one has nothing to report"
                    .to_owned(),
            );
        }
        let missed = (*self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner))?;
        let line = format!(
            "{} frames read since the last sweep; {} named no endpoint this build models, \
             {} could not be tied to a process",
            missed.frames, missed.not_modelled, missed.unattributed
        );
        // A scan is worth saying here as well as in the report, because this
        // is the line an operator reads when a sensor looks quiet and is not.
        let scanned = recent_scans();
        if scanned.is_empty() {
            return Some(line);
        }
        Some(format!(
            "{line}. {} host(s) probed across many ports, which is a scan and cannot be \
             tied to a process because a refused connection leaves no socket",
            scanned.len()
        ))
    }

    /// Flows the accumulator refused because it was full.
    ///
    /// Only the refused ones. A frame this build does not model and a frame
    /// whose socket had already closed were both seen and neither was lost, so
    /// counting them here would overstate what the sensor is missing.
    fn dropped_events(&self) -> Option<u64> {
        *self
            .lost
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Takes everything captured since the last sweep and turns it into facts.
    ///
    /// # Errors
    ///
    /// Whatever starting the capture returned. A capability that was never
    /// granted is [`CollectError::Denied`] every sweep, which is what puts a
    /// row in the coverage table saying so instead of leaving a silent gap.
    fn collect(&self, clock: &dyn Clock) -> Result<Vec<Fact>, CollectError> {
        // Whether this sweep is the one that started the capture. Asked before
        // starting it, because afterwards there is no way to tell.
        let first = cell().get().is_none();
        if let Ok(mut started) = self.started_here.lock() {
            *started = first;
        }
        let session = ensure().as_ref().map_err(Clone::clone)?;
        if let Some(detail) = session.ended() {
            return Err(CollectError::Unavailable { what: detail });
        }
        let drained = session.drain();
        if let Ok(mut lost) = self.lost.lock() {
            *lost = Some(drained.missed.overflowed);
        }
        if let Ok(mut seen) = self.seen.lock() {
            *seen = Some(drained.missed);
        }
        if let Ok(mut held) = scans().lock() {
            held.clone_from(&drained.scans);
        }
        Ok(facts_from(&drained, &owners(), clock))
    }
}

/// Which agent each process's traffic belongs to.
///
/// Not the process itself. An agent works through helpers -- a shell it
/// spawned, a `ping`, a child that lives for a second -- and those are what
/// hold the ports and send the packets. A fact anchored to the helper is a
/// fact about nobody: the fold builds agents only from processes with a
/// family, and rejects everything else. The socket collector has always
/// walked up to the nearest agent ancestor for exactly this reason, and a
/// capture that did not would have reported nothing at all for a real agent.
///
/// A process with no agent above it has no subject, and its flows are dropped.
fn owners() -> std::collections::BTreeMap<u32, Subject> {
    crate::process::agent_owners(&crate::process::snapshot())
}

/// Turns drained flows into facts.
///
/// Split from the collector so the projection is testable without a socket.
#[must_use]
pub fn facts_from(
    drained: &Drained,
    owners: &std::collections::BTreeMap<u32, Subject>,
    clock: &dyn Clock,
) -> Vec<Fact> {
    let mut facts = Vec::new();
    for (key, seen) in &drained.flows {
        let Some(subject) = owners.get(&key.pid).cloned() else {
            continue;
        };
        facts.extend(emit(
            ID,
            PROBE,
            // The packet was read from the wire, and the owner from the
            // kernel's own table. Neither is inferred, and the join between
            // them is stated in the boundary rather than weakened here.
            Confidence::Certain,
            clock,
            subject,
            Claim::TrafficObserved {
                protocol: key.protocol,
                host: key.peer.to_string(),
                port: key.peer_port,
                direction: key.direction,
                packets: seen.packets,
                first_seen: seen.first_seen,
                last_seen: seen.last_seen,
            },
        ));
    }
    facts
}
