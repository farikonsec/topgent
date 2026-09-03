//! Collectors.
//!
//! This is the only crate in Topgent that touches the operating system, and it
//! is deliberately the least trusted. A collector may crash, return nonsense, or
//! flood; none of that reaches the core, which only ever receives
//! [`Fact`](topgent_facts::Fact) values it can refuse.
//!
//! Two rules govern everything here:
//!
//! 1. **Nothing discovered ever becomes an instruction.** A config file naming a
//!    binary is a string. It is never a path to run. The one external command in
//!    the whole crate has fixed arguments and no interpolation.
//! 2. **Nothing sensitive is retained.** Collectors report that a credential is
//!    reachable. They never open it.
//!
//! Everything time-dependent goes through [`Clock`], so a collector can be
//! replayed against a fixed clock in tests.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod asset_inventory;
pub mod attribution;
pub mod config;
pub mod container;
pub mod dns_event;
pub mod editor;
pub mod filesystem;
pub mod intercept;
pub mod network_event;
pub mod overhead;
pub mod process;
pub mod reach;
pub mod resolve;
pub mod signatures;
pub mod socket;
pub mod tool;

use std::fmt;
use topgent_facts::{Confidence, Fact, Provenance, SCHEMA_VERSION, Subject, UnixMillis};

/// Where a collector gets the time.
///
/// Injected rather than read, so a collector's output is reproducible.
pub trait Clock: Send + Sync {
    /// Milliseconds since the Unix epoch.
    fn now(&self) -> UnixMillis;
}

/// The real clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> UnixMillis {
        UnixMillis(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
        )
    }
}

/// A clock that never moves, for tests.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now(&self) -> UnixMillis {
        UnixMillis(self.0)
    }
}

/// Why a collector produced nothing.
///
/// A collector that fails is reported, never silently skipped: a blank panel and
/// a panel that says "we could not look" are different claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectError {
    /// The probe is not available on this platform or this machine.
    Unavailable {
        /// What was missing.
        what: String,
    },
    /// The probe ran and its output could not be understood.
    Unreadable {
        /// What could not be parsed.
        what: String,
    },
    /// The probe needs a privilege this process does not hold.
    Denied {
        /// What was refused.
        what: String,
    },
}

/// Whether a collector completed and what kind of remediation is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityState {
    /// The collector completed, including when it correctly observed nothing.
    Available,
    /// A required probe or platform facility is absent.
    Unsupported,
    /// The operating system refused the required access.
    PermissionRequired,
    /// The probe ran but its result could not be trusted.
    Error,
}

impl CapabilityState {
    /// Stable report label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Unsupported => "unsupported",
            Self::PermissionRequired => "permission_required",
            Self::Error => "error",
        }
    }
}

/// Health of one collector in one sweep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorRun {
    /// Stable collector identity.
    pub collector: &'static str,
    /// Whether the collector completed.
    pub state: CapabilityState,
    /// Number of admissible facts it emitted.
    pub fact_count: usize,
    /// Time spent in the probe, rounded to milliseconds.
    pub duration_ms: u64,
    /// Human-readable failure detail, absent on success.
    pub detail: Option<String>,
    /// Cumulative events the underlying sensor reports losing, when measurable.
    pub dropped_events: Option<u64>,
    /// What a healthy run of this sensor still cannot supply on this host.
    ///
    /// Available is not the same as complete. A collector that works perfectly
    /// and only reports part of what the feature needs has to say so, or a
    /// green row reads as full coverage of something the platform never
    /// provided.
    pub boundary: Option<&'static str>,
}

impl fmt::Display for CollectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable { what } => write!(f, "not available here: {what}"),
            Self::Unreadable { what } => write!(f, "could not read: {what}"),
            Self::Denied { what } => write!(f, "not permitted: {what}"),
        }
    }
}

/// One source of facts.
///
/// Implementations are expected to be cheap, side-effect free apart from reading,
/// and safe to run repeatedly.
pub trait Collector {
    /// Stable name, printed in provenance.
    fn id(&self) -> &'static str;

    /// Gather what this collector can see right now.
    ///
    /// # Errors
    ///
    /// Returns [`CollectError`] when the probe could not run. A collector that
    /// simply saw nothing returns an empty vector, which is a different answer.
    fn collect(&self, clock: &dyn Clock) -> Result<Vec<Fact>, CollectError>;

    /// Cumulative dropped-event counter supplied by the sensor, when available.
    /// Snapshot collectors and sensors without a trustworthy counter return
    /// `None`; Topgent never estimates this value.
    fn dropped_events(&self) -> Option<u64> {
        None
    }

    /// What this sensor cannot supply on this host even when it is healthy.
    ///
    /// Default `None` means the sensor delivers everything its feature needs
    /// where it runs. Anything else is a standing limitation of the platform's
    /// telemetry, stated once here rather than inferred by a reader from a
    /// missing field.
    fn boundary(&self) -> Option<&'static str> {
        None
    }
}

/// Build one fact with this collector's attribution.
///
/// Every collector goes through here, so no fact can reach the core without a
/// collector name, a printable probe, and a confidence.
#[must_use]
pub fn emit(
    collector: &'static str,
    probe: &str,
    confidence: Confidence,
    clock: &dyn Clock,
    subject: Subject,
    claim: topgent_facts::Claim,
) -> Option<Fact> {
    Fact::new(
        SCHEMA_VERSION,
        subject,
        claim,
        Provenance {
            collector: collector.to_owned(),
            probe: probe.to_owned(),
            confidence,
            observed_at: clock.now(),
        },
    )
    .ok()
}

/// What a full sweep produced.
#[derive(Debug, Default)]
pub struct Sweep {
    /// Every fact gathered, in collector order.
    pub facts: Vec<Fact>,
    /// Collectors that could not run, with the reason.
    pub failures: Vec<(&'static str, CollectError)>,
    /// Health of every requested collector, including successful empty probes.
    pub runs: Vec<CollectorRun>,
}

/// Run every collector, keeping going when one fails.
///
/// One collector falling over must never blind the rest, so failures are
/// collected and reported rather than propagated.
#[must_use]
pub fn sweep(collectors: &[Box<dyn Collector>], clock: &dyn Clock) -> Sweep {
    let mut out = Sweep::default();
    for c in collectors {
        let started = std::time::Instant::now();
        match c.collect(clock) {
            Ok(facts) => {
                out.runs.push(CollectorRun {
                    collector: c.id(),
                    state: CapabilityState::Available,
                    fact_count: facts.len(),
                    duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    detail: None,
                    dropped_events: c.dropped_events(),
                    boundary: c.boundary(),
                });
                out.facts.extend(facts);
            }
            Err(error) => {
                let state = match &error {
                    CollectError::Unavailable { .. } => CapabilityState::Unsupported,
                    CollectError::Denied { .. } => CapabilityState::PermissionRequired,
                    CollectError::Unreadable { .. } => CapabilityState::Error,
                };
                out.runs.push(CollectorRun {
                    collector: c.id(),
                    state,
                    fact_count: 0,
                    duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    detail: Some(error.to_string()),
                    dropped_events: c.dropped_events(),
                    boundary: c.boundary(),
                });
                out.failures.push((c.id(), error));
            }
        }
    }
    out
}

/// The collectors that run on this machine, in the order they should run.
///
/// Process first, because everything else anchors to a process.
#[must_use]
pub fn default_collectors() -> Vec<Box<dyn Collector>> {
    vec![
        Box::new(process::ProcessCollector::default()),
        Box::new(editor::EditorExtensionCollector),
        Box::new(filesystem::FilesystemEventCollector::default()),
        Box::new(network_event::NetworkEventCollector::default()),
        Box::new(dns_event::DnsEventCollector::default()),
        Box::new(socket::SocketCollector),
        Box::new(config::ConfigCollector::default()),
        Box::new(reach::ReachCollector::default()),
    ]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{CapabilityState, Clock, CollectError, Collector, FixedClock, sweep};
    use topgent_facts::Fact;

    struct Empty;
    impl Collector for Empty {
        fn id(&self) -> &'static str {
            "empty"
        }
        fn collect(&self, _clock: &dyn Clock) -> Result<Vec<Fact>, CollectError> {
            Ok(Vec::new())
        }
    }

    struct Denied;
    impl Collector for Denied {
        fn id(&self) -> &'static str {
            "denied"
        }
        fn collect(&self, _clock: &dyn Clock) -> Result<Vec<Fact>, CollectError> {
            Err(CollectError::Denied {
                what: "test permission".to_owned(),
            })
        }
        fn dropped_events(&self) -> Option<u64> {
            Some(7)
        }
    }

    struct Partial;
    impl Collector for Partial {
        fn id(&self) -> &'static str {
            "partial"
        }
        fn collect(&self, _clock: &dyn Clock) -> Result<Vec<Fact>, CollectError> {
            Ok(Vec::new())
        }
        fn boundary(&self) -> Option<&'static str> {
            Some("this platform records no connection close")
        }
    }

    #[test]
    fn a_healthy_sensor_can_still_say_what_it_cannot_see() {
        // Available is not the same as complete. Windows runs the connection
        // collector successfully and its Security log still contains no
        // teardown, so a green row that said nothing would read as coverage of
        // something the platform never provided.
        let result = sweep(&[Box::new(Partial), Box::new(Empty)], &FixedClock(1));
        let partial = result
            .runs
            .iter()
            .find(|run| run.collector == "partial")
            .expect("the collector ran");
        assert_eq!(partial.state, CapabilityState::Available);
        assert_eq!(
            partial.boundary,
            Some("this platform records no connection close")
        );

        // A sensor with nothing missing says nothing, rather than an empty
        // string a reader has to interpret.
        let empty = result
            .runs
            .iter()
            .find(|run| run.collector == "empty")
            .expect("the collector ran");
        assert_eq!(empty.boundary, None);
    }

    #[test]
    fn a_failed_sensor_still_reports_its_standing_limitation() {
        let result = sweep(&[Box::new(Denied)], &FixedClock(1));
        let denied = result
            .runs
            .iter()
            .find(|run| run.collector == "denied")
            .expect("the collector ran");
        assert_eq!(denied.state, CapabilityState::PermissionRequired);
        assert_eq!(denied.boundary, None);
        assert_eq!(denied.dropped_events, Some(7));
    }

    #[test]
    fn successful_empty_collection_is_available_not_failed() {
        let result = sweep(&[Box::new(Empty)], &FixedClock(1));
        assert!(result.failures.is_empty());
        assert!(result.runs.iter().any(|run| {
            run.collector == "empty"
                && run.state == CapabilityState::Available
                && run.fact_count == 0
        }));
    }

    #[test]
    fn denied_collection_is_visible_as_permission_required() {
        let result = sweep(&[Box::new(Denied)], &FixedClock(1));
        assert_eq!(result.failures.len(), 1);
        assert!(result.runs.iter().any(|run| {
            run.collector == "denied"
                && run.state == CapabilityState::PermissionRequired
                && run.detail.as_deref() == Some("not permitted: test permission")
                && run.dropped_events == Some(7)
        }));
    }
}
