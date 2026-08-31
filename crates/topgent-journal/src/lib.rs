//! Durable local state: what changed, and what Topgent did about it.
//!
//! A sweep produces thousands of facts a minute. Writing all of them down would
//! be a firehose nobody reads, so this crate records **changes** and
//! **decisions** instead: an agent appearing or going away, a grade moving, a
//! credential coming into reach, a resource touched outside policy, and every
//! action Topgent itself took.
//!
//! Everything is metadata. Nothing in the fact vocabulary can carry a
//! credential's contents, so nothing here can either, and text arriving from
//! outside is bounded and stripped of control characters before it is kept.
//!
//! # Layout
//!
//! [`journal::Journal`] is the only thing that touches disk. Each kind of
//! record owns a module, holds its own type and codec, and states its own
//! retention rule:
//!
//! | Module | Record |
//! |---|---|
//! | [`event_log`] | the append-only JSONL log of what changed |
//! | [`sweep`] | the baseline one sweep compares against the next |
//! | [`activity_history`] | the causal timeline, kept across restarts |
//! | [`network`] | retained endpoint metadata |
//! | [`approval`] | a person's decision to allow a guarded response |
//! | [`cooldown`] | how long before the same target may be acted on again |
//! | [`transition`] | rising and falling edges of a policy response |
//! | [`sensor_health`] | collector health across restarts |
//! | [`attestation`] | what is known about the sensors' own binaries |
//! | [`semantic`] | optional context an agent's harness supplied about itself |
//!
//! Every write is atomic and every reader tolerates a damaged file: an
//! unparsable record is skipped, and an unparsable file is empty history rather
//! than a failure. A security log that stops recording without saying so is
//! worse than one that admits it lost something.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod activity_history;
pub mod approval;
pub mod attestation;
pub mod cooldown;
pub mod event_log;
pub mod journal;
pub mod network;
pub mod semantic;
pub mod sensor_health;
pub mod sweep;
#[cfg(test)]
mod test_support;
mod text;
pub mod transition;

pub use approval::{ApprovalRecord, ApprovalRecordState, MAX_APPROVAL_RECORDS};
pub use attestation::{MAX_TOOL_ATTESTATIONS, ToolAttestationRecord};
pub use cooldown::{MAX_RESPONSE_COOLDOWNS, ResponseCooldown};
pub use event_log::{Entry, GradeMove, Kind};
pub use journal::{Journal, state_dir};
pub use semantic::{MAX_SEMANTIC_RECORDS, SemanticRecord};
pub use sensor_health::{MAX_SENSOR_HEALTH_RECORDS, SensorHealthRecord};
pub use sweep::{SWEEP_LOCK_STALE_MS, Seen, SeenKey, UNCLASSIFIED, diff, reconcile, snapshot};
pub use transition::{MAX_RESPONSE_TRANSITIONS, ResponseTransition};

/// Largest the log is allowed to get before the oldest half is dropped.
pub const MAX_BYTES: u64 = 8 * 1024 * 1024;
