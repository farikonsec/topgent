//! The fact vocabulary.
//!
//! Everything Topgent knows arrives as a [`Fact`]: one immutable, timestamped,
//! attributed assertion emitted by one collector. Collectors are untrusted and
//! replaceable; this crate is the only thing they and the core agree on, the way
//! many filesystems agree on one VFS.
//!
//! Three properties are load-bearing and every change to this crate must keep them:
//!
//! 1. **No I/O and no dependencies.** Nothing here reads a file, opens a socket or
//!    pulls in a crate. A fact is data.
//! 2. **Provenance is not optional.** A fact cannot be constructed without naming
//!    the collector, the probe, and how confident that probe is. A finding whose
//!    source cannot be printed is not a finding.
//! 3. **Versioned by construction.** [`Fact::new`] refuses a schema version this
//!    build does not know rather than guessing at the shape.
//!
//! Facts are also the audit log. When Topgent stops a process it emits
//! [`Claim::ActionTaken`], so an action performed is the same shape in the log as
//! an action observed, and no reader has to consult two formats to reconstruct
//! what happened.
//!
//! # Layout
//!
//! | Module | What lives there |
//! |---|---|
//! | [`version`] | The schema version, and the one error constructing a fact can produce. |
//! | [`scalar`] | The small vocabulary: time, confidence, three-valued truth, direction. |
//! | [`subject`] | What a fact is about, identified exactly enough to act on. |
//! | [`asset`] | An installed thing, and the digest that says which one. |
//! | [`network`] | What a connection or a lookup did, and what the kernel counted. |
//! | [`claim`] | Everything a collector is allowed to assert. |
//! | [`fact`] | One assertion, with the provenance that makes it admissible. |

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod asset;
mod claim;
mod fact;
mod network;
mod scalar;
mod subject;
mod version;

pub use asset::{AssetDigest, InstalledAsset, InstalledAssetKind};
pub use claim::Claim;
pub use fact::{Fact, Provenance};
pub use network::{ByteCounters, ConnectionOutcome, DnsOutcome};
pub use scalar::{Access, Confidence, Direction, Protocol, Tri, UnixMillis};
pub use subject::Subject;
pub use version::{FactError, SCHEMA_VERSION, SchemaVersion};
