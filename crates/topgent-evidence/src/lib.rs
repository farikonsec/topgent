//! Evidence records, derivation quality, and claim-to-evidence traversal.
//!
//! Milestone M1 of `docs/MAJOR_UPGRADE_RESEARCH_PLAN.md`. The normative
//! definitions this crate implements are in `docs/NORMATIVE-CLAIMS.md`; where
//! the two disagree, that document wins.
//!
//! `topgent-facts` says what a collector saw. This crate says what may be
//! concluded from it, and keeps the path back. Four types carry the whole
//! contract:
//!
//! | Type | What it is |
//! |---|---|
//! | [`EvidenceRecord`] | One observation, bound to a host, boot, sensor instance, and sequence, addressed by the digest of its canonical bytes |
//! | [`DerivedClaim`] | One conclusion, naming the rule that drew it and every record for and against it |
//! | [`Ledger`] | Both sets, keyed by content address, so insertion order cannot reach the result |
//! | [`Derivation`] | One claim and every record behind it, rendered |
//!
//! Two dimensions travel with every claim and never collapse into one:
//! [`AttributionQuality`] says how well an observation was tied to its subject,
//! and [`CollectionCoverage`] says what the collector could not have seen.
//! `Exact` beside `SnapshotOnly` is legal, common, and does not mean complete.
//!
//! # Layout
//!
//! | Module | What lives there |
//! |---|---|
//! | [`canonical`] | The one byte encoding every id and signature is taken over |
//! | [`quality`] | Attribution quality, collection coverage, and limitations |
//! | [`record`] | The evidence envelope and its construction rules |
//! | [`claim`] | Derived claims, rule identity, and the contradiction rule |
//! | [`ledger`] | The addressed set, and `explain` |
//! | [`reader`] | Reading canonical bytes back, for a verifier that trusts nothing |
//! | [`chain`] | The hash chain, sensor keys, signed checkpoints, key rotation |
//! | [`bundle`] | What leaves the machine, and what a verdict on it means |
//! | [`verify`] | Checking a bundle against keys the verifier already holds |
//! | `wire` | Canonical bytes for the `topgent-facts` vocabulary |

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod bundle;
pub mod canonical;
pub mod chain;
pub mod claim;
pub mod ledger;
pub mod quality;
pub mod reader;
pub mod record;
pub mod verify;
mod wire;

pub use bundle::{Breach, Bundle, Gap, Summary, Verdict};
pub use canonical::{Canonical, Encode, digest_of};
pub use chain::{
    Chain, ChainEntry, ChainError, Checkpoint, EntryHash, KeyError, KeyId, PublicKey, Rotation,
    Sealed, SensorKey,
};
pub use claim::{ClaimError, ClaimId, DerivedClaim, RuleId};
pub use ledger::{Derivation, Ledger, LedgerError};
pub use quality::{Assessment, AttributionQuality, CollectionCoverage, Limitation};
pub use reader::{Decode, DecodeError, Reader, round_trip};
pub use record::{
    EVIDENCE_SCHEMA, EvidenceError, EvidenceId, EvidenceRecord, MAX_FIELD_BYTES, MAX_LIMITATIONS,
    MAX_OBSERVED_AT, MIN_OBSERVED_AT, Origin,
};
