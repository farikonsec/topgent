//! Version numbers other people's tooling depends on.
//!
//! Kept in one place because changing any of them is a compatibility decision,
//! not an implementation detail: something downstream is pinned to each.

/// `CycloneDX` schema version emitted by this crate.
pub const CYCLONEDX_SPEC_VERSION: &str = "1.6";

/// Machine contract version for CI policy results.
pub const POLICY_RESULT_VERSION: u32 = 1;

/// Report contract version accepted by the CI policy evaluator.
pub const REPORT_CONTRACT_VERSION: u64 = 1;
