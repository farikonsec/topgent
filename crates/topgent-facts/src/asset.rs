//! An installed thing, and the digest that says which one.
//!
//! Names collide and versions are claimed by the thing being versioned. The
//! digest is what survives someone renaming a file.

use crate::scalar::UnixMillis;

/// Inventory-only asset categories emitted by bounded installation probes.
///
/// These records deliberately remain separate from [`Claim`]: an installed
/// component is not evidence that a running process is using it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InstalledAssetKind {
    /// A reusable agent instruction package.
    Skill,
    /// An installed agent or harness plugin.
    Plugin,
    /// A model artifact stored on this machine.
    LocalModel,
}

/// Optional content identity supplied by an allowlisted package manifest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssetDigest {
    /// Stable algorithm label, such as `sha256` or `git`.
    pub algorithm: String,
    /// Lowercase digest value, without an algorithm prefix.
    pub value: String,
}

/// Bounded, sanitized evidence that an AI-related asset is installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledAsset {
    /// Asset category.
    pub kind: InstalledAssetKind,
    /// Canonical non-secret identity, independent of its display label.
    pub identity: String,
    /// Sanitized display name.
    pub name: String,
    /// Package/model version where the manifest supplies one.
    pub version: Option<String>,
    /// Package/model content identity where the manifest supplies one.
    pub digest: Option<AssetDigest>,
    /// Allowlisted source format, never a user-controlled absolute path.
    pub source: String,
    /// Observation time for later first/last-seen persistence.
    pub observed_at: UnixMillis,
}
