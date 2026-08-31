//! The schema version, and the one error constructing a fact can produce.
//!
//! A build refuses a version it does not know rather than guessing at the
//! shape. Guessing is how a field silently means something else.

use core::fmt;

/// Schema version this build emits and accepts.
pub const SCHEMA_VERSION: SchemaVersion = SchemaVersion(1);

/// Version of the fact schema a record was written against.
///
/// The core refuses a version it does not know rather than interpreting unknown
/// data optimistically, so a newer collector against an older core fails loudly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchemaVersion(pub u16);

impl fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// Why a fact could not be constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactError {
    /// The record names a schema version this build does not understand.
    UnknownSchema {
        /// The version the record claimed.
        found: SchemaVersion,
        /// The version this build speaks.
        expected: SchemaVersion,
    },
    /// Provenance was present but empty. An unattributed fact is not admissible.
    MissingProvenance {
        /// Which provenance field was blank.
        field: &'static str,
    },
}

impl fmt::Display for FactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownSchema { found, expected } => {
                write!(
                    f,
                    "unknown fact schema {found}, this build speaks {expected}"
                )
            }
            Self::MissingProvenance { field } => {
                write!(f, "fact provenance is missing `{field}`")
            }
        }
    }
}
