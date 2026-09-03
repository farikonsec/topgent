//! One observation, made addressable.
//!
//! A [`Fact`] says what a collector saw. An [`EvidenceRecord`] says which
//! sensor instance saw it, on which host and boot, in what order, how complete
//! the collector's view was, and what the observation does not cover. Only the
//! second can be pointed at by a claim, and only the second can be verified by
//! someone who does not trust the process that wrote it.
//!
//! The id is derived from the canonical bytes, so it is a content address: two
//! records with the same id are the same record, and a record that has been
//! edited no longer answers to the id anything referenced it by.

use topgent_facts::{Fact, UnixMillis};

use crate::canonical::{Canonical, Encode, digest_of};
use crate::quality::{CollectionCoverage, Limitation};

/// Schema version of the evidence envelope this build writes and accepts.
pub const EVIDENCE_SCHEMA: u16 = 1;

/// Longest permitted text field, in bytes.
///
/// A path, a host name, and a collector name all live well below this. The cap
/// exists so a malformed or hostile record cannot force an unbounded allocation
/// in a reader, which is why it is checked at construction and not at render.
pub const MAX_FIELD_BYTES: usize = 4096;

/// Most limitations one record may carry.
pub const MAX_LIMITATIONS: usize = 16;

/// Earliest observation time this build accepts, 2020-01-01T00:00:00Z.
pub const MIN_OBSERVED_AT: u64 = 1_577_836_800_000;

/// Latest observation time this build accepts, 2100-01-01T00:00:00Z.
pub const MAX_OBSERVED_AT: u64 = 4_102_444_800_000;

/// Which sensor, on which host, across which boot.
///
/// All three are needed together. A sequence number is only meaningful within
/// one sensor instance, and a replayed record from another host or another boot
/// is exactly the attack the binding prevents.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Origin {
    /// Stable host identifier, itself a digest rather than a host name.
    pub host_id: String,
    /// Boot identifier, so a record cannot be replayed across a restart.
    pub boot_id: String,
    /// Identifier of the sensor process that wrote the record.
    pub sensor_instance: String,
}

impl Encode for Origin {
    fn encode(&self, into: &mut Canonical) {
        into.text(&self.host_id);
        into.text(&self.boot_id);
        into.text(&self.sensor_instance);
    }
}

/// Content address of one evidence record.
///
/// Printed as lowercase hex. Comparing ids is how a reader checks that the
/// record a claim names is the record it was handed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EvidenceId(String);

impl EvidenceId {
    /// The hex digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The first twelve characters, for a report that has to fit on a line.
    ///
    /// Never used for lookup. A truncated id is a label, and treating one as an
    /// identifier is how two different records become the same row.
    #[must_use]
    pub fn short(&self) -> &str {
        self.0.get(..12).unwrap_or(&self.0)
    }
}

impl core::fmt::Display for EvidenceId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Encode for EvidenceId {
    fn encode(&self, into: &mut Canonical) {
        into.text(&self.0);
    }
}

/// Why a record could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceError {
    /// The envelope names a schema version this build does not understand.
    UnknownSchema {
        /// The version the record claimed.
        found: u16,
        /// The version this build speaks.
        expected: u16,
    },
    /// A required field was blank. An unattributed record is not admissible.
    BlankField {
        /// Which field.
        field: &'static str,
    },
    /// A field exceeded [`MAX_FIELD_BYTES`].
    FieldTooLarge {
        /// Which field.
        field: &'static str,
        /// How many bytes it held.
        bytes: usize,
    },
    /// The observation time is outside the range this build accepts.
    TimeOutOfRange {
        /// The time the record claimed, in Unix milliseconds.
        found: u64,
    },
    /// More limitations than [`MAX_LIMITATIONS`].
    TooManyLimitations {
        /// How many were supplied.
        count: usize,
    },
}

impl core::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownSchema { found, expected } => write!(
                f,
                "unknown evidence schema v{found}, this build speaks v{expected}"
            ),
            Self::BlankField { field } => write!(f, "evidence field `{field}` is blank"),
            Self::FieldTooLarge { field, bytes } => write!(
                f,
                "evidence field `{field}` is {bytes} bytes, over the {MAX_FIELD_BYTES} limit"
            ),
            Self::TimeOutOfRange { found } => {
                write!(f, "observation time {found} is outside the accepted range")
            }
            Self::TooManyLimitations { count } => write!(
                f,
                "{count} limitations on one record, over the {MAX_LIMITATIONS} limit"
            ),
        }
    }
}

impl core::error::Error for EvidenceError {}

/// One collector observation, addressable and bounded.
///
/// Construct with [`EvidenceRecord::new`]; the fields are read-only, because a
/// record that can be edited after the fact answers to an id that no longer
/// describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRecord {
    schema: u16,
    id: EvidenceId,
    origin: Origin,
    sequence: u64,
    collector_version: u32,
    coverage: CollectionCoverage,
    limitations: Vec<Limitation>,
    fact: Fact,
}

impl EvidenceRecord {
    /// Builds a record, refusing anything unbounded, unattributed, or misdated.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceError`] for an unknown schema, a blank or oversized
    /// origin field, an observation time outside the accepted range, or more
    /// limitations than [`MAX_LIMITATIONS`].
    pub fn new(
        schema: u16,
        origin: Origin,
        sequence: u64,
        collector_version: u32,
        coverage: CollectionCoverage,
        limitations: Vec<Limitation>,
        fact: Fact,
    ) -> Result<Self, EvidenceError> {
        if schema != EVIDENCE_SCHEMA {
            return Err(EvidenceError::UnknownSchema {
                found: schema,
                expected: EVIDENCE_SCHEMA,
            });
        }
        for (field, value) in [
            ("host_id", &origin.host_id),
            ("boot_id", &origin.boot_id),
            ("sensor_instance", &origin.sensor_instance),
        ] {
            if value.trim().is_empty() {
                return Err(EvidenceError::BlankField { field });
            }
            if value.len() > MAX_FIELD_BYTES {
                return Err(EvidenceError::FieldTooLarge {
                    field,
                    bytes: value.len(),
                });
            }
        }
        let UnixMillis(observed) = fact.observed_at();
        if !(MIN_OBSERVED_AT..=MAX_OBSERVED_AT).contains(&observed) {
            return Err(EvidenceError::TimeOutOfRange { found: observed });
        }
        if limitations.len() > MAX_LIMITATIONS {
            return Err(EvidenceError::TooManyLimitations {
                count: limitations.len(),
            });
        }

        let mut limitations = limitations;
        limitations.sort_unstable();
        limitations.dedup();

        let mut record = Self {
            schema,
            id: EvidenceId(String::new()),
            origin,
            sequence,
            collector_version,
            coverage,
            limitations,
            fact,
        };
        record.id = EvidenceId(digest_of(&record));
        Ok(record)
    }

    /// Content address of this record.
    #[must_use]
    pub const fn id(&self) -> &EvidenceId {
        &self.id
    }

    /// Envelope schema version.
    #[must_use]
    pub const fn schema(&self) -> u16 {
        self.schema
    }

    /// Which sensor, host, and boot produced it.
    #[must_use]
    pub const fn origin(&self) -> &Origin {
        &self.origin
    }

    /// Position in this sensor instance's stream.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Which build of the collector produced it.
    #[must_use]
    pub const fn collector_version(&self) -> u32 {
        self.collector_version
    }

    /// What the collector could and could not have seen.
    #[must_use]
    pub const fn coverage(&self) -> CollectionCoverage {
        self.coverage
    }

    /// What this observation does not cover, sorted and deduplicated.
    #[must_use]
    pub fn limitations(&self) -> &[Limitation] {
        &self.limitations
    }

    /// The observation itself.
    #[must_use]
    pub const fn fact(&self) -> &Fact {
        &self.fact
    }

    /// The bytes the id is taken over.
    ///
    /// Exposed so a verifier can recompute the id without reimplementing the
    /// encoding, and so a golden fixture can pin the bytes rather than a hash
    /// of them.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        Canonical::of(self)
    }
}

impl Encode for EvidenceRecord {
    /// The id field is deliberately absent.
    ///
    /// It is derived from these bytes, so including it would make the digest
    /// depend on itself.
    fn encode(&self, into: &mut Canonical) {
        into.u16(self.schema);
        self.origin.encode(into);
        into.u64(self.sequence);
        into.u32(self.collector_version);
        self.coverage.encode(into);
        into.list(&self.limitations);
        self.fact.encode(into);
    }
}

use crate::reader::{Decode, DecodeError, Reader};

impl Decode for Origin {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            host_id: from.string()?,
            boot_id: from.string()?,
            sensor_instance: from.string()?,
        })
    }
}

impl Decode for EvidenceId {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        from.string().map(Self)
    }
}

impl Decode for EvidenceRecord {
    /// The id is recomputed rather than read.
    ///
    /// It is not in the bytes, so a reader that trusted a supplied id would be
    /// trusting the thing the id exists to check.
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let schema = from.u16()?;
        let origin = Origin::decode(from)?;
        let sequence = from.u64()?;
        let collector_version = from.u32()?;
        let coverage = CollectionCoverage::decode(from)?;
        let limitations = from.list()?;
        let fact = Fact::decode(from)?;
        Self::new(
            schema,
            origin,
            sequence,
            collector_version,
            coverage,
            limitations,
            fact,
        )
        .map_err(|error| DecodeError::Rejected {
            reason: error.to_string(),
        })
    }
}
