//! One assertion, with the provenance that makes it admissible.
//!
//! A fact cannot be constructed without naming the collector, the probe, and
//! how confident that probe is. This is enforced by the constructor rather than
//! by convention, because a finding whose source cannot be printed is not a
//! finding and there must be no way to make one.

use crate::claim::Claim;
use crate::scalar::Confidence;
use crate::scalar::UnixMillis;
use crate::subject::Subject;
use crate::version::FactError;
use crate::version::SCHEMA_VERSION;
use crate::version::SchemaVersion;

/// Where a fact came from and how much to trust it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// Which collector emitted it, such as `process`.
    pub collector: String,
    /// The probe that produced it, printable to the user, such as `lsof -i -n -P`.
    pub probe: String,
    /// How much weight the probe deserves.
    pub confidence: Confidence,
    /// When the observation was made.
    pub observed_at: UnixMillis,
}

/// One immutable, attributed assertion.
///
/// Construct with [`Fact::new`]; the fields are read-only by design, because a
/// fact that can be edited after the fact is not evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fact {
    schema: SchemaVersion,
    subject: Subject,
    claim: Claim,
    provenance: Provenance,
}

impl Fact {
    /// Build a fact, refusing anything unattributed or from an unknown schema.
    ///
    /// # Errors
    ///
    /// Returns [`FactError::UnknownSchema`] when `schema` is not [`SCHEMA_VERSION`],
    /// and [`FactError::MissingProvenance`] when the collector or probe is blank.
    pub fn new(
        schema: SchemaVersion,
        subject: Subject,
        claim: Claim,
        provenance: Provenance,
    ) -> Result<Self, FactError> {
        if schema != SCHEMA_VERSION {
            return Err(FactError::UnknownSchema {
                found: schema,
                expected: SCHEMA_VERSION,
            });
        }
        if provenance.collector.trim().is_empty() {
            return Err(FactError::MissingProvenance { field: "collector" });
        }
        if provenance.probe.trim().is_empty() {
            return Err(FactError::MissingProvenance { field: "probe" });
        }
        Ok(Self {
            schema,
            subject,
            claim,
            provenance,
        })
    }

    /// Schema version this fact was written against.
    #[must_use]
    pub const fn schema(&self) -> SchemaVersion {
        self.schema
    }

    /// What the fact is about.
    #[must_use]
    pub const fn subject(&self) -> &Subject {
        &self.subject
    }

    /// What is asserted.
    #[must_use]
    pub const fn claim(&self) -> &Claim {
        &self.claim
    }

    /// Where it came from.
    #[must_use]
    pub const fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    /// When it was observed.
    #[must_use]
    pub const fn observed_at(&self) -> UnixMillis {
        self.provenance.observed_at
    }

    /// How much weight it deserves.
    #[must_use]
    pub const fn confidence(&self) -> Confidence {
        self.provenance.confidence
    }
}
