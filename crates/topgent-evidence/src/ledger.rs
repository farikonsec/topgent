//! The set of records and claims, and the traversal between them.
//!
//! The ledger is keyed by content address, so insertion order does not reach
//! the result. That is what makes a rule order-independent in practice rather
//! than by assertion: two runs that observe the same things in different orders
//! produce the same ledger, byte for byte.
//!
//! Two refusals are load-bearing. A duplicate id means two different records
//! claim the same address, which can only happen if one of them was altered. A
//! claim naming a record the ledger does not hold cannot be explained, and an
//! unexplainable claim is the thing this whole layer exists to prevent.

use std::collections::BTreeMap;

use crate::canonical::{Canonical, Encode, digest_of};
use crate::claim::{ClaimId, DerivedClaim};
use crate::record::{EvidenceId, EvidenceRecord};

/// Why a record or claim could not be admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    /// Two different records claim the same content address.
    DuplicateEvidence {
        /// The contested id.
        id: EvidenceId,
    },
    /// Two different claims claim the same content address.
    DuplicateClaim {
        /// The contested id.
        id: ClaimId,
    },
    /// A claim names a record the ledger does not hold.
    MissingEvidence {
        /// The claim that could not be admitted.
        claim: ClaimId,
        /// The record it named.
        missing: EvidenceId,
    },
}

impl core::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DuplicateEvidence { id } => {
                write!(f, "two different records claim evidence id {id}")
            }
            Self::DuplicateClaim { id } => write!(f, "two different claims claim id {id}"),
            Self::MissingEvidence { claim, missing } => {
                write!(f, "claim {claim} names evidence {missing}, which is absent")
            }
        }
    }
}

impl core::error::Error for LedgerError {}

/// Records and the claims derived from them.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Ledger {
    records: BTreeMap<EvidenceId, EvidenceRecord>,
    claims: BTreeMap<ClaimId, DerivedClaim>,
}

impl Ledger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty ledger, in a const context.
    #[must_use]
    pub const fn new_const() -> Self {
        Self {
            records: BTreeMap::new(),
            claims: BTreeMap::new(),
        }
    }

    /// Admits one record.
    ///
    /// Re-inserting a byte-identical record is not an error; it is the same
    /// record arriving twice, which happens whenever two bundles are merged.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError::DuplicateEvidence`] when a different record
    /// already holds this id.
    pub fn add_record(&mut self, record: EvidenceRecord) -> Result<(), LedgerError> {
        match self.records.get(record.id()) {
            Some(existing) if *existing != record => Err(LedgerError::DuplicateEvidence {
                id: record.id().clone(),
            }),
            Some(_) => Ok(()),
            None => {
                self.records.insert(record.id().clone(), record);
                Ok(())
            }
        }
    }

    /// Admits one claim, after checking every record it names is present.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError::MissingEvidence`] when the claim names a record
    /// the ledger does not hold, and [`LedgerError::DuplicateClaim`] when a
    /// different claim already holds this id.
    pub fn add_claim(&mut self, claim: DerivedClaim) -> Result<(), LedgerError> {
        for referenced in claim.referenced() {
            if !self.records.contains_key(referenced) {
                return Err(LedgerError::MissingEvidence {
                    claim: claim.id().clone(),
                    missing: referenced.clone(),
                });
            }
        }
        match self.claims.get(claim.id()) {
            Some(existing) if *existing != claim => Err(LedgerError::DuplicateClaim {
                id: claim.id().clone(),
            }),
            Some(_) => Ok(()),
            None => {
                self.claims.insert(claim.id().clone(), claim);
                Ok(())
            }
        }
    }

    /// One record by id.
    #[must_use]
    pub fn record(&self, id: &EvidenceId) -> Option<&EvidenceRecord> {
        self.records.get(id)
    }

    /// One claim by id.
    #[must_use]
    pub fn claim(&self, id: &ClaimId) -> Option<&DerivedClaim> {
        self.claims.get(id)
    }

    /// Every record, in content-address order.
    pub fn records(&self) -> impl Iterator<Item = &EvidenceRecord> {
        self.records.values()
    }

    /// Every claim, in content-address order.
    pub fn claims(&self) -> impl Iterator<Item = &DerivedClaim> {
        self.claims.values()
    }

    /// How many records are held.
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// How many claims are held.
    #[must_use]
    pub fn claim_count(&self) -> usize {
        self.claims.len()
    }

    /// Content address of the whole ledger.
    ///
    /// Independent of the order records and claims were added, because the
    /// maps are ordered by content address rather than by arrival.
    #[must_use]
    pub fn digest(&self) -> String {
        digest_of(self)
    }

    /// Finds a claim by an unambiguous id prefix.
    ///
    /// A short id is a label, not an identifier, so a prefix matching more than
    /// one claim resolves to none rather than to the first.
    #[must_use]
    pub fn resolve_claim(&self, prefix: &str) -> Option<&DerivedClaim> {
        let mut found = self
            .claims
            .iter()
            .filter(|(id, _)| id.as_str().starts_with(prefix))
            .map(|(_, claim)| claim);
        let first = found.next()?;
        if found.next().is_some() {
            None
        } else {
            Some(first)
        }
    }

    /// The full derivation of one claim, ready to print.
    ///
    /// This is the M1 exit test: every user-facing statement resolves to the
    /// records it was derived from, without knowing anything about how the
    /// ledger is stored.
    #[must_use]
    pub fn explain(&self, id: &ClaimId) -> Option<Derivation<'_>> {
        let claim = self.claims.get(id)?;
        let supporting = claim
            .supporting()
            .iter()
            .filter_map(|each| self.records.get(each))
            .collect();
        let contradicting = claim
            .contradicting()
            .iter()
            .filter_map(|each| self.records.get(each))
            .collect();
        Some(Derivation {
            claim,
            supporting,
            contradicting,
        })
    }
}

impl Encode for Ledger {
    fn encode(&self, into: &mut Canonical) {
        into.u32(u32::try_from(self.records.len()).unwrap_or(u32::MAX));
        for record in self.records.values() {
            record.encode(into);
        }
        into.u32(u32::try_from(self.claims.len()).unwrap_or(u32::MAX));
        for claim in self.claims.values() {
            claim.encode(into);
        }
    }
}

/// One claim and every record behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Derivation<'a> {
    /// The claim being explained.
    pub claim: &'a DerivedClaim,
    /// Records that support it.
    pub supporting: Vec<&'a EvidenceRecord>,
    /// Records that disagree with it.
    pub contradicting: Vec<&'a EvidenceRecord>,
}

impl Derivation<'_> {
    /// Renders the derivation as plain text.
    ///
    /// Quality and coverage are printed on their own line and never merged.
    /// `exact` beside `snapshot_only` is the common case, and a reader who
    /// cannot see both has been told half the answer.
    #[must_use]
    pub fn render(&self) -> String {
        use core::fmt::Write as _;
        let mut out = String::new();
        let _ = writeln!(out, "claim    {}", self.claim.id());
        let _ = writeln!(out, "rule     {}", self.claim.rule());
        let _ = writeln!(out, "says     {}", self.claim.statement());
        let _ = writeln!(
            out,
            "quality  {}   coverage  {}",
            self.claim.quality().as_str(),
            self.claim.coverage().as_str()
        );
        for limitation in self.claim.limitations() {
            let _ = writeln!(out, "limit    {}", limitation.statement());
        }
        let _ = writeln!(out, "derived from {} record(s)", self.supporting.len());
        for record in &self.supporting {
            let _ = writeln!(out, "{}", Self::line(record));
        }
        if !self.contradicting.is_empty() {
            let _ = writeln!(
                out,
                "contradicted by {} record(s)",
                self.contradicting.len()
            );
            for record in &self.contradicting {
                let _ = writeln!(out, "{}", Self::line(record));
            }
        }
        out
    }

    /// One record, on one line.
    fn line(record: &EvidenceRecord) -> String {
        use core::fmt::Write as _;
        let mut out = String::new();
        let _ = write!(
            out,
            "  {} seq {:<6} {:<24} {:<20} {}",
            record.id().short(),
            record.sequence(),
            record.fact().claim().kind(),
            record.fact().provenance().collector,
            record.coverage().as_str()
        );
        for limitation in record.limitations() {
            let _ = write!(out, " [{}]", limitation.as_str());
        }
        out
    }
}

use crate::reader::{Decode, DecodeError, Reader};

impl Decode for Ledger {
    /// Read through [`Ledger::add_record`] and [`Ledger::add_claim`], so a
    /// bundle holding a duplicate address or a dangling reference is refused on
    /// load rather than discovered during a report.
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let mut ledger = Self::new();
        let record_count = from.u32()?;
        for _ in 0..record_count {
            let record = EvidenceRecord::decode(from)?;
            ledger
                .add_record(record)
                .map_err(|error| DecodeError::Rejected {
                    reason: error.to_string(),
                })?;
        }
        let claim_count = from.u32()?;
        for _ in 0..claim_count {
            let claim = DerivedClaim::decode(from)?;
            ledger
                .add_claim(claim)
                .map_err(|error| DecodeError::Rejected {
                    reason: error.to_string(),
                })?;
        }
        Ok(ledger)
    }
}
