//! A conclusion, and the path back to what it was concluded from.
//!
//! A claim is not evidence. It is derived, by a named rule at a named version,
//! from records that can be listed. Two fields make that traversal real rather
//! than decorative: the supporting ids, and the contradicting ids. A rule that
//! drops the contradictions it saw produces a claim that reads as agreement.

use topgent_facts::Subject;

use crate::canonical::{Canonical, Encode, digest_of};
use crate::quality::{Assessment, AttributionQuality, CollectionCoverage, Limitation};
use crate::record::EvidenceId;

/// Which rule produced a claim, at which version.
///
/// The version is not cosmetic. When a rule changes, claims it produced before
/// the change were produced by a different rule, and a reader comparing two
/// runs needs to know which one they are looking at.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleId {
    /// Stable rule name, such as `agent.anchored_identity`.
    pub name: String,
    /// Version of that rule.
    pub version: u32,
}

impl core::fmt::Display for RuleId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}@v{}", self.name, self.version)
    }
}

impl Encode for RuleId {
    fn encode(&self, into: &mut Canonical) {
        into.text(&self.name);
        into.u32(self.version);
    }
}

/// Content address of one claim.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClaimId(String);

impl ClaimId {
    /// The hex digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The first twelve characters, for a report line. Never used for lookup.
    #[must_use]
    pub fn short(&self) -> &str {
        self.0.get(..12).unwrap_or(&self.0)
    }
}

impl core::fmt::Display for ClaimId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a claim could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimError {
    /// No supporting evidence. A conclusion drawn from nothing is not a claim.
    NoSupportingEvidence {
        /// The rule that tried to produce it.
        rule: RuleId,
    },
    /// The rule name was blank.
    BlankRule,
    /// Contradicting evidence was recorded but the quality does not say so.
    ///
    /// A rule that saw disagreement and reported agreement is worse than one
    /// that saw nothing, because the disagreement is in the record proving the
    /// rule knew.
    ContradictionIgnored {
        /// The quality the rule tried to report.
        reported: AttributionQuality,
        /// How many contradicting records it held.
        contradicting: usize,
    },
    /// The claim text is empty.
    BlankStatement,
}

impl core::fmt::Display for ClaimError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoSupportingEvidence { rule } => {
                write!(
                    f,
                    "rule {rule} produced a claim with no supporting evidence"
                )
            }
            Self::BlankRule => f.write_str("a claim was produced by an unnamed rule"),
            Self::ContradictionIgnored {
                reported,
                contradicting,
            } => write!(
                f,
                "{contradicting} contradicting records but quality reported as `{}`",
                reported.as_str()
            ),
            Self::BlankStatement => f.write_str("a claim was produced with no statement"),
        }
    }
}

impl core::error::Error for ClaimError {}

/// One deterministic conclusion, with its derivation attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedClaim {
    id: ClaimId,
    rule: RuleId,
    subject: Subject,
    statement: String,
    quality: AttributionQuality,
    coverage: CollectionCoverage,
    supporting: Vec<EvidenceId>,
    contradicting: Vec<EvidenceId>,
    limitations: Vec<Limitation>,
}

impl DerivedClaim {
    /// Builds a claim, refusing one that cannot be traced or that hides disagreement.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimError`] for a blank rule name or statement, for no
    /// supporting evidence, or for contradicting evidence reported under any
    /// quality other than [`AttributionQuality::Contradicted`].
    pub fn new(
        rule: RuleId,
        subject: Subject,
        statement: String,
        assessment: Assessment,
        supporting: Vec<EvidenceId>,
        contradicting: Vec<EvidenceId>,
    ) -> Result<Self, ClaimError> {
        let Assessment {
            quality,
            coverage,
            limitations,
        } = assessment;
        if rule.name.trim().is_empty() {
            return Err(ClaimError::BlankRule);
        }
        if statement.trim().is_empty() {
            return Err(ClaimError::BlankStatement);
        }
        if supporting.is_empty() {
            return Err(ClaimError::NoSupportingEvidence { rule });
        }
        if !contradicting.is_empty() && quality != AttributionQuality::Contradicted {
            return Err(ClaimError::ContradictionIgnored {
                reported: quality,
                contradicting: contradicting.len(),
            });
        }

        let mut supporting = supporting;
        let mut contradicting = contradicting;
        let mut limitations = limitations;
        supporting.sort_unstable();
        supporting.dedup();
        contradicting.sort_unstable();
        contradicting.dedup();
        limitations.sort_unstable();
        limitations.dedup();

        let mut claim = Self {
            id: ClaimId(String::new()),
            rule,
            subject,
            statement,
            quality,
            coverage,
            supporting,
            contradicting,
            limitations,
        };
        claim.id = ClaimId(digest_of(&claim));
        Ok(claim)
    }

    /// Content address of this claim.
    #[must_use]
    pub const fn id(&self) -> &ClaimId {
        &self.id
    }

    /// Which rule produced it.
    #[must_use]
    pub const fn rule(&self) -> &RuleId {
        &self.rule
    }

    /// What the claim is about.
    #[must_use]
    pub const fn subject(&self) -> &Subject {
        &self.subject
    }

    /// The claim in words.
    #[must_use]
    pub fn statement(&self) -> &str {
        &self.statement
    }

    /// How well the observation was tied to the subject.
    #[must_use]
    pub const fn quality(&self) -> AttributionQuality {
        self.quality
    }

    /// What the collector could and could not have seen.
    #[must_use]
    pub const fn coverage(&self) -> CollectionCoverage {
        self.coverage
    }

    /// Records that support it, sorted and deduplicated.
    #[must_use]
    pub fn supporting(&self) -> &[EvidenceId] {
        &self.supporting
    }

    /// Records that disagree with it, sorted and deduplicated.
    #[must_use]
    pub fn contradicting(&self) -> &[EvidenceId] {
        &self.contradicting
    }

    /// What the claim does not cover.
    #[must_use]
    pub fn limitations(&self) -> &[Limitation] {
        &self.limitations
    }

    /// Every record this claim references, supporting or contradicting.
    #[must_use]
    pub fn referenced(&self) -> Vec<&EvidenceId> {
        self.supporting.iter().chain(&self.contradicting).collect()
    }
}

impl Encode for DerivedClaim {
    /// The id field is absent, because it is derived from these bytes.
    fn encode(&self, into: &mut Canonical) {
        self.rule.encode(into);
        self.subject.encode(into);
        into.text(&self.statement);
        self.quality.encode(into);
        self.coverage.encode(into);
        into.list(&self.supporting);
        into.list(&self.contradicting);
        into.list(&self.limitations);
    }
}

use crate::reader::{Decode, DecodeError, Reader};

impl Decode for RuleId {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            name: from.string()?,
            version: from.u32()?,
        })
    }
}

impl Decode for DerivedClaim {
    /// Read through [`DerivedClaim::new`], so the contradiction rule holds on
    /// the way in as well as on the way out.
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let rule = RuleId::decode(from)?;
        let subject = Subject::decode(from)?;
        let statement = from.string()?;
        let quality = AttributionQuality::decode(from)?;
        let coverage = CollectionCoverage::decode(from)?;
        let supporting = from.list()?;
        let contradicting = from.list()?;
        let limitations = from.list()?;
        Self::new(
            rule,
            subject,
            statement,
            Assessment {
                quality,
                coverage,
                limitations,
            },
            supporting,
            contradicting,
        )
        .map_err(|error| DecodeError::Rejected {
            reason: error.to_string(),
        })
    }
}
