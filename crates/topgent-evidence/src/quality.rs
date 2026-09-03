//! The two dimensions every claim carries.
//!
//! Normative definitions live in `docs/NORMATIVE-CLAIMS.md` §4. This module is
//! that section as code, and the two enums are deliberately separate types so
//! neither can be passed where the other is expected.
//!
//! The pairing that matters is [`AttributionQuality::Exact`] with
//! [`CollectionCoverage::SnapshotOnly`]. It is legal, it is the common case on
//! every platform Topgent currently ships, and it means: what was seen was
//! matched precisely, and an unknown amount was never seen. Rendering it as a
//! confident finding is the failure the whole vocabulary exists to prevent.

use crate::canonical::{Canonical, Encode};

/// How well an observation was tied to its subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AttributionQuality {
    /// Insufficient evidence.
    Unknown,
    /// Applicable evidence disagrees.
    Contradicted,
    /// Snapshot, partial tuple, or time-window inference.
    Weak,
    /// Several independent observations agree and none conflicts.
    Strong,
    /// A native event, or a complete tuple matched to a stable process key.
    Exact,
}

impl AttributionQuality {
    /// The wire name, also what reports print.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Contradicted => "contradicted",
            Self::Weak => "weak",
            Self::Strong => "strong",
            Self::Exact => "exact",
        }
    }

    /// The weakest of two qualities.
    ///
    /// Ancestry is the reason this exists: a chain of parent edges is no
    /// stronger than its weakest edge, and a transitive claim that reported the
    /// strongest link would be an overclaim by construction.
    #[must_use]
    pub fn weakest(self, other: Self) -> Self {
        if (self as u8) <= (other as u8) {
            self
        } else {
            other
        }
    }
}

impl Encode for AttributionQuality {
    fn encode(&self, into: &mut Canonical) {
        into.tag(match self {
            Self::Unknown => 0,
            Self::Contradicted => 1,
            Self::Weak => 2,
            Self::Strong => 3,
            Self::Exact => 4,
        });
    }
}

/// What the collector could and could not have seen over the interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CollectionCoverage {
    /// The platform offers no source for this observation.
    Unsupported,
    /// The collector reported drops.
    LossObserved,
    /// The primary collector failed over to a fallback.
    CollectorDegraded,
    /// Periodic sampling. Activity shorter than the sweep can be missed.
    SnapshotOnly,
    /// An event collector accounted zero drops across the whole interval.
    ///
    /// The only state that may be described as complete, and only for the one
    /// collector and the one interval. Topgent never claims completeness across
    /// the union of its collectors.
    CompleteForWindow,
}

impl CollectionCoverage {
    /// The wire name, also what reports print.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unsupported => "unsupported",
            Self::LossObserved => "loss_observed",
            Self::CollectorDegraded => "collector_degraded",
            Self::SnapshotOnly => "snapshot_only",
            Self::CompleteForWindow => "complete_for_window",
        }
    }

    /// Whether this coverage permits the word "complete".
    #[must_use]
    pub const fn permits_completeness(self) -> bool {
        matches!(self, Self::CompleteForWindow)
    }

    /// The weaker of two coverages.
    #[must_use]
    pub fn weakest(self, other: Self) -> Self {
        if (self as u8) <= (other as u8) {
            self
        } else {
            other
        }
    }
}

impl Encode for CollectionCoverage {
    fn encode(&self, into: &mut Canonical) {
        into.tag(match self {
            Self::Unsupported => 0,
            Self::LossObserved => 1,
            Self::CollectorDegraded => 2,
            Self::SnapshotOnly => 3,
            Self::CompleteForWindow => 4,
        });
    }
}

/// A reason an observation or a claim may be incomplete.
///
/// A limitation is not an error. It is the part of the answer that says what
/// the answer does not cover, and dropping it turns a careful result into an
/// overclaim without changing a single value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Limitation {
    /// Sandbox, `TCC`, `AppArmor`, `SELinux`, or container confinement was not evaluated.
    ConfinementUnknown,
    /// The check ran with credentials that are not the subject's.
    ForeignCredentials,
    /// The platform has no access check, so only path resolution was established.
    NoAccessCheck,
    /// The process owner could not be resolved.
    OwnerUnresolved,
    /// The parent edge came from a snapshot and can be destroyed by reparenting.
    SnapshotAncestry,
    /// Only the local port was known, so the socket was not attributed.
    PartialTuple,
    /// The collector reported dropped events over this interval.
    EventsDropped,
    /// The sensor restarted, leaving a bounded gap.
    SensorGap,
    /// The socket table named an owner without saying how it matched.
    ///
    /// Appended rather than inserted. The tag is part of the wire format, so
    /// putting this in its natural alphabetical place would change every
    /// evidence id ever written.
    ProvenanceUnreported,
}

impl Limitation {
    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConfinementUnknown => "confinement_unknown",
            Self::ForeignCredentials => "foreign_credentials",
            Self::NoAccessCheck => "no_access_check",
            Self::OwnerUnresolved => "owner_unresolved",
            Self::SnapshotAncestry => "snapshot_ancestry",
            Self::PartialTuple => "partial_tuple",
            Self::EventsDropped => "events_dropped",
            Self::SensorGap => "sensor_gap",
            Self::ProvenanceUnreported => "provenance_unreported",
        }
    }

    /// One sentence a reader can act on.
    #[must_use]
    pub const fn statement(self) -> &'static str {
        match self {
            Self::ConfinementUnknown => {
                "a sandbox or privacy control could deny this access; it was not evaluated"
            }
            Self::ForeignCredentials => {
                "the check ran as an account other than the subject's, so it answers for that account"
            }
            Self::NoAccessCheck => {
                "this platform offers no access check, so only path resolution was established"
            }
            Self::OwnerUnresolved => "the operating system did not name the owner of this process",
            Self::SnapshotAncestry => {
                "the parent edge came from a snapshot and is destroyed when the parent exits"
            }
            Self::PartialTuple => "only part of the socket tuple was known",
            Self::EventsDropped => "the collector reported dropped events over this interval",
            Self::SensorGap => "the sensor restarted, leaving a bounded gap in this interval",
            Self::ProvenanceUnreported => {
                "the socket table named an owner without saying how it matched"
            }
        }
    }
}

impl Encode for Limitation {
    fn encode(&self, into: &mut Canonical) {
        into.tag(match self {
            Self::ConfinementUnknown => 0,
            Self::ForeignCredentials => 1,
            Self::NoAccessCheck => 2,
            Self::OwnerUnresolved => 3,
            Self::SnapshotAncestry => 4,
            Self::PartialTuple => 5,
            Self::EventsDropped => 6,
            Self::SensorGap => 7,
            Self::ProvenanceUnreported => 8,
        });
    }
}

/// How good a claim is, as one value.
///
/// Quality, coverage, and limitations always travel together. Bundling them
/// into one type means a caller cannot construct a claim that carries a quality
/// and forgets the coverage, which is the shape every overclaim takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    /// How well the observation was tied to its subject.
    pub quality: AttributionQuality,
    /// What the collector could and could not have seen.
    pub coverage: CollectionCoverage,
    /// What the claim does not cover.
    pub limitations: Vec<Limitation>,
}

impl Assessment {
    /// An assessment with no limitations recorded.
    #[must_use]
    pub const fn new(quality: AttributionQuality, coverage: CollectionCoverage) -> Self {
        Self {
            quality,
            coverage,
            limitations: Vec::new(),
        }
    }

    /// The same assessment, carrying one more limitation.
    #[must_use]
    pub fn limited_by(mut self, limitation: Limitation) -> Self {
        self.limitations.push(limitation);
        self
    }

    /// Whether this assessment permits the word "complete".
    #[must_use]
    pub const fn permits_completeness(&self) -> bool {
        self.coverage.permits_completeness()
    }
}

use crate::reader::{Decode, DecodeError, Reader};

/// Reads a tag and maps it, refusing an unknown one.
fn tagged<T: Copy>(
    from: &mut Reader<'_>,
    vocabulary: &'static str,
    table: &[T],
) -> Result<T, DecodeError> {
    let found = from.tag()?;
    table
        .get(found as usize)
        .copied()
        .ok_or_else(|| DecodeError::UnknownVariant {
            vocabulary,
            found: found.to_string(),
        })
}

impl Decode for AttributionQuality {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        tagged(
            from,
            "attribution_quality",
            &[
                Self::Unknown,
                Self::Contradicted,
                Self::Weak,
                Self::Strong,
                Self::Exact,
            ],
        )
    }
}

impl Decode for CollectionCoverage {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        tagged(
            from,
            "collection_coverage",
            &[
                Self::Unsupported,
                Self::LossObserved,
                Self::CollectorDegraded,
                Self::SnapshotOnly,
                Self::CompleteForWindow,
            ],
        )
    }
}

impl Decode for Limitation {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        tagged(
            from,
            "limitation",
            &[
                Self::ConfinementUnknown,
                Self::ForeignCredentials,
                Self::NoAccessCheck,
                Self::OwnerUnresolved,
                Self::SnapshotAncestry,
                Self::PartialTuple,
                Self::EventsDropped,
                Self::SensorGap,
                Self::ProvenanceUnreported,
            ],
        )
    }
}

/// What a socket attribution may be claimed at, given how it was matched.
///
/// The mapping is the whole point of `docs/NORMATIVE-CLAIMS.md` §3.5 existing:
/// a complete four-tuple matched to a live process is `Exact`, and everything
/// else is `Weak` with the reason attached. There is no middle rung, because a
/// key that had to be relaxed did not establish the tuple, and how nearly it
/// did is not a distinction a report can act on.
#[must_use]
pub fn from_match_basis(basis: topgent_facts::MatchBasis) -> Assessment {
    use topgent_facts::MatchBasis;
    let assessment = Assessment::new(
        if basis.is_exact() {
            AttributionQuality::Exact
        } else {
            AttributionQuality::Weak
        },
        CollectionCoverage::SnapshotOnly,
    );
    match basis {
        MatchBasis::ExactTuple | MatchBasis::KernelEvent => assessment,
        MatchBasis::WildcardLocal | MatchBasis::Listener => {
            assessment.limited_by(Limitation::PartialTuple)
        }
        MatchBasis::Unreported => assessment.limited_by(Limitation::ProvenanceUnreported),
    }
}
