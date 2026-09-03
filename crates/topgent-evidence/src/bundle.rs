//! The exported bundle, and the verification that trusts nothing inside it.
//!
//! A bundle is what leaves the machine: the records, the chain over them, the
//! claims derived from them, the signed checkpoints, and any key rotations. It
//! is designed to be read by something that does not trust the sensor, the
//! journal writer, or the user interface. Decision D4.
//!
//! # What verification does and does not establish
//!
//! A verified bundle establishes that its records were not modified, inserted,
//! reordered, or truncated after the covering checkpoint was signed, by a
//! holder of the signing key. It does not establish that the sensor observed
//! correctly, and it does not on its own establish that nothing was missed:
//! that is what [`Verdict::IntactWithGaps`] exists to keep separate.
//!
//! # Trust comes from outside
//!
//! [`Bundle::keys`] holds the public keys the producer chose to include. They
//! are there so a reader can see which key was claimed, not so the bundle can
//! vouch for itself. [`Bundle::verify`] takes the keys the *verifier* trusts.
//! Passing a bundle its own keys checks internal consistency and nothing about
//! where it came from, and any tool that does so must say which it did.

use crate::canonical::{Canonical, Encode, digest_of};
use crate::chain::{Chain, Checkpoint, EntryHash, KeyId, PublicKey, Rotation, SensorKey};
use crate::claim::DerivedClaim;
use crate::ledger::Ledger;
use crate::reader::{Decode, DecodeError, Reader};
use crate::record::{EvidenceId, EvidenceRecord, Origin};

/// A hole in the sequence, between two entries that are themselves intact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gap {
    /// The last sequence present before the hole.
    pub after: u64,
    /// The first sequence present after it.
    pub before: u64,
}

impl core::fmt::Display for Gap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let missing = self.before.saturating_sub(self.after).saturating_sub(1);
        write!(
            f,
            "{missing} record(s) missing between sequence {} and {}",
            self.after, self.before
        )
    }
}

/// A specific way a bundle failed.
///
/// Every variant names what was expected and what was found. "Verification
/// failed" without a reason is indistinguishable from a bug in the verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Breach {
    /// A record does not hash to the id it is filed under.
    RecordAltered {
        /// The id it claimed.
        claimed: EvidenceId,
        /// The id its bytes produce.
        recomputed: String,
    },
    /// A chain entry names a record the bundle does not hold.
    UnchainedReference {
        /// The entry's sequence.
        sequence: u64,
        /// The record it named.
        missing: EvidenceId,
    },
    /// A record is in the bundle but in no chain entry.
    RecordNotInChain {
        /// The orphan.
        id: EvidenceId,
    },
    /// An entry does not hash to the hash it carries.
    EntryAltered {
        /// The entry's sequence.
        sequence: u64,
        /// The hash it claimed.
        claimed: EntryHash,
        /// The hash its contents produce.
        recomputed: EntryHash,
    },
    /// An entry does not commit to the one before it.
    ChainBroken {
        /// Where the break is.
        sequence: u64,
        /// The hash the entry should have carried.
        expected: Option<EntryHash>,
        /// The hash it did carry.
        found: Option<EntryHash>,
    },
    /// Two entries claim the same position.
    DuplicateSequence {
        /// The contested position.
        sequence: u64,
    },
    /// Entries are not in increasing order.
    OutOfOrder {
        /// The sequence that went backwards.
        sequence: u64,
        /// What preceded it.
        after: u64,
    },
    /// A record belongs to a different host, boot, or sensor instance.
    ForeignOrigin {
        /// The record.
        id: EvidenceId,
        /// The origin the chain was opened for.
        expected: Box<Origin>,
        /// The origin the record carried.
        found: Box<Origin>,
    },
    /// A checkpoint names a key the verifier does not trust and no rotation reaches.
    UnknownKey {
        /// The key named.
        key_id: KeyId,
    },
    /// A checkpoint's signature does not verify under the key it names.
    BadSignature {
        /// The key named.
        key_id: KeyId,
        /// The sequence the checkpoint claimed to cover.
        through_sequence: u64,
    },
    /// A rotation was not signed by the key stepping down.
    BadRotation {
        /// The key that should have signed.
        retiring: KeyId,
    },
    /// A checkpoint was signed by a key that had already handed over.
    RetiredKey {
        /// The key that signed.
        key_id: KeyId,
        /// The sequence from which it was no longer authoritative.
        retired_from: u64,
    },
    /// A checkpoint covers a sequence the chain does not reach.
    CheckpointBeyondChain {
        /// The sequence claimed.
        through_sequence: u64,
        /// The highest sequence present.
        highest: u64,
    },
    /// A checkpoint's head does not match the chain at that point.
    ///
    /// This is what truncation and reordering inside a signed segment look like.
    HeadMismatch {
        /// The sequence covered.
        through_sequence: u64,
        /// The head the checkpoint was signed over.
        signed: EntryHash,
        /// The head the chain actually produces.
        found: EntryHash,
    },
    /// A checkpoint counts a different number of entries than the chain holds.
    CountMismatch {
        /// The count signed.
        signed: u64,
        /// The count present.
        found: u64,
    },
    /// A checkpoint was signed over a different host, boot, or sensor instance.
    CheckpointOrigin {
        /// The origin the chain declares.
        expected: Box<Origin>,
        /// The origin the checkpoint was signed over.
        found: Box<Origin>,
    },
    /// The bundle carries no checkpoint, so nothing is signed.
    NoCheckpoint,
    /// A claim names a record the bundle does not hold.
    ClaimReferenceMissing {
        /// The claim.
        claim: String,
        /// The record it named.
        missing: EvidenceId,
    },
}

impl core::fmt::Display for Breach {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RecordAltered {
                claimed,
                recomputed,
            } => write!(
                f,
                "record {} hashes to {}, so its bytes changed after it was written",
                claimed.short(),
                recomputed.get(..12).unwrap_or(recomputed)
            ),
            Self::UnchainedReference { sequence, missing } => write!(
                f,
                "chain position {sequence} names record {}, which the bundle does not hold",
                missing.short()
            ),
            Self::RecordNotInChain { id } => write!(
                f,
                "record {} is present but occupies no chain position",
                id.short()
            ),
            Self::EntryAltered {
                sequence,
                claimed,
                recomputed,
            } => write!(
                f,
                "chain position {sequence} carries hash {} but its contents produce {}",
                claimed.short(),
                recomputed.short()
            ),
            Self::ChainBroken {
                sequence,
                expected,
                found,
            } => write!(
                f,
                "chain position {sequence} commits to {}, but the entry before it hashes to {}",
                found.as_ref().map_or("nothing", EntryHash::short),
                expected.as_ref().map_or("nothing", EntryHash::short)
            ),
            Self::DuplicateSequence { sequence } => {
                write!(f, "two entries claim chain position {sequence}")
            }
            Self::OutOfOrder { sequence, after } => {
                write!(f, "chain position {sequence} appears after {after}")
            }
            Self::ForeignOrigin {
                id,
                expected,
                found,
            } => write!(
                f,
                "record {} belongs to {}/{}, not to {}/{}",
                id.short(),
                found.host_id,
                found.boot_id,
                expected.host_id,
                expected.boot_id
            ),
            Self::UnknownKey { key_id } => write!(
                f,
                "key {} is not trusted and no rotation reaches it from one that is",
                key_id.short()
            ),
            Self::BadSignature {
                key_id,
                through_sequence,
            } => write!(
                f,
                "the checkpoint through sequence {through_sequence} does not verify under key {}",
                key_id.short()
            ),
            Self::BadRotation { retiring } => write!(
                f,
                "a rotation away from key {} was not signed by that key",
                retiring.short()
            ),
            Self::RetiredKey {
                key_id,
                retired_from,
            } => write!(
                f,
                "key {} signed a checkpoint although it handed over at sequence {retired_from}",
                key_id.short()
            ),
            Self::CheckpointBeyondChain {
                through_sequence,
                highest,
            } => write!(
                f,
                "a checkpoint covers sequence {through_sequence}, but the chain stops at {highest}"
            ),
            Self::HeadMismatch {
                through_sequence,
                signed,
                found,
            } => write!(
                f,
                "at sequence {through_sequence} the signature covers head {} but the chain produces {}",
                signed.short(),
                found.short()
            ),
            Self::CountMismatch { signed, found } => write!(
                f,
                "the signature covers {signed} entries, the chain holds {found}"
            ),
            Self::CheckpointOrigin { expected, found } => write!(
                f,
                "a checkpoint was signed over {}/{}, the chain declares {}/{}",
                found.host_id, found.boot_id, expected.host_id, expected.boot_id
            ),
            Self::NoCheckpoint => f.write_str("the bundle carries no signature at all"),
            Self::ClaimReferenceMissing { claim, missing } => write!(
                f,
                "claim {} names record {}, which the bundle does not hold",
                claim.get(..12).unwrap_or(claim),
                missing.short()
            ),
        }
    }
}

/// What a verified bundle amounts to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// Which sensor instance, host, and boot.
    pub origin: Origin,
    /// How many records.
    pub records: usize,
    /// How many claims.
    pub claims: usize,
    /// The highest sequence covered by a verified signature.
    pub through_sequence: u64,
    /// Which key the covering signature belongs to.
    pub key_id: KeyId,
}

/// The result of verifying a bundle.
///
/// Three states, not two. Collapsing the middle one into "verified" would
/// present a bundle with holes as a complete account, which is the exact
/// substitution `docs/NORMATIVE-CLAIMS.md` §3.7 forbids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing was altered and the stream has no holes.
    Intact(Summary),
    /// Nothing was altered, and the stream is missing records.
    ///
    /// A partial disclosure looks exactly like this, and so does a sensor that
    /// dropped records. The bundle cannot tell them apart, and neither may any
    /// tool built on it.
    IntactWithGaps {
        /// What was verified.
        summary: Summary,
        /// Where the holes are.
        gaps: Vec<Gap>,
    },
    /// Something failed, with every reason listed.
    Broken(Vec<Breach>),
}

impl Verdict {
    /// Whether nothing was altered, holes or not.
    #[must_use]
    pub const fn is_intact(&self) -> bool {
        matches!(self, Self::Intact(_) | Self::IntactWithGaps { .. })
    }

    /// Every failure, empty when the bundle is intact.
    #[must_use]
    pub fn breaches(&self) -> &[Breach] {
        match self {
            Self::Broken(breaches) => breaches,
            Self::Intact(_) | Self::IntactWithGaps { .. } => &[],
        }
    }
}

/// Records, the chain over them, the claims derived from them, and the signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    ledger: Ledger,
    chain: Chain,
    keys: Vec<PublicKey>,
    rotations: Vec<Rotation>,
    checkpoints: Vec<Checkpoint>,
}

impl Bundle {
    /// Assembles a bundle from parts, without checking any of them.
    ///
    /// This is exactly what decoding does. Verification is a separate step by
    /// design: a reader has to be able to hold a bundle it does not yet trust,
    /// and a constructor that refused one could never report what was wrong
    /// with it.
    #[must_use]
    pub const fn from_parts(
        ledger: Ledger,
        chain: Chain,
        keys: Vec<PublicKey>,
        rotations: Vec<Rotation>,
        checkpoints: Vec<Checkpoint>,
    ) -> Self {
        Self {
            ledger,
            chain,
            keys,
            rotations,
            checkpoints,
        }
    }

    /// An empty bundle for one sensor instance.
    #[must_use]
    pub const fn new(origin: Origin) -> Self {
        Self {
            ledger: Ledger::new_const(),
            chain: Chain::new(origin),
            keys: Vec::new(),
            rotations: Vec::new(),
            checkpoints: Vec::new(),
        }
    }

    /// Adds a record to the ledger and the next chain position.
    ///
    /// # Errors
    ///
    /// Returns the reason as text when the record belongs to another origin,
    /// does not follow the last sequence, or collides with a different record.
    pub fn append(&mut self, record: EvidenceRecord) -> Result<(), String> {
        self.chain
            .append(&record)
            .map_err(|error| error.to_string())?;
        self.ledger
            .add_record(record)
            .map_err(|error| error.to_string())
    }

    /// Adds a claim.
    ///
    /// # Errors
    ///
    /// Returns the reason as text when the claim names an absent record.
    pub fn add_claim(&mut self, claim: DerivedClaim) -> Result<(), String> {
        self.ledger
            .add_claim(claim)
            .map_err(|error| error.to_string())
    }

    /// Signs the current head and records the public key alongside it.
    ///
    /// The key is included so a reader can see which key was claimed. It is not
    /// what verification trusts.
    pub fn seal(&mut self, key: &SensorKey) {
        if let Some(checkpoint) = self.chain.checkpoint(key) {
            self.checkpoints.push(checkpoint);
        }
        if !self.keys.iter().any(|known| known.id() == key.id()) {
            self.keys.push(key.public().clone());
        }
    }

    /// Records a key handover.
    pub fn rotate(&mut self, rotation: Rotation) {
        if !self
            .keys
            .iter()
            .any(|known| known.id() == rotation.body().replacing.id())
        {
            self.keys.push(rotation.body().replacing.clone());
        }
        self.rotations.push(rotation);
    }

    /// The records and claims.
    #[must_use]
    pub const fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// The chain over the records.
    #[must_use]
    pub const fn chain(&self) -> &Chain {
        &self.chain
    }

    /// The public keys the producer included.
    ///
    /// Present for inspection. Verification trusts the keys the verifier holds.
    #[must_use]
    pub fn keys(&self) -> &[PublicKey] {
        &self.keys
    }

    /// The signed checkpoints.
    #[must_use]
    pub fn checkpoints(&self) -> &[Checkpoint] {
        &self.checkpoints
    }

    /// The recorded key handovers.
    #[must_use]
    pub fn rotations(&self) -> &[Rotation] {
        &self.rotations
    }

    /// Content address of the whole bundle.
    #[must_use]
    pub fn digest(&self) -> String {
        digest_of(self)
    }
}

impl Encode for Bundle {
    fn encode(&self, into: &mut Canonical) {
        into.text("topgent-bundle-v1");
        self.ledger.encode(into);
        self.chain.encode(into);
        into.list(&self.keys);
        into.list(&self.rotations);
        into.list(&self.checkpoints);
    }
}

impl Decode for Bundle {
    fn decode(from: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let magic = from.text()?;
        if magic != "topgent-bundle-v1" {
            return Err(DecodeError::UnknownVariant {
                vocabulary: "bundle",
                found: magic.to_owned(),
            });
        }
        Ok(Self {
            ledger: Ledger::decode(from)?,
            chain: Chain::decode(from)?,
            keys: from.list()?,
            rotations: from.list()?,
            checkpoints: from.list()?,
        })
    }
}
