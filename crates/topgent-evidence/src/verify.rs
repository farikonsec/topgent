//! Verifying a bundle against keys the verifier already holds.
//!
//! Every check here answers one question and names what it expected. A verifier
//! that returns a boolean is indistinguishable from a verifier with a bug, so
//! the result is a list of specific [`Breach`] values or an explicit
//! [`Verdict::Intact`].
//!
//! The order is deliberate. Key authority is resolved first, because a
//! signature checked against a key nobody trusts is not evidence of anything.
//! Then the records, then the chain, then the signatures over it: each layer
//! only means something once the one beneath it holds.

use std::collections::{BTreeMap, BTreeSet};

use crate::bundle::{Breach, Bundle, Gap, Summary, Verdict};
use crate::canonical::digest_of;
use crate::chain::{KeyId, PublicKey};
use crate::record::EvidenceId;

/// One key, and the sequence from which it no longer signs.
struct Authority {
    key: PublicKey,
    retired_from: Option<u64>,
}

impl Bundle {
    /// Verifies the bundle against keys the caller trusts.
    ///
    /// Passing this bundle's own [`Bundle::keys`] checks internal consistency
    /// and says nothing about where the bundle came from. Any tool that does
    /// that must tell its user which of the two it did.
    #[must_use]
    pub fn verify(&self, trusted: &[PublicKey]) -> Verdict {
        let mut breaches = Vec::new();
        let authority = self.resolve_authority(trusted, &mut breaches);
        self.check_records(&mut breaches);
        let gaps = self.check_chain(&mut breaches);
        let covering = self.check_checkpoints(&authority, &mut breaches);

        if !breaches.is_empty() {
            return Verdict::Broken(breaches);
        }
        let Some((key_id, through_sequence)) = covering else {
            return Verdict::Broken(vec![Breach::NoCheckpoint]);
        };
        let summary = Summary {
            origin: self.chain().origin().clone(),
            records: self.ledger().record_count(),
            claims: self.ledger().claim_count(),
            through_sequence,
            key_id,
        };
        if gaps.is_empty() {
            Verdict::Intact(summary)
        } else {
            Verdict::IntactWithGaps { summary, gaps }
        }
    }

    /// Works out which keys may sign, and from when they may not.
    ///
    /// A rotation is only honoured when the key stepping down was itself
    /// authoritative and actually signed the handover. Otherwise anyone holding
    /// a bundle could mint a key, write a rotation to it, and sign whatever
    /// they liked.
    fn resolve_authority(
        &self,
        trusted: &[PublicKey],
        breaches: &mut Vec<Breach>,
    ) -> BTreeMap<KeyId, Authority> {
        let mut authority: BTreeMap<KeyId, Authority> = trusted
            .iter()
            .map(|key| {
                (
                    key.id().clone(),
                    Authority {
                        key: key.clone(),
                        retired_from: None,
                    },
                )
            })
            .collect();

        let mut ordered: Vec<_> = self.rotations().iter().collect();
        ordered.sort_by_key(|rotation| rotation.body().from_sequence);
        for rotation in ordered {
            let body = rotation.body();
            let Some(retiring) = authority.get(&body.retiring) else {
                breaches.push(Breach::UnknownKey {
                    key_id: body.retiring.clone(),
                });
                continue;
            };
            if !rotation.signed_by(&retiring.key) {
                breaches.push(Breach::BadRotation {
                    retiring: body.retiring.clone(),
                });
                continue;
            }
            if let Some(existing) = authority.get_mut(&body.retiring) {
                existing.retired_from = Some(body.from_sequence);
            }
            authority.insert(
                body.replacing.id().clone(),
                Authority {
                    key: body.replacing.clone(),
                    retired_from: None,
                },
            );
        }
        authority
    }

    /// Each record hashes to its own id and belongs to this sensor instance.
    fn check_records(&self, breaches: &mut Vec<Breach>) {
        for record in self.ledger().records() {
            let recomputed = digest_of(record);
            if recomputed != record.id().as_str() {
                breaches.push(Breach::RecordAltered {
                    claimed: record.id().clone(),
                    recomputed,
                });
            }
            if record.origin() != self.chain().origin() {
                breaches.push(Breach::ForeignOrigin {
                    id: record.id().clone(),
                    expected: Box::new(self.chain().origin().clone()),
                    found: Box::new(record.origin().clone()),
                });
            }
        }
        for claim in self.ledger().claims() {
            for referenced in claim.referenced() {
                if self.ledger().record(referenced).is_none() {
                    breaches.push(Breach::ClaimReferenceMissing {
                        claim: claim.id().as_str().to_owned(),
                        missing: referenced.clone(),
                    });
                }
            }
        }
    }

    /// The chain links, in order, with each entry committing to the one before.
    ///
    /// Returns the holes. A hole is not a breach: a partial disclosure and a
    /// sensor that dropped records produce the same shape, and the bundle
    /// cannot tell them apart.
    fn check_chain(&self, breaches: &mut Vec<Breach>) -> Vec<Gap> {
        let mut gaps = Vec::new();
        let mut seen: BTreeSet<u64> = BTreeSet::new();
        let mut chained: BTreeSet<&EvidenceId> = BTreeSet::new();
        let mut previous = None;
        let mut last = None;

        for entry in self.chain().entries() {
            let recomputed = entry.recomputed();
            if recomputed != *entry.hash() {
                breaches.push(Breach::EntryAltered {
                    sequence: entry.sequence(),
                    claimed: entry.hash().clone(),
                    recomputed,
                });
            }
            if entry.previous() != previous {
                breaches.push(Breach::ChainBroken {
                    sequence: entry.sequence(),
                    expected: previous.cloned(),
                    found: entry.previous().cloned(),
                });
            }
            if !seen.insert(entry.sequence()) {
                breaches.push(Breach::DuplicateSequence {
                    sequence: entry.sequence(),
                });
            }
            if let Some(before) = last {
                if entry.sequence() <= before {
                    breaches.push(Breach::OutOfOrder {
                        sequence: entry.sequence(),
                        after: before,
                    });
                } else if entry.sequence() > before.saturating_add(1) {
                    gaps.push(Gap {
                        after: before,
                        before: entry.sequence(),
                    });
                }
            }
            match self.ledger().record(entry.record_id()) {
                None => breaches.push(Breach::UnchainedReference {
                    sequence: entry.sequence(),
                    missing: entry.record_id().clone(),
                }),
                Some(record) => {
                    chained.insert(record.id());
                }
            }
            previous = Some(entry.hash());
            last = Some(entry.sequence());
        }

        for record in self.ledger().records() {
            if !chained.contains(record.id()) {
                breaches.push(Breach::RecordNotInChain {
                    id: record.id().clone(),
                });
            }
        }
        gaps
    }

    /// Every checkpoint verifies, and the strongest one names how far.
    ///
    /// Returns the key and sequence of the checkpoint reaching furthest, or
    /// `None` when nothing signed the chain.
    fn check_checkpoints(
        &self,
        authority: &BTreeMap<KeyId, Authority>,
        breaches: &mut Vec<Breach>,
    ) -> Option<(KeyId, u64)> {
        if self.checkpoints().is_empty() {
            breaches.push(Breach::NoCheckpoint);
            return None;
        }
        let entries = self.chain().entries();
        let highest = entries.last().map_or(0, crate::chain::ChainEntry::sequence);
        let mut furthest: Option<(KeyId, u64)> = None;

        for checkpoint in self.checkpoints() {
            let body = checkpoint.body();
            if body.origin != *self.chain().origin() {
                breaches.push(Breach::CheckpointOrigin {
                    expected: Box::new(self.chain().origin().clone()),
                    found: Box::new(body.origin.clone()),
                });
                continue;
            }
            let Some(holder) = authority.get(&body.key_id) else {
                breaches.push(Breach::UnknownKey {
                    key_id: body.key_id.clone(),
                });
                continue;
            };
            if let Some(retired) = holder.retired_from
                && body.through_sequence >= retired
            {
                breaches.push(Breach::RetiredKey {
                    key_id: body.key_id.clone(),
                    retired_from: retired,
                });
                continue;
            }
            if !checkpoint.signed_by(&holder.key) {
                breaches.push(Breach::BadSignature {
                    key_id: body.key_id.clone(),
                    through_sequence: body.through_sequence,
                });
                continue;
            }
            let Some(at) = entries
                .iter()
                .position(|entry| entry.sequence() == body.through_sequence)
            else {
                breaches.push(Breach::CheckpointBeyondChain {
                    through_sequence: body.through_sequence,
                    highest,
                });
                continue;
            };
            let Some(entry) = entries.get(at) else {
                continue;
            };
            if *entry.hash() != body.head {
                breaches.push(Breach::HeadMismatch {
                    through_sequence: body.through_sequence,
                    signed: body.head.clone(),
                    found: entry.hash().clone(),
                });
                continue;
            }
            let counted = u64::try_from(at.saturating_add(1)).unwrap_or(u64::MAX);
            if counted != body.entry_count {
                breaches.push(Breach::CountMismatch {
                    signed: body.entry_count,
                    found: counted,
                });
                continue;
            }
            if furthest
                .as_ref()
                .is_none_or(|(_, reach)| body.through_sequence > *reach)
            {
                furthest = Some((body.key_id.clone(), body.through_sequence));
            }
        }
        furthest
    }
}
