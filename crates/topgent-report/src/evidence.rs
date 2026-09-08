//! Turning one sweep into a signed evidence bundle.
//!
//! `topgent-evidence` defines what a record is, chains records, signs
//! checkpoints and verifies a bundle offline. Until this module existed it had
//! no producer: the crate's only consumers were the `evidence` subcommand and
//! `topgent-verify`, and both of them read. A scan produced a report and
//! nothing else, so every claim about tamper-evidence described a format
//! rather than an artefact anybody could obtain.
//!
//! # Why the producer lives in this crate
//!
//! Because this is where a sweep already happens. A bundle is a second
//! artefact from the same collection run, and building it anywhere else means
//! either sweeping twice or keeping a second collector list. The second list
//! is not hypothetical: [`crate::scan`] carries a comment about the time a
//! registered collector was absent from every report for exactly that reason.
//! One sweep, two artefacts, one list.
//!
//! # What a record inherits from its collector
//!
//! Coverage and limitations are properties of the collector that ran, not of
//! the individual observation, so each fact is joined back to its
//! [`CollectorRun`] by the collector name its provenance already carries. A
//! fact whose collector cannot be found is refused rather than admitted with a
//! guessed coverage, because a record that overstates its own completeness is
//! worse than a missing record.
//!
//! # Ordering
//!
//! Sequence numbers are assigned over facts sorted by their canonical bytes,
//! not by the order collectors happened to return them. Two sweeps of an
//! unchanged host therefore produce the same sequence assignment, which is
//! what makes two bundles comparable. Within one bundle the order is fixed at
//! write time, which is what makes replay of that bundle deterministic.

use topgent_collect::{CapabilityState, CollectorRun};
use topgent_core::{Agent, Risk};
use topgent_evidence::{
    Assessment, AttributionQuality, Bundle, Canonical, CollectionCoverage, DerivedClaim,
    EVIDENCE_SCHEMA, EvidenceId, EvidenceRecord, Limitation, Origin, RuleId, SensorKey,
};
use topgent_facts::{Claim, Confidence, Fact, Subject, UnixMillis};

/// Longest text this build will admit into a record field.
///
/// Every field the fact vocabulary carries is a path, a process name, a user
/// name or a host name. None of them is prose. A value longer than this is
/// content that has arrived somewhere it should not be, and the gate refuses
/// the whole bundle rather than truncating it, because a silently shortened
/// record still says it observed something it did not.
pub const MAX_ADMISSIBLE_TEXT: usize = 1024;

/// Why a bundle could not be produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProduceError {
    /// A fact named a collector that did not appear in the sweep.
    UnknownCollector {
        /// The collector the fact's provenance named.
        collector: String,
    },
    /// The redaction gate refused a fact.
    Redacted {
        /// Which field held it.
        field: &'static str,
        /// How many bytes it held.
        bytes: usize,
    },
    /// The evidence crate refused the record or the chain refused the append.
    Rejected(String),
}

impl core::fmt::Display for ProduceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownCollector { collector } => write!(
                f,
                "fact names collector `{collector}`, which did not run in this sweep"
            ),
            Self::Redacted { field, bytes } => write!(
                f,
                "field `{field}` held {bytes} bytes, over the {MAX_ADMISSIBLE_TEXT} limit; \
                 refusing to write content into evidence"
            ),
            Self::Rejected(detail) => write!(f, "{detail}"),
        }
    }
}

impl core::error::Error for ProduceError {}

/// The collection coverage one collector's facts are entitled to claim.
///
/// Ordered by severity: an unsupported collector cannot also be complete, and
/// a collector that reported loss cannot be complete whatever else is true.
/// Only a collector that measured its drops and found none may say
/// `CompleteForWindow`, and only for its own interval.
#[must_use]
pub fn coverage_for(run: &CollectorRun) -> CollectionCoverage {
    match run.state {
        CapabilityState::Unsupported => CollectionCoverage::Unsupported,
        CapabilityState::PermissionRequired | CapabilityState::Error => {
            CollectionCoverage::CollectorDegraded
        }
        CapabilityState::Available => match run.dropped_events {
            Some(0) => CollectionCoverage::CompleteForWindow,
            Some(_) => CollectionCoverage::LossObserved,
            // The collector does not account for drops, so nothing may be
            // said about what happened between two sweeps.
            None => CollectionCoverage::SnapshotOnly,
        },
    }
}

/// What a collector's facts cannot cover, stated rather than implied.
#[must_use]
pub fn limitations_for(run: &CollectorRun) -> Vec<Limitation> {
    let mut out = Vec::new();
    if matches!(run.dropped_events, Some(n) if n > 0) {
        out.push(Limitation::EventsDropped);
    }
    // A collector's declared boundary is deliberately NOT mapped to
    // `SensorGap`. `boundary` says what a healthy run of this sensor cannot
    // supply on this platform; `SensorGap` says the sensor restarted and left
    // a hole. Mapping one to the other put "the sensor restarted, leaving a
    // bounded gap" on every claim during development, which was simply untrue.
    // A platform boundary is already carried by the coverage state, and there
    // is no limitation in the vocabulary that means what `boundary` means.
    out
}

/// Refuses a fact whose fields hold content rather than metadata.
///
/// The fact vocabulary already excludes process arguments, file contents,
/// prompts and payloads by construction; `ChildProcessSeen` keeps a name and
/// discards `argv` on purpose. This gate is the runtime backstop for that
/// design decision, so a future collector cannot quietly widen what reaches a
/// signed artefact. It checks length, because every legitimate field here is
/// short and content is not.
///
/// # Errors
///
/// Returns [`ProduceError::Redacted`] naming the field and its size.
pub fn redaction_gate(fact: &Fact) -> Result<(), ProduceError> {
    let provenance = fact.provenance();
    for (field, value) in [
        ("provenance.collector", provenance.collector.as_str()),
        ("provenance.probe", provenance.probe.as_str()),
    ] {
        if value.len() > MAX_ADMISSIBLE_TEXT {
            return Err(ProduceError::Redacted {
                field,
                bytes: value.len(),
            });
        }
    }
    match fact.subject() {
        Subject::Process { .. } => {}
        Subject::Resource { path } => bounded("subject.path", path)?,
        Subject::Endpoint { host, .. } => bounded("subject.host", host)?,
    }
    // Matched variant by variant, exhaustively and on purpose. A collector
    // added later that carries a new text field will not compile until someone
    // decides what the gate should do with it, which is the whole point: the
    // set of things allowed into a signed artefact must never widen by
    // accident.
    match fact.claim() {
        Claim::ProcessSeen { exe, user, .. } => {
            bounded("claim.exe", exe)?;
            bounded("claim.user", user)?;
        }
        Claim::ProcessParent { .. } => {}
        Claim::ChildProcessSeen { name, .. } => bounded("claim.name", name)?,
        Claim::SocketOpen { host, .. }
        | Claim::SocketClosed { host, .. }
        | Claim::ConnectionAttempt { host, .. }
        | Claim::TrafficObserved { host, .. } => bounded("claim.host", host)?,
        Claim::DnsQueryObserved { name, .. } | Claim::ConnectorDeclared { name, .. } => {
            bounded("claim.name", name)?;
        }
        Claim::FileTouched { path, .. }
        | Claim::PermissionDeclared { path, .. }
        | Claim::ResourceReachable { path, .. } => bounded("claim.path", path)?,
        Claim::AgentFamily { family, .. } => bounded("claim.family", family)?,
        Claim::EditorExtensionActive {
            family,
            extension_id,
            ..
        } => {
            bounded("claim.family", family)?;
            bounded("claim.extension_id", extension_id)?;
        }
        Claim::ModelInUse {
            provider, model, ..
        } => {
            bounded("claim.provider", provider)?;
            bounded("claim.model", model)?;
        }
        Claim::InvokesAgent { via, .. } => bounded("claim.via", via)?,
        Claim::SubjectNotEvaluated { reason, .. } => bounded("claim.reason", reason)?,
        Claim::ActionTaken { action, .. } => bounded("claim.action", action)?,
    }
    Ok(())
}

/// Refuses one field that is too long to be metadata.
fn bounded(field: &'static str, value: &str) -> Result<(), ProduceError> {
    if value.len() > MAX_ADMISSIBLE_TEXT {
        return Err(ProduceError::Redacted {
            field,
            bytes: value.len(),
        });
    }
    Ok(())
}

/// Builds a sealed bundle from one sweep.
///
/// Facts are sorted by canonical bytes, joined to their collector run for
/// coverage and limitations, wrapped as records, chained, and signed once at
/// the end. One checkpoint covers every entry before it because each entry
/// commits to its predecessor, which is what stops a holder of a disclosed
/// segment reordering inside it.
///
/// # Errors
///
/// Returns [`ProduceError`] when a fact names a collector that did not run,
/// when the redaction gate refuses a fact, or when the evidence crate refuses
/// a record or an append.
pub fn bundle_from_sweep(
    facts: &[Fact],
    runs: &[CollectorRun],
    scored: &[(Agent, Risk)],
    origin: &Origin,
    key: &SensorKey,
    collector_version: u32,
) -> Result<Bundle, ProduceError> {
    let mut ordered: Vec<&Fact> = facts.iter().collect();
    ordered.sort_by_cached_key(|fact| Canonical::of(*fact));

    let mut bundle = Bundle::new(origin.clone());
    for (index, fact) in ordered.iter().enumerate() {
        redaction_gate(fact)?;
        let name = fact.provenance().collector.as_str();
        let run = runs
            .iter()
            .find(|run| run.collector == name)
            .ok_or_else(|| ProduceError::UnknownCollector {
                collector: name.to_owned(),
            })?;
        let sequence = u64::try_from(index).unwrap_or(u64::MAX);
        let record = EvidenceRecord::new(
            EVIDENCE_SCHEMA,
            origin.clone(),
            sequence,
            collector_version,
            coverage_for(run),
            limitations_for(run),
            (*fact).clone(),
        )
        .map_err(|error| ProduceError::Rejected(error.to_string()))?;
        bundle.append(record).map_err(ProduceError::Rejected)?;
    }
    // Claims are attached before the seal so the checkpoint is taken over a
    // finished artefact. The signature still covers the chain rather than the
    // claims, which is a property of the evidence format and is recorded as a
    // finding rather than worked around here.
    attach_claims(&mut bundle, scored)?;
    bundle.seal(key);
    Ok(bundle)
}

/// Version of the risk catalogue a claim was drawn by.
///
/// Carried on every [`RuleId`] so a claim read years later says which edition
/// of the rules produced it. A finding that cannot name its rule version
/// cannot be argued with.
pub const RULE_CATALOGUE_VERSION: u32 = 1;

/// How complete a claim may say it is, given every record behind it.
///
/// The weakest record wins. A claim resting on one snapshot and one complete
/// window is a snapshot claim, because the conclusion is only as covered as
/// the thinnest observation it needs.
fn weakest(coverages: &[CollectionCoverage]) -> CollectionCoverage {
    let rank = |coverage: CollectionCoverage| match coverage {
        CollectionCoverage::Unsupported => 0_u8,
        CollectionCoverage::LossObserved => 1,
        CollectionCoverage::CollectorDegraded => 2,
        CollectionCoverage::SnapshotOnly => 3,
        CollectionCoverage::CompleteForWindow => 4,
    };
    coverages
        .iter()
        .copied()
        .min_by_key(|coverage| rank(*coverage))
        .unwrap_or(CollectionCoverage::Unsupported)
}

/// How firmly one observation was tied to its subject.
const fn quality_of(confidence: Confidence) -> AttributionQuality {
    match confidence {
        Confidence::Certain => AttributionQuality::Exact,
        Confidence::Likely => AttributionQuality::Strong,
        Confidence::Possible => AttributionQuality::Weak,
    }
}

/// Writes one claim per risk factor, each naming the records behind it.
///
/// This is what makes `topgent evidence explain` answer for a live scan rather
/// than only for a fixture. Every factor the scorer produced becomes a claim
/// that cites the records for that process, so a number on a screen can be
/// walked back to the observations it was computed from.
///
/// A factor with no surviving records is skipped rather than written with an
/// empty citation: a claim that cannot be traced is exactly what the evidence
/// crate refuses, and forcing one through would be worse than its absence.
///
/// # Errors
///
/// Returns [`ProduceError::Rejected`] when the evidence crate refuses a claim.
pub fn attach_claims(bundle: &mut Bundle, scored: &[(Agent, Risk)]) -> Result<usize, ProduceError> {
    // Built from the bundle rather than from the sweep, so a claim can only
    // cite a record that is actually present in the artefact being written.
    let mut by_subject: Vec<(
        u32,
        UnixMillis,
        EvidenceId,
        CollectionCoverage,
        Vec<Limitation>,
    )> = Vec::new();
    for record in bundle.ledger().records() {
        if let Subject::Process { pid, started_at } = record.fact().subject() {
            by_subject.push((
                *pid,
                *started_at,
                record.id().clone(),
                record.coverage(),
                record.limitations().to_vec(),
            ));
        }
    }

    let mut written = 0_usize;
    for (agent, risk) in scored {
        let supporting: Vec<&(
            u32,
            UnixMillis,
            EvidenceId,
            CollectionCoverage,
            Vec<Limitation>,
        )> = by_subject
            .iter()
            .filter(|(pid, started, ..)| *pid == agent.id.pid && *started == agent.id.started_at)
            .collect();
        if supporting.is_empty() {
            continue;
        }
        let ids: Vec<EvidenceId> = supporting
            .iter()
            .map(|(_, _, id, _, _)| id.clone())
            .collect();
        let coverages: Vec<CollectionCoverage> =
            supporting.iter().map(|(_, _, _, c, _)| *c).collect();
        let mut limitations: Vec<Limitation> = supporting
            .iter()
            .flat_map(|(_, _, _, _, l)| l.iter().copied())
            .collect();
        limitations.sort_unstable();
        limitations.dedup();
        limitations.truncate(topgent_evidence::MAX_LIMITATIONS);

        for factor in &risk.factors {
            let claim = DerivedClaim::new(
                RuleId {
                    name: format!("risk.{}", factor.code.as_str().to_lowercase()),
                    version: RULE_CATALOGUE_VERSION,
                },
                Subject::Process {
                    pid: agent.id.pid,
                    started_at: agent.id.started_at,
                },
                format!("{} ({})", factor.title, factor.source),
                Assessment {
                    quality: quality_of(factor.confidence),
                    coverage: weakest(&coverages),
                    limitations: limitations.clone(),
                },
                ids.clone(),
                Vec::new(),
            )
            .map_err(|error| ProduceError::Rejected(error.to_string()))?;
            bundle.add_claim(claim).map_err(ProduceError::Rejected)?;
            written += 1;
        }
    }
    Ok(written)
}
