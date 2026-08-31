//! What to do about a factor.
//!
//! Written for the person who has to act, in terms of their own machine. A
//! finding without a next step is a complaint.

use super::factor::FactorCode;
use super::grade::Risk;
use std::collections::BTreeMap;

/// A change that would lower the score, paired with the factor it cancels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remediation {
    /// The factor this would remove.
    pub cancels: FactorCode,
    /// Points it would return.
    pub points: u32,
    /// What to do.
    pub action: &'static str,
    /// Where to do it.
    pub site: &'static str,
}

/// What would bring an agent's score down, strongest first.
///
/// Derived from the factors that actually fired, so it never suggests fixing
/// something that is not wrong. One entry per code even when a code fired more
/// than once: two reachable secrets are one filesystem problem, not two, and the
/// points are summed so the entry is worth what fixing it is worth.
#[must_use]
pub fn remediations(risk: &Risk) -> Vec<Remediation> {
    // Sum by code first. Doing it in one pass over a growing Vec needed a
    // "we inserted it, so it must be there" branch that nothing could ever
    // exercise; a map has no such arm.
    let mut totals: BTreeMap<FactorCode, u32> = BTreeMap::new();
    for f in &risk.factors {
        let entry = totals.entry(f.code).or_insert(0);
        *entry = entry.saturating_add(f.points);
    }

    let mut out: Vec<Remediation> = totals
        .into_iter()
        .map(|(cancels, points)| {
            let (action, site) = cancels.remedy();
            Remediation {
                cancels,
                points,
                action,
                site,
            }
        })
        .collect();

    out.sort_by(|a, b| {
        b.points
            .cmp(&a.points)
            .then_with(|| a.cancels.cmp(&b.cancels))
    });
    out
}
