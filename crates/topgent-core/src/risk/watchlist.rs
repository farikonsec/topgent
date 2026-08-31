//! Matching an agent against the operator's own rules.
//!
//! An operator's rule is not a heuristic: it is a statement about this estate,
//! so a match is reported as a match and never softened by confidence.

use super::factor::Factor;
use super::factor::FactorCode;
use crate::graph::Agent;

/// Factors from the user's watchlist rules that this agent matches.
///
/// A rule is a path substring plus a condition. The match reads the same three
/// columns the UI shows: can reach, has touched, can write. No rule language,
/// just the resources Topgent already knows about.
pub(super) fn resource_matches_rule(
    resource: &crate::ResourceAccess,
    rule: &topgent_policy::Rule,
) -> bool {
    use topgent_policy::Condition;
    if !resource.path.contains(&rule.path) {
        return false;
    }
    match rule.condition {
        Condition::Reachable => resource.reachable.is_yes(),
        Condition::Observed => resource.observed.is_yes(),
        Condition::Write => {
            resource
                .access
                .is_some_and(topgent_facts::Access::is_mutating)
                && (resource.declared.is_yes() || resource.observed.is_yes())
        }
    }
}

pub(super) fn watchlist_rule_matches(agent: &Agent, rule: &topgent_policy::Rule) -> bool {
    agent
        .resources
        .iter()
        .any(|resource| resource_matches_rule(resource, rule))
}

/// Indices of local watchlist rules currently matched by an agent.
#[must_use]
pub fn matched_watchlist_rules(agent: &Agent, rules: &[topgent_policy::Rule]) -> Vec<usize> {
    rules
        .iter()
        .enumerate()
        .filter_map(|(index, rule)| watchlist_rule_matches(agent, rule).then_some(index))
        .collect()
}

pub(super) fn watchlist_factors(agent: &Agent, rules: &[topgent_policy::Rule]) -> Vec<Factor> {
    let mut out = Vec::new();
    for rule in rules {
        if let Some(resource) = agent
            .resources
            .iter()
            .find(|resource| resource_matches_rule(resource, rule))
        {
            out.push(Factor {
                code: FactorCode::Watchlist,
                points: rule.severity.points(),
                title: format!("Watchlist: {} {}", rule.condition.label(), rule.path),
                source: format!("matched {}", resource.path),
                confidence: topgent_facts::Confidence::Certain,
            });
        }
    }
    out
}
