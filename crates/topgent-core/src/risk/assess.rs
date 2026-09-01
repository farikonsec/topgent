//! Scoring one agent, start to finish.
//!
//! Gathers the factors, sums them, applies the ceiling and names the grade.
//! Nothing is computed here that a factor did not already state.

use super::factor::Factor;
use super::factor::FactorCode;
use super::factors::behaviour_factors;
use super::factors::disallowed_asset_factors;
use super::factors::recon_factor;
use super::factors::sandbox_factor;
use super::grade::Grade;
use super::grade::MAX_SCORE;
use super::grade::Risk;
use super::watchlist::watchlist_factors;
use crate::graph::Agent;
use crate::graph::IdentityKind;

/// Score one agent with the default policy.
///
/// Pure: same agent in, same risk out, no clock and no I/O.
#[must_use]
pub fn assess(agent: &Agent) -> Risk {
    assess_with(agent, &topgent_policy::Policy::default())
}

/// Score one agent against a policy.
///
/// The policy carries the weights, thresholds and the user's watchlist, so this
/// stays a short function of its inputs and the tuning lives in one config file.
#[must_use]
pub fn assess_with(agent: &Agent, policy: &topgent_policy::Policy) -> Risk {
    let w = &policy.weights;
    let mult = agent.identity.multiplier();
    let scaled = |base: u32| base.saturating_mul(mult) / 100;

    let mut factors = Vec::new();

    if agent.can_execute() {
        factors.push(Factor {
            code: FactorCode::ArbitraryExecution,
            points: scaled(w.arbitrary_execution),
            title: "Can execute arbitrary processes".to_owned(),
            source: "its own configuration grants execute".to_owned(),
            confidence: agent.confidence_for("permission_declared"),
        });
    }

    if agent.can_write_broadly() {
        factors.push(Factor {
            code: FactorCode::BroadWrite,
            points: scaled(w.broad_write),
            title: "Can write outside its project directory".to_owned(),
            source: "a declared write grant contains a recursive glob".to_owned(),
            confidence: agent.confidence_for("permission_declared"),
        });
    }

    let outbound = agent.outbound_count();
    if outbound >= policy.thresholds.network_spread {
        factors.push(Factor {
            code: FactorCode::UnrestrictedNetwork,
            points: scaled(w.unrestricted_network),
            title: "Unrestricted outbound network".to_owned(),
            source: format!("{outbound} distinct destinations, no egress policy"),
            confidence: agent.confidence_for("socket_open"),
        });
    }

    // Credentials in reach that nothing has touched. No runtime signal will ever
    // fire for these, which is the whole reason the reachable column exists.
    for (n, secret) in agent.latent_secrets().iter().enumerate() {
        let base = if n == 0 {
            w.first_secret
        } else {
            w.further_secret
        };
        factors.push(Factor {
            code: FactorCode::SecretReachable,
            points: scaled(base),
            title: format!("{} is within reach", secret.path),
            source: "readable by this process owner, never touched".to_owned(),
            confidence: agent.confidence_for("resource_reachable"),
        });
    }

    let drift = agent.drift();
    if let Some(first) = drift.first() {
        factors.push(Factor {
            code: FactorCode::DeclarationDrift,
            points: scaled(w.declaration_drift),
            title: format!("Touched {} without declaring it", first.path),
            source: format!("{} resource(s) observed but not granted", drift.len()),
            confidence: agent.confidence_for("file_touched"),
        });
    }

    if !agent.invokes.is_empty() {
        let n = agent.invokes.len();
        factors.push(Factor {
            code: FactorCode::AgentChain,
            points: scaled(w.agent_chain),
            title: format!("Can invoke {n} other agent(s)"),
            source: "their reach becomes its reach at the second hop".to_owned(),
            confidence: agent.confidence_for("invokes_agent"),
        });
    }

    // A reachable credential is only dangerous if something can act on it, and
    // the ability to run commands is only dangerous if there is something worth
    // taking. Each alone is a factor; together they are a complete path from
    // "can read a secret" to "can send it somewhere", which is more than the
    // sum of the two. Additive scoring loses that, so it is stated explicitly.
    if agent.can_execute() && !agent.latent_secrets().is_empty() {
        factors.push(Factor {
            code: FactorCode::ExfiltrationPath,
            points: scaled(w.exfiltration_path),
            title: "Can reach a credential and act on it".to_owned(),
            source: "shell plus a readable credential is a complete path out".to_owned(),
            confidence: agent.confidence_for("resource_reachable"),
        });
    }

    // Recon is NOT scaled by identity. The identity multiplier discounts the
    // blast radius of stolen credentials, which is smaller for a service account.
    // Active scanning is not about blast radius: a process reaching across your
    // network is doing it whoever it runs as, so it carries full weight.
    factors.extend(recon_factor(agent, w.recon_fanout, &policy.thresholds));
    factors.extend(watchlist_factors(agent, &policy.watchlist));

    factors.extend(behaviour_factors(agent, policy));

    factors.extend(disallowed_asset_factors(agent, policy));

    // The strongest IoC we can form: declared confinement versus observed
    // behaviour outside it.
    if let Some(factor) = sandbox_factor(agent) {
        factors.push(factor);
    }

    // Highest first, then by code, so two identical agents always print the same
    // list in the same order.
    factors.sort_by(|a, b| b.points.cmp(&a.points).then_with(|| a.code.cmp(&b.code)));

    let score = factors
        .iter()
        .fold(0_u32, |acc, f| acc.saturating_add(f.points))
        .min(MAX_SCORE);

    Risk {
        score,
        grade: Grade::from_score(score),
        factors,
        identity_multiplier: mult,
    }
}

/// Identity kinds ordered by how much they amplify risk, worst first.
///
/// Exposed so the UI can explain the multiplier rather than just apply it.
#[must_use]
pub const fn identity_order() -> [IdentityKind; 3] {
    [
        IdentityKind::DelegatedHuman,
        IdentityKind::Unknown,
        IdentityKind::ServiceAccount,
    ]
}
