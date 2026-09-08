//! Scoring one agent, start to finish.
//!
//! Gathers the factors, sums them, applies the ceiling and names the grade.
//! Nothing is computed here that a factor did not already state.

use super::factor::Factor;
use super::factor::FactorCode;
use super::factors::disallowed_asset_factors;
use super::factors::per_item_factors;
use super::factors::process_explosion_factor;
use super::factors::recon_factor;
use super::factors::sandbox_factor;
use super::grade::Grade;
use super::grade::MAX_SCORE;
use super::grade::Risk;
use super::watchlist::watchlist_factors;
use crate::graph::Agent;
use crate::graph::IdentityKind;
use topgent_policy::Signals;

/// The values one agent presents to the catalogue's firing conditions.
///
/// Every count is derived here and nowhere else, so a condition and the scorer
/// can never disagree about what a signal means. The struct is defined in
/// `topgent-policy` beside the vocabulary it belongs to; this is the only
/// place that fills it.
#[must_use]
pub fn signals_for(agent: &Agent) -> Signals {
    let count = |value: usize| u32::try_from(value).unwrap_or(u32::MAX);
    Signals {
        can_execute: agent.can_execute(),
        can_write_broadly: agent.can_write_broadly(),
        is_sandboxed: agent.is_sandboxed(),
        exe_path_known: agent.exe_path_known,
        family_known: agent.family.is_some(),
        outbound_count: count(agent.outbound_count()),
        distinct_hosts: count(agent.distinct_hosts()),
        max_ports_to_one_host: count(agent.max_ports_to_one_host()),
        latent_secret_count: count(agent.latent_secrets().len()),
        drift_count: count(agent.drift().len()),
        invokes_count: count(agent.invokes.len()),
        children_count: count(agent.children.len()),
        connector_count: count(agent.connectors.len()),
        endpoint_count: count(agent.endpoints.len()),
        resource_count: count(agent.resources.len()),
        unevaluated_count: count(agent.unevaluated.len()),
        fact_count: count(agent.fact_count),
    }
}

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
// One factor per block, in the order the catalogue lists them. Splitting it
// would hide the fact that this is a flat list of independent contributions.
#[allow(clippy::too_many_lines)]
pub fn assess_with(agent: &Agent, policy: &topgent_policy::Policy) -> Risk {
    let w = &policy.weights;
    let mult = agent.identity.multiplier();
    let scaled = |base: u32| base.saturating_mul(mult) / 100;

    // Whether each agent-level factor fires is read from the catalogue rather
    // than written here. A catalogue that will not load leaves `fires` false
    // for everything, which is the safe direction: the loader has already
    // refused it and reported that the rules in force are not the operator's.
    let signals = signals_for(agent);
    let th = &policy.thresholds;
    let fires = |code: FactorCode| {
        topgent_policy::catalogue::builtin()
            .is_ok_and(|catalogue| catalogue.fires(code.as_str(), &signals, th))
    };

    let mut factors = Vec::new();

    if fires(FactorCode::ArbitraryExecution) {
        factors.push(Factor {
            code: FactorCode::ArbitraryExecution,
            points: scaled(w.arbitrary_execution),
            title: "Can execute arbitrary processes".to_owned(),
            source: "its own configuration grants execute".to_owned(),
            confidence: agent.confidence_for("permission_declared"),
        });
    }

    if fires(FactorCode::BroadWrite) {
        factors.push(Factor {
            code: FactorCode::BroadWrite,
            points: scaled(w.broad_write),
            title: "Can write outside its project directory".to_owned(),
            source: "a declared write grant contains a recursive glob".to_owned(),
            confidence: agent.confidence_for("permission_declared"),
        });
    }

    let outbound = agent.outbound_count();
    if fires(FactorCode::UnrestrictedNetwork) {
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
    // The gate is agent-level and lives in the catalogue; the iteration stays
    // here because each secret needs its own sentence and the first is worth
    // more than the rest. Data says whether, Rust says what it says.
    let latent = agent.latent_secrets();
    for (n, secret) in latent
        .iter()
        .enumerate()
        .filter(|_| fires(FactorCode::SecretReachable))
    {
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
    if let Some(first) = drift
        .first()
        .filter(|_| fires(FactorCode::DeclarationDrift))
    {
        factors.push(Factor {
            code: FactorCode::DeclarationDrift,
            points: scaled(w.declaration_drift),
            title: format!("Touched {} without declaring it", first.path),
            source: format!("{} resource(s) observed but not granted", drift.len()),
            confidence: agent.confidence_for("file_touched"),
        });
    }

    if fires(FactorCode::AgentChain) {
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
    if fires(FactorCode::ExfiltrationPath) {
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
    if fires(FactorCode::ReconFanout) {
        factors.extend(recon_factor(agent, w.recon_fanout, &policy.thresholds));
    }
    factors.extend(watchlist_factors(agent, &policy.watchlist));

    // Eleven factors used to be eleven hand-written loops here. They are now
    // one loop over the catalogue's per-item entries.
    factors.extend(per_item_factors(agent, policy));

    if fires(FactorCode::ProcessExplosion) {
        factors.push(process_explosion_factor(agent, policy));
    }

    factors.extend(disallowed_asset_factors(agent, policy));

    // The strongest IoC we can form: declared confinement versus observed
    // behaviour outside it.
    if let Some(factor) = sandbox_factor(agent) {
        factors.push(factor);
    }

    // Highest first, then by code, so two identical agents always print the same
    // list in the same order.
    factors.sort_by(|a, b| b.points.cmp(&a.points).then_with(|| a.code.cmp(&b.code)));

    apply_ceilings(&mut factors);

    let score = factors
        .iter()
        .fold(0_u32, |acc, f| acc.saturating_add(f.points))
        .min(MAX_SCORE);

    // A collector that refused to gather its inputs makes every total below
    // meaningless, however carefully it was computed. The band says so rather
    // than the number pretending otherwise.
    let grade = if agent.unevaluated.is_empty() {
        Grade::from_score(score)
    } else {
        Grade::NotEvaluated
    };

    Risk {
        score,
        grade,
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

/// Applies the operator's accepted findings to one scored agent.
///
/// Deliberately separate from [`assess_with`], which is documented as pure and
/// clock-free and stays that way. An exception has an expiry, so applying one
/// needs a moment, and the moment belongs to the caller: the live path passes
/// the sweep time and a replay passes the bundle's own. Scoring a bundle from
/// last month against today's clock would answer a question nobody asked.
///
/// Returns the risk with suppressed factors removed and the score recomputed,
/// alongside what was suppressed. A suppression that left no trace would make
/// an exception indistinguishable from the finding never having happened.
#[must_use]
pub fn apply_exceptions(
    risk: &Risk,
    agent: &Agent,
    policy: &topgent_policy::Policy,
    as_of: u64,
) -> (Risk, Vec<topgent_policy::Suppression>) {
    if policy.exceptions.is_empty() {
        return (risk.clone(), Vec::new());
    }
    let family = agent.family.as_deref();
    let mut kept = Vec::with_capacity(risk.factors.len());
    let mut suppressed = Vec::new();

    for factor in &risk.factors {
        // The subject an exception narrows against is the sentence the finding
        // prints, because that is where the path or host it is about appears.
        let subject = format!("{} {}", factor.title, factor.source);
        let matched = policy
            .exceptions
            .iter()
            .filter(|exception| exception.active_at(as_of))
            .find(|exception| exception.covers(factor.code.as_str(), family, &subject));
        match matched {
            Some(exception) => suppressed.push(topgent_policy::Suppression {
                exception: exception.name.clone(),
                factor: factor.code.as_str().to_owned(),
                title: factor.title.clone(),
                points: factor.points,
                expires_at: exception.expires_at,
            }),
            None => kept.push(factor.clone()),
        }
    }

    let score = kept
        .iter()
        .fold(0_u32, |acc, factor| acc.saturating_add(factor.points))
        .min(MAX_SCORE);
    // The band is recomputed from the surviving score, except that an agent
    // nobody could examine stays unevaluated: accepting a finding says nothing
    // about the evidence that was never gathered.
    let grade = if agent.unevaluated.is_empty() {
        Grade::from_score(score)
    } else {
        Grade::NotEvaluated
    };

    (
        Risk {
            score,
            grade,
            factors: kept,
            identity_multiplier: risk.identity_multiplier,
        },
        suppressed,
    )
}

/// Trims a recurring factor's contribution to the ceiling its catalogue entry
/// declares.
///
/// The occurrences past the ceiling are kept and set to zero rather than
/// dropped. Dropping them would hide findings an operator wants to see: which
/// credentials are reachable is useful even when the ninth adds nothing to the
/// score. Keeping them at full points would let a property of the machine
/// dominate a score about the agent, which is what this exists to stop.
///
/// Runs after the sort, so the highest-valued occurrences survive.
fn apply_ceilings(factors: &mut [Factor]) {
    let Ok(catalogue) = topgent_policy::catalogue::builtin() else {
        return;
    };
    let mut spent: std::collections::BTreeMap<&'static str, u32> =
        std::collections::BTreeMap::new();
    for factor in factors.iter_mut() {
        let code = factor.code.as_str();
        let Some(ceiling) = catalogue.entry(code).and_then(|entry| entry.max_points) else {
            continue;
        };
        let used = spent.entry(code).or_insert(0);
        let room = ceiling.saturating_sub(*used);
        let allowed = factor.points.min(room);
        *used = used.saturating_add(allowed);
        factor.points = allowed;
    }
}
