//! The risk legend: every factor, what it costs, and where it maps.
//!
//! The interface renders this rather than carrying its own copy, so what a user
//! reads about a rule and what the scorer applied cannot drift apart.

use serde_json::{Value, json};
use topgent_policy::Policy;

/// Every factor, what it costs here, and where it maps.
///
/// The sentences and technique mapping come from the factor catalogue, and the
/// points come from the policy actually in force — which is the whole purpose
/// of this function. A user who has tuned a weight must be shown the number
/// their scores were computed with, not the shipped default.
///
/// The two untunable factors are shown at their fixed value. A sandbox escape
/// and a critical watchlist match both mean an agent is doing something it said
/// it would not, and a policy that could quietly discount that would defeat the
/// point of declaring it.
pub(crate) fn legend(policy: &Policy) -> Value {
    let Ok(catalogue) = topgent_policy::catalogue::builtin() else {
        // A build that cannot read its own catalogue explains nothing rather
        // than explaining it wrongly.
        return json!([]);
    };
    let items: Vec<Value> = catalogue
        .factors
        .iter()
        .map(|entry| {
            json!({
                "code": entry.code,
                "points": points_in_force(entry, policy),
                "description": entry.description,
                "atlas_id": entry.atlas_id,
            })
        })
        .collect();
    json!(items)
}

/// The points this installation actually applies to one factor.
fn points_in_force(entry: &topgent_policy::catalogue::FactorEntry, policy: &Policy) -> u32 {
    if !entry.tunable {
        return entry.points;
    }
    let w = &policy.weights;
    match entry.code.as_str() {
        "RECON_FANOUT" => w.recon_fanout,
        "ARBITRARY_EXECUTION" => w.arbitrary_execution,
        "BROAD_WRITE" => w.broad_write,
        "UNRESTRICTED_NETWORK" => w.unrestricted_network,
        "SECRET_REACHABLE" => w.first_secret,
        "EXFILTRATION_PATH" => w.exfiltration_path,
        "AGENT_CHAIN" => w.agent_chain,
        "DECLARATION_DRIFT" => w.declaration_drift,
        "EXPOSED_LISTENER" => w.exposed_listener,
        "OFFENSIVE_TOOL" => w.offensive_tool,
        "PROCESS_EXPLOSION" => w.process_explosion,
        "SUSPICIOUS_ENDPOINT" => w.suspicious_endpoint,
        "PRIVATE_PEER" => w.private_peer,
        "METADATA_SERVICE" => w.metadata_service,
        "CREDENTIAL_ACCESS" => w.credential_access,
        "PERSISTENCE_WRITE" => w.persistence_write,
        "SELF_TAMPERING" => w.self_tampering,
        "DISALLOWED_ASSET" => w.disallowed_asset,
        // Validation guarantees every code is known, so this is unreachable in
        // a build that starts. The shipped value is the honest answer anyway.
        _ => entry.points,
    }
}

/// The technique one factor maps to, and what that technique is.
pub(crate) fn atlas_for(code: &str) -> (&'static str, &'static str) {
    topgent_policy::catalogue::builtin()
        .ok()
        .and_then(|catalogue| catalogue.entry(code))
        .map_or(("", ""), |entry| {
            (entry.atlas_id.as_str(), entry.atlas_description.as_str())
        })
}
