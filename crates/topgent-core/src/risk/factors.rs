//! Deciding which factors an agent has actually earned.
//!
//! Each function here answers one question and returns nothing when the answer
//! is no. A sandboxed agent is not charged for shell it cannot use, and an
//! endpoint is not a finding merely because it is an endpoint.

use super::factor::Factor;
use super::factor::FactorCode;
use crate::graph::Agent;
use topgent_facts::Confidence;

/// The scanning-shape factor, when an agent's live sockets have it.
///
/// Reaching out to many hosts at once, or many ports to one host, is what
/// scanning a network or a host looks like from socket metadata, with nothing
/// decrypted. A quiet coding agent that suddenly starts doing it is the moment a
/// person needs to look, so the factor is deliberately expensive.
pub(super) fn recon_factor(
    agent: &Agent,
    points: u32,
    th: &topgent_policy::Thresholds,
) -> Option<Factor> {
    let hosts = agent.distinct_hosts();
    let ports = agent.max_ports_to_one_host();
    if hosts < th.recon_hosts && ports < th.recon_ports {
        return None;
    }
    let source = if ports >= th.recon_ports {
        format!("{ports} ports open to a single host")
    } else {
        format!("{hosts} distinct hosts contacted at once")
    };
    Some(Factor {
        code: FactorCode::ReconFanout,
        points,
        title: "Connection pattern looks like scanning".to_owned(),
        source,
        confidence: agent.confidence_for("socket_open"),
    })
}

/// The one snapshot factor that is about a count rather than about an item.
///
/// A burst of descendants is a property of the agent, not of any one child, so
/// it cannot be a per-item entry. Its gate lives in the catalogue with the rest
/// of the agent-level ones; this only builds the finding.
pub(super) fn process_explosion_factor(agent: &Agent, policy: &topgent_policy::Policy) -> Factor {
    Factor {
        code: FactorCode::ProcessExplosion,
        points: policy.weights.process_explosion,
        title: "Process tree expanded unusually fast".to_owned(),
        source: format!("{} descendants are running", agent.children.len()),
        confidence: agent.confidence_for("child_process_seen"),
    }
}

pub(super) fn sandbox_factor(agent: &Agent) -> Option<Factor> {
    let drift = !agent.drift().is_empty();
    if !agent.is_sandboxed() || (!drift && agent.outbound_count() == 0) {
        return None;
    }
    let source = if drift {
        "touched a path outside its sandbox".to_owned()
    } else {
        format!(
            "opened {} outbound connection(s) from a sandbox",
            agent.outbound_count()
        )
    };
    Some(Factor {
        code: FactorCode::SandboxEscape,
        points: 100,
        title: "Sandboxed agent is acting outside its sandbox".to_owned(),
        source,
        confidence: agent.confidence_for("file_touched"),
    })
}

pub(super) fn disallowed_asset_factors(
    agent: &Agent,
    policy: &topgent_policy::Policy,
) -> Vec<Factor> {
    let inventory = crate::inventory::build(std::slice::from_ref(agent), policy);
    let mut factors = inventory
        .relationships
        .iter()
        .filter(|relationship| relationship.disposition == topgent_policy::Disposition::Disallowed)
        .map(|relationship| {
            let asset = inventory
                .assets
                .iter()
                .find(|asset| asset.id == relationship.to);
            Factor {
                code: FactorCode::DisallowedAsset,
                points: policy.weights.disallowed_asset,
                title: format!(
                    "Using disallowed {}",
                    asset.map_or("asset", |item| item.name.as_str())
                ),
                source: format!("{} is disallowed by your asset policy", relationship.to.0),
                confidence: asset.map_or(Confidence::Possible, |item| item.confidence),
            }
        })
        .collect::<Vec<_>>();
    let agent_id = crate::inventory::agent_asset_id(agent);
    let family = agent.family.as_deref().unwrap_or("unclassified");
    if policy.asset_disposition(&agent_id.0, Some(family))
        == topgent_policy::Disposition::Disallowed
    {
        factors.push(Factor {
            code: FactorCode::DisallowedAsset,
            points: policy.weights.disallowed_asset,
            title: format!("Using disallowed agent {family}"),
            source: format!("{} is disallowed by your asset policy", agent_id.0),
            confidence: agent.discovery_confidence,
        });
    }
    factors
}

/// Every finding the catalogue's per-item entries produce for one agent.
///
/// Eleven factors used to be a hand-written loop each, in this file, with the
/// sentence and the points and the condition all in the same `if`. They are now
/// one loop over the catalogue: which collection to walk, which items match,
/// and what each match says all come from data, and what stays here is the part
/// that has to — classifying an address or a path, and turning a matched item
/// into a `Factor` the scorer already understands.
pub(super) fn per_item_factors(agent: &Agent, policy: &topgent_policy::Policy) -> Vec<Factor> {
    let Ok(catalogue) = topgent_policy::catalogue::builtin() else {
        // The loader has already refused it and said the rules in force are not
        // the operator's. Producing findings from a catalogue this build could
        // not validate would be worse than producing none.
        return Vec::new();
    };
    let ports = |list: topgent_policy::NumberList| -> Vec<u32> {
        match list {
            topgent_policy::NumberList::SuspiciousPorts => topgent_policy::signals::builtin()
                .map(|signals| {
                    signals
                        .suspicious_ports
                        .iter()
                        .map(|p| u32::from(*p))
                        .collect()
                })
                .unwrap_or_default(),
        }
    };

    let mut factors = Vec::new();
    for entry in &catalogue.factors {
        let Some(per_item) = &entry.per_item else {
            continue;
        };
        let Some(code) = FactorCode::named(&entry.code) else {
            continue;
        };
        if !entry.maturity.on_by_default() {
            continue;
        }
        let (Ok(title), Ok(source)) = (per_item.title_template(), per_item.source_template())
        else {
            continue;
        };
        let confidence = agent.confidence_for(evidence_kind(per_item.of));
        let base = weight_of(code, &policy.weights);

        let items = crate::risk::items_of(agent, per_item.of);
        let matched = items
            .iter()
            .filter(|item| per_item.matching.holds(item, &ports));
        for (n, item) in matched.enumerate() {
            if per_item.first_only && n > 0 {
                break;
            }
            let points = if n == 0 {
                base
            } else {
                per_item.subsequent_points.unwrap_or(base)
            };
            factors.push(Factor {
                code,
                points,
                title: title.render(item),
                source: source.render(item),
                confidence,
            });
        }
    }
    factors
}

/// Which kind of evidence a finding over this collection rests on.
///
/// A factor reads its own evidence kind rather than borrowing the agent's best
/// signal, so an inference is never presented with the authority of a direct
/// observation.
const fn evidence_kind(kind: topgent_policy::ItemKind) -> &'static str {
    match kind {
        topgent_policy::ItemKind::Endpoints => "socket_open",
        topgent_policy::ItemKind::Children => "child_process_seen",
        topgent_policy::ItemKind::Resources => "file_touched",
    }
}

/// The tunable weight for one code.
///
/// Exhaustive on purpose: a code added to the enum will not compile until
/// somebody decides what it is worth.
const fn weight_of(code: FactorCode, w: &topgent_policy::Weights) -> u32 {
    match code {
        FactorCode::ArbitraryExecution => w.arbitrary_execution,
        FactorCode::BroadWrite => w.broad_write,
        FactorCode::UnrestrictedNetwork => w.unrestricted_network,
        FactorCode::SecretReachable => w.first_secret,
        FactorCode::DeclarationDrift => w.declaration_drift,
        FactorCode::AgentChain => w.agent_chain,
        FactorCode::ExfiltrationPath => w.exfiltration_path,
        FactorCode::ReconFanout => w.recon_fanout,
        FactorCode::ExposedListener => w.exposed_listener,
        FactorCode::OffensiveTool => w.offensive_tool,
        FactorCode::ProcessExplosion => w.process_explosion,
        FactorCode::SuspiciousEndpoint => w.suspicious_endpoint,
        FactorCode::PrivatePeer => w.private_peer,
        FactorCode::MetadataService => w.metadata_service,
        FactorCode::CredentialAccess => w.credential_access,
        FactorCode::PersistenceWrite => w.persistence_write,
        FactorCode::SelfTampering => w.self_tampering,
        FactorCode::DisallowedAsset => w.disallowed_asset,
        // Both are fixed by design: a sandbox escape and a critical watchlist
        // match mean the agent is doing something it said it would not, and
        // being able to tune those down would defeat declaring them.
        FactorCode::SandboxEscape | FactorCode::Watchlist => 100,
    }
}
