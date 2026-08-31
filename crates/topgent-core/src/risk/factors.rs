//! Deciding which factors an agent has actually earned.
//!
//! Each function here answers one question and returns nothing when the answer
//! is no. A sandboxed agent is not charged for shell it cannot use, and an
//! endpoint is not a finding merely because it is an endpoint.

use super::classify::executable_name;
use super::classify::is_loopback;
use super::classify::is_private_peer;
use super::classify::offensive_tool;
use super::classify::persistence_path;
use super::classify::suspicious_port;
use super::classify::topgent_path;
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

pub(super) fn endpoint_behaviour_factors(
    agent: &Agent,
    policy: &topgent_policy::Policy,
) -> Vec<Factor> {
    let w = &policy.weights;
    let mut factors = Vec::new();
    for endpoint in &agent.endpoints {
        if matches!(endpoint.direction, topgent_facts::Direction::Listening)
            && !is_loopback(&endpoint.host)
        {
            factors.push(Factor {
                code: FactorCode::ExposedListener,
                points: w.exposed_listener,
                title: format!("Opened a listener on {}:{}", endpoint.host, endpoint.port),
                source: "live listening socket exposed beyond loopback".to_owned(),
                confidence: agent.confidence_for("socket_open"),
            });
        }
        if matches!(endpoint.direction, topgent_facts::Direction::Outbound) {
            let raw = endpoint.host.parse::<std::net::IpAddr>().is_ok();
            if crate::network::is_metadata_service(&endpoint.host) {
                factors.push(Factor {
                    code: FactorCode::MetadataService,
                    points: w.metadata_service,
                    title: "Contacted a cloud instance metadata service".to_owned(),
                    source: format!("outbound connection to {}:{}", endpoint.host, endpoint.port),
                    confidence: agent.confidence_for("socket_open"),
                });
            }
            if raw && suspicious_port(endpoint.port) {
                factors.push(Factor {
                    code: FactorCode::SuspiciousEndpoint,
                    points: w.suspicious_endpoint,
                    title: format!("Raw address on unusual port {}", endpoint.port),
                    source: format!(
                        "{}:{} has no DNS name in the socket metadata",
                        endpoint.host, endpoint.port
                    ),
                    confidence: agent.confidence_for("socket_open"),
                });
            }
            if is_private_peer(&endpoint.host) && !is_loopback(&endpoint.host) {
                factors.push(Factor {
                    code: FactorCode::PrivatePeer,
                    points: w.private_peer,
                    title: "Reached another host on the private network".to_owned(),
                    source: format!("outbound connection to {}:{}", endpoint.host, endpoint.port),
                    confidence: agent.confidence_for("socket_open"),
                });
            }
        }
    }
    factors
}

/// Snapshot-only rogue behaviour. Each factor is derived from metadata already
/// present in the graph; none reads payloads or performs I/O.
pub(super) fn behaviour_factors(agent: &Agent, policy: &topgent_policy::Policy) -> Vec<Factor> {
    let w = &policy.weights;
    let mut factors = endpoint_behaviour_factors(agent, policy);
    if let Some(child) = agent.children.iter().find(|c| offensive_tool(&c.name)) {
        factors.push(Factor {
            code: FactorCode::OffensiveTool,
            points: w.offensive_tool,
            title: format!(
                "Spawned offensive tooling: {}",
                executable_name(&child.name)
            ),
            source: format!("child pid {}, depth {}", child.pid, child.depth),
            confidence: agent.confidence_for("child_process_seen"),
        });
    }
    if agent.children.len() >= policy.thresholds.process_children {
        factors.push(Factor {
            code: FactorCode::ProcessExplosion,
            points: w.process_explosion,
            title: "Process tree expanded unusually fast".to_owned(),
            source: format!("{} descendants are running", agent.children.len()),
            confidence: agent.confidence_for("child_process_seen"),
        });
    }
    for resource in agent.resources.iter().filter(|r| r.observed.is_yes()) {
        if resource.sensitive {
            factors.push(Factor {
                code: FactorCode::CredentialAccess,
                points: w.credential_access,
                title: format!("Credential actually opened: {}", resource.path),
                source: "observed filesystem access, not inferred reachability".to_owned(),
                confidence: agent.confidence_for("file_touched"),
            });
        }
        if resource
            .access
            .is_some_and(topgent_facts::Access::is_mutating)
            && persistence_path(&resource.path)
        {
            factors.push(Factor {
                code: FactorCode::PersistenceWrite,
                points: w.persistence_write,
                title: format!("Wrote a persistence location: {}", resource.path),
                source: "observed mutating filesystem access".to_owned(),
                confidence: agent.confidence_for("file_touched"),
            });
        }
        if resource
            .access
            .is_some_and(topgent_facts::Access::is_mutating)
            && topgent_path(&resource.path)
        {
            factors.push(Factor {
                code: FactorCode::SelfTampering,
                points: w.self_tampering,
                title: "Modified Topgent or its policy".to_owned(),
                source: resource.path.clone(),
                confidence: agent.confidence_for("file_touched"),
            });
        }
    }
    factors
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
