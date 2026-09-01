//! Typed inventory derived from the agent graph.
//!
//! This is the one AI asset model used by the dashboard, policy decisions and
//! future `CycloneDX` export. It is pure: collectors provide graph evidence and
//! this module normalizes, deduplicates and relates it without performing I/O.

use crate::Agent;
use std::collections::BTreeMap;
use topgent_facts::{AssetDigest, Confidence, InstalledAsset, InstalledAssetKind, UnixMillis};
use topgent_policy::{Disposition, Policy};

/// A kind of AI or execution asset Topgent can identify today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AssetKind {
    /// A recognized running agent family.
    Agent,
    /// An active agent extension inside a shared editor host.
    AgentExtension,
    /// A model and provider pair.
    Model,
    /// A declared connector, including MCP-facing connectors.
    Connector,
    /// A network destination and port.
    Endpoint,
    /// A descendant executable used by an agent.
    Tool,
    /// An installed reusable instruction package.
    Skill,
    /// An installed harness or agent plugin.
    Plugin,
    /// A locally stored model artifact.
    LocalModel,
}

impl AssetKind {
    /// Stable machine label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::AgentExtension => "agent_extension",
            Self::Model => "model",
            Self::Connector => "connector",
            Self::Endpoint => "endpoint",
            Self::Tool => "tool",
            Self::Skill => "skill",
            Self::Plugin => "plugin",
            Self::LocalModel => "local_model",
        }
    }
}

/// Stable identity of an asset across scans.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssetId(pub String);

/// One deduplicated AI asset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    /// Stable identifier used by policy and export relationships.
    pub id: AssetId,
    /// Asset category.
    pub kind: AssetKind,
    /// Sanitized human-readable identity.
    pub name: String,
    /// Strongest evidence supporting this asset.
    pub confidence: Confidence,
    /// Fact/graph field from which the identity was derived.
    pub source: &'static str,
    /// Package/model version, when an allowlisted manifest supplies one.
    pub version: Option<String>,
    /// Content identity, when an allowlisted manifest supplies one.
    pub digest: Option<AssetDigest>,
    /// Whether the asset was found installed independently of a running agent.
    pub installed: bool,
    /// Whether current runtime/config evidence relates it to an agent.
    pub active: bool,
    /// Earliest observation in the supplied inventory evidence.
    pub first_seen: Option<UnixMillis>,
    /// Latest observation in the supplied inventory evidence.
    pub last_seen: Option<UnixMillis>,
}

/// One directed relationship between inventory assets.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Relationship {
    /// Source asset.
    pub from: AssetId,
    /// Target asset.
    pub to: AssetId,
    /// Stable relationship label.
    pub kind: &'static str,
    /// Running agent instance that supplied this relationship.
    pub agent_pid: u32,
    /// Agent family used for scoped policy resolution.
    pub agent_family: String,
    /// Effective user decision for the target in this agent scope.
    pub disposition: Disposition,
}

/// Deduplicated assets and their observed relationships.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    /// Assets in stable identifier order.
    pub assets: Vec<Asset>,
    /// Relationships in stable tuple order.
    pub relationships: Vec<Relationship>,
}

fn escaped(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_') {
            output.push(char::from(byte.to_ascii_lowercase()));
        } else {
            use std::fmt::Write;
            let _ = write!(output, "%{byte:02X}");
        }
    }
    output
}

fn asset_id(kind: AssetKind, identity: &str) -> AssetId {
    AssetId(format!(
        "urn:topgent:{}:{}",
        kind.as_str(),
        escaped(identity.trim())
    ))
}

/// Stable inventory identity for one agent installation/family under one user.
/// Running process instances remain separately identified by pid and start time.
#[must_use]
pub fn agent_asset_id(agent: &Agent) -> AssetId {
    let family = agent.family.as_deref().unwrap_or("unclassified");
    let identity = format!("{family}:uid{}", agent.uid.unwrap_or(u32::MAX));
    asset_id(AssetKind::Agent, &identity)
}

/// Stable inventory identity for one editor-agent extension family and package.
#[must_use]
pub fn extension_asset_id(family: &str, extension_id: &str) -> AssetId {
    asset_id(
        AssetKind::AgentExtension,
        &format!("{family}:{extension_id}"),
    )
}

fn safe_connector_name(value: &str) -> String {
    let without_tail = value.split(['?', '#']).next().unwrap_or(value);
    let Some((scheme, rest)) = without_tail.split_once("://") else {
        return without_tail.to_owned();
    };
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if path.is_empty() {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}/{path}")
    }
}

fn insert_asset(assets: &mut BTreeMap<AssetId, Asset>, asset: Asset) {
    assets
        .entry(asset.id.clone())
        .and_modify(|current| {
            current.confidence = current.confidence.max(asset.confidence);
            current.installed |= asset.installed;
            current.active |= asset.active;
            if current.version.is_none() {
                current.version.clone_from(&asset.version);
            }
            if current.digest.is_none() {
                current.digest.clone_from(&asset.digest);
            }
            current.first_seen = match (current.first_seen, asset.first_seen) {
                (Some(left), Some(right)) => Some(left.min(right)),
                (left, right) => left.or(right),
            };
            current.last_seen = match (current.last_seen, asset.last_seen) {
                (Some(left), Some(right)) => Some(left.max(right)),
                (left, right) => left.or(right),
            };
        })
        .or_insert(asset);
}

fn relate(
    relationships: &mut Vec<Relationship>,
    policy: &Policy,
    agent: &Agent,
    from: &AssetId,
    to: &AssetId,
    kind: &'static str,
) {
    let family = agent.family.as_deref().unwrap_or("unclassified");
    relate_as(relationships, policy, agent, from, to, kind, family);
}

#[allow(clippy::too_many_arguments)]
fn relate_as(
    relationships: &mut Vec<Relationship>,
    policy: &Policy,
    agent: &Agent,
    from: &AssetId,
    to: &AssetId,
    kind: &'static str,
    family: &str,
) {
    relationships.push(Relationship {
        from: from.clone(),
        to: to.clone(),
        kind,
        agent_pid: agent.id.pid,
        agent_family: family.to_owned(),
        disposition: policy.asset_disposition(&to.0, Some(family)),
    });
}

#[allow(clippy::too_many_arguments)]
fn add_related(
    assets: &mut BTreeMap<AssetId, Asset>,
    relationships: &mut Vec<Relationship>,
    policy: &Policy,
    agent: &Agent,
    agent_id: &AssetId,
    kind: AssetKind,
    name: String,
    confidence: Confidence,
    source: &'static str,
    relationship: &'static str,
) {
    let id = asset_id(kind, &name);
    insert_asset(
        assets,
        Asset {
            id: id.clone(),
            kind,
            name,
            confidence,
            source,
            version: None,
            digest: None,
            installed: false,
            active: true,
            first_seen: None,
            last_seen: None,
        },
    );
    relate(relationships, policy, agent, agent_id, &id, relationship);
}

fn add_extensions(
    assets: &mut BTreeMap<AssetId, Asset>,
    relationships: &mut Vec<Relationship>,
    policy: &Policy,
    agent: &Agent,
    host_id: &AssetId,
) {
    for extension in &agent.extensions {
        let id = extension_asset_id(&extension.family, &extension.extension_id);
        insert_asset(
            assets,
            Asset {
                id: id.clone(),
                kind: AssetKind::AgentExtension,
                name: extension.family.clone(),
                confidence: agent.confidence_for("editor_extension_active"),
                source: "editor_extension_active",
                version: None,
                digest: None,
                installed: false,
                active: true,
                first_seen: None,
                last_seen: None,
            },
        );
        relate_as(
            relationships,
            policy,
            agent,
            host_id,
            &id,
            "hosts_extension",
            &extension.family,
        );
    }
}

/// Build the portable AI inventory from scored or unscored agents.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn build(agents: &[Agent], policy: &Policy) -> Inventory {
    let mut assets = BTreeMap::new();
    let mut relationships = Vec::new();
    let agent_ids: BTreeMap<u32, AssetId> = agents
        .iter()
        .map(|agent| (agent.id.pid, agent_asset_id(agent)))
        .collect();

    for agent in agents {
        let Some(agent_id) = agent_ids.get(&agent.id.pid) else {
            continue;
        };
        let family = agent.family.as_deref().unwrap_or("unclassified");
        insert_asset(
            &mut assets,
            Asset {
                id: agent_id.clone(),
                kind: AssetKind::Agent,
                name: family.to_owned(),
                confidence: agent.discovery_confidence,
                source: "agent_family",
                version: None,
                digest: None,
                installed: false,
                active: true,
                first_seen: None,
                last_seen: None,
            },
        );

        add_extensions(&mut assets, &mut relationships, policy, agent, agent_id);

        if let Some((provider, model)) = &agent.model {
            add_related(
                &mut assets,
                &mut relationships,
                policy,
                agent,
                agent_id,
                AssetKind::Model,
                format!("{provider}/{model}"),
                agent.confidence_for("model_in_use"),
                "model_in_use",
                "uses_model",
            );
        }

        for connector in &agent.connectors {
            let name = safe_connector_name(&connector.name);
            add_related(
                &mut assets,
                &mut relationships,
                policy,
                agent,
                agent_id,
                AssetKind::Connector,
                name,
                agent.confidence_for("connector_declared"),
                "connector_declared",
                "declares_connector",
            );
        }

        for endpoint in &agent.endpoints {
            let name = format!("{}:{}", endpoint.host.to_lowercase(), endpoint.port);
            add_related(
                &mut assets,
                &mut relationships,
                policy,
                agent,
                agent_id,
                AssetKind::Endpoint,
                name,
                agent.confidence_for("socket_open"),
                "socket_open",
                "connects_to",
            );
        }

        for child in &agent.children {
            let name = child.name.to_lowercase();
            add_related(
                &mut assets,
                &mut relationships,
                policy,
                agent,
                agent_id,
                AssetKind::Tool,
                name,
                agent.confidence_for("child_process_seen"),
                "child_process_seen",
                "spawns_tool",
            );
        }

        for invoked in &agent.invokes {
            if let Some(target) = agent_ids.get(&invoked.target_pid) {
                relate(
                    &mut relationships,
                    policy,
                    agent,
                    agent_id,
                    target,
                    "invokes",
                );
            }
        }
    }

    relationships.sort();
    relationships.dedup();
    Inventory {
        assets: assets.into_values().collect(),
        relationships,
    }
}

/// Build inventory while retaining installed-only assets as distinct from
/// assets proven active by process/config evidence.
#[must_use]
pub fn build_with_installed(
    agents: &[Agent],
    policy: &Policy,
    installed: &[InstalledAsset],
) -> Inventory {
    let mut inventory = build(agents, policy);
    let mut assets = inventory
        .assets
        .drain(..)
        .map(|asset| (asset.id.clone(), asset))
        .collect::<BTreeMap<_, _>>();
    for evidence in installed {
        let kind = match evidence.kind {
            InstalledAssetKind::Skill => AssetKind::Skill,
            InstalledAssetKind::Plugin => AssetKind::Plugin,
            InstalledAssetKind::LocalModel => AssetKind::LocalModel,
        };
        insert_asset(
            &mut assets,
            Asset {
                id: asset_id(kind, &evidence.identity),
                kind,
                name: evidence.name.clone(),
                confidence: Confidence::Certain,
                source: "installed_manifest",
                version: evidence.version.clone(),
                digest: evidence.digest.clone(),
                installed: true,
                active: false,
                first_seen: Some(evidence.observed_at),
                last_seen: Some(evidence.observed_at),
            },
        );
    }
    inventory.assets = assets.into_values().collect();
    inventory
}

#[cfg(test)]
mod tests {
    use super::safe_connector_name;

    #[test]
    fn connector_identity_drops_credentials_query_and_fragment() {
        assert_eq!(
            safe_connector_name("https://user:secret@example.com/mcp?token=secret#x"),
            "https://example.com/mcp"
        );
        assert_eq!(safe_connector_name("local-tool?secret=yes"), "local-tool");
    }
}
