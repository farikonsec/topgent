//! Assembling one report from one sweep of this host.
//!
//! Collectors run, facts fold into agents, risk is scored, and every section
//! the interface reads is projected from those same values. Nothing is computed
//! twice and nothing is derived in the front end: the report is the contract,
//! and the desktop app, the command line, the exports and the CI evaluator are
//! all readers of it.

use crate::activity::activity_json;
use crate::agents::agent_json;
use crate::context::context_json;
use crate::events::event_json;
use crate::health::{detection_coverage, sensor_health, tool_attestations};
use crate::legend::legend;
use crate::network::{baseline_json, network_json};
use crate::response::response_json;
use serde_json::{Value, json};
use topgent_collect::asset_inventory::AssetInventoryCollector;
use topgent_collect::{
    Collector, SystemClock, config, dns_event, filesystem, network_event, process, reach, sweep,
};
use topgent_core::{
    MAX_ACTIVITY_EVENTS, MAX_NETWORK_RECORDS, analyse_with, build_activity,
    build_inventory_with_installed, build_network_baselines, merge_activity_history,
    merge_network_history,
};
use topgent_journal::Journal;
use topgent_policy::{AssetPolicy, Disposition, Policy};

pub(crate) const TERMINATION_COOLDOWN_MS: u64 = 30_000;

/// Milliseconds since the epoch.
#[must_use]
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The collectors a report is built from.
///
/// A second list beside `default_collectors`, because the reach collector here
/// is configured from policy and that one is not. The cost of two lists is that
/// a collector added to one and not the other silently never runs, which one
/// did: registered, built, tested, and absent from every report. The test at
/// the bottom of this file is what stops it happening again.
fn report_collectors(policy: &Policy) -> Vec<Box<dyn Collector>> {
    vec![
        Box::new(process::ProcessCollector::default()),
        Box::new(topgent_collect::editor::EditorExtensionCollector),
        Box::new(filesystem::FilesystemEventCollector::default()),
        Box::new(network_event::NetworkEventCollector::default()),
        Box::new(dns_event::DnsEventCollector::default()),
        Box::new(topgent_collect::socket::SocketCollector),
        Box::new(config::ConfigCollector::default()),
        Box::new(reach::ReachCollector {
            home: None,
            sensitive: Some(policy.sensitive.clone()),
            watchlist: Some(
                policy
                    .watchlist
                    .iter()
                    .map(|rule| rule.path.clone())
                    .collect(),
            ),
        }),
    ]
}

fn persisted_activity(
    journal: &Journal,
    current: &topgent_core::Activity,
    generated_at: u64,
) -> topgent_core::Activity {
    let previous = journal.activity_history().unwrap_or_default();
    merge_activity_history(&previous, current, generated_at, MAX_ACTIVITY_EVENTS)
}

/// Run one full sweep and return the report every front end renders.
///
/// Side effect: the change since the last sweep is written to the event log.
/// That write is the point of calling this on a timer, so it is not optional,
/// but a log that cannot be written is surfaced in the report rather than
/// crashing the caller.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn scan() -> Value {
    let generated_at = now_ms();
    let (policy, policy_health) = Policy::load_checked(&Policy::path());
    let collectors = report_collectors(&policy);
    let result = sweep(&collectors, &SystemClock);
    let scored = analyse_with(&result.facts, &policy);
    let inventory_agents = scored
        .iter()
        .map(|(agent, _)| agent.clone())
        .collect::<Vec<_>>();
    let installed_assets =
        AssetInventoryCollector::default().collect(topgent_facts::UnixMillis(generated_at));
    let inventory = build_inventory_with_installed(&inventory_agents, &policy, &installed_assets);
    let current_activity = build_activity(&result.facts, &inventory_agents);

    let journal = Journal::open_default();
    let activity = persisted_activity(&journal, &current_activity, generated_at);
    let previous_network = journal.network_history().unwrap_or_default();
    let network = merge_network_history(
        &previous_network,
        &inventory_agents,
        generated_at,
        MAX_NETWORK_RECORDS,
    );
    let network_baselines = build_network_baselines(&network, generated_at);
    let mut journal_error: Option<String> = None;
    if let Err(e) = journal.advance_sweep(&scored, now_ms()) {
        journal_error = Some(e.to_string());
    }
    if let Err(e) = journal.save_network_history(&network) {
        journal_error = Some(e.to_string());
    }
    if let Err(e) = journal.save_activity_history(&activity) {
        journal_error = Some(e.to_string());
    }

    let events = journal
        .tail(500)
        .unwrap_or_default()
        .iter()
        .map(event_json)
        .collect::<Vec<_>>();
    json!({
        "contract_version": topgent_export::REPORT_CONTRACT_VERSION,
        "version": env!("CARGO_PKG_VERSION"),
        "generated_at": generated_at,
        "fact_count": result.facts.len(),
        "journal_error": journal_error,
        "failures": result
            .failures
            .iter()
            .map(|(c, e)| json!({ "collector": c, "reason": e.to_string() }))
            .collect::<Vec<_>>(),
        "platform": { "os": std::env::consts::OS, "arch": std::env::consts::ARCH },
        "sensors": sensor_health(&result.runs, generated_at, &journal),
        "tools": tool_attestations(generated_at, &journal),
        "interception": {
            // Whether an action can be stopped before it happens, and what it
            // would take here. A ladder that offers Block and Approval owes the
            // operator this rather than one flat refusal on every host.
            "state": topgent_collect::intercept::probe().state(),
            "detail": topgent_collect::intercept::probe().detail(),
        },
        "coverage": detection_coverage(&result.runs),
        // Which rules are actually in force. A policy that broke and fell back
        // to built-in defaults used to look identical to a fresh install, so
        // every finding on the host silently changed meaning.
        "policy_health": {
            "state": policy_health.as_str(),
            "detail": policy_health.detail(),
            "digest": policy_health.digest(),
            "operator_rules_in_force": policy_health.rules_are_the_operators(),
            "path": Policy::path().to_string_lossy(),
        },
        "response": response_json(&inventory_agents, &policy, &journal, generated_at),
        "context": context_json(policy.semantic.enabled, &journal, &inventory_agents, generated_at),
        "agents": scored.iter().map(|agent| agent_json(agent, &policy, generated_at)).collect::<Vec<_>>(),
        "assets": inventory.assets.iter().map(|asset| json!({
            "id": asset.id.0,
            "kind": asset.kind.as_str(),
            "name": asset.name,
            "confidence": asset.confidence.label(),
            "source": asset.source,
            "version": asset.version,
            "digest": asset.digest.as_ref().map(|digest| json!({
                "algorithm": digest.algorithm,
                "value": digest.value,
            })),
            "installed": asset.installed,
            "active": asset.active,
            "first_seen": asset.first_seen.map(|at| at.0),
            "last_seen": asset.last_seen.map(|at| at.0),
            "disposition": policy.asset_disposition(&asset.id.0, None).label(),
        })).collect::<Vec<_>>(),
        "relationships": inventory.relationships.iter().map(|relationship| json!({
            "from": relationship.from.0,
            "to": relationship.to.0,
            "kind": relationship.kind,
            "agent_pid": relationship.agent_pid,
            "agent_family": relationship.agent_family,
            "disposition": relationship.disposition.label(),
        })).collect::<Vec<_>>(),
        "aibom": {
            "format": "CycloneDX",
            "spec_version": topgent_export::CYCLONEDX_SPEC_VERSION,
            "component_count": inventory.assets.iter().filter(|asset| asset.kind != topgent_core::AssetKind::Endpoint).count(),
            "service_count": inventory.assets.iter().filter(|asset| asset.kind == topgent_core::AssetKind::Endpoint).count(),
            "relationship_count": inventory.relationships.len(),
            "unresolved_identities": inventory.assets.iter().filter(|asset| asset.name == "unclassified").count(),
            "redaction": "secrets, prompt content, file content, credential content, and TLS payloads excluded",
        },
        "activity": activity_json(&activity, &inventory_agents),
        "network": network_json(&network, &network_baselines, &inventory_agents, generated_at, &policy),
        "network_baselines": baseline_json(&network_baselines),
        "events": events,
        "legend": legend(&policy),
        "watchlist": policy.watchlist.iter().enumerate().map(|(i, r)| json!({
            "index": i,
            "path": r.path,
            "condition": r.condition.label(),
            "severity": match r.severity { topgent_policy::Severity::Critical => "Critical".to_owned(), topgent_policy::Severity::Points(p) => format!("+{p}") },
            "response": r.response.as_str(),
        })).collect::<Vec<_>>(),
    })
}

/// Export a fresh scan as a `CycloneDX` 1.6 AI-BOM.
#[must_use]
pub fn cyclonedx_scan() -> Value {
    let report = scan();
    cyclonedx_from_report(&report).unwrap_or_else(|message| json!({ "error": message }))
}

/// Project a report inventory into `CycloneDX` without rescanning the machine.
///
/// # Errors
///
/// Returns an explanation when the report inventory is missing or malformed.
#[allow(clippy::too_many_lines)]
pub fn cyclonedx_from_report(report: &Value) -> Result<Value, String> {
    let assets = report["assets"]
        .as_array()
        .ok_or("report has no assets array")?;
    let relationships = report["relationships"]
        .as_array()
        .ok_or("report has no relationships array")?;
    let mut inventory = topgent_core::Inventory {
        assets: Vec::new(),
        relationships: Vec::new(),
    };
    let mut export_policy = Policy::default();
    for value in assets {
        let kind = match value["kind"].as_str().ok_or("asset has no kind")? {
            "agent" => topgent_core::AssetKind::Agent,
            "agent_extension" => topgent_core::AssetKind::AgentExtension,
            "model" => topgent_core::AssetKind::Model,
            "connector" => topgent_core::AssetKind::Connector,
            "endpoint" => topgent_core::AssetKind::Endpoint,
            "tool" => topgent_core::AssetKind::Tool,
            "skill" => topgent_core::AssetKind::Skill,
            "plugin" => topgent_core::AssetKind::Plugin,
            "local_model" => topgent_core::AssetKind::LocalModel,
            other => return Err(format!("unsupported asset kind {other}")),
        };
        let confidence = match value["confidence"]
            .as_str()
            .ok_or("asset has no confidence")?
        {
            "Confirmed" => topgent_facts::Confidence::Certain,
            "Probable" => topgent_facts::Confidence::Likely,
            "Possible" => topgent_facts::Confidence::Possible,
            other => return Err(format!("unsupported confidence {other}")),
        };
        inventory.assets.push(topgent_core::Asset {
            id: topgent_core::AssetId(value["id"].as_str().ok_or("asset has no id")?.to_owned()),
            kind,
            name: value["name"]
                .as_str()
                .ok_or("asset has no name")?
                .to_owned(),
            confidence,
            source: "report_inventory",
            version: value["version"].as_str().map(str::to_owned),
            digest: value["digest"].as_object().and_then(|digest| {
                Some(topgent_facts::AssetDigest {
                    algorithm: digest.get("algorithm")?.as_str()?.to_owned(),
                    value: digest.get("value")?.as_str()?.to_owned(),
                })
            }),
            installed: value["installed"].as_bool().unwrap_or(false),
            active: value["active"].as_bool().unwrap_or(false),
            first_seen: value["first_seen"].as_u64().map(topgent_facts::UnixMillis),
            last_seen: value["last_seen"].as_u64().map(topgent_facts::UnixMillis),
        });
        let disposition = match value["disposition"].as_str().unwrap_or("unreviewed") {
            "approved" => Disposition::Approved,
            "restricted" => Disposition::Restricted,
            "disallowed" => Disposition::Disallowed,
            _ => Disposition::Unreviewed,
        };
        export_policy.set_asset_disposition(AssetPolicy {
            asset_id: value["id"].as_str().ok_or("asset has no id")?.to_owned(),
            agent_family: None,
            disposition,
        });
    }
    for value in relationships {
        let disposition = match value["disposition"].as_str().unwrap_or("unreviewed") {
            "approved" => Disposition::Approved,
            "restricted" => Disposition::Restricted,
            "disallowed" => Disposition::Disallowed,
            _ => Disposition::Unreviewed,
        };
        inventory.relationships.push(topgent_core::Relationship {
            from: topgent_core::AssetId(
                value["from"]
                    .as_str()
                    .ok_or("relationship has no from")?
                    .to_owned(),
            ),
            to: topgent_core::AssetId(
                value["to"]
                    .as_str()
                    .ok_or("relationship has no to")?
                    .to_owned(),
            ),
            kind: "reported_relationship",
            agent_pid: value["agent_pid"]
                .as_u64()
                .and_then(|pid| u32::try_from(pid).ok())
                .ok_or("relationship has invalid pid")?,
            agent_family: value["agent_family"]
                .as_str()
                .unwrap_or("unclassified")
                .to_owned(),
            disposition,
        });
    }
    let timestamp = report["generated_at"]
        .as_u64()
        .ok_or("report has no generated_at")?;
    let document = topgent_export::cyclonedx(&inventory, &export_policy, timestamp);
    topgent_export::validate_cyclonedx(&document)?;
    Ok(document)
}

#[cfg(test)]
mod tests {
    use topgent_policy::Policy;

    /// Every collector the product knows about runs in a report.
    ///
    /// There are two lists: `default_collectors` in the collect crate, and
    /// `report_collectors` here, which exists because the reach collector is
    /// configured from policy. A collector added to one and not the other
    /// silently never runs, and one did exactly that: registered, built,
    /// tested, and absent from every report.
    ///
    /// A sensor that is missing from a report is worse than one that fails in
    /// it. A failure is visible in sensor health; an absence is not visible
    /// anywhere.
    #[test]
    fn the_report_runs_every_collector_the_product_has() {
        let ours: Vec<&str> = super::report_collectors(&Policy::default())
            .iter()
            .map(|c| c.id())
            .collect();
        let theirs: Vec<&str> = topgent_collect::default_collectors()
            .iter()
            .map(|c| c.id())
            .collect();
        for id in &theirs {
            assert!(
                ours.contains(id),
                "{id} runs in a sweep and never in a report: {ours:?}"
            );
        }
    }
}
