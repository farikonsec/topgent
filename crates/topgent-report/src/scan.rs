//! Assembling one report from one sweep of this host.
//!
//! Collectors run, facts fold into agents, risk is scored, and every section
//! the interface reads is projected from those same values. Nothing is computed
//! twice and nothing is derived in the front end: the report is the contract,
//! and the desktop app, the command line, the exports and the CI evaluator are
//! all readers of it.

use crate::activity::activity_json;
use crate::agents::{Naming, agent_json, agent_json_named};
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

/// The version this build reports, with its build tag when it has one.
///
/// A binary built from a working branch and one built from a release look
/// identical on disk and identical in a screenshot. `TOPGENT_BUILD_TAG` at
/// compile time appends the branch to every place the version appears — the
/// `--version` line, the report, the table header and the window title — so a
/// report from an experiment cannot be mistaken for one from a shipped build.
/// Absent, which is the release case, this is the package version alone.
#[must_use]
pub fn version() -> String {
    match option_env!("TOPGENT_BUILD_TAG") {
        Some(tag) if !tag.trim().is_empty() => {
            format!("{}+{}", env!("CARGO_PKG_VERSION"), tag.trim())
        }
        _ => env!("CARGO_PKG_VERSION").to_owned(),
    }
}

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
        // Last of the network sources, and the only one that reports traffic
        // rather than sockets. It runs whether or not the capability has been
        // granted: a collector that vanished when it could not run would leave
        // no row in the coverage table, and a missing row reads as a source
        // nobody needed rather than one nobody permitted.
        Box::new(topgent_collect::capture::live::CaptureCollector::default()),
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
    report_from_sweep(&policy, &policy_health, &result, generated_at)
}

/// One sweep, kept, so a second artefact can be built from the same collection.
///
/// A report and an evidence bundle describe the same moment. Sweeping twice
/// would give them different moments and let one contradict the other, and a
/// second collector list would eventually diverge from the first. So the sweep
/// is separated from the projection and both readers take the same result.
pub struct Observed {
    /// The facts and collector runs.
    pub sweep: topgent_collect::Sweep,
    /// The policy in force during the sweep.
    pub policy: Policy,
    /// Whether that policy is the operator's or a fallback.
    pub health: topgent_policy::PolicyHealth,
    /// When the sweep started, in Unix milliseconds.
    pub generated_at: u64,
}

/// Runs the collectors once and hands back everything derived from them.
#[must_use]
pub fn observe() -> Observed {
    let generated_at = now_ms();
    let (policy, health) = Policy::load_checked(&Policy::path());
    let collectors = report_collectors(&policy);
    let sweep = sweep(&collectors, &SystemClock);
    Observed {
        sweep,
        policy,
        health,
        generated_at,
    }
}

/// Projects one sweep into the report every front end reads.
#[must_use]
// One `json!` expression naming every section of the report. Splitting it would
// scatter the contract across helpers without making any of it clearer.
#[allow(clippy::too_many_lines)]
pub fn report_from_sweep(
    policy: &Policy,
    policy_health: &topgent_policy::PolicyHealth,
    result: &topgent_collect::Sweep,
    generated_at: u64,
) -> Value {
    let policy = policy.clone();
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
        "version": version(),
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
        // Hosts probed across enough ports to call it a scan.
        //
        // Reported about the host and not about an agent, because a scan's
        // connections are refused and a refused connection leaves no socket
        // for any snapshot to attribute. Putting it on an agent's row would
        // need a guess; leaving it out would lose a real finding. It is stated
        // here, unattributed, which is what is actually known.
        "network_scans": topgent_collect::capture::live::recent_scans()
            .into_iter()
            .map(|scan| json!({
                "peer": scan.peer.to_string(),
                "distinct_ports": scan.ports,
                "packets": scan.packets,
                "first_seen": scan.first_seen.0,
                "last_seen": scan.last_seen.0,
                "attributed": false,
                "why_unattributed": "a refused connection leaves no socket, so no process \
                                     can be named for it at this tier",
            }))
            .collect::<Vec<_>>(),
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

/// Runs the collectors once, then returns both artefacts of that one sweep.
///
/// The report is always produced. The bundle is a `Result` because evidence
/// can fail for reasons a report cannot: no randomness, an unwritable state
/// directory, or a fact the redaction gate refuses. A failure to produce
/// evidence must never suppress the report, and must never be reported as an
/// empty bundle, so the two are returned side by side.
pub fn scan_with_evidence(
    state: &std::path::Path,
) -> (Value, Result<topgent_evidence::Bundle, String>) {
    let observed = observe();
    let report = report_from_sweep(
        &observed.policy,
        &observed.health,
        &observed.sweep,
        observed.generated_at,
    );
    let bundle = build_bundle(state, &observed);
    (report, bundle)
}

/// Version of the collectors, as a single number a record can carry.
///
/// `0.4.0` becomes `400`. A record has to be able to say which build observed
/// it, and the crate version is the only honest answer.
#[must_use]
pub fn collector_version() -> u32 {
    let mut parts = env!("CARGO_PKG_VERSION").split('.');
    let value = |part: Option<&str>| part.and_then(|p| p.parse::<u32>().ok()).unwrap_or(0);
    let major = value(parts.next());
    let minor = value(parts.next());
    let patch = value(parts.next());
    major
        .saturating_mul(10_000)
        .saturating_add(minor.saturating_mul(100))
        .saturating_add(patch)
}

fn build_bundle(
    state: &std::path::Path,
    observed: &Observed,
) -> Result<topgent_evidence::Bundle, String> {
    let (origin, _binding) = crate::identity::origin_at(state).map_err(|e| e.to_string())?;
    let key = crate::identity::sensor_key(state).map_err(|e| e.to_string())?;
    let scored = analyse_with(&observed.sweep.facts, &observed.policy);
    crate::evidence::bundle_from_sweep(
        &observed.sweep.facts,
        &observed.sweep.runs,
        &scored,
        &origin,
        &key,
        collector_version(),
    )
    .map_err(|error| error.to_string())
}

/// Contract version of the replay projection.
///
/// Separate from the report contract, because a replay deliberately contains
/// less: everything a report gets from the live host at print time — sensor
/// probes, journal state, the clock — is absent from a bundle and must not be
/// invented to fill the shape.
pub const REPLAY_CONTRACT_VERSION: u32 = 1;

/// Projects a bundle into the findings it supports, and nothing else.
///
/// This is the deterministic half of a report: facts in, fold, risk model,
/// grades out. Two runs over the same bundle produce identical bytes, which is
/// the property that makes a bundle worth keeping. The timestamp used for any
/// age calculation is the latest observation in the bundle rather than the
/// clock, because a projection that reads the clock is not a replay.
#[must_use]
pub fn replay(bundle: &topgent_evidence::Bundle, policy: &Policy) -> Value {
    let facts: Vec<topgent_facts::Fact> = bundle
        .ledger()
        .records()
        .map(|record| record.fact().clone())
        .collect();
    let as_of = facts
        .iter()
        .map(|fact| fact.observed_at().0)
        .max()
        .unwrap_or(0);
    // No home and no resolver. Both would make the projection depend on the
    // machine doing the replaying rather than on the bundle.
    let scored = topgent_core::analyse_at(&facts, policy, None);
    let origin = bundle.chain().origin();
    json!({
        "replay_contract": REPLAY_CONTRACT_VERSION,
        "bundle_digest": bundle.digest(),
        "origin": {
            "host_id": origin.host_id,
            "boot_id": origin.boot_id,
            "sensor_instance": origin.sensor_instance,
        },
        "record_count": bundle.ledger().record_count(),
        "fact_count": facts.len(),
        "observed_through": as_of,
        "checkpoints": bundle.checkpoints().len(),
        "agents": scored
            .iter()
            .map(|agent| agent_json_named(agent, policy, as_of, Naming::Literal))
            .collect::<Vec<_>>(),
    })
}

/// What one policy would have decided differently from another, on one bundle.
///
/// The question an operator asks before changing a rule is not "is the new
/// policy correct" but "what stops firing, and what starts". Answering it by
/// deploying the change and watching is how a gate silently goes quiet. This
/// answers it against evidence already collected, with no sensor opened and no
/// response executed.
///
/// Both sides are replayed over the same bundle, so any difference is the
/// policy and nothing else.
#[must_use]
pub fn simulate(bundle: &topgent_evidence::Bundle, baseline: &Policy, candidate: &Policy) -> Value {
    let facts: Vec<topgent_facts::Fact> = bundle
        .ledger()
        .records()
        .map(|record| record.fact().clone())
        .collect();
    let as_of = facts
        .iter()
        .map(|fact| fact.observed_at().0)
        .max()
        .unwrap_or(0);

    let before = topgent_core::analyse_at(&facts, baseline, None);
    let after = topgent_core::analyse_at(&facts, candidate, None);

    let mut agents = Vec::new();
    for (agent, base_risk) in &before {
        let Some((_, cand_risk)) = after.iter().find(|(other, _)| other.id == agent.id) else {
            continue;
        };
        let (base_risk, base_suppressed) =
            topgent_core::apply_exceptions(base_risk, agent, baseline, as_of);
        let (cand_risk, cand_suppressed) =
            topgent_core::apply_exceptions(cand_risk, agent, candidate, as_of);

        let names = |risk: &topgent_core::Risk| -> Vec<String> {
            risk.factors
                .iter()
                .map(|factor| format!("{}|{}", factor.code.as_str(), factor.title))
                .collect()
        };
        let base_names = names(&base_risk);
        let cand_names = names(&cand_risk);
        let started: Vec<&String> = cand_names
            .iter()
            .filter(|name| !base_names.contains(name))
            .collect();
        let stopped: Vec<&String> = base_names
            .iter()
            .filter(|name| !cand_names.contains(name))
            .collect();

        if started.is_empty()
            && stopped.is_empty()
            && base_risk.score == cand_risk.score
            && base_risk.grade == cand_risk.grade
            && base_suppressed.len() == cand_suppressed.len()
        {
            continue;
        }

        agents.push(json!({
            "pid": agent.id.pid,
            "family": agent.family,
            "score": { "before": base_risk.score, "after": cand_risk.score },
            "grade": {
                "before": base_risk.grade.label(),
                "after": cand_risk.grade.label(),
                "changed": base_risk.grade != cand_risk.grade,
            },
            "started_matching": started,
            "stopped_matching": stopped,
            "suppressed": {
                "before": base_suppressed,
                "after": cand_suppressed,
            },
        }));
    }

    json!({
        "replay_contract": REPLAY_CONTRACT_VERSION,
        "bundle_digest": bundle.digest(),
        "observed_through": as_of,
        "agents_examined": before.len(),
        "agents_changed": agents.len(),
        // Named so a reader cannot mistake this for something that happened.
        "enforcement": "none: a simulation never executes a response",
        "changes": agents,
    })
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
