//! One row per agent, and the evidence behind it.
//!
//! An unrecognised process is two different situations. If the executable path
//! was refused, recognition never ran and the process has not been ruled out;
//! if the path was read and matched nothing, that is a genuine negative. Saying
//! which is the difference between "not an agent" and "cannot tell".

use crate::legend::atlas_for;
use serde_json::{Value, json};
use topgent_collect::resolve;
use topgent_core::{Agent, Risk, agent_asset_id};
use topgent_policy::Policy;

/// How long a connection had been open when the report was taken.
///
/// A sweep is not instantaneous. A connection created while it was running is
/// genuinely newer than the report's own timestamp, and reporting no age at all
/// loses a fact the operating system did supply; its true age is effectively
/// zero. Beyond a sweep's plausible length the timestamp is something Topgent
/// cannot vouch for, and stays unreported rather than being clamped into
/// looking reasonable.
pub(crate) fn connection_age(opened_at: u64, generated_at: u64) -> Option<u64> {
    if opened_at <= generated_at {
        return Some(generated_at.saturating_sub(opened_at));
    }
    (opened_at.saturating_sub(generated_at) <= MAX_SWEEP_MS).then_some(0)
}

/// Longest a sweep is assumed to take, for judging a connection newer than the
/// report that mentions it.
pub(crate) const MAX_SWEEP_MS: u64 = 60_000;

/// What Topgent holds about an agent's identity, and what it could not read.
///
/// An unrecognised process is two different situations, and the interface used
/// to draw them the same way: an empty card saying `unclassified`. If the
/// executable path was refused, recognition never ran on real evidence and the
/// process has not been ruled out. If the path was read and matched nothing,
/// that is a genuine negative. Saying which is the difference between "not an
/// agent" and "cannot tell", and only one of them deserves the user's trust.
pub(crate) fn identity_evidence(a: &Agent) -> Value {
    let state = match (a.family.is_some(), a.exe_path_known) {
        (true, _) => "confirmed",
        (false, false) => "unexamined",
        (false, true) => "unrecognised",
    };
    let mut limits: Vec<&str> = Vec::new();
    if !a.exe_path_known {
        limits.push(
            "The executable path was refused by the operating system, so this \
             process has not been compared against any agent family. Only its \
             reported name is known.",
        );
    }
    if a.user.is_none() {
        limits.push("The owning account was not readable for this process.");
    }
    if a.parent_pid.is_none() {
        limits.push("No parent process was reported for this process.");
    }
    json!({
        "state": state,
        "exe_path_known": a.exe_path_known,
        "owner_known": a.user.is_some(),
        "parent_known": a.parent_pid.is_some(),
        "limits": limits,
    })
}

pub(crate) fn agent_json((a, r): &(Agent, Risk), policy: &Policy, generated_at: u64) -> Value {
    let asset_id = agent_asset_id(a);
    let asset_disposition = policy.asset_disposition(&asset_id.0, a.family.as_deref());
    json!({
        "pid": a.id.pid,
        "asset_id": asset_id.0,
        "asset_disposition": asset_disposition.label(),
        "started_at": a.id.started_at.0,
        "family": a.family,
        "extensions": a.extensions.iter().map(|extension| json!({
            "family": extension.family,
            "extension_id": extension.extension_id,
            "asset_id": topgent_core::extension_asset_id(&extension.family, &extension.extension_id).0,
            "asset_disposition": policy.asset_disposition(
                &topgent_core::extension_asset_id(&extension.family, &extension.extension_id).0,
                Some(&extension.family),
            ).label(),
            "evidence_scope": "shared_host",
        })).collect::<Vec<_>>(),
        "exe": a.exe,
        "user": a.user,
        "identity": a.identity.label(),
        "identity_evidence": identity_evidence(a),
        "attribution_scope": if a.extensions.is_empty() { "process" } else { "shared_host" },
        "attribution_note": if a.extensions.is_empty() {
            "Behavior is attributed to this process identity."
        } else {
            "Behavior and response are attributed to the shared editor host; Topgent does not claim which active extension caused a host-level event."
        },
        "model": a.model.as_ref().map(|(p, m)| format!("{p}/{m}")),
        "discovery_confidence": a.discovery_confidence.label(),
        "score": r.score,
        "grade": r.grade.label(),
        "pips": r.grade.pips(),
        "outbound": a.outbound_count(),
        "factors": r.factors.iter().map(|f| {
            let (id, desc) = atlas_for(f.code.as_str());
            json!({
                "code": f.code.as_str(),
                "points": f.points,
                "title": f.title,
                "source": f.source,
                "confidence": f.confidence.label(),
                "atlas_id": id,
                "atlas_desc": desc,
            })
        }).collect::<Vec<_>>(),
        "resources": a.resources.iter().map(|res| json!({
            "path": res.path,
            "declared": res.declared.label(),
            "observed": res.observed.label(),
            "reachable": res.reachable.label(),
            // What the reachability probe actually established, and the
            // sentence a reader should get. "Reachable: unknown" alone reads as
            // "nobody looked"; this says whether the path resolved, and states
            // that readability is an answer about the account rather than about
            // the process.
            "reachable_evidence": res.reach_evidence.map(topgent_facts::Reachability::as_str),
            "reachable_statement": res.reach_evidence.map(topgent_facts::Reachability::statement),
            "sensitive": res.sensitive,
            "drift": res.is_drift(),
            "latent_secret": res.is_latent_secret(),
            "evidence": res.evidence,
        })).collect::<Vec<_>>(),
        "endpoints": a.endpoints.iter().map(|e| {
            let (name, owner) = resolve::label(&e.host);
            json!({
                "protocol": e.protocol.as_str(),
                // Whether the platform could have named a peer here at all.
                // An absent host with this false is a property of the platform,
                // not a missed observation, and a reader must be able to tell
                // the two apart.
                "peer_observable": e.protocol.peer_observable() && e.host != "*",
                "host": e.host,
                "name": name,
                "owner": owner,
                "port": e.port,
                "direction": format!("{:?}", e.direction).to_lowercase(),
                // The operating system's own record of when it made this
                // connection, and the age that follows from it. Absent where
                // the platform keeps no such record: never zero, and never the
                // gap between two sweeps.
                "opened_at": e.opened_at.map(|opened| opened.0),
                "open_for_ms": e.opened_at
                    .and_then(|opened| connection_age(opened.0, generated_at)),
                // The kernel's own cumulative counters for this connection.
                // Absent where the platform keeps none: never zero, and never a
                // count of how often a sweep saw the endpoint.
                "bytes_sent": e.bytes.map(|bytes| bytes.sent),
                "bytes_received": e.bytes.map(|bytes| bytes.received),
            })
        }).collect::<Vec<_>>(),
        "connectors": a.connectors.iter().map(|c| json!({
            "name": c.name,
            "access": c.access.label(),
        })).collect::<Vec<_>>(),
        "invokes": a.invokes.iter().map(|e| json!({
            "target_pid": e.target_pid,
            "via": e.via,
        })).collect::<Vec<_>>(),
        "children": a.children.iter().map(|c| json!({
            "pid": c.pid,
            "name": c.name,
            "depth": c.depth,
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::expect_used)]

    use super::{connection_age, identity_evidence};
    use topgent_facts::UnixMillis;
    use topgent_policy::Policy;

    fn unidentified(exe_path_known: bool) -> topgent_core::Agent {
        use topgent_core::{AgentId, IdentityKind};
        topgent_core::Agent {
            id: AgentId {
                pid: 18_246,
                started_at: UnixMillis(1_000),
            },
            family: None,
            extensions: Vec::new(),
            exe: Some("codex".to_owned()),
            exe_path_known,
            uid: None,
            user: None,
            identity: IdentityKind::Unknown,
            model: None,
            parent_pid: None,
            children: Vec::new(),
            connectors: Vec::new(),
            endpoints: Vec::new(),
            resources: Vec::new(),
            invokes: Vec::new(),
            actions: Vec::new(),
            discovery_confidence: topgent_facts::Confidence::Certain,
            evidence_confidence: std::collections::BTreeMap::new(),
            fact_count: 1,
        }
    }

    #[test]
    fn a_connections_age_comes_from_the_system_clock_or_from_nowhere() {
        use topgent_core::{Endpoint, Grade, Risk};
        use topgent_facts::Direction;

        let generated_at = 10_000_u64;
        let mut agent = unidentified(true);
        agent.endpoints = vec![
            Endpoint {
                protocol: topgent_facts::Protocol::Tcp,
                bytes: None,
                host: "52.123.242.66".to_owned(),
                port: 443,
                direction: Direction::Outbound,
                opened_at: Some(UnixMillis(4_000)),
            },
            Endpoint {
                protocol: topgent_facts::Protocol::Tcp,
                bytes: None,
                host: "github.com".to_owned(),
                port: 443,
                direction: Direction::Outbound,
                opened_at: None,
            },
            Endpoint {
                protocol: topgent_facts::Protocol::Tcp,
                bytes: None,
                host: "10.0.0.1".to_owned(),
                port: 443,
                direction: Direction::Outbound,
                opened_at: Some(UnixMillis(generated_at + 5_000)),
            },
        ];
        let risk = Risk {
            score: 0,
            grade: Grade::Low,
            factors: Vec::new(),
            identity_multiplier: 100,
        };
        let value = super::agent_json(&(agent, risk), &Policy::default(), generated_at);
        let endpoints = value["endpoints"].as_array().expect("endpoints render");

        // A real recorded creation time yields a real age.
        let timed = endpoints
            .iter()
            .find(|endpoint| endpoint["host"] == "52.123.242.66")
            .expect("the timed endpoint renders");
        assert_eq!(timed["opened_at"], 4_000);
        assert_eq!(timed["open_for_ms"], 6_000);

        // No record means no age. Not zero, and not the gap between sweeps.
        let untimed = endpoints
            .iter()
            .find(|endpoint| endpoint["host"] == "github.com")
            .expect("the untimed endpoint renders");
        assert!(untimed["opened_at"].is_null());
        assert!(untimed["open_for_ms"].is_null());

        // A connection created while the sweep was running is genuinely newer
        // than the report that mentions it, and its age is effectively zero.
        // Reporting nothing there lost a fact the system did supply.
        let future = endpoints
            .iter()
            .find(|endpoint| endpoint["host"] == "10.0.0.1")
            .expect("the newer-than-the-report endpoint renders");
        assert_eq!(future["opened_at"], generated_at + 5_000);
        assert_eq!(future["open_for_ms"], 0);

        // Beyond a sweep's plausible length it is a timestamp Topgent cannot
        // vouch for, and an age must never come out negative or wrap.
        assert_eq!(connection_age(4_000, 10_000), Some(6_000));
        assert_eq!(connection_age(10_000, 10_000), Some(0));
        assert_eq!(
            connection_age(10_000 + crate::agents::MAX_SWEEP_MS, 10_000),
            Some(0)
        );
        assert_eq!(
            connection_age(10_000 + crate::agents::MAX_SWEEP_MS + 1, 10_000),
            None
        );
        assert_eq!(connection_age(u64::MAX, 10_000), None);
    }

    #[test]
    fn an_unrecognised_process_states_whether_it_was_actually_examined() {
        // The evidence-free `unclassified` card. Recognition reads the
        // executable path, so a process whose path was refused has not been
        // ruled out as an agent; presenting that as a verdict is the defect.
        let refused = identity_evidence(&unidentified(false));
        assert_eq!(refused["state"], "unexamined");
        assert_eq!(refused["exe_path_known"], false);
        assert_eq!(refused["owner_known"], false);
        assert_eq!(refused["parent_known"], false);
        let limits = refused["limits"].as_array().expect("limits are listed");
        assert_eq!(
            limits.len(),
            3,
            "every unreadable fact is named: {limits:?}"
        );
        assert!(
            limits[0]
                .as_str()
                .is_some_and(|limit| limit.contains("executable path was refused")),
            "the sensor limit is stated in plain words: {limits:?}"
        );

        // A path that was read and matched nothing is a genuine negative.
        let examined = identity_evidence(&unidentified(true));
        assert_eq!(examined["state"], "unrecognised");
        assert_eq!(examined["exe_path_known"], true);
        assert!(
            !examined["limits"]
                .as_array()
                .expect("limits are listed")
                .iter()
                .any(|limit| limit
                    .as_str()
                    .is_some_and(|text| text.contains("executable path"))),
            "a readable path is not a limitation"
        );
    }

    #[test]
    fn a_recognised_agent_reports_confirmed_identity() {
        let mut agent = unidentified(true);
        agent.family = Some("codex-cli".to_owned());
        agent.user = Some("testuser".to_owned());
        agent.parent_pid = Some(1);
        let evidence = identity_evidence(&agent);
        assert_eq!(evidence["state"], "confirmed");
        assert_eq!(evidence["owner_known"], true);
        assert_eq!(evidence["parent_known"], true);
        assert!(
            evidence["limits"]
                .as_array()
                .is_some_and(std::vec::Vec::is_empty)
        );
    }
}
