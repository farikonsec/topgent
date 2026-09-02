//! The operations the interface and the command line can ask for.
//!
//! Each one is a change to the machine or to policy, so each rechecks the exact
//! identity it was authorised against immediately before acting. A pid that has
//! been reused between the decision and the action is refused rather than acted
//! on, and every outcome is journaled whether it succeeded or not.

use crate::scan::{TERMINATION_COOLDOWN_MS, now_ms};
use serde_json::{Value, json};
use topgent_collect::{SystemClock, process};
use topgent_enforce::{
    Action, ContainerAction, Guard, SystemDockerController, SystemSignaller, execute,
    execute_container,
};
use topgent_journal::Journal;
use topgent_policy::{AssetPolicy, Disposition, Policy, ResponseMode, Rule};

/// The policy, when it is safe to edit and write back.
///
/// Every action here is load, modify, save. If the file on disk is broken and
/// there is no last-known-good copy behind it, `load` returns built-in defaults
/// — and saving those back would overwrite the operator's rules with defaults
/// plus whatever they just clicked, destroying the only copy of what they had
/// written. Refusing is the answer; the report already says the policy is
/// unhealthy, and the message names the file so it can be fixed by hand.
fn editable_policy() -> Result<Policy, Value> {
    let (policy, health) = Policy::load_checked(&Policy::path());
    if health.rules_are_the_operators() {
        return Ok(policy);
    }
    Err(json!({
        "ok": false,
        "message": format!(
            "{} could not be read, and writing to it now would replace your rules with \
             defaults: {}",
            Policy::path().display(),
            health.detail().unwrap_or("no detail recorded"),
        ),
    }))
}

/// Enable or disable optional semantic context collection and display.
#[must_use]
pub fn set_semantic_enabled(enabled: bool) -> Value {
    let mut policy = match editable_policy() {
        Ok(policy) => policy,
        Err(refusal) => return refusal,
    };
    policy.semantic.enabled = enabled;
    match policy.save() {
        Ok(()) => json!({ "ok": true, "enabled": enabled }),
        Err(error) => json!({ "ok": false, "message": error.to_string() }),
    }
}

/// Delete every locally retained semantic context record.
#[must_use]
pub fn clear_semantic_context() -> Value {
    match Journal::open_default().clear_semantic() {
        Ok(()) => json!({ "ok": true }),
        Err(error) => json!({ "ok": false, "message": error.to_string() }),
    }
}

/// Reset the network baseline for one exact, currently running agent instance.
///
/// Both PID and process start time must still match the live process. This
/// prevents a delayed UI or CLI request from clearing history for a recycled
/// PID. The next scan records the agent's currently visible endpoints as the
/// first sample of a fresh collecting baseline.
#[must_use]
pub fn reset_network_baseline(pid: u32, started_at: u64) -> Value {
    let processes = process::snapshot();
    reset_network_baseline_at(&Journal::open_default(), &processes, pid, started_at)
}

pub(crate) fn reset_network_baseline_at(
    journal: &Journal,
    processes: &[process::ProcInfo],
    pid: u32,
    started_at: u64,
) -> Value {
    let Some(target) = processes.iter().find(|candidate| {
        candidate.pid == pid && candidate.started_at.0 == started_at && candidate.family.is_some()
    }) else {
        return json!({
            "ok": false,
            "message": format!("agent identity pid {pid} / start {started_at} is no longer running")
        });
    };
    let label = target.family.unwrap_or("unrecognised process");
    match journal.reset_network_baseline(pid, started_at) {
        Ok(0) => json!({
            "ok": false,
            "message": format!("no retained network baseline exists for {label} (pid {pid})")
        }),
        Ok(removed) => {
            let detail = format!(
                "network baseline reset for exact identity; removed {removed} endpoint record{}",
                if removed == 1 { "" } else { "s" }
            );
            if let Err(error) = journal.record_action(now_ms(), pid, label, &detail) {
                return json!({
                    "ok": false,
                    "message": format!("baseline reset succeeded but audit logging failed: {error}")
                });
            }
            json!({
                "ok": true,
                "pid": pid,
                "started_at": started_at,
                "removed_records": removed,
                "message": format!("{label} (pid {pid}): baseline reset; relearning from current observations")
            })
        }
        Err(error) => json!({ "ok": false, "message": error.to_string() }),
    }
}

/// Write this session to a file the operator can read and send.
///
/// Into the state directory beside the journal, named by the time it was
/// written, so two exports never overwrite each other and the file says when it
/// is from without being opened.
#[must_use]
pub fn export_session(redacted: bool) -> Value {
    let report = crate::scan::scan();
    let detail = if redacted {
        topgent_export::Detail::Redacted
    } else {
        topgent_export::Detail::Full
    };
    let dir = topgent_journal::state_dir().join("sessions");
    if let Err(error) = std::fs::create_dir_all(&dir) {
        return json!({ "ok": false, "message": error.to_string() });
    }
    let name = format!("topgent-session-{}", now_ms());
    let html = dir.join(format!("{name}.html"));
    let data = dir.join(format!("{name}.json"));

    if let Err(error) = std::fs::write(&html, topgent_export::session_html(&report, detail)) {
        return json!({ "ok": false, "message": error.to_string() });
    }
    let json_text = serde_json::to_string_pretty(&topgent_export::session_json(&report, detail))
        .unwrap_or_else(|error| error.to_string());
    if let Err(error) = std::fs::write(&data, json_text) {
        return json!({ "ok": false, "message": error.to_string() });
    }
    json!({
        "ok": true,
        "path": html.display().to_string(),
        "message": format!("session written to {}", html.display()),
    })
}

/// The outcome of a stop request, as the front ends render it.
#[must_use]
pub fn stop(pid: u32) -> Value {
    let processes = process::snapshot();
    let Some(target) = processes.iter().find(|p| p.pid == pid) else {
        return json!({ "ok": false, "message": format!("no process {pid}") });
    };
    stop_exact(pid, target.started_at.0)
}

/// Resolve one persisted termination approval and, when approved, consume it
/// exactly once through the guarded stop path.
#[must_use]
pub fn resolve_termination_approval(
    request_id: &str,
    pid: u32,
    started_at: u64,
    approve: bool,
) -> Value {
    let journal = Journal::open_default();
    let processes = process::snapshot();
    let resolved = match resolve_termination_approval_at(
        &journal,
        &processes,
        request_id,
        pid,
        started_at,
        approve,
        now_ms(),
    ) {
        Ok(record) => record,
        Err(message) => return json!({ "ok": false, "message": message }),
    };
    if !approve {
        let _ = journal.record_action(
            now_ms(),
            pid,
            "approval",
            &format!("denied termination request {}", resolved.id),
        );
        return json!({
            "ok": true,
            "state": "denied",
            "message": format!("Termination denied for pid {pid}")
        });
    }
    stop_exact(pid, started_at)
}

pub(crate) fn resolve_termination_approval_at(
    journal: &Journal,
    processes: &[process::ProcInfo],
    request_id: &str,
    pid: u32,
    started_at: u64,
    approve: bool,
    now: u64,
) -> Result<topgent_journal::ApprovalRecord, String> {
    let decision = if approve {
        topgent_journal::ApprovalRecordState::Approved
    } else {
        topgent_journal::ApprovalRecordState::Denied
    };
    if approve
        && !processes.iter().any(|process| {
            process.pid == pid && process.started_at.0 == started_at && process.family.is_some()
        })
    {
        return Err("approval target is no longer the same running agent".to_owned());
    }
    match journal.resolve_approval(
        request_id,
        pid,
        started_at,
        decision,
        now,
    ) {
        Ok(Some(record)) => Ok(record),
        Ok(None) => Err(
            "approval request is missing, expired, already resolved, or belongs to another process identity"
                .to_owned(),
        ),
        Err(error) => Err(error.to_string()),
    }
}

fn stop_exact(pid: u32, started_at: u64) -> Value {
    let processes = process::snapshot();
    let Some(target) = processes
        .iter()
        .find(|process| process.pid == pid && process.started_at.0 == started_at)
    else {
        return json!({
            "ok": false,
            "message": format!("process identity pid {pid} / start {started_at} changed before termination")
        });
    };
    let label = target.family.unwrap_or("unrecognised process");
    let journal = Journal::open_default();
    let attempted_at = now_ms();
    match journal.acquire_response_cooldown(
        pid,
        started_at,
        "termination",
        attempted_at,
        TERMINATION_COOLDOWN_MS,
    ) {
        Ok(Some(retry_after)) => {
            let detail =
                format!("termination suppressed by exact-agent cooldown until {retry_after}");
            let _ = journal.record_action(attempted_at, pid, label, &detail);
            return json!({
                "ok": false,
                "retry_after": retry_after,
                "message": format!("{label} (pid {pid}): {detail}")
            });
        }
        Ok(None) => {}
        Err(error) => {
            return json!({
                "ok": false,
                "message": format!("{label} (pid {pid}): response cooldown persistence failed closed: {error}")
            });
        }
    }

    let container = topgent_collect::container::snapshot(&processes)
        .into_iter()
        .find(|container| container.init_pid == pid && Some(container.family) == target.family);
    let done = container.map_or_else(
        || {
            execute(
                &Action::KillTree {
                    pid,
                    started_at: topgent_facts::UnixMillis(started_at),
                },
                &Guard::current(),
                &SystemSignaller,
                &SystemClock,
            )
        },
        |container| {
            execute_container(
                &ContainerAction {
                    container_id: container.id,
                    init_pid: pid,
                    started_at: topgent_facts::UnixMillis(started_at),
                    family: label.to_owned(),
                },
                &SystemDockerController,
                &SystemClock,
            )
        },
    );

    match done.result {
        Ok(outcome) => {
            let _ = journal.record_action(attempted_at, pid, label, outcome.label());
            json!({ "ok": true, "message": format!("{label} (pid {pid}): {}", outcome.label()) })
        }
        Err(refusal) => {
            let _ = journal.record_action(attempted_at, pid, label, &refusal.to_string());
            json!({ "ok": false, "message": format!("{label} (pid {pid}): {refusal}") })
        }
    }
}

/// Add a watchlist rule and persist it.
#[must_use]
pub fn add_rule(path: &str, condition: &str, severity: &str) -> Value {
    use topgent_policy::{Condition, Severity};
    let condition = match condition {
        "observed" => Condition::Observed,
        "write" => Condition::Write,
        _ => Condition::Reachable,
    };
    let severity = if severity == "critical" {
        Severity::Critical
    } else {
        Severity::Points(severity.parse().unwrap_or(20))
    };
    // Stored the way the graph keys a resource, not the way it was typed. A
    // rule reading /home/you/.ssh/id_rsa was accepted, reported ok, and then
    // matched nothing, because the resource it meant is keyed ~/.ssh/id_rsa.
    // A rule that silently never fires is worse than one that is refused.
    let path = topgent_core::resource_key(path.trim(), std::env::var("HOME").ok().as_deref());
    let mut policy = match editable_policy() {
        Ok(policy) => policy,
        Err(refusal) => return refusal,
    };
    policy.add_rule(Rule {
        path,
        condition,
        severity,
        response: ResponseMode::Alert,
    });
    match policy.save() {
        Ok(()) => json!({ "ok": true }),
        Err(e) => json!({ "ok": false, "message": e.to_string() }),
    }
}

/// Remove a watchlist rule by index and persist.
#[must_use]
pub fn remove_rule(index: usize) -> Value {
    let mut policy = match editable_policy() {
        Ok(policy) => policy,
        Err(refusal) => return refusal,
    };
    if !policy.remove_rule(index) {
        return json!({ "ok": false, "message": "rule no longer exists" });
    }
    match policy.save() {
        Ok(()) => json!({ "ok": true }),
        Err(e) => json!({ "ok": false, "message": e.to_string() }),
    }
}

/// Change the requested response for one local watchlist rule.
#[must_use]
pub fn set_rule_response(index: usize, response: &str) -> Value {
    let response = match response {
        "observe" => ResponseMode::Observe,
        "alert" => ResponseMode::Alert,
        "approval" => ResponseMode::Approval,
        "block" => ResponseMode::Block,
        "kill" => ResponseMode::Kill,
        _ => return json!({ "ok": false, "message": "invalid response mode" }),
    };
    let mut policy = match editable_policy() {
        Ok(policy) => policy,
        Err(refusal) => return refusal,
    };
    let Some(rule) = policy.watchlist.get_mut(index) else {
        return json!({ "ok": false, "message": "rule no longer exists" });
    };
    rule.response = response;
    match policy.save() {
        Ok(()) => json!({ "ok": true }),
        Err(error) => json!({ "ok": false, "message": error.to_string() }),
    }
}

/// Persist a global or agent-scoped decision about one discovered asset.
#[must_use]
pub fn set_asset_disposition(
    asset_id: &str,
    agent_family: Option<&str>,
    disposition: &str,
) -> Value {
    let asset_id = asset_id.trim();
    if !asset_id.starts_with("urn:topgent:") || asset_id.len() > 512 {
        return json!({ "ok": false, "message": "invalid asset identifier" });
    }
    let agent_family = agent_family
        .map(str::trim)
        .filter(|family| !family.is_empty());
    if agent_family.is_some_and(|family| family.len() > 128) {
        return json!({ "ok": false, "message": "invalid agent scope" });
    }
    let disposition = match disposition {
        "unreviewed" => Disposition::Unreviewed,
        "approved" => Disposition::Approved,
        "restricted" => Disposition::Restricted,
        "disallowed" => Disposition::Disallowed,
        _ => return json!({ "ok": false, "message": "invalid asset disposition" }),
    };
    let mut policy = match editable_policy() {
        Ok(policy) => policy,
        Err(refusal) => return refusal,
    };
    policy.set_asset_disposition(AssetPolicy {
        asset_id: asset_id.to_owned(),
        agent_family: agent_family.map(str::to_owned),
        disposition,
    });
    match policy.save() {
        Ok(()) => json!({ "ok": true }),
        Err(error) => json!({ "ok": false, "message": error.to_string() }),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{reset_network_baseline_at, resolve_termination_approval_at};
    use crate::test_support::test_dir;
    use serde_json::Value;
    use topgent_collect::process::ProcInfo;
    use topgent_core::{NetworkRecord, NetworkVerdict};
    use topgent_facts::{Direction, UnixMillis};
    use topgent_journal::Journal;

    #[test]
    fn baseline_reset_requires_a_current_exact_agent_identity() -> std::io::Result<()> {
        let dir = test_dir("baseline-reset");
        let journal = Journal::at(&dir);
        journal.save_network_history(&[NetworkRecord {
            protocol: topgent_facts::Protocol::Tcp,
            agent_pid: 42,
            agent_started_at: 1_000,
            agent_family: "codex-cli".to_owned(),
            host: "api.openai.com".to_owned(),
            port: 443,
            direction: Direction::Outbound,
            first_seen: 2_000,
            last_seen: 3_000,
            observations: 2,
            sample_times: vec![2_000, 3_000],
            currently_observed: false,
            last_visibility_change: 3_000,
            visibility_changes: 2,
            verdict: NetworkVerdict::Observed,
        }])?;
        let process = |family| ProcInfo {
            owner: topgent_collect::process::Owner::Uid(501),
            exe_path_known: true,
            pid: 42,
            started_at: UnixMillis(1_000),
            exe: "/opt/codex".to_owned(),
            name: "codex".to_owned(),
            uid: 501,
            user: "test".to_owned(),
            parent: None,
            family,
        };

        assert_eq!(
            reset_network_baseline_at(&journal, &[process(Some("codex-cli"))], 42, 999)
                .get("ok")
                .and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(journal.network_history()?.len(), 1);
        assert_eq!(
            reset_network_baseline_at(&journal, &[process(None)], 42, 1_000)
                .get("ok")
                .and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(journal.network_history()?.len(), 1);
        let result = reset_network_baseline_at(&journal, &[process(Some("codex-cli"))], 42, 1_000);
        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result.get("removed_records").and_then(Value::as_u64),
            Some(1)
        );
        assert!(journal.network_history()?.is_empty());
        assert!(
            journal
                .tail(1)?
                .first()
                .is_some_and(|entry| entry.detail.contains("exact identity"))
        );
        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn termination_approval_resolution_is_exact_one_shot_and_stale_safe() -> std::io::Result<()> {
        let dir = test_dir("approval");
        let journal = Journal::at(&dir);
        let process = ProcInfo {
            owner: topgent_collect::process::Owner::Uid(501),
            exe_path_known: true,
            pid: 42,
            started_at: UnixMillis(1_000),
            exe: "/opt/codex".to_owned(),
            name: "codex".to_owned(),
            uid: 501,
            user: "test".to_owned(),
            parent: None,
            family: Some("codex-cli"),
        };
        let approval = journal.request_approval(42, 1_000, "watchlist:0:kill", 2_000, 500)?;
        assert!(
            resolve_termination_approval_at(&journal, &[], &approval.id, 42, 1_000, true, 2_100)
                .is_err()
        );
        assert!(
            journal
                .approval_records(2_100)?
                .first()
                .is_some_and(|record| {
                    record.state == topgent_journal::ApprovalRecordState::Pending
                })
        );
        let approved = resolve_termination_approval_at(
            &journal,
            std::slice::from_ref(&process),
            &approval.id,
            42,
            1_000,
            true,
            2_200,
        )
        .map_err(std::io::Error::other)?;
        assert_eq!(
            approved.state,
            topgent_journal::ApprovalRecordState::Approved
        );
        assert!(
            resolve_termination_approval_at(
                &journal,
                std::slice::from_ref(&process),
                &approval.id,
                42,
                1_000,
                true,
                2_300
            )
            .is_err(),
            "approved requests cannot be replayed"
        );

        let denied = journal.request_approval(43, 3_000, "watchlist:1:kill", 4_000, 500)?;
        let resolved =
            resolve_termination_approval_at(&journal, &[], &denied.id, 43, 3_000, false, 4_100)
                .map_err(std::io::Error::other)?;
        assert_eq!(resolved.state, topgent_journal::ApprovalRecordState::Denied);
        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }
}
