//! The response queue: what a rule would do, and what it is waiting on.
//!
//! Every rung states the truth about this host. A response the installation
//! cannot deliver is reported as a capability mismatch rather than offered and
//! failed, and one that needs a person says so and waits rather than acting.

use serde_json::{Value, json};
use topgent_core::Agent;
use topgent_enforce::{ApprovalState, EnforcementCapability, decide_response};
use topgent_journal::Journal;
use topgent_policy::{Policy, ResponseMode};

const APPROVAL_TTL_MS: u64 = 5 * 60 * 1_000;

#[allow(clippy::too_many_lines)]
pub(crate) fn response_json(
    agents: &[Agent],
    policy: &Policy,
    journal: &Journal,
    now: u64,
) -> Value {
    let capability = EnforcementCapability::local();
    let mut decisions = Vec::new();
    for agent in agents {
        let matched = topgent_core::matched_watchlist_rules(agent, &policy.watchlist)
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        for (index, rule) in policy.watchlist.iter().enumerate() {
            let active = matched.contains(&index);
            let transition_key = format!(
                "response:{}:{}:{index}:{}:{}:{}:{}",
                agent.id.pid,
                agent.id.started_at.0,
                rule.response.as_str(),
                rule.severity.points(),
                rule.condition.label(),
                rule.path
            );
            let transition = journal.record_response_transition(&transition_key, active, now);
            if !active {
                continue;
            }
            let (transition_label, transition_record, transition_persistent) = match transition {
                Ok((label, record)) => (label, Some(record), true),
                Err(_) => ("unknown", None, false),
            };
            if rule.response == ResponseMode::Alert && transition_label == "triggered" {
                let _ = journal.record_action(
                    now,
                    agent.id.pid,
                    agent.family.as_deref().unwrap_or("unclassified"),
                    &format!("policy alert triggered by watchlist rule {index}"),
                );
            }
            let approval = if rule.response == ResponseMode::Kill && capability.can_terminate {
                let scope = format!(
                    "watchlist:{index}:{}:{}:{}",
                    rule.response.as_str(),
                    rule.condition.label(),
                    rule.path
                );
                journal
                    .request_approval(
                        agent.id.pid,
                        agent.id.started_at.0,
                        &scope,
                        now,
                        APPROVAL_TTL_MS,
                    )
                    .ok()
            } else {
                None
            };
            let approval_state = approval.as_ref().map(|record| match record.state {
                topgent_journal::ApprovalRecordState::Pending => ApprovalState::Pending,
                topgent_journal::ApprovalRecordState::Approved => ApprovalState::Approved,
                topgent_journal::ApprovalRecordState::Denied => ApprovalState::Denied,
                topgent_journal::ApprovalRecordState::Expired => ApprovalState::Expired,
            });
            let outcome = decide_response(true, rule.response, capability, approval_state);
            decisions.push(json!({
                "rule_index": index,
                "agent_pid": agent.id.pid,
                "agent_started_at": agent.id.started_at.0,
                "agent_family": agent.family.as_deref().unwrap_or("unclassified"),
                "path": rule.path,
                "condition": rule.condition.label(),
                "requested": rule.response.as_str(),
                "outcome": outcome.as_str(),
                "transition": transition_label,
                "transition_persistent": transition_persistent,
                "trigger_count": transition_record.as_ref().map(|record| record.trigger_count),
                "last_transition_at": transition_record.as_ref().map(|record| record.last_changed_at),
                "approval": approval.as_ref().map(|record| json!({
                    "id": record.id,
                    "state": record.state.as_str(),
                    "created_at": record.created_at,
                    "expires_at": record.expires_at,
                    "resolved_at": record.resolved_at,
                    "persistent": true,
                })),
                "detail": if outcome == topgent_enforce::DecisionOutcome::CapabilityMismatch {
                    "The installed sensors have no pre-execution interception point; the request was not downgraded."
                } else if outcome == topgent_enforce::DecisionOutcome::AwaitingApproval {
                    "Explicit local confirmation is required before guarded termination."
                } else {
                    "Evaluated from the current local evidence."
                },
                "response_scope": if agent.extensions.is_empty() { "process" } else { "shared_host" },
                "affected_extensions": agent.extensions.iter().map(|extension| extension.family.clone()).collect::<Vec<_>>(),
            }));
        }
    }
    json!({
        "capability": {
            "observe": true,
            "alert": true,
            "intercept": capability.can_intercept,
            "terminate": capability.can_terminate,
        },
        "decisions": decisions,
    })
}
