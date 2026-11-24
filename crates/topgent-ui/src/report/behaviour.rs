//! Runtime behaviour: which rules fired, on whom, and what each rule needs.
//!
//! Separate because it is its own contract with the core: the rule catalogue
//! the build carries, the findings kept across sweeps, and the limits of the
//! syscall stream they were read from. None of it is shared with the Audit
//! action rows, which say what happened; a finding says a rule held.

use serde::Deserialize;

use super::nullable;

/// The behaviour section of a report. Absent from reports before S7.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Behaviour {
    /// The rules this build carries.
    #[serde(deserialize_with = "nullable")]
    pub catalogue: Catalogue,
    /// Rules that held, newest first.
    pub findings: Vec<Finding>,
    /// Findings removed by the retention bound.
    #[serde(deserialize_with = "nullable")]
    pub evicted: u64,
    /// Syscall events read this sweep.
    #[serde(deserialize_with = "nullable")]
    pub syscall_events: u64,
    /// Syscall events lost in the handover this sweep.
    #[serde(deserialize_with = "nullable")]
    pub syscall_queue_losses: u64,
}

/// The pinned rule catalogue, and which of its rules can fire here.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Catalogue {
    /// Where the rules come from.
    #[serde(deserialize_with = "nullable")]
    pub source: String,
    /// The pinned revision.
    #[serde(deserialize_with = "nullable")]
    pub commit: String,
    /// Rules carried.
    #[serde(deserialize_with = "nullable")]
    pub rules: u64,
    /// Rules enabled as shipped.
    #[serde(deserialize_with = "nullable")]
    pub enabled: u64,
    /// Rules whose every field this host supplies.
    #[serde(deserialize_with = "nullable")]
    pub live: u64,
    /// Which syscall source `live` was counted for: `ebpf` or `audit`.
    /// Empty in reports from builds before E5.
    #[serde(deserialize_with = "nullable")]
    pub syscall_source: String,
    /// Every rule, with what it needs.
    pub coverage: Vec<RuleState>,
}

/// One rule and whether it can fire on this host.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RuleState {
    /// The rule's name.
    #[serde(deserialize_with = "nullable")]
    pub rule: String,
    /// `stable`, `incubating` or `sandbox`.
    #[serde(deserialize_with = "nullable")]
    pub maturity: String,
    /// `CRITICAL` down to `DEBUG`.
    #[serde(deserialize_with = "nullable")]
    pub priority: String,
    /// Whether it runs as shipped.
    #[serde(deserialize_with = "nullable")]
    pub enabled: bool,
    /// Whether every field it reads is supplied here.
    #[serde(deserialize_with = "nullable")]
    pub live: bool,
    /// The fields it reads that this host does not supply.
    pub needs: Vec<String>,
    /// What the rule is for.
    #[serde(deserialize_with = "nullable")]
    pub desc: String,
    /// One-line plain-English summary of the rule.
    #[serde(deserialize_with = "nullable")]
    pub summary: String,
}

/// A rule that held, and the process it held on.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Finding {
    /// The rule's name.
    #[serde(deserialize_with = "nullable")]
    pub rule: String,
    /// The rule's maturity.
    #[serde(deserialize_with = "nullable")]
    pub maturity: String,
    /// The rule's priority.
    #[serde(deserialize_with = "nullable")]
    pub priority: String,
    /// The rule's tags: MITRE techniques and areas.
    pub tags: Vec<String>,
    /// `audit` or `process sensor`.
    #[serde(deserialize_with = "nullable")]
    pub source: String,
    /// The Audit record, when the event came from one.
    #[serde(deserialize_with = "nullable")]
    pub record: String,
    /// First seen, wall clock.
    #[serde(deserialize_with = "nullable")]
    pub at: u64,
    /// Last seen, wall clock.
    #[serde(deserialize_with = "nullable")]
    pub last_at: u64,
    /// Times seen.
    #[serde(deserialize_with = "nullable")]
    pub count: u64,
    /// The process that acted.
    #[serde(deserialize_with = "nullable")]
    pub actor_pid: u32,
    /// Its name as of the event.
    #[serde(deserialize_with = "nullable")]
    pub actor_name: String,
    /// Which run of that pid, when established.
    pub actor_started_at: Option<u64>,
    /// What it touched: a path, an address or a program.
    #[serde(deserialize_with = "nullable")]
    pub target: String,
    /// Where it happened: "host", a container id, or empty when unknown.
    #[serde(deserialize_with = "nullable")]
    pub container: String,
    /// The agent it belongs to; absent for a host finding.
    pub agent_pid: Option<u32>,
    /// Which run of the agent.
    pub agent_started_at: Option<u64>,
    /// The agent's name as process history knew it, so it can be named after
    /// it exits.
    #[serde(deserialize_with = "nullable")]
    pub agent_name: String,
    /// Agent's child down to the actor.
    pub chain: Vec<u32>,
    /// Plain-language explanation for a Topgent-native temporal finding.
    #[serde(deserialize_with = "nullable")]
    pub explanation: String,
    /// One-line plain-English summary of the rule.
    #[serde(deserialize_with = "nullable")]
    pub summary: String,
}

impl Finding {
    /// Whether this finding belongs to exactly this run of an agent.
    #[must_use]
    pub fn belongs_to(&self, pid: u32, started_at: u64) -> bool {
        self.agent_pid == Some(pid) && self.agent_started_at == Some(started_at)
    }
}

#[cfg(test)]
mod tests {
    use super::{Behaviour, Finding};

    /// A report from before S7 has no behaviour section; one from a build
    /// that sent nulls must still open.
    #[test]
    fn an_absent_or_null_section_reads_as_empty() {
        let absent: crate::report::Report =
            serde_json::from_value(serde_json::json!({})).unwrap_or_default();
        assert!(absent.behaviour.findings.is_empty());
        let nulls: Behaviour = serde_json::from_value(serde_json::json!({
            "catalogue": null, "evicted": null, "findings": [
                {"rule": "R", "actor_pid": 7, "agent_pid": null, "count": null}
            ]
        }))
        .unwrap_or_default();
        assert_eq!(nulls.findings.len(), 1);
        assert_eq!(nulls.findings.first().map(|f| f.agent_pid), Some(None));
    }

    #[test]
    fn a_reused_agent_pid_does_not_inherit_findings() {
        let finding = Finding {
            agent_pid: Some(4),
            agent_started_at: Some(10),
            ..Finding::default()
        };
        assert!(finding.belongs_to(4, 10));
        assert!(!finding.belongs_to(4, 11));
        assert!(!Finding::default().belongs_to(0, 0), "a host finding");
    }
}
