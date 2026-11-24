//! Incidents: one agent run that read a large part of a workspace and then
//! sent it somewhere that is not its model service.
//!
//! Separate because it is the human-first contract: the core has already done
//! the reasoning and written the sentences, so the interface renders them and
//! does not re-derive anything. Every field the card shows is named here; a
//! missing one becomes its default so an older report still opens.

use serde::Deserialize;

use super::nullable;

/// One incident, as the core phrased it.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Incident {
    /// A stable identity across sweeps (`pid:started_at`).
    #[serde(deserialize_with = "nullable")]
    pub id: String,
    /// The incident's plain name, such as `Persistence`. Absent from older
    /// reports, where the only incident was workspace exfiltration.
    #[serde(deserialize_with = "nullable")]
    pub name: String,
    /// `critical` or `high`.
    #[serde(deserialize_with = "nullable")]
    pub severity: String,
    /// When Topgent first saw it, in Unix milliseconds. Zero when unknown.
    #[serde(deserialize_with = "nullable")]
    pub first_seen: u64,
    /// One sentence: what happened, in numbers.
    #[serde(deserialize_with = "nullable")]
    pub headline: String,
    /// Why it matters, one point per line.
    pub why: Vec<String>,
    /// What to do, in order.
    pub actions: Vec<IncidentAction>,
    /// The process this run belongs to.
    #[serde(deserialize_with = "nullable")]
    pub agent: IncidentAgent,
    /// The counts behind the headline.
    #[serde(deserialize_with = "nullable")]
    pub numbers: IncidentNumbers,
    /// The retained evidence.
    #[serde(deserialize_with = "nullable")]
    pub evidence: IncidentEvidence,
    /// What the evidence does not establish.
    pub limits: Vec<String>,
    /// The incident's kind, such as `offensive_tool`.
    #[serde(deserialize_with = "nullable")]
    pub kind: String,
    /// For a tool incident: the tools that ran, by name.
    pub tools: Vec<String>,
    /// For a tool incident: the last run's process id.
    pub process_pid: Option<u32>,
}

impl Incident {
    /// The tools this incident names: its own list, else its findings'.
    #[must_use]
    pub fn tool_names(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        let named = if self.tools.is_empty() {
            self.evidence
                .findings
                .iter()
                .map(|f| f.summary.as_str())
                .collect::<Vec<_>>()
        } else {
            self.tools.iter().map(String::as_str).collect()
        };
        for name in named {
            if !name.is_empty() && !out.contains(&name) {
                out.push(name);
            }
        }
        out
    }
}

/// One remediation step.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct IncidentAction {
    /// The plain instruction.
    #[serde(deserialize_with = "nullable")]
    pub label: String,
    /// A command that carries it out, when there is one.
    #[serde(deserialize_with = "nullable")]
    pub command: String,
}

/// Who the incident is about.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct IncidentAgent {
    /// What to call it.
    #[serde(deserialize_with = "nullable")]
    pub name: String,
    /// Its process id.
    #[serde(deserialize_with = "nullable")]
    pub pid: u32,
    /// Whether Topgent recognises it as an AI agent.
    #[serde(deserialize_with = "nullable")]
    pub recognised: bool,
    /// Its family, when recognised.
    pub family: Option<String>,
}

/// The headline figures.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct IncidentNumbers {
    /// Distinct files read under the workspace root.
    #[serde(deserialize_with = "nullable")]
    pub files_read: u64,
    /// Of those, version-control history.
    #[serde(deserialize_with = "nullable")]
    pub history_files_read: u64,
    /// Bytes written to the destinations.
    #[serde(deserialize_with = "nullable")]
    pub bytes_sent: u64,
    /// Connection attempts.
    #[serde(deserialize_with = "nullable")]
    pub connection_attempts: u64,
    /// Of those, failed.
    #[serde(deserialize_with = "nullable")]
    pub failed_attempts: u64,
    /// Whether an encryption tool ran during the activity.
    #[serde(deserialize_with = "nullable")]
    pub encrypted: bool,
    /// How long it took, in words.
    #[serde(deserialize_with = "nullable")]
    pub duration: String,
}

/// The retained evidence a person can inspect.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct IncidentEvidence {
    /// The workspace read.
    #[serde(deserialize_with = "nullable")]
    pub workspace: IncidentWorkspace,
    /// Where bytes went.
    pub destinations: Vec<IncidentDestination>,
    /// Encryption tools the run exec'd.
    pub encryption_tools: Vec<String>,
    /// For a behaviour incident: the rule findings behind it.
    pub findings: Vec<IncidentFinding>,
    /// For a secret incident: the secret files read.
    pub secrets: Vec<IncidentSecret>,
    /// For a secret incident: where data went after.
    pub sent_to: Vec<IncidentDestination>,
}

/// One secret file an agent read.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct IncidentSecret {
    /// Its path.
    #[serde(deserialize_with = "nullable")]
    pub path: String,
    /// The plain name of its class, such as `private key`.
    #[serde(deserialize_with = "nullable")]
    pub class_name: String,
    /// Its size when read, zero when it could not be sized.
    #[serde(deserialize_with = "nullable")]
    pub bytes: u64,
}

/// One behaviour-rule finding behind an incident.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct IncidentFinding {
    /// The rule that matched.
    #[serde(deserialize_with = "nullable")]
    pub rule: String,
    /// What it matched on: a path, an address or a program.
    #[serde(deserialize_with = "nullable")]
    pub target: String,
    /// The process that made the call.
    #[serde(deserialize_with = "nullable")]
    pub actor_name: String,
    /// Its pid.
    #[serde(deserialize_with = "nullable")]
    pub actor_pid: u32,
    /// How many times it matched.
    #[serde(deserialize_with = "nullable")]
    pub count: u64,
    /// What matched in a word, such as the tool's name.
    #[serde(deserialize_with = "nullable")]
    pub summary: String,
}

/// A named incident and how many of its rules can fire on this host.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct IncidentKind {
    /// Its plain name.
    #[serde(deserialize_with = "nullable")]
    pub name: String,
    /// The rules behind it.
    pub rules: Vec<IncidentKindRule>,
}

/// One rule behind a named incident.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct IncidentKindRule {
    /// The rule's name.
    #[serde(deserialize_with = "nullable")]
    pub rule: String,
    /// Whether it can fire on this host.
    #[serde(deserialize_with = "nullable")]
    pub live: bool,
}

/// The workspace root and what was read under it.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct IncidentWorkspace {
    /// The root directory.
    #[serde(deserialize_with = "nullable")]
    pub root: String,
    /// Distinct files read under it.
    #[serde(deserialize_with = "nullable")]
    pub files: u64,
    /// Of those, git history.
    #[serde(deserialize_with = "nullable")]
    pub history_files: u64,
    /// The subdirectories read most.
    pub top_directories: Vec<IncidentDirectory>,
}

/// A subdirectory and how many of its files were read.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct IncidentDirectory {
    /// The subdirectory name.
    #[serde(deserialize_with = "nullable")]
    pub directory: String,
    /// Distinct files read in it.
    #[serde(deserialize_with = "nullable")]
    pub files: u64,
}

/// One destination bytes went to.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct IncidentDestination {
    /// Address literal, or empty for a socket whose connect was not seen.
    #[serde(deserialize_with = "nullable")]
    pub address: String,
    /// Port, zero when unknown.
    #[serde(deserialize_with = "nullable")]
    pub port: u16,
    /// A name for the address, when one is known.
    #[serde(deserialize_with = "nullable")]
    pub name: String,
    /// Whether it is cloud object storage.
    #[serde(deserialize_with = "nullable")]
    pub object_storage: bool,
    /// Whether it is the agent's own model service (secret incidents).
    #[serde(deserialize_with = "nullable")]
    pub own_service: bool,
    /// Connection attempts.
    #[serde(deserialize_with = "nullable")]
    pub attempts: u64,
    /// Of those, failed.
    #[serde(deserialize_with = "nullable")]
    pub failed: u64,
    /// Bytes written to it.
    #[serde(deserialize_with = "nullable")]
    pub bytes: u64,
}

/// Whether this host can observe what the rule needs.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct IncidentCoverage {
    /// `available`, `degraded`, or `unsupported`.
    #[serde(deserialize_with = "nullable")]
    pub state: String,
    /// What is and is not observed here.
    #[serde(deserialize_with = "nullable")]
    pub detail: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_incident_names_its_tools_from_its_own_list_or_its_evidence() {
        let finding = |summary: &str| IncidentFinding {
            summary: summary.to_owned(),
            ..IncidentFinding::default()
        };
        let mut incident = Incident {
            evidence: IncidentEvidence {
                findings: vec![finding("nmap"), finding("hydra"), finding("nmap")],
                ..IncidentEvidence::default()
            },
            ..Incident::default()
        };
        assert_eq!(incident.tool_names(), vec!["nmap", "hydra"]);
        incident.tools = vec!["masscan".to_owned()];
        assert_eq!(incident.tool_names(), vec!["masscan"]);
    }
}
