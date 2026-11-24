//! The shape the interface reads, and the sweep that produces it.
//!
//! The core emits a large JSON document. Rather than pass a `Value` around and
//! index into it at every draw, the fields the interface uses are named here.
//! A missing field becomes a default rather than a panic: the interface must
//! stay legible against a report from a different version, because a monitor
//! that will not open is worse than one that draws a row it cannot explain.

use serde::Deserialize;

mod behaviour;
mod flows;
mod incidents;
pub use behaviour::{Behaviour, Catalogue, Finding, RuleState};
pub use flows::{AgentFlow, FlowDestination, FlowFolder};
pub use incidents::{Incident, IncidentCoverage, IncidentKind};

/// Read a value that the report may send as `null`.
///
/// `#[serde(default)]` covers a field that is absent. It does not cover one
/// that is present and null, and the report sends null for anything it has
/// nothing to say about: a sensor with no boundary, an asset with no version,
/// a decision with no count yet. Applied to every field including the numbers,
/// because a null in a `u64` refused the whole report and left the window
/// showing nothing but the error.
///
/// The window must stay readable against a report from any build, so a null
/// becomes the default rather than an error.
fn nullable<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// One sweep, as the interface needs it.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Report {
    /// The version that produced this report.
    #[serde(deserialize_with = "nullable")]
    pub version: String,
    /// Facts behind it.
    #[serde(deserialize_with = "nullable")]
    pub fact_count: u64,
    /// When the sweep that produced this ran, in Unix milliseconds.
    #[serde(deserialize_with = "nullable")]
    pub generated_at: u64,
    /// Executable layout, kernel and adjacent helper readiness.
    pub deployment: Deployment,
    /// Which operating system, on which architecture.
    pub platform: Platform,
    /// The rules, each with the index the core's setter takes.
    pub watchlist: Vec<Rule>,
    /// Every agent found running in this sweep.
    pub agents: Vec<Agent>,
    /// Agents seen earlier in this session and not running now, each as it
    /// was last seen, most recently seen first.
    pub ended_agents: Vec<Agent>,
    /// Ended agents the session let go to stay bounded.
    #[serde(deserialize_with = "nullable")]
    pub ended_agents_evicted: u64,
    /// Collectors that could not run, and why.
    pub failures: Vec<Failure>,
    /// Every collector's health, whether or not it produced anything.
    pub sensors: Vec<Sensor>,
    /// Prerequisites are distinct from a functioning prevention backend.
    #[serde(deserialize_with = "nullable")]
    pub interception: Interception,
    /// Which rules this host can detect, and how well.
    pub coverage: Vec<Coverage>,
    /// The security-change journal, newest first.
    pub events: Vec<Event>,
    /// Endpoint history, keyed by exact process identity.
    pub network: Vec<Endpoint>,
    /// Every agent's recorded descendants, including those that have gone.
    /// Absent from reports before S4.
    pub process_history: Vec<ProcessRow>,
    /// Audit file and network actions, including unresolved records.
    pub observed_actions: Vec<ActionRow>,
    /// Limits of the retained Audit action stream.
    pub action_coverage: ActionCoverage,
    /// Runtime behaviour rules and what they found.
    #[serde(deserialize_with = "nullable")]
    pub behaviour: Behaviour,
    /// Workspace-exfiltration incidents, newest first. Absent from older
    /// reports, so defaulted.
    pub incidents: Vec<Incident>,
    /// Whether this host can observe what the incident rule needs.
    #[serde(deserialize_with = "nullable")]
    pub incident_coverage: IncidentCoverage,
    /// Where each agent sent data and what it read first, whether or not an
    /// incident fired. Absent from older reports, and sent null when empty.
    #[serde(deserialize_with = "nullable")]
    pub agent_flows: Vec<AgentFlow>,
    /// The named incidents this build can raise, with the rules behind each.
    #[serde(deserialize_with = "nullable")]
    pub incident_kinds: Vec<IncidentKind>,
    /// Every AI asset discovered.
    pub assets: Vec<Asset>,
    /// Bounded causal history.
    pub activity: Activity,
    /// What this host can do about a finding, and what it has done.
    pub response: Response,
    /// Optional agent-supplied session context.
    pub context: Context,
    /// The binaries the sensors run, and what can be said about each.
    pub tools: Vec<Tool>,
    /// Whether the rules in force are the configured ones.
    pub policy_health: PolicyHealth,
}

/// Installed executable and helper layout.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Deployment {
    /// Versioned install, portable/source run, or unknown.
    #[serde(deserialize_with = "nullable")]
    pub mode: String,
    /// Running kernel release where available.
    #[serde(deserialize_with = "nullable")]
    pub kernel: String,
    /// Narrow helper files expected beside the executable.
    pub helpers: Vec<DeploymentHelper>,
}

/// One adjacent helper's package-level readiness.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct DeploymentHelper {
    /// Binary name.
    #[serde(deserialize_with = "nullable")]
    pub name: String,
    /// `ready`, `missing`, `unsafe_permissions`, or `exposed_to_other_users`.
    #[serde(deserialize_with = "nullable")]
    pub state: String,
}

/// One sensor binary, and how far it can be trusted.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Tool {
    /// Short name.
    #[serde(deserialize_with = "nullable")]
    pub name: String,
    /// `system_trusted`, `user_managed`, `unverified`, `rejected` or `missing`.
    #[serde(deserialize_with = "nullable")]
    pub state: String,
    /// The absolute path accepted, when one was.
    #[serde(deserialize_with = "nullable")]
    pub path: String,
}

/// Which rules produced this report.
///
/// A policy that broke and fell back to built-in defaults used to look exactly
/// like a fresh install, so every finding on the host quietly changed meaning.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PolicyHealth {
    /// `absent`, `valid`, `recovered` or `malformed`.
    #[serde(deserialize_with = "nullable")]
    pub state: String,
    /// What went wrong, where something did.
    #[serde(deserialize_with = "nullable")]
    pub detail: String,
    /// Whether the rules in force are the ones the operator wrote.
    #[serde(deserialize_with = "nullable")]
    pub operator_rules_in_force: bool,
    /// Where the policy is read from.
    #[serde(deserialize_with = "nullable")]
    pub path: String,
}

/// The operating system the report came from.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Platform {
    /// `linux`, `macos`, `windows`.
    pub os: String,
    /// `aarch64`, `x86_64`.
    pub arch: String,
    /// The system's own name and version, when it says.
    pub name: Option<String>,
}

impl Report {
    /// The host's system, for the top of the window: its name, architecture
    /// and kernel, as far as the report says.
    #[must_use]
    pub fn system_line(&self) -> String {
        let name = self
            .platform
            .name
            .clone()
            .unwrap_or_else(|| self.platform.os.clone());
        let mut parts = vec![name];
        if !self.platform.arch.is_empty() {
            parts.push(self.platform.arch.clone());
        }
        if !self.deployment.kernel.is_empty() {
            parts.push(format!("kernel {}", self.deployment.kernel));
        }
        parts.retain(|p| !p.is_empty());
        parts.join(" \u{b7} ")
    }
}

/// One agent.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Agent {
    /// Process id.
    #[serde(deserialize_with = "nullable")]
    pub pid: u32,
    /// When this session first saw it, in Unix milliseconds.
    pub first_seen: Option<u64>,
    /// For an ended agent, when this session last saw it running.
    pub last_seen: Option<u64>,
    /// `false` for an agent that has ended; absent in older reports.
    pub live: Option<bool>,
    /// When the operating system started this process, in Unix milliseconds.
    ///
    /// Half of the identity key, and the answer to "how long has this been
    /// running", which the table had no way to say.
    #[serde(deserialize_with = "nullable")]
    pub started_at: u64,
    /// Recognised family, absent when the process was not identified.
    pub family: Option<String>,
    /// Risk band.
    #[serde(deserialize_with = "nullable")]
    pub grade: String,
    /// Points.
    #[serde(deserialize_with = "nullable")]
    pub score: u32,
    /// Owning account.
    pub user: Option<String>,
    /// Executable path, absent when the system refused it.
    pub exe: Option<String>,
    /// Whether the identity was confirmed, unexamined, or unrecognised.
    #[serde(deserialize_with = "nullable")]
    pub discovery_confidence: String,
    /// Named findings with their evidence.
    pub factors: Vec<Factor>,
    /// What the agent declared, touched, or can reach.
    pub resources: Vec<Resource>,
    /// Descendant processes.
    pub children: Vec<Child>,
    /// Other agents this one can invoke. The edge nobody else draws.
    pub invokes: Vec<Invocation>,
    /// Model in use, where one was declared.
    pub model: Option<String>,
    /// Where the model was read and how much was read to find it. Absent in
    /// reports from builds before S3, which said nothing about it.
    pub model_evidence: Option<ModelEvidence>,
    /// Why identity is what it is: which facts the system gave up, and which
    /// it refused. A refused executable path means the process has not been
    /// ruled out as an agent, only that it was never examined.
    pub identity_evidence: IdentityEvidence,
    /// The container it runs in, when its cgroup named one.
    #[serde(default)]
    pub container: Option<AgentContainer>,
    /// What kind of product the family is: `agent`, `agent_editor` or
    /// `model_runtime`. Absent for an unrecognised process.
    pub kind: Option<String>,
    /// Other models the agent used recently, as `provider/model`, newest first.
    pub models_seen: Vec<String>,
    /// The agent's risks in plain words, worst first.
    pub summary: Option<Summary>,
}

/// An agent's risks as a person reads them, from the report's plain-words
/// catalogue. The interface arranges these sentences and writes none of its own.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Summary {
    /// `act`, `watch`, `info` or `none`: the worst level among the risks.
    #[serde(deserialize_with = "nullable")]
    pub level: String,
    /// The level as a word, such as `Critical`.
    #[serde(deserialize_with = "nullable")]
    pub label: String,
    /// The worst risk's headline.
    #[serde(deserialize_with = "nullable")]
    pub headline: String,
    /// Whether any risk is something the agent did, not only could do.
    #[serde(deserialize_with = "nullable")]
    pub did_something: bool,
    /// Every risk, worst first.
    pub risks: Vec<SummaryRisk>,
}

/// One risk in plain words.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SummaryRisk {
    /// Stable identity, the same across agents.
    #[serde(deserialize_with = "nullable")]
    pub id: String,
    /// `act`, `watch` or `info`.
    #[serde(deserialize_with = "nullable")]
    pub level: String,
    /// The level as a word.
    #[serde(deserialize_with = "nullable")]
    pub label: String,
    /// The risk in a few words.
    #[serde(deserialize_with = "nullable")]
    pub headline: String,
}

/// An agent's container: its short id, and its image when the runtime said.
/// Reports from the first build with this field gave the id alone.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum AgentContainer {
    /// `{"id": …, "image": …, "privileged": …}`.
    Described {
        /// Short id.
        id: String,
        /// Image repository, when the runtime said.
        #[serde(default)]
        image: Option<String>,
    },
    /// The id alone.
    Id(String),
}

impl AgentContainer {
    /// "container 047b9fcae3c1 (forgex)", or without the image when unknown.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Described {
                id,
                image: Some(image),
            } => format!("container {id} ({image})"),
            Self::Described { id, image: None } | Self::Id(id) => format!("container {id}"),
        }
    }
}

/// One agent-to-agent invocation edge.
///
/// Current reports preserve the target pid and the mechanism. Older reports
/// used a single display string, which remains readable for saved evidence.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Invocation {
    /// Current structured report shape.
    Detailed {
        /// Invoked process.
        target_pid: u32,
        /// Mechanism that established the edge.
        #[serde(deserialize_with = "nullable")]
        via: String,
    },
    /// Historical report shape.
    Legacy(String),
}

impl Invocation {
    /// Compact text for the blast-radius panel.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Detailed { target_pid, via } if via.is_empty() => format!("pid {target_pid}"),
            Self::Detailed { target_pid, via } => format!("pid {target_pid} via {via}"),
            Self::Legacy(label) => label.clone(),
        }
    }
}

/// One scored finding.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Factor {
    /// Stable code.
    #[serde(deserialize_with = "nullable")]
    pub code: String,
    /// Points contributed.
    #[serde(deserialize_with = "nullable")]
    pub points: u32,
    /// The sentence shown to a reader.
    #[serde(deserialize_with = "nullable")]
    pub title: String,
    /// Where the finding came from.
    #[serde(deserialize_with = "nullable")]
    pub source: String,
}

/// One resource an agent declared, touched, or can reach.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Resource {
    /// Path as reported.
    #[serde(deserialize_with = "nullable")]
    pub path: String,
    /// What the configuration permits.
    #[serde(deserialize_with = "nullable")]
    pub declared: String,
    /// What was seen.
    #[serde(deserialize_with = "nullable")]
    pub observed: String,
    /// What could be opened now.
    #[serde(deserialize_with = "nullable")]
    pub reachable: String,
    /// What the reachability probe established, when one ran.
    ///
    /// `account_readable` where the kernel answered, `path_resolves` where only
    /// the path could be established. Empty where nothing probed the path.
    #[serde(deserialize_with = "nullable")]
    pub reachable_evidence: String,
    /// The same, in the words a reader needs.
    #[serde(deserialize_with = "nullable")]
    pub reachable_statement: String,
    /// A credential in reach that nothing has touched.
    #[serde(deserialize_with = "nullable")]
    pub latent_secret: bool,
    /// Whether the path holds a credential, touched or not.
    #[serde(deserialize_with = "nullable")]
    pub sensitive: bool,
}

/// One collector that could not run.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Failure {
    /// Which collector.
    #[serde(deserialize_with = "nullable")]
    pub collector: String,
    /// Stated in the collector's own words.
    #[serde(deserialize_with = "nullable")]
    pub reason: String,
}

impl Resource {
    /// A credential readable now, whether or not anything has opened it.
    #[must_use]
    pub fn credential_in_reach(&self) -> bool {
        self.sensitive && self.reachable == "yes"
    }

    /// A credential something was observed opening.
    #[must_use]
    pub fn credential_read(&self) -> bool {
        self.sensitive && self.observed == "yes"
    }
}

impl Report {
    /// The agent carrying the highest score, for the default selection.
    #[must_use]
    pub fn worst(&self) -> Option<&Agent> {
        self.agents.iter().max_by_key(|a| a.score)
    }

    /// An agent by pid: a running one, else one that ended this session.
    #[must_use]
    pub fn find_agent(&self, pid: u32) -> Option<&Agent> {
        self.agents
            .iter()
            .find(|a| a.pid == pid)
            .or_else(|| self.ended_agents.iter().find(|a| a.pid == pid))
    }

    /// One run of an agent, running or ended: its pid, and its start when
    /// the row knows it, so a reused pid is not taken for another run.
    #[must_use]
    pub fn agent_run(&self, pid: u32, started_at: Option<u64>) -> Option<&Agent> {
        self.agents
            .iter()
            .chain(&self.ended_agents)
            .find(|a| a.pid == pid && started_at.is_none_or(|at| at == a.started_at))
    }

    /// What a row that names an agent by family calls it: the run's family
    /// and model when this report has the run, else the family the row gave.
    #[must_use]
    pub fn run_name(&self, pid: u32, started_at: Option<u64>, family: &str) -> String {
        match self.agent_run(pid, started_at) {
            Some(agent) => agent.named(),
            None if family.is_empty() => "agent".to_owned(),
            None => crate::brand::agent_name(Some(family)),
        }
    }
}

impl Agent {
    /// Whether this agent ended earlier in the session.
    #[must_use]
    pub fn has_ended(&self) -> bool {
        self.live == Some(false)
    }

    /// Running since when, or ended and last seen when: what happened, and
    /// what is still happening, in the reader's local time.
    #[must_use]
    pub fn state_line(&self) -> String {
        let started = crate::clock::stamp(self.started_at);
        match (self.has_ended(), self.last_seen) {
            (true, Some(last)) => format!(
                "Ended \u{b7} ran {started} to {}",
                crate::clock::stamp(last)
            ),
            (true, None) => format!("Ended \u{b7} started {started}"),
            (false, _) => format!("Running since {started}"),
        }
    }

    /// The agent and the model it runs on, as a column names it:
    /// `opencode · deepseek-v4-flash`. The family alone when no model was
    /// read.
    #[must_use]
    pub fn named(&self) -> String {
        match self
            .model
            .as_deref()
            .map(short_model)
            .filter(|m| !m.is_empty())
        {
            Some(model) => format!("{} \u{b7} {model}", self.label()),
            None => self.label(),
        }
    }

    /// What to show in the agent column when the family is unknown.
    #[must_use]
    pub fn label(&self) -> String {
        if let Some(family) = &self.family {
            return crate::brand::agent_name(Some(family));
        }
        // Not "not examined". These processes were examined; the core records
        // them as unrecognised, and the interface said the opposite. A monitor
        // that overstates what it did not do is worse than one that says
        // nothing. The executable's own name is the honest answer, and the
        // identity column carries the state.
        self.exe
            .as_deref()
            .and_then(|path| path.rsplit(['/', '\\']).next())
            .filter(|name| !name.is_empty())
            .map_or_else(|| format!("pid {}", self.pid), ToOwned::to_owned)
    }

    /// What Topgent managed to establish about what this process is.
    #[must_use]
    pub fn recognition(&self) -> &'static str {
        match self.identity_evidence.class.as_str() {
            "known" => match self.identity_evidence.strength.as_deref() {
                Some("known_install_path") => "known agent · install path",
                Some("active_extension") => "known agent · active extension",
                _ => "known agent",
            },
            "suspected" => "suspected agent · name only",
            "unknown" if self.exe.is_some() => "unknown application · no family match",
            "unknown" => "unknown application · executable unreadable",
            // Compatibility with reports written before the S8 class field.
            _ if self.family.is_some() => match self.identity_evidence.strength.as_deref() {
                Some("known_install_path") => "known install path",
                Some("name_only") => "name match only",
                _ => "recognised",
            },
            _ if self.exe.is_some() => "unrecognised",
            _ => "unreadable",
        }
    }

    /// The model with how it was established, for the identity line.
    #[must_use]
    pub fn model_line(&self) -> String {
        match (&self.model, &self.model_evidence) {
            (Some(model), Some(evidence)) if !evidence.certainty.is_empty() => {
                format!("{model} · {}", evidence.certainty)
            }
            (Some(model), _) => model.clone(),
            (None, _) => "no model named in its own files".to_owned(),
        }
    }

    /// Where the model came from, for the record.
    #[must_use]
    pub fn model_provenance(&self) -> String {
        match (&self.model, &self.model_evidence) {
            (Some(_), Some(evidence)) if !evidence.source.is_empty() => {
                let how = if evidence.certainty == "observed" {
                    "observed in"
                } else {
                    "declared in"
                };
                format!("{how} {}; read {}", evidence.source, evidence.read)
            }
            (Some(_), _) => "named in the agent's own files; source not reported".to_owned(),
            (None, _) => "not found in the agent's files".to_owned(),
        }
    }
}

/// Run one sweep off the interface thread.
///
/// `topgent_report::scan()` is synchronous and, on Windows, spends seconds in
/// event-log queries. Running it on the thread that draws froze the window for
/// the length of every sweep, which is the defect this signature exists to
/// prevent from returning.
/// # Errors
///
/// The sweep thread failing, or a report this build cannot read. The second is
/// the one that matters: it means the interface's model and the core's output
/// have drifted, and the window says so rather than drawing a partial answer.
pub async fn sweep() -> Result<Report, String> {
    let value = tokio::task::spawn_blocking(topgent_report::scan)
        .await
        .map_err(|_| "the sweep thread failed".to_owned())?;
    serde_json::from_value(value).map_err(|e| format!("the report could not be read: {e}"))
}

/// Set one watchlist rule's response mode.
///
/// Through the core's own validated path. The interface does not know what a
/// mode means, cannot invent one, and does not write the policy file: it sends
/// an index and a word, and the core refuses anything it does not recognise.
pub async fn set_rule_response(index: usize, mode: &'static str) -> String {
    let outcome =
        tokio::task::spawn_blocking(move || topgent_report::set_rule_response(index, mode)).await;
    match outcome {
        Ok(value) => {
            let ok = value
                .get("ok")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            value
                .get("message")
                .and_then(serde_json::Value::as_str)
                .map_or_else(
                    || {
                        if ok {
                            format!("rule {index} now responds with {mode}")
                        } else {
                            format!("rule {index} was not changed")
                        }
                    },
                    ToOwned::to_owned,
                )
        }
        Err(_) => "the policy thread failed".to_owned(),
    }
}

/// Add one watchlist rule.
///
/// The path is whatever the reader typed, trimmed by the core. It is a
/// substring match, not a glob and not a regular expression, which is what
/// makes it something an operator can predict.
pub async fn add_rule(path: String, condition: &'static str, severity: &'static str) -> String {
    through(
        move || topgent_report::add_rule(&path, condition, severity),
        "rule added",
    )
    .await
}

/// Remove one watchlist rule by its position.
pub async fn remove_rule(index: usize) -> String {
    through(move || topgent_report::remove_rule(index), "rule removed").await
}

/// Set an asset's disposition: approved, restricted, disallowed, unreviewed.
///
/// Scoped to the asset and not to one agent, which is how the report itself
/// reads a disposition back. Scoping a decision here that the report ignores
/// would make the control appear to work and change nothing.
pub async fn set_asset_disposition(id: String, disposition: &'static str) -> String {
    through(
        move || topgent_report::set_asset_disposition(&id, None, disposition),
        "decision recorded",
    )
    .await
}

/// Run one core action off the drawing thread and report what it said.
///
/// Every one of these writes the policy file. None of them is run on the thread
/// that draws, and none of them is retried: a policy write that failed is told
/// to the reader rather than attempted again behind their back.
async fn through(
    action: impl FnOnce() -> serde_json::Value + Send + 'static,
    done: &'static str,
) -> String {
    match tokio::task::spawn_blocking(action).await {
        Ok(value) => value
            .get("message")
            .and_then(serde_json::Value::as_str)
            .map_or_else(
                || {
                    if value
                        .get("ok")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false)
                    {
                        done.to_owned()
                    } else {
                        format!("{done}: refused, and the core gave no reason")
                    }
                },
                ToOwned::to_owned,
            ),
        Err(_) => "the policy thread failed".to_owned(),
    }
}

/// Write this session to a file.
///
/// The whole sweep, structured, with headings, in a form someone can read and
/// send. Two files: one for a person and one for a machine, both stating the
/// redaction they were written with rather than leaving it to be inferred.
pub async fn export_session(redacted: bool) -> String {
    through(
        move || topgent_report::export_session(redacted),
        "session written",
    )
    .await
}

/// Asks the operating system for packet capture, off the interface thread.
///
/// The elevation helper puts a password prompt on screen and blocks until it
/// is answered. Doing that inside `update` froze the whole window, so the
/// dialog stayed on screen after the password was accepted and looked as
/// though nothing had happened. It is blocking work and belongs on a blocking
/// thread.
///
/// Returns whether the capability is now present, and the sentence to show.
pub async fn grant_capture() -> (bool, String) {
    use topgent_collect::capture::Granted;
    let outcome = tokio::task::spawn_blocking(topgent_collect::capture::grant).await;
    match outcome {
        Ok(Granted::Yes) => (
            true,
            "Packet capture enabled. Restart Topgent to use it.".to_owned(),
        ),
        Ok(Granted::Declined) => (false, "Cancelled. Nothing changed.".to_owned()),
        Ok(Granted::NoChange { detail }) => (
            false,
            if detail.is_empty() {
                "That ran but capture is still unavailable.".to_owned()
            } else {
                format!("That ran but capture is still unavailable. {detail}")
            },
        ),
        Ok(Granted::NotAttempted { reason }) => (false, reason),
        Err(_) => (false, "The elevation thread failed.".to_owned()),
    }
}

/// Ask the core to stop one process.
///
/// The interface does not decide anything about this. It sends a pid; the core
/// takes its own process snapshot, checks the guard, rechecks that the pid
/// still names the process that was approved, signals, and records a fact
/// either way. The window between the reader pressing the button and the
/// signal arriving is where a reused pid would be stopped in place of the
/// process someone meant, and closing it is the core's job, not this one's.
///
/// Hand the capture capability back, off the drawing thread.
pub async fn revoke_capture() -> (bool, String) {
    use topgent_collect::capture::Granted;
    match tokio::task::spawn_blocking(topgent_collect::capture::revoke).await {
        Ok(Granted::Yes) => (true, "Permission removed. Capture is off.".to_owned()),
        Ok(Granted::Declined) => (false, "Cancelled. Nothing changed.".to_owned()),
        Ok(Granted::NoChange { detail }) => (
            false,
            if detail.is_empty() {
                "That ran and the permission is still there.".to_owned()
            } else {
                format!("That ran and the permission is still there. {detail}")
            },
        ),
        Ok(Granted::NotAttempted { reason }) => (false, reason),
        Err(_) => (false, "The elevation thread failed.".to_owned()),
    }
}

/// Set the event log aside, off the drawing thread.
pub async fn clear_events() -> String {
    tokio::task::spawn_blocking(topgent_report::clear_event_log)
        .await
        .map_or_else(
            |_| "the clear thread failed".to_owned(),
            |value| {
                value
                    .get("message")
                    .and_then(serde_json::Value::as_str)
                    .map_or_else(|| "Event log cleared.".to_owned(), ToOwned::to_owned)
            },
        )
}

/// Ask the core to stop one process.
///
/// Off the drawing thread for the same reason a sweep is: it takes a process
/// snapshot and blocks.
pub async fn stop(pid: u32) -> String {
    let outcome = tokio::task::spawn_blocking(move || topgent_report::stop(pid))
        .await
        .map_err(|_| "the stop thread failed".to_owned());
    match outcome {
        Ok(value) => value
            .get("message")
            .and_then(serde_json::Value::as_str)
            .map_or_else(
                || format!("pid {pid}: no answer from the core"),
                ToOwned::to_owned,
            ),
        Err(why) => why,
    }
}

/// One descendant process.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Child {
    /// Process id.
    #[serde(deserialize_with = "nullable")]
    pub pid: u32,
    /// Executable name as reported.
    #[serde(deserialize_with = "nullable")]
    pub name: String,
    /// Distance from the agent.
    #[serde(deserialize_with = "nullable")]
    pub depth: u32,
}

/// One collector's health.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Sensor {
    /// Evidence coverage, independent of sensor availability.
    #[serde(deserialize_with = "nullable")]
    pub collection_coverage: String,
    /// Which sources of loss the counter measures.
    #[serde(deserialize_with = "nullable")]
    pub loss_accounting: String,
    /// Unknown remains distinct from a measured zero.
    pub dropped_events: Option<u64>,
    /// Collector name.
    #[serde(deserialize_with = "nullable")]
    pub id: String,
    /// `available`, `degraded`, `permission_required`, `unsupported`, `error`.
    #[serde(deserialize_with = "nullable")]
    pub state: String,
    /// What it says about itself when it is not simply working.
    #[serde(deserialize_with = "nullable")]
    pub detail: String,
    /// What it still cannot cover even when healthy. A green row is not
    /// coverage, and this field is why.
    #[serde(deserialize_with = "nullable")]
    pub boundary: String,
    /// What access it needs.
    #[serde(deserialize_with = "nullable")]
    pub permission: String,
    /// Facts from the last run.
    #[serde(deserialize_with = "nullable")]
    pub fact_count: u64,
    /// How long the last run took.
    #[serde(deserialize_with = "nullable")]
    pub duration_ms: u64,
}

/// Runtime prevention status emitted by the collector probe.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Interception {
    /// Stable backend/prerequisite state; absence means unknown.
    #[serde(deserialize_with = "nullable")]
    pub state: String,
    /// Why prevention is unavailable or which prerequisite is missing.
    #[serde(deserialize_with = "nullable")]
    pub detail: String,
}

/// One rule and whether this host can detect it.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Coverage {
    /// Factor code.
    #[serde(deserialize_with = "nullable")]
    pub rule: String,
    /// The sensor it depends on.
    #[serde(deserialize_with = "nullable")]
    pub sensor: String,
    /// That sensor's state.
    #[serde(deserialize_with = "nullable")]
    pub state: String,
    /// How the rule was last shown to work.
    #[serde(deserialize_with = "nullable")]
    pub verification: String,
}

/// One journal entry.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Event {
    /// Milliseconds since the epoch.
    #[serde(deserialize_with = "nullable")]
    pub at: u64,
    /// What happened.
    #[serde(deserialize_with = "nullable")]
    pub kind: String,
    /// Which agent.
    #[serde(deserialize_with = "nullable")]
    pub agent: String,
    /// Process id.
    #[serde(deserialize_with = "nullable")]
    pub pid: u32,
    /// When that process started.
    pub started_at: Option<u64>,
    /// In words.
    #[serde(deserialize_with = "nullable")]
    pub detail: String,
    /// How serious.
    #[serde(deserialize_with = "nullable")]
    pub severity: String,
    /// Whether a grade moved up or down. A reduction must never read as an
    /// escalation, which is why direction is carried rather than inferred.
    pub direction: Option<String>,
}

/// One recorded descendant of an agent.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ProcessRow {
    /// The agent it belongs to.
    #[serde(deserialize_with = "nullable")]
    pub agent_pid: u32,
    /// Hops below the agent: 1 for a child, 2 for a grandchild.
    #[serde(deserialize_with = "nullable")]
    pub depth: u32,
    /// Its program's path, when it was read.
    pub exe: Option<String>,
    /// Its pid.
    #[serde(deserialize_with = "nullable")]
    pub pid: u32,
    /// When the kernel started it.
    #[serde(deserialize_with = "nullable")]
    pub started_at: u64,
    /// Its name.
    #[serde(deserialize_with = "nullable")]
    pub name: String,
    /// The parent it started with, when resolved.
    pub parent_pid: Option<u32>,
    /// `running`, `gone`, or `exited`.
    #[serde(deserialize_with = "nullable")]
    pub state: String,
    /// First sighting.
    #[serde(deserialize_with = "nullable")]
    pub first_seen: u64,
    /// Latest sighting.
    #[serde(deserialize_with = "nullable")]
    pub last_seen: u64,
    /// The first sighting that no longer found it.
    pub gone_after: Option<u64>,
    /// When it exited, from an exit record.
    pub exited_at: Option<u64>,
    /// Its exit status, from an exit record.
    pub exit_code: Option<u32>,
    /// `kernel_event` when the kernel reported it as it happened, `sweep`
    /// when only a sweep saw it running. Absent before S5.
    pub observed_by: Option<String>,
    /// Whether another process adopted it.
    #[serde(deserialize_with = "nullable")]
    pub reparented: bool,
    /// Whether it runs in a different pid namespace from its parent.
    #[serde(deserialize_with = "nullable")]
    pub crossed_namespace: bool,
    /// How many times it replaced its program.
    #[serde(deserialize_with = "nullable")]
    pub exec_generation: u32,
    /// Whether its last exec was gone before the program could be read.
    /// Absent before S5.
    #[serde(deserialize_with = "nullable")]
    pub program_unread: bool,
    /// Its current program's name.
    pub program: Option<String>,
    /// Programs it ran before, oldest first.
    pub previous_programs: Vec<String>,
    /// Parents between it and its agent, nearest first.
    pub chain: Vec<u32>,
}

/// One endpoint an agent was seen using.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Endpoint {
    /// Owning agent's family.
    #[serde(deserialize_with = "nullable")]
    pub agent_family: String,
    /// Owning process id.
    #[serde(deserialize_with = "nullable")]
    pub agent_pid: u32,
    /// When that agent started, which tells its run from a reused pid.
    pub agent_started_at: Option<u64>,
    /// Which protocol carries it.
    #[serde(deserialize_with = "nullable")]
    pub protocol: String,
    /// Whether this platform could have named a peer at all. `false` means an
    /// absent host is the platform's limit and not a missed observation, which
    /// is the difference between a ping nobody saw and a ping to nowhere.
    #[serde(deserialize_with = "nullable")]
    pub peer_observable: bool,
    /// Address or name as the socket reported it.
    #[serde(deserialize_with = "nullable")]
    pub host: String,
    /// Port.
    pub port: u16,
    /// Inbound or outbound.
    #[serde(deserialize_with = "nullable")]
    pub direction: String,
    /// The metadata verdict: observed, exposed listener, suspicious endpoint,
    /// private peer, metadata service.
    #[serde(deserialize_with = "nullable")]
    pub verdict: String,
    /// Whether it was in the most recent snapshot.
    #[serde(deserialize_with = "nullable")]
    pub currently_observed: bool,
    /// Resolved name, where one was available.
    pub dns_name: Option<String>,
    /// Country from the report's offline ownership table.
    #[serde(deserialize_with = "nullable")]
    pub country: String,
    /// Announcing network from the report's offline ownership table.
    #[serde(deserialize_with = "nullable")]
    pub network_owner: String,
    /// Whether the ownership table had an answer.
    #[serde(deserialize_with = "nullable")]
    pub owner_known: bool,
    /// Number of sweeps in which this endpoint was visible.
    #[serde(deserialize_with = "nullable")]
    pub observations: u64,
    /// Packets a capture counted moving to or from here.
    ///
    /// `None` where no capture ran or none saw this destination. Never zero,
    /// and never a count of how often a sweep saw the endpoint: those are
    /// observations, and the difference is the whole point of capturing.
    pub packets: Option<u64>,
    /// Traffic bytes when a sensor can count them.
    pub bytes: Option<u64>,
}

/// One discovered AI asset.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Asset {
    /// Stable identity.
    #[serde(deserialize_with = "nullable")]
    pub id: String,
    /// Display name.
    #[serde(deserialize_with = "nullable")]
    pub name: String,
    /// Agent, model, connector, endpoint, tool.
    #[serde(deserialize_with = "nullable")]
    pub kind: String,
    /// The operator's decision.
    #[serde(deserialize_with = "nullable")]
    pub disposition: String,
    /// Whether it is in use rather than merely installed.
    #[serde(deserialize_with = "nullable")]
    pub active: bool,
    /// Version, where one was determined.
    pub version: Option<String>,
}

/// Bounded causal history.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Activity {
    /// Observations, newest last.
    pub events: Vec<ActivityEvent>,
}

/// One observation in the causal history.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ActivityEvent {
    /// Milliseconds since the epoch.
    #[serde(deserialize_with = "nullable")]
    pub at: u64,
    /// What kind of observation.
    #[serde(deserialize_with = "nullable")]
    pub kind: String,
    /// One sentence.
    #[serde(deserialize_with = "nullable")]
    pub title: String,
    /// The supporting detail.
    #[serde(deserialize_with = "nullable")]
    pub detail: String,
    /// Which collector saw it.
    #[serde(deserialize_with = "nullable")]
    pub collector: String,
    /// How strongly it is attributed. Correlation is not causation and the
    /// field carries the difference rather than the wording implying it.
    #[serde(deserialize_with = "nullable")]
    pub confidence: String,
    /// Owning process.
    #[serde(deserialize_with = "nullable")]
    pub agent_pid: u32,
}

/// What this host can do about a finding.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Response {
    /// Per-mode capability on this platform.
    pub capability: Capability,
    /// Actions taken or queued.
    pub decisions: Vec<Decision>,
}

/// Whether each response mode is available here.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Capability {
    /// Record without acting.
    pub observe: serde_json::Value,
    /// Raise a notification.
    pub alert: serde_json::Value,
    /// Stop an action before it happens.
    pub intercept: serde_json::Value,
    /// Stop the process.
    pub terminate: serde_json::Value,
}

/// One response taken or queued.
///
/// The field names are the report's, not names that read well here. Three were
/// invented, every one deserialised to an empty string, and the panel printed
/// `· · observed ·` while the suite stayed green: `serde(default)` fills a
/// field nobody supplied without complaining. `the_fields_this_interface_reads`
/// is what makes that impossible to ship again.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Decision {
    /// Which rule, by its position in the policy.
    #[serde(deserialize_with = "nullable")]
    pub rule_index: usize,
    /// What the rule watches.
    #[serde(deserialize_with = "nullable")]
    pub path: String,
    /// When it applies.
    #[serde(deserialize_with = "nullable")]
    pub condition: String,
    /// The agent it was evaluated against.
    #[serde(deserialize_with = "nullable")]
    pub agent_family: String,
    /// That agent's process.
    #[serde(deserialize_with = "nullable")]
    pub agent_pid: u32,
    /// When that agent started.
    pub agent_started_at: Option<u64>,
    /// The mode the rule asked for.
    #[serde(deserialize_with = "nullable")]
    pub requested: String,
    /// What actually happened, which is not always what was requested.
    #[serde(deserialize_with = "nullable")]
    pub outcome: String,
    /// Why.
    #[serde(deserialize_with = "nullable")]
    pub detail: String,
    /// Whether this fired now, or was suppressed as a repeat.
    #[serde(deserialize_with = "nullable")]
    pub transition: String,
    /// How many times the rule has matched.
    #[serde(deserialize_with = "nullable")]
    pub trigger_count: u64,
}

/// One watchlist rule, as the report carries it.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Rule {
    /// Position in the policy, which is what the core's setter takes.
    #[serde(deserialize_with = "nullable")]
    pub index: usize,
    /// What is watched.
    #[serde(deserialize_with = "nullable")]
    pub path: String,
    /// When it applies.
    #[serde(deserialize_with = "nullable")]
    pub condition: String,
    /// What it is worth.
    #[serde(deserialize_with = "nullable")]
    pub severity: String,
    /// What Topgent does about it. Settable from the response panel.
    #[serde(deserialize_with = "nullable")]
    pub response: String,
}

/// Optional agent-supplied session context.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Context {
    /// Whether it is accepted at all. Off on a fresh install.
    #[serde(deserialize_with = "nullable")]
    pub enabled: bool,
    /// Which evidence wins when the two disagree.
    #[serde(deserialize_with = "nullable")]
    pub authority: String,
    /// What is retained.
    #[serde(deserialize_with = "nullable")]
    pub privacy: String,
    /// Retained records.
    pub records: Vec<ContextRecord>,
}

/// One sanitized context record.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ContextRecord {
    /// Harness session.
    #[serde(deserialize_with = "nullable")]
    pub session_id: String,
    /// Sanitized summary. Never a prompt.
    #[serde(deserialize_with = "nullable")]
    pub summary: String,
    /// Coarse category.
    #[serde(deserialize_with = "nullable")]
    pub objective: String,
    /// Where it came from.
    #[serde(deserialize_with = "nullable")]
    pub source: String,
    /// Whether it matched a live process exactly.
    #[serde(deserialize_with = "nullable")]
    pub matched: bool,
}

/// The evidence behind an agent's model.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ModelEvidence {
    /// `observed` in the running session's own output, or `declared` in a
    /// configuration it may have overridden.
    #[serde(deserialize_with = "nullable")]
    pub certainty: String,
    /// The file or flag, in its `~` form.
    #[serde(deserialize_with = "nullable")]
    pub source: String,
    /// How much was read, in plain words.
    #[serde(deserialize_with = "nullable")]
    pub read: String,
}

/// What the operating system did and did not say about a process.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct IdentityEvidence {
    /// Product-level identity class: `known`, `suspected`, or `unknown`.
    #[serde(deserialize_with = "nullable")]
    pub class: String,
    /// `confirmed`, `name_only`, `unexamined`, or `unrecognised`.
    #[serde(deserialize_with = "nullable")]
    pub state: String,
    /// What a recognition rests on: `known_install_path` or `name_only`.
    pub strength: Option<String>,
    /// Whether the executable path was readable.
    #[serde(deserialize_with = "nullable")]
    pub exe_path_known: bool,
    /// Whether the owning account was readable.
    #[serde(deserialize_with = "nullable")]
    pub owner_known: bool,
    /// Whether the parent was reported.
    #[serde(deserialize_with = "nullable")]
    pub parent_known: bool,
    /// Each fact the system refused, named in plain words.
    pub limits: Vec<String>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::{Invocation, Report};

    #[test]
    fn coverage_and_prevention_preserve_unknown_in_old_and_new_reports() {
        for source in [
            "{}",
            r#"{"interception":null,"sensors":[{"dropped_events":null}]}"#,
        ] {
            let parsed: Report = serde_json::from_str(source).expect("old report readable");
            assert!(parsed.interception.state.is_empty());
            assert!(
                parsed
                    .sensors
                    .iter()
                    .all(|sensor| sensor.dropped_events.is_none())
            );
        }
        let parsed: Report = serde_json::from_str(r#"{"interception":{"state":"not_installed","detail":"no interception backend"},"sensors":[{"collection_coverage":"snapshot_only","loss_accounting":"Accumulator only","dropped_events":0,"fact_count":7},{"dropped_events":3}]}"#).expect("new report readable");
        let sensor = parsed.sensors.first().expect("sensor");
        assert_eq!(sensor.dropped_events, Some(0));
        assert_eq!(sensor.collection_coverage, "snapshot_only");
        assert_eq!(sensor.loss_accounting, "Accumulator only");
        assert_eq!(sensor.fact_count, 7);
        assert_eq!(parsed.interception.state, "not_installed");
        assert_eq!(
            parsed.sensors.last().expect("loss row").dropped_events,
            Some(3)
        );
    }

    /// The regression this exists for.
    ///
    /// `identity_evidence` is an object in the report and was declared here as
    /// a sequence. Every unit test passed, because every one built its own
    /// fixture by hand and none read what the product actually emits. The
    /// window opened and said "the report could not be read".
    ///
    /// This test runs a real sweep on the machine running it. It is the only
    /// test in this crate that touches the system, and it is here because the
    /// alternative is a model that agrees with itself and with nothing else.
    /// Deserialising is not the same as reading. Every field is
    /// `serde(default)`, so a name this interface invented becomes an empty
    /// string and the panel prints separators with nothing between them, while
    /// the suite stays green. This asserts the fields carry what the report
    /// actually put in them.
    #[test]
    fn the_fields_this_interface_reads_are_the_fields_the_report_writes() {
        let value = topgent_report::scan();
        let parsed: Report = match serde_json::from_value(value) {
            Ok(report) => report,
            Err(why) => panic!("the interface cannot read a report this build produced: {why}"),
        };

        assert!(
            !parsed.version.is_empty(),
            "the report arrived with no version"
        );
        assert!(
            parsed.generated_at > 0,
            "the report arrived with no timestamp"
        );

        if let Some(agent) = parsed.agents.first() {
            assert!(agent.pid > 0, "an agent arrived with no process id");
            assert!(!agent.grade.is_empty(), "an agent arrived with no grade");
            assert!(
                !agent.discovery_confidence.is_empty(),
                "an agent arrived with no confidence"
            );
        }

        // A sensor row that says nothing is the green-row-meaning-no-coverage
        // failure this product exists to prevent.
        for sensor in &parsed.sensors {
            assert!(
                !sensor.collection_coverage.is_empty(),
                "missing coverage contract"
            );
            assert!(!sensor.loss_accounting.is_empty(), "missing loss scope");
            assert!(!sensor.id.is_empty(), "a sensor arrived with no name");
            assert!(
                !sensor.state.is_empty(),
                "sensor {} arrived with no state",
                sensor.id
            );
        }

        assert!(!parsed.interception.state.is_empty());
        assert!(!parsed.interception.detail.is_empty());

        // This is the one that failed. Three of these field names were
        // invented and the panel printed empty separators for months.
        for d in &parsed.response.decisions {
            assert!(
                !d.agent_family.is_empty(),
                "a decision arrived with no agent"
            );
            assert!(
                !d.requested.is_empty(),
                "a decision arrived with no requested mode"
            );
            assert!(!d.outcome.is_empty(), "a decision arrived with no outcome");
            assert!(!d.path.is_empty(), "a decision arrived with no path");
        }

        // A rule whose index is not its position sends every control in the
        // response panel to the wrong rule.
        for (position, rule) in parsed.watchlist.iter().enumerate() {
            assert_eq!(rule.index, position, "a rule's index is not its position");
            assert!(
                !rule.response.is_empty(),
                "rule {position} arrived with no response mode"
            );
            assert!(
                !rule.path.is_empty(),
                "rule {position} arrived with no path"
            );
        }
    }

    #[test]
    fn a_real_report_from_this_machine_deserialises() {
        let value = topgent_report::scan();
        let parsed: Result<Report, _> = serde_json::from_value(value);
        if let Err(why) = parsed {
            panic!("the interface cannot read a report this build produced: {why}");
        }
    }

    /// Fields the interface does not know about must not break it, because a
    /// user can run an interface and a core from different builds.
    #[test]
    fn an_unknown_field_is_ignored_rather_than_fatal() {
        let json = serde_json::json!({
            "version": "9.9.9",
            "agents": [],
            "something_added_later": { "shape": "unforeseen" }
        });
        assert!(serde_json::from_value::<Report>(json).is_ok());
    }

    #[test]
    fn stopped_agent_invocation_edges_accept_current_and_saved_report_shapes() {
        let json = serde_json::json!({
            "agents": [{
                "pid": 8907,
                "invokes": [
                    {"target_pid": 8429, "via": "Bash(opencode run)"},
                    "legacy child agent"
                ]
            }]
        });
        let report: Report = serde_json::from_value(json).expect("report remains readable");
        let invokes = &report.agents.first().expect("agent").invokes;
        assert_eq!(invokes.len(), 2);
        assert_eq!(
            invokes.first().map(Invocation::label).as_deref(),
            Some("pid 8429 via Bash(opencode run)")
        );
        assert_eq!(
            invokes.last().map(Invocation::label).as_deref(),
            Some("legacy child agent")
        );
    }
}

/// One retained syscall observation and its event-time attribution.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ActionRow {
    /// Agent owning the actor, absent when unresolved.
    pub agent_pid: Option<u32>,
    /// Exact agent instance.
    pub agent_started_at: Option<u64>,
    /// Direct syscall actor.
    pub actor_pid: u32,
    /// Exact actor instance, when resolved.
    pub actor_started_at: Option<u64>,
    /// Executable named by Audit, rather than a later snapshot.
    #[serde(deserialize_with = "nullable")]
    pub actor_name: String,
    /// Latest known actor state.
    #[serde(deserialize_with = "nullable")]
    pub actor_state: String,
    /// Syscall category.
    pub action: String,
    /// File path or addressed endpoint.
    pub target: String,
    /// Actual syscall result.
    pub result: String,
    /// Wall-clock time of the record.
    pub at: u64,
    /// Original Audit record id.
    pub record: String,
    /// Agent child through direct actor.
    pub chain: Vec<u32>,
}

/// Audit visibility and bounded-history limits.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ActionCoverage {
    /// Measured handover drops in this sweep, excluding upstream losses.
    pub queue_losses: u64,
    /// Records removed by the retention bound.
    pub evicted: u64,
    /// What the sensor cannot establish.
    pub detail: String,
}

/// A model's name without its route: `openrouter/z-ai/glm-4.7-flash` is
/// `glm-4.7-flash`. The full name stays in the agent's details.
#[must_use]
pub fn short_model(model: &str) -> &str {
    model.rsplit('/').next().unwrap_or(model).trim()
}
