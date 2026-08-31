//! The shape the interface reads, and the sweep that produces it.
//!
//! The core emits a large JSON document. Rather than pass a `Value` around and
//! index into it at every draw, the fields the interface uses are named here.
//! A missing field becomes a default rather than a panic: the interface must
//! stay legible against a report from a different version, because a monitor
//! that will not open is worse than one that draws a row it cannot explain.

use serde::Deserialize;

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
    /// The rules, each with the index the core's setter takes.
    pub watchlist: Vec<Rule>,
    /// Every agent found.
    pub agents: Vec<Agent>,
    /// Collectors that could not run, and why.
    pub failures: Vec<Failure>,
    /// Every collector's health, whether or not it produced anything.
    pub sensors: Vec<Sensor>,
    /// Which rules this host can detect, and how well.
    pub coverage: Vec<Coverage>,
    /// The security-change journal, newest first.
    pub events: Vec<Event>,
    /// Endpoint history, keyed by exact process identity.
    pub network: Vec<Endpoint>,
    /// Every AI asset discovered.
    pub assets: Vec<Asset>,
    /// Bounded causal history.
    pub activity: Activity,
    /// What this host can do about a finding, and what it has done.
    pub response: Response,
    /// Optional agent-supplied session context.
    pub context: Context,
}

/// One agent.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Agent {
    /// Process id.
    #[serde(deserialize_with = "nullable")]
    pub pid: u32,
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
    pub invokes: Vec<String>,
    /// Model in use, where one was declared.
    pub model: Option<String>,
    /// Why identity is what it is: which facts the system gave up, and which
    /// it refused. A refused executable path means the process has not been
    /// ruled out as an agent, only that it was never examined.
    pub identity_evidence: IdentityEvidence,
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
    /// Whether the path holds a credential.
    #[serde(deserialize_with = "nullable")]
    pub latent_secret: bool,
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

impl Report {
    /// The agent carrying the highest score, for the default selection.
    #[must_use]
    pub fn worst(&self) -> Option<&Agent> {
        self.agents.iter().max_by_key(|a| a.score)
    }
}

impl Agent {
    /// What to show in the agent column when the family is unknown.
    #[must_use]
    pub fn label(&self) -> String {
        if let Some(family) = &self.family {
            return family.clone();
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
        if self.family.is_some() {
            "recognised"
        } else if self.exe.is_some() {
            "unrecognised"
        } else {
            "unreadable"
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

/// Ask the core to stop one process.
///
/// The interface does not decide anything about this. It sends a pid; the core
/// takes its own process snapshot, checks the guard, rechecks that the pid
/// still names the process that was approved, signals, and records a fact
/// either way. The window between the reader pressing the button and the
/// signal arriving is where a reused pid would be stopped in place of the
/// process someone meant, and closing it is the core's job, not this one's.
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

/// What the operating system did and did not say about a process.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct IdentityEvidence {
    /// `confirmed`, `unexamined`, or `unrecognised`. Three different claims.
    #[serde(deserialize_with = "nullable")]
    pub state: String,
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

    use super::Report;

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
            assert!(!sensor.id.is_empty(), "a sensor arrived with no name");
            assert!(
                !sensor.state.is_empty(),
                "sensor {} arrived with no state",
                sensor.id
            );
        }

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
}
