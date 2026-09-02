//! Detection policy, as data.
//!
//! Everything Topgent uses to decide how alarming an agent is lives here, not
//! scattered through the scoring code: the points each factor is worth, the
//! thresholds that make a connection pattern read as scanning, the paths worth
//! watching for credentials, and the user's own watchlist rules. It loads from
//! one file, `~/.config/topgent/policy.json`, and a fresh install ships the
//! defaults below.
//!
//! Keeping it here means the scoring code stays a short, readable function of a
//! `Policy`, the config file is the one place to tune detection, and a user can
//! see and change exactly what makes an agent critical without touching Rust.
//!
//! One deliberate line is NOT drawn here: the base points are tunable, but the
//! app does not invite users to retune every weight. A score is only comparable
//! across machines if the weights are shared, so the intended way to make an
//! agent more or less critical is a **watchlist rule** — a path plus a
//! condition — not rewriting the model. The file allows it for the determined;
//! the UI offers the safe, legible knob.

//! The factor table itself — points, sentences, remedies and technique
//! mapping — lives in `data/risk-factors.json` and is loaded by [`catalogue`].
//! See that module for why it is a data file and why the vocabulary is not.
//! The shipped credential locations live in `data/sensitive-paths.json` and are
//! loaded by [`locations`]; the user may still override them here.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod catalogue;
pub mod health;
pub mod locations;
pub mod signals;

pub use health::PolicyHealth;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The points each built-in factor contributes, before the identity multiplier.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Weights {
    /// Can run arbitrary commands.
    pub arbitrary_execution: u32,
    /// Can write outside anything it declared.
    pub broad_write: u32,
    /// Unbounded outbound network.
    pub unrestricted_network: u32,
    /// First reachable credential.
    pub first_secret: u32,
    /// Each further reachable credential.
    pub further_secret: u32,
    /// Touched something never granted.
    pub declaration_drift: u32,
    /// Can invoke another agent.
    pub agent_chain: u32,
    /// Shell plus a reachable credential.
    pub exfiltration_path: u32,
    /// Connection pattern looks like scanning.
    pub recon_fanout: u32,
    /// Exposed listening socket.
    pub exposed_listener: u32,
    /// Offensive utility running below the agent.
    pub offensive_tool: u32,
    /// Excessive process-tree fan-out.
    pub process_explosion: u32,
    /// Raw address on a port commonly used by shells or implants.
    pub suspicious_endpoint: u32,
    /// Connection to another private-network host.
    pub private_peer: u32,
    /// Connection to a cloud instance metadata service.
    pub metadata_service: u32,
    /// A sensitive credential was actually opened.
    pub credential_access: u32,
    /// A persistence location was modified.
    pub persistence_write: u32,
    /// Topgent's own code or policy was modified by an agent.
    pub self_tampering: u32,
    /// The agent is using an asset the user explicitly disallowed.
    pub disallowed_asset: u32,
}

impl Default for Weights {
    /// The shipped weights, read from the factor catalogue.
    ///
    /// Not restated here. When the defaults were a second copy of the numbers,
    /// nothing made the copy agree with the table the interface showed the
    /// user, and a score could be computed from one set while being explained
    /// by the other.
    ///
    /// A catalogue this build cannot read leaves every weight at zero, which
    /// scores every agent zero. That is deliberate: an obviously broken output
    /// is safer than a plausible one, and `doctor` reports the failure by name.
    fn default() -> Self {
        let points = |code: &str, subsequent: bool| {
            catalogue::builtin()
                .ok()
                .and_then(|c| c.entry(code))
                .map_or(0, |entry| {
                    if subsequent {
                        entry.subsequent_points.unwrap_or(entry.points)
                    } else {
                        entry.points
                    }
                })
        };
        Self {
            arbitrary_execution: points("ARBITRARY_EXECUTION", false),
            broad_write: points("BROAD_WRITE", false),
            unrestricted_network: points("UNRESTRICTED_NETWORK", false),
            first_secret: points("SECRET_REACHABLE", false),
            further_secret: points("SECRET_REACHABLE", true),
            declaration_drift: points("DECLARATION_DRIFT", false),
            agent_chain: points("AGENT_CHAIN", false),
            exfiltration_path: points("EXFILTRATION_PATH", false),
            recon_fanout: points("RECON_FANOUT", false),
            exposed_listener: points("EXPOSED_LISTENER", false),
            offensive_tool: points("OFFENSIVE_TOOL", false),
            process_explosion: points("PROCESS_EXPLOSION", false),
            suspicious_endpoint: points("SUSPICIOUS_ENDPOINT", false),
            private_peer: points("PRIVATE_PEER", false),
            metadata_service: points("METADATA_SERVICE", false),
            credential_access: points("CREDENTIAL_ACCESS", false),
            persistence_write: points("PERSISTENCE_WRITE", false),
            self_tampering: points("SELF_TAMPERING", false),
            disallowed_asset: points("DISALLOWED_ASSET", false),
        }
    }
}

/// Thresholds for the behavioural signals.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Thresholds {
    /// Distinct outbound destinations before the network counts as unrestricted.
    pub network_spread: usize,
    /// Distinct hosts before a pattern reads as scanning a network.
    pub recon_hosts: usize,
    /// Distinct ports to one host before it reads as scanning a host.
    pub recon_ports: usize,
    /// Descendants before process creation reads as a burst.
    pub process_children: usize,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            network_spread: 5,
            recon_hosts: 12,
            recon_ports: 8,
            process_children: 20,
        }
    }
}

pub use locations::Sensitive;

/// The credential locations a fresh install watches, read from the catalogue.
///
/// Not restated here. When the shipped list was a Rust literal it was the only
/// statement of what Topgent treats as a credential, and reviewing it meant
/// reading a constructor.
///
/// A file this build cannot read leaves the list empty, which finds no
/// credentials at all. That is the same choice the factor catalogue makes: an
/// output that is obviously broken beats a plausible one, and the file is
/// compiled in, so the failure is a build-time mistake the tests catch.
fn default_sensitive() -> Vec<Sensitive> {
    locations::builtin().map_or_else(
        |_| Vec::new(),
        |locations| locations.sensitive_paths.clone(),
    )
}

/// When a watchlist rule applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Condition {
    /// The agent could reach the path, whether or not it has.
    Reachable,
    /// The agent has actually touched the path.
    Observed,
    /// The agent can write to the path.
    Write,
}

impl Condition {
    /// Display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Reachable => "can reach",
            Self::Observed => "has touched",
            Self::Write => "can write to",
        }
    }
}

/// How much a matching rule raises risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Force the agent to Critical.
    Critical,
    /// Add this many points.
    Points(u32),
}

/// Requested response when a rule matches.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResponseMode {
    /// Record the match without raising an active notification.
    Observe,
    /// Raise an alert but do not change the agent.
    #[default]
    Alert,
    /// Pause an action at a real interception point for a user decision.
    Approval,
    /// Prevent an action at a real interception point.
    Block,
    /// Terminate the matched agent after explicit local confirmation.
    Kill,
}

impl ResponseMode {
    /// Stable report label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Alert => "alert",
            Self::Approval => "approval",
            Self::Block => "block",
            Self::Kill => "kill",
        }
    }
}

impl Severity {
    /// The points this severity contributes. `Critical` is worth the whole scale.
    #[must_use]
    pub const fn points(self) -> u32 {
        match self {
            Self::Critical => 100,
            Self::Points(p) => p,
        }
    }
}

/// One user watchlist rule: a path, a condition, and how much it matters.
///
/// This is the simple knob that replaces a rules language. "If an agent can
/// write to `~/.ssh`, mark it Critical" is one of these, chosen from menus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Substring matched against a resource path (e.g. `.ssh` or `/etc/`).
    pub path: String,
    /// When it applies.
    pub condition: Condition,
    /// How much it raises risk.
    pub severity: Severity,
    /// Response requested when this rule matches.
    #[serde(default)]
    pub response: ResponseMode,
}

/// The user's decision about whether an AI asset belongs in this environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    /// Discovered but not reviewed by the user yet.
    Unreviewed,
    /// Expected and allowed for the selected scope.
    Approved,
    /// Expected only for a narrower agent or future constraint.
    Restricted,
    /// Not permitted in this environment.
    Disallowed,
}

impl Disposition {
    /// Stable UI and report label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unreviewed => "unreviewed",
            Self::Approved => "approved",
            Self::Restricted => "restricted",
            Self::Disallowed => "disallowed",
        }
    }
}

/// One persisted decision about an asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetPolicy {
    /// Stable Topgent asset identifier.
    pub asset_id: String,
    /// Optional agent-family scope. `None` applies to every agent.
    pub agent_family: Option<String>,
    /// The decision applied in this scope.
    pub disposition: Disposition,
}

/// Privacy controls for optional, agent-supplied session context.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SemanticSettings {
    /// Accept and display sanitized semantic events. Disabled on fresh installs.
    pub enabled: bool,
}

/// The whole policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    /// Scoring weights.
    pub weights: Weights,
    /// Behavioural thresholds.
    pub thresholds: Thresholds,
    /// Paths watched for reachable credentials.
    pub sensitive: Vec<Sensitive>,
    /// User watchlist rules.
    pub watchlist: Vec<Rule>,
    /// User decisions about discovered AI assets.
    pub assets: Vec<AssetPolicy>,
    /// Optional semantic context. Host monitoring does not depend on it.
    pub semantic: SemanticSettings,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            weights: Weights::default(),
            thresholds: Thresholds::default(),
            sensitive: default_sensitive(),
            watchlist: Vec::new(),
            assets: Vec::new(),
            semantic: SemanticSettings::default(),
        }
    }
}

/// The user's home directory, however this platform names it.
fn home_directory() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("HOME") {
        return Some(PathBuf::from(home));
    }
    if cfg!(windows) {
        if let Some(profile) = std::env::var_os("USERPROFILE") {
            return Some(PathBuf::from(profile));
        }
        if let (Some(drive), Some(path)) =
            (std::env::var_os("HOMEDRIVE"), std::env::var_os("HOMEPATH"))
        {
            let mut joined = PathBuf::from(drive);
            joined.push(PathBuf::from(path));
            return Some(joined);
        }
    }
    None
}

impl Policy {
    /// Where the policy file lives.
    ///
    /// The home directory is not read from `HOME` alone. Windows does not set
    /// it outside a shell that supplies one, so a desktop launch fell back to
    /// the temp directory and read a policy nobody wrote: every rule the
    /// operator had configured silently did not exist. The same defect made
    /// credential reachability report nothing, and lost the journal between
    /// runs, in two other places.
    #[must_use]
    pub fn path() -> PathBuf {
        if let Some(explicit) = std::env::var_os("XDG_CONFIG_HOME") {
            return PathBuf::from(explicit).join("topgent").join("policy.json");
        }
        home_directory()
            .map_or_else(std::env::temp_dir, |home| home.join(".config"))
            .join("topgent")
            .join("policy.json")
    }

    /// The last-known-good copy kept beside the policy.
    ///
    /// Written by [`Policy::save_to`] after a successful replace, so a crash
    /// mid-write leaves the previous rules recoverable rather than gone.
    #[must_use]
    pub fn backup_path(path: &std::path::Path) -> PathBuf {
        let mut backup = path.as_os_str().to_owned();
        backup.push(".last-known-good");
        PathBuf::from(backup)
    }

    /// Load the policy, falling back to defaults for anything missing or absent.
    ///
    /// A malformed file never crashes Topgent, but it is no longer silent
    /// either: see [`Policy::load_checked`] for what actually happened.
    #[must_use]
    pub fn load() -> Self {
        Self::load_from(&Self::path())
    }

    /// Load from a specific file, defaulting on absence or a parse error.
    ///
    /// Kept for the many callers that only want the rules. Anything that
    /// reports, enforces, or gates on the policy uses [`Policy::load_checked`],
    /// because those callers must be able to tell defaults-by-choice from
    /// defaults-because-the-file-broke.
    #[must_use]
    pub fn load_from(path: &std::path::Path) -> Self {
        Self::load_checked(path).0
    }

    /// Load, and say which of the four states the policy is in.
    ///
    /// The order matters. A file that is absent is not a fault. A file that is
    /// present and unreadable falls back to the last-known-good copy, and only
    /// a file that is broken with no copy behind it withholds the operator's
    /// rules — which is the one case enforcement and CI must fail closed on.
    #[must_use]
    pub fn load_checked(path: &std::path::Path) -> (Self, crate::PolicyHealth) {
        use crate::PolicyHealth;

        let text = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return (Self::default(), PolicyHealth::Absent);
            }
            Err(error) => {
                return Self::recover(
                    path,
                    format!("{} could not be read: {error}", path.display()),
                );
            }
        };

        match Self::parse(&text) {
            Ok(policy) => (
                policy,
                PolicyHealth::Valid {
                    digest: crate::health::digest_of(&text),
                },
            ),
            Err(detail) => Self::recover(path, detail),
        }
    }

    /// Parse policy bytes, refusing anything a reader would have to guess at.
    ///
    /// Public because it is the only untrusted-input boundary of this crate: a
    /// person edits the file by hand, and anything running as the user can
    /// write it. The fuzz harness drives it directly.
    ///
    /// # Errors
    ///
    /// Returns what was wrong with the bytes, in the words the report uses.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let text = std::str::from_utf8(bytes)
            .map_err(|error| format!("the policy is not valid UTF-8: {error}"))?;
        // The byte-order mark PowerShell's redirection writes is not part of
        // the document, and refusing a file over it refuses the user's own
        // tooling rather than anything wrong with their policy.
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let document: serde_json::Value = serde_json::from_str(text)
            .map_err(|error| format!("the policy is not valid JSON: {error}"))?;
        // Serde will deserialise a struct out of a JSON *array*, filling fields
        // positionally. Found by the `config` fuzz target: `[[0]]` parsed
        // cleanly into a policy whose every weight was zero, which scores every
        // agent on the host at zero — a worse outcome than the defaults, and
        // silent. A policy is an object.
        if !document.is_object() {
            return Err("the policy is not a JSON object".to_owned());
        }
        serde_json::from_value(document)
            .map_err(|error| format!("the policy is not valid JSON: {error}"))
    }

    /// Fall back to the last-known-good copy, or to built-in defaults.
    fn recover(path: &std::path::Path, detail: String) -> (Self, crate::PolicyHealth) {
        use crate::PolicyHealth;

        let backup = Self::backup_path(path);
        if let Ok(bytes) = std::fs::read(&backup)
            && let Ok(policy) = Self::parse(&bytes)
        {
            return (
                policy,
                PolicyHealth::Recovered {
                    detail,
                    digest: crate::health::digest_of(&bytes),
                },
            );
        }
        (Self::default(), PolicyHealth::Malformed { detail })
    }

    /// Write the policy back to its file.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error.
    pub fn save(&self) -> std::io::Result<()> {
        self.save_to(&Self::path())
    }

    /// Write to a specific file, creating parent directories.
    ///
    /// A bare `fs::write` truncates first and writes second, so a crash, a full
    /// disk or a second writer between the two leaves a half-file that parses
    /// as nothing. This writes a fresh temporary file in the same directory,
    /// flushes it to the platter, renames it over the target, and only then
    /// refreshes the last-known-good copy — so at every instant the reader
    /// either sees the old policy or the new one, and never half of either.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error.
    pub fn save_to(&self, path: &std::path::Path) -> std::io::Result<()> {
        use std::io::Write as _;

        if let Some(dir) = path.parent()
            && !dir.as_os_str().is_empty()
        {
            std::fs::create_dir_all(dir)?;
        }
        let body = serde_json::to_string_pretty(self)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;

        // Named for this process and this attempt rather than a fixed suffix,
        // so two writers do not land on one another's temporary file.
        let scratch = Self::backup_path(path).with_extension(format!(
            "tmp-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |since| since.as_nanos())
        ));
        let outcome = (|| -> std::io::Result<()> {
            let mut file = std::fs::File::create(&scratch)?;
            restrict(&file)?;
            file.write_all(body.as_bytes())?;
            file.flush()?;
            file.sync_all()?;
            drop(file);
            // Rename over an existing file is atomic on Unix and replaces on
            // Windows through the same call in the standard library, which is
            // why replacement is asserted on every platform in the suite.
            std::fs::rename(&scratch, path)
        })();
        if outcome.is_err() {
            let _ = std::fs::remove_file(&scratch);
            return outcome;
        }

        // Best effort, and deliberately after the replace: a policy that saved
        // but whose backup could not be refreshed is still a saved policy, and
        // failing the write would be the wrong answer.
        let _ = std::fs::write(Self::backup_path(path), &body);
        Ok(())
    }

    /// Add a watchlist rule, replacing any identical path+condition.
    pub fn add_rule(&mut self, rule: Rule) {
        self.watchlist
            .retain(|r| !(r.path == rule.path && r.condition == rule.condition));
        self.watchlist.push(rule);
    }

    /// Remove a watchlist rule by index.
    ///
    /// Returns `true` only when a rule was actually removed. An out-of-range
    /// index remains safe, but callers can now report a stale UI operation
    /// instead of claiming success.
    pub fn remove_rule(&mut self, index: usize) -> bool {
        if index < self.watchlist.len() {
            self.watchlist.remove(index);
            true
        } else {
            false
        }
    }

    /// Set one asset disposition, replacing the same asset and scope.
    pub fn set_asset_disposition(&mut self, decision: AssetPolicy) {
        self.assets.retain(|existing| {
            existing.asset_id != decision.asset_id || existing.agent_family != decision.agent_family
        });
        if decision.disposition != Disposition::Unreviewed {
            self.assets.push(decision);
        }
    }

    /// Resolve an asset disposition. An agent-specific decision wins over a
    /// global decision; absence is explicitly `Unreviewed`.
    #[must_use]
    pub fn asset_disposition(&self, asset_id: &str, agent_family: Option<&str>) -> Disposition {
        self.assets
            .iter()
            .rev()
            .find(|decision| {
                decision.asset_id == asset_id
                    && decision.agent_family.as_deref() == agent_family
                    && decision.agent_family.is_some()
            })
            .or_else(|| {
                self.assets.iter().rev().find(|decision| {
                    decision.asset_id == asset_id && decision.agent_family.is_none()
                })
            })
            .map_or(Disposition::Unreviewed, |decision| decision.disposition)
    }
}

/// Keep the policy readable only by its owner, where the platform says so.
///
/// The file names the paths being watched and the rules being enforced, which
/// is a map of what a monitored agent should avoid touching. Windows inherits
/// the directory's access control list and has no mode bits, so there is
/// nothing to set there.
#[cfg(unix)]
fn restrict(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)] // Keep the same fallible interface on every platform.
fn restrict(_file: &std::fs::File) -> std::io::Result<()> {
    Ok(())
}
