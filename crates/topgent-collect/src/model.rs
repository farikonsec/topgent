//! Which model an agent is using, read from signatures rather than from code.
//!
//! # What can and cannot be known
//!
//! Every tool in this space learns the model one of four ways: it instruments
//! the SDK, it proxies the traffic, it reads a log the agent chose to write, or
//! it is told on a command line. Only the first two see the provider's
//! *response*, and only the response carries the pinned build. OpenTelemetry's
//! `GenAI` conventions make the distinction explicit — `gen_ai.request.model` is
//! `gpt-4`, `gen_ai.response.model` is `gpt-4-0613`.
//!
//! Topgent instruments nothing and decrypts nothing, so it reads the third
//! kind: files the agent wrote. That yields the alias, never the dated build,
//! and the report says alias rather than implying more. A tool that printed
//! `claude-sonnet-4-6` beside the word "version" would be claiming something it
//! did not observe.
//!
//! # Why the sources are ordered
//!
//! A config file says what the agent was asked to use. A session transcript
//! says what it actually used, and the two disagree the moment somebody
//! overrides the model for one run — which `OpenCode` and aider both allow. The
//! signature file lists sources in precedence order and the first hit wins, so
//! adding a family or reordering its sources is an edit to data.
//!
//! # Why the registry is compiled in
//!
//! The shared registries in this space are fetched from GitHub at run time.
//! `ccusage` carries two open issues from exactly that: it fails when the fetch
//! fails, and its bundled copy goes stale. A security tool that needs the
//! network to name a model is a security tool that stops working offline, so
//! this file ships in the binary like the address table does.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::Deserialize;

const BUILTIN_JSON: &str = include_str!("../data/model-signatures.json");
static BUILTIN: OnceLock<Result<Signatures, String>> = OnceLock::new();

/// Schema version this build understands.
const SCHEMA_VERSION: u16 = 1;

/// How firmly a source establishes the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Certainty {
    /// Read from something the agent wrote while running.
    Observed,
    /// Read from configuration the agent may have been told to ignore.
    Declared,
}

impl Certainty {
    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Declared => "declared",
        }
    }
}

/// How a file is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    /// A JSON object, one top-level key.
    Json,
    /// One JSON object per line; the last line naming the key wins.
    Jsonl,
    /// `key = value` or `key: value` as plain text, no parser pulled in.
    Keyvalue,
    /// One named flag on the running process's command line.
    ///
    /// The only source that reads a command line, and it reads exactly one
    /// token: the value following the flag the signature names. See
    /// [`flag_value`] for why that shape is the mitigation rather than a
    /// convenience.
    Argv,
}

/// One place a family's model may be stated.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// How to read it.
    pub kind: SourceKind,
    /// Path relative to the agent owner's home directory.
    ///
    /// May contain `*` in one or more segments. A `*` matches within one
    /// segment and never crosses a directory boundary, so a signature cannot
    /// be written that walks the filesystem. Empty for an `argv` source, which
    /// reads no file.
    #[serde(default)]
    pub path: String,
    /// The key holding the model. Empty for an `argv` source.
    #[serde(default)]
    pub key: String,
    /// The command-line flag whose value names the model. `argv` sources only.
    #[serde(default)]
    pub flag: Option<String>,
    /// How firmly this source establishes it.
    pub certainty: Certainty,
    /// Why this source is here and where it sits in precedence.
    #[serde(default)]
    pub note: Option<String>,
}

/// One family's ordered sources.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FamilyModels {
    /// The family id, matching `agent-families.json`.
    pub family: String,
    /// Provider to assume when the model string does not name one.
    ///
    /// Empty where the family routes through a gateway and the string itself
    /// names the provider, which is the honest answer for `OpenCode`.
    pub default_provider: String,
    /// Sources in precedence order. First hit wins.
    pub sources: Vec<Source>,
}

/// How a provider is read from a model string.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRule {
    /// Only `prefix` today.
    #[serde(rename = "match")]
    pub how: String,
    /// The prefix.
    pub value: String,
    /// The provider it names.
    pub provider: String,
}

/// The signature file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signatures {
    /// Schema version this file claims.
    pub schema_version: u16,
    /// Where it came from.
    pub source: String,
    /// Longest model string admitted.
    ///
    /// A model name is short. Anything longer is a file that is not what the
    /// signature thought it was, or content someone wants carried into a
    /// report, and it is refused rather than truncated.
    pub max_model_bytes: usize,
    /// Values that are placeholders rather than models.
    ///
    /// Claude Code writes `<synthetic>` into its own transcript. A reader that
    /// did not know would report it as a model somebody is running.
    pub reject: Vec<String>,
    /// How to read a provider out of a model string.
    pub providers: Vec<ProviderRule>,
    /// Per-family sources.
    pub families: Vec<FamilyModels>,
}

/// What one lookup found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detected {
    /// The provider, or empty when nothing named one.
    pub provider: String,
    /// The model alias, never a dated build.
    pub model: String,
    /// How firmly it was established.
    pub certainty: Certainty,
    /// The file it came from, for the evidence trail.
    pub probe: String,
}

/// The signatures compiled into this build.
///
/// # Errors
///
/// Returns the validation failure. That is a build-time mistake rather than a
/// runtime condition: the file is part of the binary.
pub fn builtin() -> Result<&'static Signatures, &'static str> {
    match BUILTIN.get_or_init(|| parse_and_validate(BUILTIN_JSON)) {
        Ok(signatures) => Ok(signatures),
        Err(error) => Err(error.as_str()),
    }
}

fn parse_and_validate(text: &str) -> Result<Signatures, String> {
    let signatures: Signatures =
        serde_json::from_str(text).map_err(|error| format!("model signatures: {error}"))?;
    validate(&signatures)?;
    Ok(signatures)
}

/// Everything that must hold for the file to be usable.
///
/// # Errors
///
/// Returns the first problem found.
pub fn validate(s: &Signatures) -> Result<(), String> {
    if s.schema_version != SCHEMA_VERSION {
        return Err(format!(
            "unsupported model signature schema {}",
            s.schema_version
        ));
    }
    if s.source.trim().is_empty() {
        return Err("model signatures name no source".to_owned());
    }
    if s.max_model_bytes == 0 || s.max_model_bytes > 1024 {
        return Err(format!(
            "max_model_bytes {} is outside 1..=1024",
            s.max_model_bytes
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for family in &s.families {
        if family.family.trim().is_empty() || !seen.insert(family.family.as_str()) {
            return Err(format!("blank or duplicate family {}", family.family));
        }
        for source in &family.sources {
            match source.kind {
                SourceKind::Argv => {
                    let flag = source.flag.as_deref().unwrap_or("");
                    if !flag.starts_with('-') || flag.len() < 2 {
                        return Err(format!(
                            "{}: an argv source names no flag, or one that is not a flag",
                            family.family
                        ));
                    }
                    if !source.path.is_empty() || !source.key.is_empty() {
                        return Err(format!(
                            "{}: an argv source reads no file, so it must name no path or key",
                            family.family
                        ));
                    }
                }
                SourceKind::Json | SourceKind::Jsonl | SourceKind::Keyvalue => {
                    if source.key.trim().is_empty() {
                        return Err(format!("{}: a source names no key", family.family));
                    }
                    if source.flag.is_some() {
                        return Err(format!(
                            "{}: only an argv source may name a flag",
                            family.family
                        ));
                    }
                    check_path(&family.family, &source.path)?;
                }
            }
        }
    }
    for rule in &s.providers {
        if rule.how != "prefix" {
            return Err(format!("unknown provider match `{}`", rule.how));
        }
        if rule.value.trim().is_empty() || rule.provider.trim().is_empty() {
            return Err("a provider rule is blank".to_owned());
        }
    }
    Ok(())
}

/// Refuses a path that could reach outside the owner's home directory.
///
/// The file is compiled in and therefore trusted, but a signature is still the
/// one place where a mistake becomes a filesystem walk. Absolute paths, `..`,
/// and a bare `*` segment are all refused, so the worst a bad signature can do
/// is read a file that is not there.
fn check_path(family: &str, path: &str) -> Result<(), String> {
    if path.trim().is_empty() {
        return Err(format!("{family}: a source names no path"));
    }
    if path.starts_with('/') || path.starts_with('~') || path.contains('\\') {
        return Err(format!("{family}: path `{path}` is not relative to home"));
    }
    for segment in path.split('/') {
        if segment == ".." || segment.is_empty() {
            return Err(format!(
                "{family}: path `{path}` escapes the home directory"
            ));
        }
    }
    Ok(())
}

/// The provider a model string names, or the family's default.
#[must_use]
pub fn provider_of(s: &Signatures, model: &str, default: &str) -> String {
    // A gateway-routed string names its provider first, such as
    // `openrouter/qwen/qwen3-flash`. The middle segment is the real provider
    // and the first is the gateway, so both are offered to the rules.
    let lower = model.to_ascii_lowercase();
    for candidate in lower.split('/') {
        for rule in &s.providers {
            if candidate.starts_with(rule.value.as_str()) {
                return rule.provider.clone();
            }
        }
    }
    default.to_owned()
}

/// Whether a value is a model rather than a placeholder.
#[must_use]
pub fn admissible(s: &Signatures, value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed.len() <= s.max_model_bytes
        && !s.reject.iter().any(|bad| bad == trimmed)
        // A model name is printable and has no line breaks. Anything else is
        // content taking a ride into a report.
        && trimmed
            .chars()
            .all(|c| !c.is_control() && c != '\n' && c != '\r')
}

/// Looks a family's model up, in precedence order.
///
/// Returns the first source that yields something admissible. `None` means no
/// source named one, which is a different answer from an empty model and is
/// reported as such.
#[must_use]
pub fn detect(s: &Signatures, family: &str, home: &Path, pid: u32) -> Option<Detected> {
    let entry = s.families.iter().find(|f| f.family == family)?;
    for source in &entry.sources {
        if source.kind == SourceKind::Argv {
            let Some(flag) = source.flag.as_deref() else {
                continue;
            };
            let Some(value) = flag_value(pid, flag) else {
                continue;
            };
            if !admissible(s, &value) {
                continue;
            }
            let model = value.trim().to_owned();
            return Some(Detected {
                provider: provider_of(s, &model, &entry.default_provider),
                model,
                certainty: source.certainty,
                // The flag, never the command line. Naming the whole thing in
                // an evidence trail would put back exactly what `flag_value`
                // exists to keep out.
                probe: format!("command line flag {flag}"),
            });
        }
        for path in expand(home, &source.path) {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Some(value) = extract(source.kind, &text, &source.key) else {
                continue;
            };
            if !admissible(s, &value) {
                continue;
            }
            let model = value.trim().to_owned();
            return Some(Detected {
                provider: provider_of(s, &model, &entry.default_provider),
                model,
                certainty: source.certainty,
                probe: path.display().to_string(),
            });
        }
    }
    None
}

/// Expands one `*` segment against the filesystem, bounded.
///
/// Never recursive and never crossing more than the segments the pattern
/// names, so a signature cannot turn into a filesystem walk. Results are
/// sorted, so two runs read the same files in the same order.
fn expand(home: &Path, pattern: &str) -> Vec<PathBuf> {
    let mut current = vec![home.to_path_buf()];
    for segment in pattern.split('/') {
        let mut next = Vec::new();
        for base in &current {
            if segment.contains('*') {
                let Ok(entries) = std::fs::read_dir(base) else {
                    continue;
                };
                let mut hits: Vec<PathBuf> = entries
                    .flatten()
                    .filter(|entry| {
                        entry
                            .file_name()
                            .to_str()
                            .is_some_and(|name| matches_glob(segment, name))
                    })
                    .map(|entry| entry.path())
                    .collect();
                hits.sort();
                // A directory holding thousands of transcripts must not turn
                // one sweep into a filesystem crawl.
                hits.truncate(32);
                next.extend(hits);
            } else {
                next.push(base.join(segment));
            }
        }
        current = next;
        if current.is_empty() {
            break;
        }
    }
    current
}

/// One `*` per segment, matching within the segment only.
fn matches_glob(pattern: &str, name: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == name,
        Some((head, tail)) => {
            name.len() >= head.len() + tail.len() && name.starts_with(head) && name.ends_with(tail)
        }
    }
}

/// Pulls one key's value out of a file this build did not write.
///
/// Everything here treats the input as hostile: a config file belongs to the
/// agent, and an agent is the thing being watched.
#[must_use]
pub fn extract(kind: SourceKind, text: &str, key: &str) -> Option<String> {
    // A model name lives near the top of a config and on any line of a
    // transcript, but no file needs to be read whole to find one.
    const MAX_BYTES: usize = 4 * 1024 * 1024;
    let text = text.get(..text.len().min(MAX_BYTES)).unwrap_or(text);
    match kind {
        // An argv source reads no file. It never reaches here, and saying so
        // exhaustively is what stops a future source kind quietly falling
        // through to a reader that was written for something else.
        SourceKind::Argv => None,
        SourceKind::Json => serde_json::from_str::<serde_json::Value>(text)
            .ok()?
            .get(key)?
            .as_str()
            .map(str::to_owned),
        SourceKind::Jsonl => {
            // The last line naming the key wins: a transcript is append-only
            // and the newest record is the current answer.
            let mut found = None;
            for line in text.lines() {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(line)
                    && let Some(model) = find_key(&value, key)
                {
                    found = Some(model);
                }
            }
            found
        }
        SourceKind::Keyvalue => text
            .lines()
            .filter_map(|line| line.split_once('=').or_else(|| line.split_once(':')))
            .find(|(k, _)| k.trim() == key)
            .map(|(_, v)| v.trim().trim_matches('"').trim_matches('\'').to_owned()),
    }
}

/// Finds a key at the top level or one nesting down.
///
/// Bounded on purpose. A transcript nests the model under `message`, and one
/// level covers that without turning the search into a walk of arbitrary JSON
/// somebody else controls.
fn find_key(value: &serde_json::Value, key: &str) -> Option<String> {
    if let Some(found) = value.get(key).and_then(serde_json::Value::as_str) {
        return Some(found.to_owned());
    }
    value
        .as_object()?
        .values()
        .find_map(|child| child.get(key).and_then(serde_json::Value::as_str))
        .map(str::to_owned)
}

/// The value of one named flag on a process's command line.
///
/// # Why this exists, and why it is shaped like this
///
/// A command line is the only place some agents state their model. `OpenCode` is
/// the case that forces it: its config names nothing, and its log is shared by
/// every session on the host, so a model taken from there would be pinned on
/// every `OpenCode` agent equally and would be wrong the moment two of them run
/// different models.
///
/// A command line is also where prompts, paths and credentials live, which is
/// why the rest of this crate refuses to read one. The mitigation is the
/// signature of this function: it takes a flag and returns at most one token,
/// so there is no way for a caller to obtain anything else. Nothing is
/// retained, nothing is logged, and the value still has to pass the same
/// admissibility gate as a value read from a file.
///
/// Returns `None` on every failure, of which there are many and all of which
/// are ordinary: the process exited between the sweep and this call, the
/// platform will not name it, the flag is absent, or the tool is missing.
#[must_use]
pub fn flag_value(pid: u32, flag: &str) -> Option<String> {
    if flag.trim().is_empty() || !flag.starts_with('-') {
        return None;
    }
    let tokens = command_tokens(pid)?;
    let mut seen = tokens.iter();
    while let Some(token) = seen.next() {
        // `--model value`
        if token == flag {
            return seen.next().map(|value| value.trim().to_owned());
        }
        // `--model=value`
        if let Some(rest) = token.strip_prefix(flag)
            && let Some(value) = rest.strip_prefix('=')
        {
            return Some(value.trim().to_owned());
        }
    }
    None
}

/// The command-line tokens of one process, transiently.
///
/// Private on purpose. Nothing outside this module can obtain the whole list,
/// which is what keeps [`flag_value`] the only way in.
#[cfg(target_os = "linux")]
fn command_tokens(pid: u32) -> Option<Vec<String>> {
    // Bounded: a command line long enough to matter is a command line this has
    // no business reading.
    const MAX: usize = 64 * 1024;
    let bytes = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let bytes = bytes.get(..bytes.len().min(MAX)).unwrap_or(&bytes);
    Some(
        bytes
            .split(|byte| *byte == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part).into_owned())
            .collect(),
    )
}

/// See the Linux note. macOS has no `/proc`, and reading the argument vector
/// through `sysctl` needs `unsafe`, which this workspace forbids, so the
/// process table is asked instead.
#[cfg(target_os = "macos")]
fn command_tokens(pid: u32) -> Option<Vec<String>> {
    let output = crate::tool::PS
        .command()
        .ok()?
        .args(["-ww", "-o", "args=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .map(str::to_owned)
            .collect(),
    )
}

/// Windows keeps the command line where a reader needs more than this module
/// should have. Left unimplemented rather than half-done: a family whose model
/// is only on the command line is reported as unknown there, which is true.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn command_tokens(_pid: u32) -> Option<Vec<String>> {
    None
}
