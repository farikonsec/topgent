//! Data-driven identities for agent-family process recognition.
//!
//! Rust owns the schema, validation, and matching safety. Individual product
//! identities live in `data/agent-families.json`, so adding a family does not
//! expand collector control flow.

use serde::Deserialize;
use std::collections::BTreeSet;
use std::sync::OnceLock;

const SCHEMA_VERSION: u16 = 1;
const BUILTIN_JSON: &str = include_str!("../data/agent-families.json");
static BUILTIN: OnceLock<Result<Catalogue, String>> = OnceLock::new();

/// The role a recognised family plays on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductKind {
    /// An interactive or autonomous agent.
    Agent,
    /// An editor whose agent runs inside the application process tree.
    AgentEditor,
    /// A local model-serving runtime, not itself an autonomous agent.
    ModelRuntime,
}

impl ProductKind {
    /// Stable machine-readable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::AgentEditor => "agent_editor",
            Self::ModelRuntime => "model_runtime",
        }
    }
}

/// How an executable basename is compared.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "match", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutableMatch {
    /// The lowercased basename must exactly equal `value`.
    Exact {
        /// Lowercase executable basename.
        value: String,
    },
    /// The lowercased basename must begin with a product-specific prefix.
    Prefix {
        /// Lowercase executable prefix.
        value: String,
    },
}

impl ExecutableMatch {
    fn matches(&self, basename: &str) -> bool {
        match self {
            Self::Exact { value } => basename == value,
            Self::Prefix { value } => basename.starts_with(value),
        }
    }

    fn value(&self) -> &str {
        match self {
            Self::Exact { value } | Self::Prefix { value } => value,
        }
    }
}

/// One catalogue entry. Runtime support is established separately by the lab.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FamilySignature {
    /// Stable family identifier used in facts and policy.
    pub id: String,
    /// User-facing product name.
    pub name: String,
    /// Product role, preventing a model runtime being described as an agent.
    pub kind: ProductKind,
    /// Narrow executable matches accepted as primary runtime evidence.
    pub executables: Vec<ExecutableMatch>,
    /// Package-path fragments required as corroborating evidence.
    #[serde(default)]
    pub path_markers: Vec<String>,
    /// Exact container image repositories accepted as runtime provenance.
    #[serde(default)]
    pub container_images: Vec<String>,
    /// Exact editor extension IDs accepted as activation evidence.
    #[serde(default)]
    pub extension_ids: Vec<String>,
    /// Platforms on which this definition has been live verified.
    #[serde(default)]
    pub verified_platforms: Vec<String>,
    /// Most recent live validation date, absent for catalogue-only entries.
    pub last_verified_at: Option<String>,
}

/// A versioned collection of family identities.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalogue {
    /// Signature schema version.
    pub schema_version: u16,
    /// Human-readable provenance for the catalogue.
    pub source: String,
    /// Family definitions.
    pub families: Vec<FamilySignature>,
}

/// The validated built-in catalogue.
///
/// # Errors
///
/// Returns a stable validation message when the embedded definitions are bad.
pub fn builtin() -> Result<&'static Catalogue, &'static str> {
    match BUILTIN.get_or_init(|| parse_and_validate(BUILTIN_JSON)) {
        Ok(catalogue) => Ok(catalogue),
        Err(error) => Err(error.as_str()),
    }
}

/// Recognise a family from an executable path or basename.
#[must_use]
pub fn recognise(executable: &str) -> Option<&'static FamilySignature> {
    recognise_in(builtin().ok()?, executable)
}

/// Recognise a family from an exact container image repository.
///
/// Tags and digests are version metadata and are stripped before comparison;
/// repository substrings and container names never match.
#[must_use]
pub fn recognise_container_image(image: &str) -> Option<&'static FamilySignature> {
    let lower = image.to_ascii_lowercase();
    let without_digest = lower.split('@').next().unwrap_or(&lower);
    let last_slash = without_digest.rfind('/');
    let repository = match without_digest.rfind(':') {
        Some(colon) if last_slash.is_none_or(|slash| colon > slash) => &without_digest[..colon],
        _ => without_digest,
    };
    builtin().ok()?.families.iter().find(|family| {
        family
            .container_images
            .iter()
            .any(|candidate| candidate == repository)
    })
}

/// Recognise a family from an exact editor extension ID.
#[must_use]
pub fn recognise_extension(extension_id: &str) -> Option<&'static FamilySignature> {
    let extension_id = extension_id.to_ascii_lowercase();
    builtin().ok()?.families.iter().find(|family| {
        family
            .extension_ids
            .iter()
            .any(|candidate| candidate == &extension_id)
    })
}

fn recognise_in<'a>(catalogue: &'a Catalogue, executable: &str) -> Option<&'a FamilySignature> {
    let lower = executable.to_ascii_lowercase().replace('\\', "/");
    let basename = lower.rsplit('/').next().unwrap_or(&lower);
    catalogue.families.iter().find(|family| {
        let executable_matches = family
            .executables
            .iter()
            .any(|signature| signature.matches(basename));
        let path_matches = family.path_markers.is_empty()
            || family
                .path_markers
                .iter()
                .any(|marker| lower.contains(marker));
        executable_matches && path_matches
    })
}

/// Parse and validate a candidate catalogue.
///
/// # Errors
///
/// Rejects malformed JSON and every unsafe or incomplete definition.
pub fn parse_and_validate(input: &str) -> Result<Catalogue, String> {
    let catalogue: Catalogue =
        serde_json::from_str(input).map_err(|error| format!("invalid signature JSON: {error}"))?;
    validate(&catalogue)?;
    Ok(catalogue)
}

/// Validate catalogue invariants used to prevent ambiguous attribution.
///
/// # Errors
///
/// Returns a description of the first unsafe or incomplete definition.
pub fn validate(catalogue: &Catalogue) -> Result<(), String> {
    if catalogue.schema_version != SCHEMA_VERSION {
        return Err(format!(
            "unsupported signature schema {}",
            catalogue.schema_version
        ));
    }
    if catalogue.source.trim().is_empty() {
        return Err("signature catalogue source is empty".to_owned());
    }
    let mut ids = BTreeSet::new();
    let mut container_images = BTreeSet::new();
    let mut extension_ids = BTreeSet::new();
    let mut patterns: Vec<(&str, &ExecutableMatch)> = Vec::new();
    for family in &catalogue.families {
        if family.id.is_empty()
            || !family.id.chars().all(|character| {
                character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
            })
        {
            return Err(format!("invalid family id {}", family.id));
        }
        if !ids.insert(family.id.as_str()) {
            return Err(format!("duplicate family id {}", family.id));
        }
        if family.name.trim().is_empty()
            || (family.executables.is_empty()
                && family.container_images.is_empty()
                && family.extension_ids.is_empty())
        {
            return Err(format!("family {} is incomplete", family.id));
        }
        if family.path_markers.iter().any(|marker| {
            marker.is_empty() || marker != &marker.to_ascii_lowercase() || !marker.starts_with('/')
        }) {
            return Err(format!("invalid path marker for {}", family.id));
        }
        if family.container_images.iter().any(|image| {
            image.is_empty()
                || image != &image.to_ascii_lowercase()
                || image.contains([' ', '@', ':'])
                || !image.contains('/')
        }) {
            return Err(format!("invalid container image for {}", family.id));
        }
        for image in &family.container_images {
            if !container_images.insert(image.as_str()) {
                return Err(format!("duplicate container image {image}"));
            }
        }
        validate_extension_ids(family, &mut extension_ids)?;
        for platform in &family.verified_platforms {
            if !matches!(
                platform.as_str(),
                "linux-aarch64"
                    | "linux-x86_64"
                    | "macos-aarch64"
                    | "macos-x86_64"
                    | "windows-x86_64"
            ) {
                return Err(format!("invalid verified platform for {}", family.id));
            }
        }
        for signature in &family.executables {
            let value = signature.value();
            if value.is_empty()
                || value != value.to_ascii_lowercase()
                || value.contains(['/', '\\'])
            {
                return Err(format!("invalid executable pattern for {}", family.id));
            }
            for (other_id, other) in &patterns {
                let overlaps = match (signature, *other) {
                    (ExecutableMatch::Exact { value: a }, ExecutableMatch::Exact { value: b }) => {
                        a == b
                    }
                    (ExecutableMatch::Prefix { value: a }, ExecutableMatch::Exact { value: b })
                    | (ExecutableMatch::Exact { value: b }, ExecutableMatch::Prefix { value: a }) => {
                        b.starts_with(a)
                    }
                    (
                        ExecutableMatch::Prefix { value: a },
                        ExecutableMatch::Prefix { value: b },
                    ) => a.starts_with(b) || b.starts_with(a),
                };
                if overlaps {
                    return Err(format!(
                        "ambiguous executable patterns for {} and {other_id}",
                        family.id
                    ));
                }
            }
            patterns.push((family.id.as_str(), signature));
        }
    }
    Ok(())
}

fn validate_extension_ids<'a>(
    family: &'a FamilySignature,
    seen: &mut BTreeSet<&'a str>,
) -> Result<(), String> {
    for extension_id in &family.extension_ids {
        if extension_id.is_empty()
            || extension_id != &extension_id.to_ascii_lowercase()
            || extension_id.matches('.').count() != 1
            || extension_id.contains([' ', '/', '\\'])
        {
            return Err(format!("invalid extension id for {}", family.id));
        }
        if !seen.insert(extension_id.as_str()) {
            return Err(format!("duplicate extension id {extension_id}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{ProductKind, builtin, parse_and_validate, recognise_in};

    #[test]
    fn every_shipped_family_has_positive_and_decoy_coverage() {
        let catalogue = builtin().expect("built-in catalogue must validate");
        assert_eq!(catalogue.families.len(), 19);
        for family in &catalogue.families {
            let Some(first) = family.executables.first() else {
                assert!(!family.extension_ids.is_empty() || !family.container_images.is_empty());
                continue;
            };
            let basename = first.value();
            let positive = family.path_markers.first().map_or_else(
                || basename.to_owned(),
                |marker| format!("{marker}/{basename}"),
            );
            assert_eq!(
                recognise_in(catalogue, &positive).map(|found| found.id.as_str()),
                Some(family.id.as_str()),
                "positive fixture for {}",
                family.id
            );
            assert_eq!(
                recognise_in(catalogue, &format!("not-{basename}")),
                None,
                "prefix decoy for {}",
                family.id
            );
            if !family.path_markers.is_empty() {
                assert_eq!(
                    recognise_in(catalogue, &format!("/tmp/decoy/{basename}")),
                    None,
                    "same-name path decoy for {}",
                    family.id
                );
            }
        }
        assert_eq!(
            catalogue
                .families
                .iter()
                .find(|family| family.id == "ollama")
                .map(|family| family.kind),
            Some(ProductKind::ModelRuntime)
        );
    }

    #[test]
    fn every_codex_runtime_on_a_real_host_is_recognised_and_no_impostor_is() {
        // Both paths are taken verbatim from the macOS host where the PID
        // 18246 incident happened: the npm-installed CLI and the runtime
        // bundled inside the ChatGPT desktop app. Both are Codex; a `codex`
        // sitting anywhere else has not earned the name.
        let catalogue = builtin().expect("built-in catalogue must validate");
        let recognise = |path: &str| recognise_in(catalogue, path).map(|family| family.id.as_str());

        assert_eq!(
            recognise(
                "/Users/testuser/.local/lib/node_modules/@openai/codex/node_modules/@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/bin/codex"
            ),
            Some("codex-cli")
        );
        assert_eq!(
            recognise("/Applications/ChatGPT.app/Contents/Resources/codex"),
            Some("codex-cli")
        );
        assert_eq!(
            recognise("/Users/testuser/.codex/bin/codex"),
            Some("codex-cli")
        );

        for impostor in [
            "/tmp/codex",
            "/Users/testuser/Downloads/codex",
            "/usr/local/bin/codex",
            "/Applications/NotChatGPT.app/Contents/Resources/codex",
        ] {
            assert_eq!(recognise(impostor), None, "same-name decoy: {impostor}");
        }
    }

    #[test]
    fn an_apple_text_caret_helper_is_not_the_cursor_editor() {
        // Observed on every macOS host: an XPC service for the text caret
        // whose name begins with "cursor". A bare prefix match reported it as
        // the Cursor AI editor, which is a fabricated agent in the inventory.
        let catalogue = builtin().expect("built-in catalogue must validate");
        let recognise = |path: &str| recognise_in(catalogue, path).map(|family| family.id.as_str());

        assert_eq!(
            recognise(
                "/System/Library/PrivateFrameworks/TextInputUIMacHelper.framework/Versions/A/XPCServices/CursorUIViewService.xpc/Contents/MacOS/CursorUIViewService"
            ),
            None
        );
        assert_eq!(
            recognise("/Applications/Cursor.app/Contents/MacOS/Cursor"),
            Some("cursor")
        );
        assert_eq!(
            recognise("/home/testuser/Applications/cursor.AppImage"),
            Some("cursor")
        );
    }

    #[test]
    fn every_real_windows_install_shape_is_recognised_and_its_decoys_are_not() {
        // All taken verbatim from the running processes of real agents
        // installed on Windows Server 2025. An npm agent is a node process
        // running an entry script, a native binary under the package, or both.
        const NPM: &str = r"C:\Users\Administrator\AppData\Roaming\npm\node_modules";
        let catalogue = builtin().expect("built-in catalogue must validate");
        let recognise = |path: &str| recognise_in(catalogue, path).map(|family| family.id.as_str());

        for (path, family) in [
            (
                format!(r"{NPM}\@google\gemini-cli\bundle\gemini.js"),
                "gemini-cli",
            ),
            (
                format!(r"{NPM}\@qwen-code\qwen-code\cli-entry.js"),
                "qwen-code",
            ),
            (format!(r"{NPM}\@openai\codex\bin\codex.js"), "codex-cli"),
            (
                format!(
                    r"{NPM}\@openai\codex\node_modules\@openai\codex-win32-x64\vendor\x86_64-pc-windows-msvc\bin\codex.exe"
                ),
                "codex-cli",
            ),
            (
                format!(r"{NPM}\@anthropic-ai\claude-code\bin\claude.exe"),
                "claude-code",
            ),
            (
                format!(r"{NPM}\@sourcegraph\amp\node_modules\@ampcode\cli\bin\amp.exe"),
                "amp",
            ),
        ] {
            assert_eq!(recognise(&path), Some(family), "not recognised: {path}");
        }

        // The package gates every family that has one, so a same-named binary
        // dropped somewhere else is refused.
        for decoy in [
            r"C:\Temp\codex.exe",
            r"C:\Temp\codex.js",
            r"C:\Users\Administrator\Downloads\gemini.js",
            r"C:\Temp\cli-entry.js",
            r"C:\Temp\amp.exe",
        ] {
            assert_eq!(recognise(decoy), None, "same-name decoy admitted: {decoy}");
        }

        // Two more Windows shapes, from the publishers' own packages.
        assert_eq!(
            recognise(r"C:\TopgentLab\agents\ollama\ollama.exe"),
            Some("ollama")
        );
        assert_eq!(
            recognise(r"C:\TopgentLab\agents\goose\goose-package\goose.exe"),
            Some("goose")
        );
        // Goose is package-gated, so a bare copy is still refused.
        assert_eq!(recognise(r"C:\Temp\goose.exe"), None);

        // Node itself is never an agent, whatever it is running.
        for runtime in [
            r"C:\Program Files\nodejs\node.exe",
            r"C:\Windows\system32\cmd.exe",
            r"C:\Windows\py.exe",
        ] {
            assert_eq!(
                recognise(runtime),
                None,
                "a runtime was named as an agent: {runtime}"
            );
        }
    }

    #[test]
    fn windows_paths_use_the_same_bounded_marker_contract() {
        let catalogue = builtin().expect("built-in catalogue must validate");
        assert_eq!(
            recognise_in(
                catalogue,
                r"C:\TopgentLab\agents\opencode\node_modules\opencode-ai\bin\opencode.exe"
            )
            .map(|family| family.id.as_str()),
            Some("opencode")
        );
        assert_eq!(recognise_in(catalogue, r"C:\Temp\decoy\opencode.exe"), None);
    }

    #[test]
    fn malformed_unknown_and_incomplete_catalogues_fail_closed() {
        for bad in [
            "not json",
            r#"{"schema_version":2,"source":"test","families":[]}"#,
            r#"{"schema_version":1,"source":"","families":[]}"#,
            r#"{"schema_version":1,"source":"test","extra":true,"families":[]}"#,
            r#"{"schema_version":1,"source":"test","families":[{"id":"Bad ID","name":"Bad","kind":"agent","executables":[],"last_verified_at":null}]}"#,
            r#"{"schema_version":1,"source":"test","families":[{"id":"bad","name":"Bad","kind":"unknown","executables":[{"match":"exact","value":"bad"}],"last_verified_at":null}]}"#,
        ] {
            assert!(parse_and_validate(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn duplicate_and_overlapping_patterns_are_rejected() {
        let duplicate = r#"{
          "schema_version":1,"source":"test","families":[
            {"id":"one","name":"One","kind":"agent","executables":[{"match":"prefix","value":"agent"}],"last_verified_at":null},
            {"id":"two","name":"Two","kind":"agent","executables":[{"match":"exact","value":"agent-cli"}],"last_verified_at":null}
          ]} "#;
        assert!(parse_and_validate(duplicate).is_err());
    }

    #[test]
    fn unsafe_paths_platforms_and_patterns_are_rejected() {
        for bad_field in [
            r#""path_markers":["relative/path"]"#,
            r#""path_markers":["/UPPER/path"]"#,
            r#""verified_platforms":["linux-mips"]"#,
            r#""executables":[{"match":"exact","value":"../agent"}]"#,
        ] {
            let executable = if bad_field.starts_with("\"executables") {
                bad_field.to_owned()
            } else {
                format!(r#""executables":[{{"match":"exact","value":"agent"}}],{bad_field}"#)
            };
            let json = format!(
                r#"{{"schema_version":1,"source":"test","families":[{{"id":"agent","name":"Agent","kind":"agent",{executable},"last_verified_at":null}}]}}"#
            );
            assert!(parse_and_validate(&json).is_err(), "{json}");
        }
    }
}
