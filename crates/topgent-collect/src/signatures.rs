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
    /// Whether a name match without any marker is still accepted.
    ///
    /// Some products cannot always be placed by path: a native Claude Code
    /// install resolves to a file named after its version, and a portable
    /// runtime can live anywhere. Those families opt in here, so dropping them
    /// is never silent, and every such match is published as
    /// [`IdentityStrength::NameOnly`] rather than as a confirmation.
    #[serde(default)]
    pub name_only: bool,
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

/// What a recognition rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityStrength {
    /// The executable sits under an install location this build knows for
    /// the family. That is substring corroboration of a path, not a check of
    /// the binary: a location the account can write to can be imitated.
    KnownInstallPath,
    /// Only the name matched. A portable install and a program named to look
    /// like one read the same here.
    NameOnly,
}

/// The identity state shown to an operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityClass {
    /// Executable name and a catalogue install marker both match.
    Known,
    /// Only a family that explicitly permits name-only recognition matches.
    Suspected,
    /// No executable signature matches with the evidence available.
    Unknown,
}

impl IdentityClass {
    /// Stable report and evaluation label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Known => "known",
            Self::Suspected => "suspected",
            Self::Unknown => "unknown",
        }
    }
}

impl IdentityStrength {
    /// Stable report label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KnownInstallPath => "known_install_path",
            Self::NameOnly => "name_only",
        }
    }
}

/// How strongly an executable path places a process in a family it was
/// recognised as. `None` when the family is not in the catalogue.
#[must_use]
pub fn identity_strength(family_id: &str, executable: &str) -> Option<IdentityStrength> {
    let family = builtin()
        .ok()?
        .families
        .iter()
        .find(|family| family.id == family_id)?;
    let lower = executable.to_ascii_lowercase().replace('\\', "/");
    Some(
        if family
            .path_markers
            .iter()
            .any(|marker| lower.contains(marker.as_str()))
        {
            IdentityStrength::KnownInstallPath
        } else {
            IdentityStrength::NameOnly
        },
    )
}

/// The role of a family, by id. `None` when the family is not in the catalogue.
#[must_use]
pub fn kind_of(family_id: &str) -> Option<ProductKind> {
    builtin()
        .ok()?
        .families
        .iter()
        .find(|family| family.id == family_id)
        .map(|family| family.kind)
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

/// Classify an executable and return the matching family when one exists.
///
/// A mutable name alone never becomes [`IdentityClass::Known`]. Families that
/// do not explicitly allow name-only matching fail closed as unknown.
#[must_use]
pub fn classify(executable: &str) -> (IdentityClass, Option<&'static FamilySignature>) {
    let Some(family) = recognise(executable) else {
        return (IdentityClass::Unknown, None);
    };
    let class = match identity_strength(&family.id, executable) {
        Some(IdentityStrength::KnownInstallPath) => IdentityClass::Known,
        Some(IdentityStrength::NameOnly) | None => IdentityClass::Suspected,
    };
    (class, Some(family))
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

/// The family a *declared command* names, matched on the command alone.
///
/// Process recognition also requires the install path, because a file can be
/// renamed. A declaration has no path to check: `Bash(gemini *)` in an agent's
/// own configuration is a statement about a command it may run, and the only
/// thing to match is the command. Facts built from this carry `Likely`, not
/// `Certain`, because a declaration is not an observation.
#[must_use]
pub fn recognise_declared_command(command: &str) -> Option<&'static FamilySignature> {
    let lower = command.to_ascii_lowercase().replace('\\', "/");
    let basename = lower.rsplit('/').next().unwrap_or(&lower);
    let named = |family: &FamilySignature| {
        family
            .executables
            .iter()
            .any(|signature| signature.matches(basename))
    };
    let families = &builtin().ok()?.families;
    let mut candidates = families.iter().filter(|family| named(family));
    let first = candidates.next()?;
    // Two families share this name, the first gated by its install path: a
    // command without that path is the second's. `claude --print` is Claude
    // Code, not the desktop app whose bundle binary is also named Claude.
    let placed = first
        .path_markers
        .iter()
        .any(|marker| lower.contains(marker.as_str()));
    match candidates.next() {
        Some(second) if !placed => Some(second),
        _ => Some(first),
    }
}

fn recognise_in<'a>(catalogue: &'a Catalogue, executable: &str) -> Option<&'a FamilySignature> {
    let lower = executable.to_ascii_lowercase().replace('\\', "/");
    let basename = lower.rsplit('/').next().unwrap_or(&lower);
    catalogue.families.iter().find(|family| {
        let executable_matches = family
            .executables
            .iter()
            .any(|signature| signature.matches(basename));
        let path_matches = family.name_only
            || family
                .path_markers
                .iter()
                .any(|marker| lower.contains(marker));
        executable_matches && path_matches
    })
}

/// A family with executables says where it installs, or opts in to name-only
/// recognition. Silence would make a same-name decoy a confirmation.
fn validate_install_paths(family: &FamilySignature) -> Result<(), String> {
    if !family.executables.is_empty() && family.path_markers.is_empty() && !family.name_only {
        return Err(format!(
            "family {} names executables but no install path, and does not opt in to \
             name-only recognition",
            family.id
        ));
    }
    Ok(())
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
    // (family, pattern, gated): a gated family claims a name only under one of
    // its install paths, so a later family may share that name.
    let mut patterns: Vec<(&str, &ExecutableMatch, bool)> = Vec::new();
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
        validate_install_paths(family)?;
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
            for (other_id, other, other_gated) in &patterns {
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
                if overlaps && !other_gated {
                    return Err(format!(
                        "ambiguous executable patterns for {} and {other_id}",
                        family.id
                    ));
                }
            }
            patterns.push((
                family.id.as_str(),
                signature,
                !family.name_only && !family.path_markers.is_empty(),
            ));
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

    use super::{
        IdentityClass, IdentityStrength, ProductKind, builtin, classify, identity_strength,
        parse_and_validate, recognise_in, validate,
    };

    #[test]
    fn every_shipped_family_has_positive_and_decoy_coverage() {
        let catalogue = builtin().expect("built-in catalogue must validate");
        assert_eq!(catalogue.families.len(), 27);
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
            if !family.path_markers.is_empty() && !family.name_only {
                assert_ne!(
                    recognise_in(catalogue, &format!("/tmp/decoy/{basename}"))
                        .map(|found| found.id.as_str()),
                    Some(family.id.as_str()),
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

    /// The four families that can be recognised by name alone are the ones a
    /// decoy can imitate. Each is still recognised, so a portable install is
    /// not dropped, and each is published as a name match, so neither is it
    /// confirmed.
    /// The Claude desktop app's binary is named `Claude`, the same basename as
    /// Claude Code. The desktop family is gated by its bundle path and listed
    /// first, so it claims only its own bundle, and Claude Code keeps every
    /// other `claude`.
    #[test]
    fn the_claude_desktop_app_is_not_claude_code() {
        let catalogue = builtin().expect("built-in catalogue must validate");
        let found = |exe: &str| recognise_in(catalogue, exe).map(|family| family.id.as_str());
        assert_eq!(
            found("/Applications/Claude.app/Contents/MacOS/Claude"),
            Some("claude-desktop")
        );
        assert_eq!(
            found("C:/Users/a/AppData/Local/AnthropicClaude/app-1.0.0/claude.exe"),
            Some("claude-desktop")
        );
        assert_eq!(
            found("/Users/a/.local/share/claude/versions/2.1.0/claude"),
            Some("claude-code")
        );
        assert_eq!(
            found(
                "/Users/a/Library/Application Support/Claude/claude-code/2.1.330/abc/claude.app/Contents/MacOS/claude"
            ),
            Some("claude-code"),
            "the Claude Code the desktop app bundles is still Claude Code"
        );
        assert_eq!(
            found("/Users/a/Applications/Claude.app/Contents/MacOS/Claude"),
            Some("claude-desktop")
        );
        assert_eq!(found("/tmp/elsewhere/claude"), Some("claude-code"));
        assert_eq!(
            super::kind_of("claude-desktop"),
            Some(ProductKind::AgentEditor)
        );
    }

    /// Unsloth Studio on macOS: the app, and the llama.cpp server it starts
    /// for the model, each recognised as what it is.
    #[test]
    fn unsloth_studio_and_its_model_server_are_recognised() {
        let catalogue = builtin().expect("built-in catalogue must validate");
        let found = |exe: &str| recognise_in(catalogue, exe).map(|family| family.id.as_str());
        assert_eq!(
            found("/Applications/Unsloth.app/Contents/MacOS/unsloth-studio"),
            Some("unsloth")
        );
        assert_eq!(
            found("/Users/a/.unsloth/llama.cpp/build/bin/llama-server"),
            Some("llama-cpp")
        );
        assert_eq!(
            found("/opt/homebrew/Cellar/llama.cpp/1/bin/llama-cli"),
            Some("llama-cpp")
        );
        assert_eq!(found("/usr/bin/llama-servers"), None);
        assert_eq!(
            found("/Applications/ChatGPT.app/Contents/MacOS/ChatGPT"),
            Some("chatgpt-desktop")
        );
        assert_eq!(
            found(
                "/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex"
            ),
            Some("codex-cli"),
            "the Codex the ChatGPT app bundles is still Codex"
        );
    }

    #[test]
    fn a_name_only_match_is_recognised_and_labelled_as_one() {
        let catalogue = builtin().expect("built-in catalogue must validate");
        for (decoy, family) in [
            ("/tmp/claude", "claude-code"),
            ("/opt/tools/claude", "claude-code"),
            ("/tmp/x/ollama", "ollama"),
            ("/home/u/Downloads/windsurf", "windsurf"),
        ] {
            assert_eq!(
                recognise_in(catalogue, decoy).map(|f| f.id.as_str()),
                Some(family),
                "{decoy}"
            );
            assert_eq!(
                identity_strength(family, decoy),
                Some(IdentityStrength::NameOnly),
                "{decoy}"
            );
        }
    }

    #[test]
    fn a_known_install_location_is_published_as_such() {
        for (path, family) in [
            ("/home/u/.local/share/claude/versions/2.1.3", "claude-code"),
            (
                "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js",
                "claude-code",
            ),
            ("/usr/local/bin/ollama", "ollama"),
            (
                "/Applications/Ollama.app/Contents/Resources/ollama",
                "ollama",
            ),
            ("/usr/share/windsurf/windsurf", "windsurf"),
            (
                "/home/u/.npm-global/lib/node_modules/opencode-ai/bin/opencode.exe",
                "opencode",
            ),
        ] {
            assert_eq!(
                identity_strength(family, path),
                Some(IdentityStrength::KnownInstallPath),
                "{path}"
            );
        }
        assert_eq!(identity_strength("not-a-family", "/usr/bin/x"), None);
    }

    #[test]
    fn classification_never_promotes_a_name_only_match_to_known() {
        assert_eq!(classify("/tmp/claude").0, IdentityClass::Suspected);
        assert_eq!(classify("/usr/local/bin/ollama").0, IdentityClass::Known);
        assert_eq!(classify("/tmp/codex").0, IdentityClass::Unknown);
    }

    #[test]
    fn new_cli_families_require_install_evidence_to_be_known() {
        for (installed, decoy, family) in [
            (
                "/home/u/.npm-global/lib/node_modules/@charmland/crush/crush",
                "/tmp/crush",
                "crush",
            ),
            (
                "/home/u/.npm-global/lib/node_modules/@github/copilot/npm-loader.js",
                "/tmp/copilot",
                "github-copilot-cli",
            ),
            (
                "/home/u/.npm-global/lib/node_modules/droid/bin/droid",
                "/tmp/droid",
                "factory-droid",
            ),
        ] {
            let (installed_class, installed_family) = classify(installed);
            assert_eq!(installed_class, IdentityClass::Known, "{installed}");
            assert_eq!(
                installed_family.map(|entry| entry.id.as_str()),
                Some(family)
            );

            let (decoy_class, decoy_family) = classify(decoy);
            assert_eq!(decoy_class, IdentityClass::Suspected, "{decoy}");
            assert_eq!(decoy_family.map(|entry| entry.id.as_str()), Some(family));
        }
    }

    /// A family with executables must say where it installs, or say that it
    /// may be recognised without that. Silence is refused at load.
    #[test]
    fn a_family_without_install_paths_must_opt_in_to_name_only() {
        let mut catalogue = builtin().expect("loads").clone();
        let claude = catalogue
            .families
            .iter_mut()
            .find(|f| f.id == "claude-code")
            .expect("claude-code");
        claude.path_markers.clear();
        claude.name_only = false;
        assert!(validate(&catalogue).is_err());
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
    fn every_zcode_install_shape_is_recognised_and_no_impostor_is() {
        // Shapes from the 3.15.1 release: the AppImage runs from a FUSE mount
        // named after the file, the deb installs under /opt, the dmg is an
        // app bundle, and the Windows installer is per-user.
        let catalogue = builtin().expect("built-in catalogue must validate");
        let recognise = |path: &str| recognise_in(catalogue, path).map(|family| family.id.as_str());
        for installed in [
            "/tmp/.mount_ZCode-x8Kq2a/zcode",
            "/opt/ZCode/zcode",
            "/Applications/ZCode.app/Contents/MacOS/ZCode",
            "/Applications/ZCode Preview.app/Contents/MacOS/ZCode",
            "C:\\Users\\testuser\\AppData\\Local\\Programs\\ZCode\\ZCode.exe",
        ] {
            assert_eq!(recognise(installed), Some("zcode"), "{installed}");
            assert_eq!(classify(installed).0, IdentityClass::Known, "{installed}");
        }
        for impostor in [
            "/tmp/zcode",
            "/home/testuser/Downloads/zcode",
            "/usr/local/bin/zcode",
            "/tmp/.mount_Other-x8Kq2a/zcode",
            "/opt/zcode-helper",
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
