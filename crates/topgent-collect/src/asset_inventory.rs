//! Bounded inventory probes for installed skills, plugins, and local models.
//!
//! Installation evidence is intentionally not emitted as a process [`Fact`].
//! The caller may relate an asset to an agent only when separate runtime or
//! configuration evidence proves that relationship.

use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use topgent_facts::{AssetDigest, InstalledAsset, InstalledAssetKind, UnixMillis};

const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_ASSETS: usize = 256;
const MAX_TEXT: usize = 160;

/// Bounded installation inventory rooted at an injectable home directory.
#[derive(Debug, Clone, Default)]
pub struct AssetInventoryCollector {
    /// Home directory to inspect. `None` uses the real `HOME`.
    pub home: Option<PathBuf>,
}

impl AssetInventoryCollector {
    /// Discover supported installed assets without following symlinks or
    /// reading arbitrary package contents.
    #[must_use]
    pub fn collect(&self, observed_at: UnixMillis) -> Vec<InstalledAsset> {
        let Some(home) = self
            .home
            .clone()
            .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        else {
            return Vec::new();
        };
        discover(&home, observed_at)
    }
}

fn bounded_text(value: &str) -> Option<String> {
    let value = value
        .chars()
        .filter(|character| !character.is_control())
        .collect::<String>();
    let value = value.trim();
    (!value.is_empty() && value.len() <= MAX_TEXT).then(|| value.to_owned())
}

fn bounded_read(path: &Path) -> Option<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_FILE_BYTES {
        return None;
    }
    std::fs::read(path).ok()
}

fn manifest_field(text: &str, key: &str) -> Option<String> {
    text.lines().take(80).find_map(|line| {
        let (candidate, value) = line.split_once(':')?;
        (candidate.trim() == key)
            .then(|| value.trim().trim_matches(['\'', '"']))
            .and_then(bounded_text)
    })
}

fn skills(
    home: &Path,
    output: &mut BTreeMap<(InstalledAssetKind, String), InstalledAsset>,
    at: UnixMillis,
) {
    for (root, source) in [
        (home.join(".claude/skills"), "claude-skill-manifest"),
        (home.join(".codex/skills"), "codex-skill-manifest"),
    ] {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten().take(MAX_ASSETS) {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if !kind.is_dir() || kind.is_symlink() {
                continue;
            }
            let path = entry.path().join("SKILL.md");
            let Some(bytes) = bounded_read(&path) else {
                continue;
            };
            let Ok(text) = std::str::from_utf8(&bytes) else {
                continue;
            };
            let Some(directory) = entry.file_name().to_str().and_then(bounded_text) else {
                continue;
            };
            let name = manifest_field(text, "name").unwrap_or_else(|| directory.clone());
            let identity = format!("{source}:{directory}").to_ascii_lowercase();
            output.insert(
                (InstalledAssetKind::Skill, identity.clone()),
                InstalledAsset {
                    kind: InstalledAssetKind::Skill,
                    identity,
                    name,
                    version: manifest_field(text, "version"),
                    digest: None,
                    source: source.to_owned(),
                    observed_at: at,
                },
            );
        }
    }
}

fn plugins(
    home: &Path,
    output: &mut BTreeMap<(InstalledAssetKind, String), InstalledAsset>,
    at: UnixMillis,
) {
    let path = home.join(".claude/plugins/installed_plugins.json");
    let Some(bytes) = bounded_read(&path) else {
        return;
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return;
    };
    let Some(entries) = value.get("plugins").and_then(Value::as_object) else {
        return;
    };
    for (id, installations) in entries.iter().take(MAX_ASSETS) {
        let Some(identity) = bounded_text(id).map(|value| value.to_ascii_lowercase()) else {
            continue;
        };
        let Some(record) = installations.as_array().and_then(|values| values.first()) else {
            continue;
        };
        let version = record
            .get("version")
            .and_then(Value::as_str)
            .and_then(bounded_text);
        let digest = record
            .get("gitCommitSha")
            .and_then(Value::as_str)
            .and_then(bounded_text)
            .filter(|value| value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .map(|value| AssetDigest {
                algorithm: "git".to_owned(),
                value: value.to_ascii_lowercase(),
            });
        output.insert(
            (InstalledAssetKind::Plugin, identity.clone()),
            InstalledAsset {
                kind: InstalledAssetKind::Plugin,
                name: identity.clone(),
                identity,
                version,
                digest,
                source: "claude-plugin-registry".to_owned(),
                observed_at: at,
            },
        );
    }
}

fn model_manifests(root: &Path) -> Vec<PathBuf> {
    let mut directories = vec![(root.to_path_buf(), 0_u8)];
    let mut files = Vec::new();
    while let Some((directory, depth)) = directories.pop() {
        if depth > 6 || files.len() >= MAX_ASSETS {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten().take(MAX_ASSETS - files.len()) {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_symlink() {
                continue;
            }
            if kind.is_dir() {
                directories.push((entry.path(), depth + 1));
            } else if kind.is_file() {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    files.truncate(MAX_ASSETS);
    files
}

fn local_models(
    home: &Path,
    output: &mut BTreeMap<(InstalledAssetKind, String), InstalledAsset>,
    at: UnixMillis,
) {
    let root = home.join(".ollama/models/manifests");
    for path in model_manifests(&root) {
        let Some(bytes) = bounded_read(&path) else {
            continue;
        };
        let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        let Ok(relative) = path.strip_prefix(&root) else {
            continue;
        };
        let identity_tail = relative
            .iter()
            .filter_map(|part| part.to_str())
            .collect::<Vec<_>>()
            .join("/");
        let Some(identity_tail) = bounded_text(&identity_tail) else {
            continue;
        };
        let digest_value = value
            .get("config")
            .and_then(|config| config.get("digest"))
            .and_then(Value::as_str)
            .and_then(|digest| digest.strip_prefix("sha256:"))
            .filter(|digest| {
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            .map(str::to_ascii_lowercase);
        let identity = format!("ollama:{identity_tail}").to_ascii_lowercase();
        output.insert(
            (InstalledAssetKind::LocalModel, identity.clone()),
            InstalledAsset {
                kind: InstalledAssetKind::LocalModel,
                name: identity_tail,
                identity: identity.clone(),
                version: relative
                    .file_name()
                    .and_then(|value| value.to_str())
                    .and_then(bounded_text),
                digest: digest_value.map(|value| AssetDigest {
                    algorithm: "sha256".to_owned(),
                    value,
                }),
                source: "ollama-manifest".to_owned(),
                observed_at: at,
            },
        );
    }
}

fn discover(home: &Path, observed_at: UnixMillis) -> Vec<InstalledAsset> {
    let mut output = BTreeMap::new();
    skills(home, &mut output, observed_at);
    plugins(home, &mut output, observed_at);
    local_models(home, &mut output, observed_at);
    output.into_values().take(MAX_ASSETS).collect()
}

#[cfg(test)]
mod tests {
    use super::AssetInventoryCollector;
    use topgent_facts::{InstalledAssetKind, UnixMillis};

    fn root() -> std::path::PathBuf {
        // nosemgrep: rust.lang.security.temp-dir.temp-dir - test fixture, per-process name, not a trust boundary
        std::env::temp_dir().join(format!("topgent-assets-{}", std::process::id()))
    }

    #[test]
    fn discovers_only_bounded_allowlisted_manifests_without_following_symlinks()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = root();
        let skill = root.join(".claude/skills/review");
        let model = root.join(".ollama/models/manifests/registry.ollama.ai/library/qwen3");
        std::fs::create_dir_all(&skill)?;
        std::fs::create_dir_all(&model)?;
        std::fs::create_dir_all(root.join(".claude/plugins"))?;
        std::fs::write(
            skill.join("SKILL.md"),
            "---\nname: Security Review\nversion: 2.1\n---\nsecret: ignored",
        )?;
        std::fs::write(
            root.join(".claude/plugins/installed_plugins.json"),
            r#"{"plugins":{"example@vendor":[{"version":"1.4","gitCommitSha":"ABCDEF12","installPath":"/secret/path"}]}}"#,
        )?;
        std::fs::write(
            model.join("latest"),
            format!(r#"{{"config":{{"digest":"sha256:{}"}}}}"#, "a".repeat(64)),
        )?;
        std::fs::write(root.join("not-allowlisted.json"), r#"{"token":"secret"}"#)?;

        let assets = AssetInventoryCollector {
            home: Some(root.clone()),
        }
        .collect(UnixMillis(42));
        assert_eq!(assets.len(), 3);
        assert!(
            assets
                .iter()
                .any(|asset| asset.kind == InstalledAssetKind::Skill
                    && asset.name == "Security Review"
                    && asset.version.as_deref() == Some("2.1"))
        );
        assert!(assets.iter().any(|asset| {
            asset.kind == InstalledAssetKind::Plugin
                && asset
                    .digest
                    .as_ref()
                    .is_some_and(|digest| digest.value == "abcdef12")
        }));
        assert!(assets.iter().any(|asset| {
            asset.kind == InstalledAssetKind::LocalModel
                && asset
                    .digest
                    .as_ref()
                    .is_some_and(|digest| digest.algorithm == "sha256")
        }));
        assert!(assets.iter().all(|asset| !asset.identity.contains("secret") && !asset.source.contains("secret")));
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
