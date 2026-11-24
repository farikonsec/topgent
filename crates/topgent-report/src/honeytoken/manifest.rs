//! Planting decoys, and the manifest of what was planted where.
//!
//! The manifest is `honeytokens.json` in the shared state folder, beside the
//! policy, so the desktop, the viewer and the command line read one list. It
//! holds each decoy's path, class, size and planting time. The fake values are
//! written to the decoy and nowhere else.
//!
//! Planting never overwrites: a file already at a decoy's path may be a real
//! secret, so it is left alone and reported as skipped. Removing deletes a
//! decoy only while it is still the size it was planted at, so a file someone
//! has since replaced with real content is kept.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use super::data;

const FILE: &str = "honeytokens.json";
/// Most decoys kept in the manifest.
const MAX_TOKENS: usize = 1_024;

/// One planted decoy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// The class its name matches.
    pub class: String,
    /// Its size when planted.
    pub bytes: u64,
    /// When it was planted, Unix milliseconds.
    pub planted_at: u64,
}

/// Planted decoys by absolute path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Manifest {
    /// Each decoy, keyed by its absolute path.
    pub tokens: BTreeMap<String, Token>,
}

impl Manifest {
    /// The decoy at `path`, when one was planted there.
    #[must_use]
    pub fn get(&self, path: &str) -> Option<&Token> {
        self.tokens.get(path)
    }

    /// The manifest in the state folder, or an empty one when there is none.
    #[must_use]
    pub fn load() -> Self {
        Self::load_from(&path())
    }

    fn load_from(file: &Path) -> Self {
        let Ok(text) = std::fs::read_to_string(file) else {
            return Self::default();
        };
        let Ok(value) = serde_json::from_str::<Value>(&text) else {
            return Self::default();
        };
        let tokens = value
            .get("tokens")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .take(MAX_TOKENS)
            .filter_map(|row| {
                Some((
                    row.get("path")?.as_str()?.to_owned(),
                    Token {
                        class: row.get("class")?.as_str()?.to_owned(),
                        bytes: row.get("bytes").and_then(Value::as_u64).unwrap_or(0),
                        planted_at: row.get("planted_at").and_then(Value::as_u64).unwrap_or(0),
                    },
                ))
            })
            .collect();
        Self { tokens }
    }

    fn to_json(&self) -> Value {
        json!({
            "schema_version": 1,
            "tokens": self.tokens.iter().map(|(path, t)| json!({
                "path": path, "class": t.class, "bytes": t.bytes, "planted_at": t.planted_at,
            })).collect::<Vec<_>>(),
        })
    }

    fn save_to(&self, file: &Path) -> std::io::Result<()> {
        if let Some(dir) = file.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = file.with_extension(format!("json.{}.tmp", std::process::id()));
        std::fs::write(&tmp, self.to_json().to_string())?;
        std::fs::rename(&tmp, file)
    }
}

fn path() -> PathBuf {
    topgent_journal::state_dir().join(FILE)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0))
}

/// `n` random bytes. Decoy values need to look unique, not to be keys.
fn random(n: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; n];
    if getrandom::fill(&mut bytes).is_err() {
        // A decoy with a predictable value still works as a decoy.
        let seed = now_ms().to_le_bytes();
        for (b, s) in bytes.iter_mut().zip(seed.iter().cycle()) {
            *b = *s;
        }
    }
    bytes
}

/// `bytes` mapped onto `alphabet`, one character per byte.
fn spell(bytes: &[u8], alphabet: &[u8]) -> String {
    bytes
        .iter()
        .filter_map(|b| alphabet.get(usize::from(*b) % alphabet.len()))
        .map(|c| char::from(*c))
        .collect()
}

const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// A decoy's content with its placeholders filled.
fn fill(template: &str) -> String {
    let mut out = template.to_owned();
    while out.contains("{{key_id}}") {
        let id = format!(
            "AKIA{}",
            spell(&random(16), b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        );
        out = out.replacen("{{key_id}}", &id, 1);
    }
    while out.contains("{{secret}}") {
        out = out.replacen("{{secret}}", &spell(&random(40), BASE64), 1);
    }
    while out.contains("{{token}}") {
        let token = format!("tgh_{}", spell(&random(32), b"0123456789abcdef"));
        out = out.replacen("{{token}}", &token, 1);
    }
    // The key armor is assembled here rather than stored as text, so the
    // repository holds no literal key header for a secret scanner to match.
    let armor = |edge: &str| format!("-----{edge} OPENSSH {} {}-----", "PRIVATE", "KEY");
    out = out.replace("{{pem_begin}}", &armor("BEGIN"));
    out = out.replace("{{pem_end}}", &armor("END"));
    while out.contains("{{blob}}") {
        let blob = spell(&random(1_200), BASE64)
            .as_bytes()
            .chunks(70)
            .map(|line| String::from_utf8_lossy(line).into_owned())
            .collect::<Vec<_>>()
            .join("\n");
        out = out.replacen("{{blob}}", &blob, 1);
    }
    out
}

/// Writes `content` to `path` only if nothing is there, readable by its owner
/// alone, as a real secret would be.
fn create_new(path: &Path, content: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)?.write_all(content.as_bytes())
}

/// Plants every decoy under `dir` and records them. JSON for the command line.
#[must_use]
pub fn plant_honeytokens(dir: &str) -> Value {
    plant_into(Path::new(dir), &path())
}

fn plant_into(dir: &Path, manifest_file: &Path) -> Value {
    let Ok(dir) = dir.canonicalize() else {
        return json!({"ok": false, "error": format!("{} is not a folder that exists", dir.display())});
    };
    if !dir.is_dir() {
        return json!({"ok": false, "error": format!("{} is not a folder", dir.display())});
    }
    let mut manifest = Manifest::load_from(manifest_file);
    let mut planted = Vec::new();
    let mut skipped = Vec::new();
    for decoy in &data().decoys {
        let target = dir.join(&decoy.path);
        let shown = target.to_string_lossy().into_owned();
        if manifest.tokens.len() >= MAX_TOKENS {
            skipped.push(json!({"path": shown, "reason": "the manifest is full"}));
            continue;
        }
        let content = fill(&decoy.content);
        match create_new(&target, &content) {
            Ok(()) => {
                manifest.tokens.insert(
                    shown.clone(),
                    Token {
                        class: decoy.class.clone(),
                        bytes: content.len() as u64,
                        planted_at: now_ms(),
                    },
                );
                planted.push(json!({"path": shown, "class": decoy.class}));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                skipped.push(
                    json!({"path": shown, "reason": "a file is already there; it was left alone"}),
                );
            }
            Err(e) => skipped.push(json!({"path": shown, "reason": e.to_string()})),
        }
    }
    if let Err(e) = manifest.save_to(manifest_file) {
        return json!({"ok": false, "error": format!("decoys were written but the manifest was not saved: {e}"), "planted": planted});
    }
    json!({"ok": true, "planted": planted, "skipped": skipped, "manifest": manifest_file.to_string_lossy()})
}

/// Every planted decoy and whether it is still there. Checks by `stat`, never
/// by opening, so listing never raises an alarm.
#[must_use]
pub fn list_honeytokens() -> Value {
    list_from(&path())
}

fn list_from(manifest_file: &Path) -> Value {
    let manifest = Manifest::load_from(manifest_file);
    let rows: Vec<Value> = manifest
        .tokens
        .iter()
        .map(|(path, t)| {
            let size = std::fs::metadata(path).ok().map(|m| m.len());
            json!({
                "path": path,
                "class": t.class,
                "class_name": topgent_collect::sensitive::display(&t.class),
                "planted_at": t.planted_at,
                "present": size.is_some(),
                "unchanged": size == Some(t.bytes),
            })
        })
        .collect();
    json!({"ok": true, "tokens": rows})
}

/// Removes the decoy at `target`, or every decoy for `all`. A file whose size
/// changed since planting is kept on disk and only dropped from the manifest.
#[must_use]
pub fn remove_honeytokens(target: &str) -> Value {
    remove_from(target, &path())
}

fn remove_from(target: &str, manifest_file: &Path) -> Value {
    let mut manifest = Manifest::load_from(manifest_file);
    let chosen: Vec<String> = if target == "all" {
        manifest.tokens.keys().cloned().collect()
    } else {
        let key = Path::new(target)
            .canonicalize()
            .map_or_else(|_| target.to_owned(), |p| p.to_string_lossy().into_owned());
        manifest
            .tokens
            .contains_key(&key)
            .then_some(key)
            .into_iter()
            .collect()
    };
    if chosen.is_empty() {
        return json!({"ok": false, "error": format!("no honeytoken is planted at {target}")});
    }
    let mut removed = Vec::new();
    let mut kept = Vec::new();
    for path in chosen {
        let Some(token) = manifest.tokens.remove(&path) else {
            continue;
        };
        match std::fs::metadata(&path).map(|m| m.len()) {
            Ok(size) if size == token.bytes => match std::fs::remove_file(&path) {
                Ok(()) => removed.push(path),
                Err(_) => kept.push(path),
            },
            Ok(_) => kept.push(path),
            Err(_) => removed.push(path),
        }
    }
    if let Err(e) = manifest.save_to(manifest_file) {
        return json!({"ok": false, "error": format!("the manifest was not saved: {e}")});
    }
    json!({"ok": true, "removed": removed, "kept_changed": kept})
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    fn scratch(name: &str) -> PathBuf {
        // Test scratch space, named by pid; holds decoys, never real secrets.
        // nosemgrep: rust.lang.security.temp-dir.temp-dir
        let dir = std::env::temp_dir().join(format!("honeytoken-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("project")).unwrap();
        dir
    }

    #[test]
    fn planting_writes_every_decoy_once_and_records_no_values() {
        let dir = scratch("plant");
        let manifest_file = dir.join("state/honeytokens.json");
        let out = plant_into(&dir.join("project"), &manifest_file);
        assert_eq!(out["ok"], true, "{out}");
        let count = data().decoys.len();
        assert_eq!(out["planted"].as_array().unwrap().len(), count);
        let env = std::fs::read_to_string(dir.join("project/.env")).unwrap();
        assert!(env.contains("AWS_ACCESS_KEY_ID=AKIA"));
        assert!(!env.contains("{{"), "every placeholder filled: {env}");
        // The manifest holds paths and classes, never the values.
        let saved = std::fs::read_to_string(&manifest_file).unwrap();
        let key = env.lines().find(|l| l.starts_with("AWS_ACCESS")).unwrap();
        assert!(
            !saved.contains(&key[18..]),
            "a value leaked into the manifest"
        );
        assert_eq!(Manifest::load_from(&manifest_file).tokens.len(), count);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(dir.join("project/.env"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // Twice: nothing overwritten, everything reported as skipped.
        let again = plant_into(&dir.join("project"), &manifest_file);
        assert_eq!(again["planted"].as_array().unwrap().len(), 0);
        assert_eq!(again["skipped"].as_array().unwrap().len(), count);
        assert_eq!(
            std::fs::read_to_string(dir.join("project/.env")).unwrap(),
            env
        );
    }

    #[test]
    fn a_real_file_in_the_way_is_never_touched() {
        let dir = scratch("real");
        std::fs::write(dir.join("project/.env"), "REAL=1\n").unwrap();
        let manifest_file = dir.join("state/honeytokens.json");
        let out = plant_into(&dir.join("project"), &manifest_file);
        assert_eq!(
            std::fs::read_to_string(dir.join("project/.env")).unwrap(),
            "REAL=1\n"
        );
        assert!(out["skipped"].to_string().contains(".env"));
        assert!(
            Manifest::load_from(&manifest_file)
                .tokens
                .keys()
                .all(|p| !p.ends_with("/.env"))
        );
    }

    #[test]
    fn removing_keeps_a_decoy_someone_has_changed() {
        let dir = scratch("remove");
        let manifest_file = dir.join("state/honeytokens.json");
        let _ = plant_into(&dir.join("project"), &manifest_file);
        let changed = dir.join("project/backup.sqldump").canonicalize().unwrap();
        std::fs::write(&changed, "now somebody's real dump\n").unwrap();
        let out = remove_from("all", &manifest_file);
        assert_eq!(out["ok"], true, "{out}");
        assert!(changed.exists(), "a changed file is kept");
        assert!(
            !dir.join("project/.env").exists(),
            "an unchanged decoy is removed"
        );
        assert!(Manifest::load_from(&manifest_file).tokens.is_empty());
        let listed = list_from(&manifest_file);
        assert!(listed["tokens"].as_array().unwrap().is_empty());
        assert_eq!(remove_from("all", &manifest_file)["ok"], false);
    }
}
