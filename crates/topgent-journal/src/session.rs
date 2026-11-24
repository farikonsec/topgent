//! One launch, one session, as a capture tool keeps one capture.
//!
//! A new instance of the desktop application starts with nothing: its
//! histories (processes, network, activity, behaviour, events) live in a
//! directory of its own under `live/`, made fresh at start. Closing asks
//! whether to save it; saved, it becomes one file that can be opened again
//! later; not saved, the directory is removed. What is not captured data
//! stays shared across launches, in the state directory itself: interface
//! settings, identities, approvals, response cooldowns and transitions, and
//! tool attestations.
//!
//! The command line and anything else that never begins a session keep
//! writing the state directory directly, as before, unless
//! `TOPGENT_SESSION_DIR` names a directory for them (the development viewer
//! sets one per run).

use std::fs::{self, File};
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde_json::{Map, Value, json};

use crate::journal::state_dir;

/// Environment variable naming a session directory for a process that does
/// not begin its own.
pub const SESSION_DIR_ENV: &str = "TOPGENT_SESSION_DIR";
/// What a saved session file says it is.
pub const SESSION_FORMAT: &str = "topgent-session";
/// The saved-session format this build writes and reads.
pub const SESSION_VERSION: u64 = 1;
/// A saved session's file extension.
pub const SESSION_EXTENSION: &str = "topgent";
/// Largest saved session read back. The histories are bounded, so a real one
/// is a few megabytes; anything far larger is not one.
pub const MAX_SESSION_BYTES: u64 = 64 * 1024 * 1024;
/// Held for the life of the instance: a live directory whose lock can be
/// taken belongs to an instance that is gone.
const INSTANCE_LOCK: &str = "instance.lock";

/// The session this process began, and the lock that marks it alive.
struct Live {
    dir: PathBuf,
    _lock: File,
}

static LIVE: OnceLock<Live> = OnceLock::new();

/// Where this process keeps its session's histories: the session it began,
/// else [`SESSION_DIR_ENV`], else the state directory itself.
#[must_use]
pub fn session_dir() -> PathBuf {
    if let Some(live) = LIVE.get() {
        return live.dir.clone();
    }
    match std::env::var_os(SESSION_DIR_ENV) {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => state_dir(),
    }
}

/// The directory live sessions are made in.
#[must_use]
pub fn live_root() -> PathBuf {
    state_dir().join("live")
}

/// Starts a fresh session for this process, removing the directories of
/// instances that are no longer running. Idempotent: a second call returns
/// the session already begun.
///
/// # Errors
///
/// The session directory or its lock could not be made.
pub fn begin_session() -> io::Result<PathBuf> {
    if let Some(live) = LIVE.get() {
        return Ok(live.dir.clone());
    }
    let root = live_root();
    fs::create_dir_all(&root)?;
    remove_abandoned(&root);
    let at = now_ms();
    let dir = root.join(format!("{at}-{}", std::process::id()));
    fs::create_dir(&dir)?;
    let lock = File::create(dir.join(INSTANCE_LOCK))?;
    lock.try_lock().map_err(io::Error::other)?;
    let _ = LIVE.set(Live { dir, _lock: lock });
    Ok(session_dir())
}

/// Removes the session this process began, after it was saved or when it is
/// not to be. Does nothing for a process that began none: the state
/// directory itself is never removed.
///
/// # Errors
///
/// The directory could not be removed.
pub fn discard_session() -> io::Result<()> {
    match LIVE.get() {
        Some(live) => fs::remove_dir_all(&live.dir),
        None => Ok(()),
    }
}

/// Removes every live directory whose instance lock nobody holds: what a
/// crashed or killed instance left behind.
fn remove_abandoned(root: &Path) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let abandoned = match File::options().write(true).open(dir.join(INSTANCE_LOCK)) {
            // Taken and released at once: no instance holds it.
            Ok(lock) => lock.try_lock().is_ok(),
            // No lock at all: never finished starting.
            Err(error) => error.kind() == io::ErrorKind::NotFound,
        };
        if abandoned {
            let _ = fs::remove_dir_all(&dir);
        }
    }
}

/// Where saved sessions go by default: `Documents/Topgent` in the home
/// directory, or `Topgent` in it when there is no `Documents`.
#[must_use]
pub fn saved_sessions_dir() -> PathBuf {
    let home = crate::journal::home_directory().unwrap_or_else(std::env::temp_dir);
    let documents = home.join("Documents");
    if documents.is_dir() {
        documents.join("Topgent")
    } else {
        home.join("Topgent")
    }
}

/// Writes the session to `to` as one file: the report it last showed, and
/// every history file of the session directory, so it can be opened again as
/// it was. Written readable by its owner only.
///
/// # Errors
///
/// A history file could not be read, or the file could not be written.
pub fn save_session(report: &Value, dir: &Path, to: &Path) -> io::Result<()> {
    let mut files = Map::new();
    for entry in fs::read_dir(dir)?.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !path.is_file() || !kept(name) {
            continue;
        }
        files.insert(name.to_owned(), Value::String(fs::read_to_string(&path)?));
    }
    let bundle = json!({
        "format": SESSION_FORMAT,
        "version": SESSION_VERSION,
        "saved_at": now_ms(),
        "report": report,
        "journal": files,
    });
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)?;
    }
    let scratch = to.with_extension(format!("{SESSION_EXTENSION}.{}.tmp", std::process::id()));
    write_private(&scratch, bundle.to_string().as_bytes())?;
    fs::rename(&scratch, to).inspect_err(|_| {
        let _ = fs::remove_file(&scratch);
    })
}

/// Whether a session directory's file is part of what it captured: its
/// histories and events, not its locks or scratch files.
fn kept(name: &str) -> bool {
    // The journal names its own files, all lower case.
    let extension = Path::new(name).extension().and_then(|e| e.to_str());
    matches!(extension, Some("json" | "jsonl")) && !name.contains(".tmp")
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = File::options()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::write(path, bytes)
}

/// A saved session, read back.
#[derive(Debug, Clone)]
pub struct SavedSession {
    /// When it was saved, in Unix milliseconds.
    pub saved_at: u64,
    /// The report it last showed, as the report builder wrote it.
    pub report: Value,
    /// How many history files it carries.
    pub files: usize,
}

/// Reads a saved session, refusing anything that is not one: a file too
/// large, not JSON, of another format or a newer version, or with no report.
///
/// # Errors
///
/// The file could not be read, or is not a saved session this build reads.
pub fn load_session(path: &Path) -> io::Result<SavedSession> {
    let file = File::open(path)?;
    if file.metadata()?.len() > MAX_SESSION_BYTES {
        return Err(invalid("larger than any saved session"));
    }
    let mut text = String::new();
    file.take(MAX_SESSION_BYTES).read_to_string(&mut text)?;
    parse_session(&text)
}

/// [`load_session`] on text already read.
///
/// # Errors
///
/// The text is not a saved session this build reads.
pub fn parse_session(text: &str) -> io::Result<SavedSession> {
    let value: Value =
        serde_json::from_str(text).map_err(|_| invalid("not a Topgent session file"))?;
    if value.get("format").and_then(Value::as_str) != Some(SESSION_FORMAT) {
        return Err(invalid("not a Topgent session file"));
    }
    match value.get("version").and_then(Value::as_u64) {
        Some(version) if version <= SESSION_VERSION => {}
        _ => return Err(invalid("saved by a newer Topgent")),
    }
    let report = value
        .get("report")
        .filter(|r| r.is_object())
        .cloned()
        .ok_or_else(|| invalid("has no report"))?;
    Ok(SavedSession {
        saved_at: value.get("saved_at").and_then(Value::as_u64).unwrap_or(0),
        report,
        files: value
            .get("journal")
            .and_then(Value::as_object)
            .map_or(0, Map::len),
    })
}

fn invalid(why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why.to_owned())
}

/// Saved sessions in `dir`, newest first, as `(path, modified ms)`.
#[must_use]
pub fn list_saved(dir: &Path) -> Vec<(PathBuf, u64)> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found: Vec<(PathBuf, u64)> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some(SESSION_EXTENSION))
        .map(|p| {
            let modified = fs::metadata(&p)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
            (p, modified)
        })
        .collect();
    found.sort_by_key(|(_, modified)| std::cmp::Reverse(*modified));
    found
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::test_support::test_dir;

    #[test]
    fn a_saved_session_reads_back_with_its_report_and_histories() {
        let dir = test_dir("session-save");
        fs::create_dir_all(&dir).expect("a session directory");
        fs::write(dir.join("network-history.json"), "[]").expect("a history");
        fs::write(dir.join("events.jsonl"), "{}\n").expect("events");
        fs::write(dir.join("sweep.lock"), "").expect("a lock");
        fs::write(dir.join("x.json.1.2.tmp"), "").expect("scratch");
        let to = dir.join("out").join("s.topgent");
        let report = json!({"version": "0.5.1", "agents": []});
        save_session(&report, &dir, &to).expect("saved");
        let back = load_session(&to).expect("read back");
        assert_eq!(back.report, report);
        assert_eq!(back.files, 2, "histories, not locks or scratch files");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&to).expect("stat").permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "owner only");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn anything_but_a_saved_session_is_refused() {
        for text in [
            "",
            "not json",
            "[]",
            r#"{"format":"other","version":1,"report":{}}"#,
            r#"{"format":"topgent-session","version":99,"report":{}}"#,
            r#"{"format":"topgent-session","version":1}"#,
            r#"{"format":"topgent-session","version":1,"report":[]}"#,
        ] {
            assert!(parse_session(text).is_err(), "{text:?}");
        }
        assert!(parse_session(r#"{"format":"topgent-session","version":1,"report":{}}"#).is_ok());
    }

    #[test]
    fn an_abandoned_live_directory_is_removed_and_a_held_one_is_kept() {
        let root = test_dir("session-live");
        let gone = root.join("1-1");
        let held = root.join("2-2");
        let unfinished = root.join("3-3");
        for dir in [&gone, &held, &unfinished] {
            fs::create_dir_all(dir).expect("a live directory");
        }
        File::create(gone.join(INSTANCE_LOCK)).expect("a lock nobody holds");
        let lock = File::create(held.join(INSTANCE_LOCK)).expect("a lock");
        lock.try_lock().expect("held by this test");
        remove_abandoned(&root);
        assert!(!gone.exists(), "no holder: removed");
        assert!(!unfinished.exists(), "no lock at all: removed");
        assert!(held.exists(), "held: kept");
        drop(lock);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn saved_sessions_are_listed_newest_first() {
        let dir = test_dir("session-list");
        fs::create_dir_all(&dir).expect("a directory");
        fs::write(dir.join("a.topgent"), "{}").expect("one");
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(dir.join("b.topgent"), "{}").expect("two");
        fs::write(dir.join("c.txt"), "{}").expect("not one");
        let names: Vec<_> = list_saved(&dir)
            .into_iter()
            .map(|(p, _)| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["b.topgent", "a.topgent"]);
        let _ = fs::remove_dir_all(&dir);
    }
}
