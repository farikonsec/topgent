//! Which transcript may name a running agent's model, and how much of it is read.
//!
//! Claude Code keeps one directory of transcripts per working directory, every
//! session it has ever run. Reading "the first transcript that names a model"
//! answers a question about some other session: another project, or this
//! project last week. And a transcript is the agent's whole conversation, so
//! reading all of it to find one short string reads prompts nobody needed.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use topgent_collect::model::{
    Certainty, HEAD_BYTES, Session, SourceKind, TAIL_BYTES, builtin, detect, project_slug,
    read_bounded,
};

/// A pid no process can hold, so the command-line source never answers.
const NO_PID: u32 = u32::MAX;

fn write_at(path: &Path, body: &str, modified: SystemTime) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(modified)
        .unwrap();
}

fn line(model: &str) -> String {
    format!("{{\"type\":\"assistant\",\"message\":{{\"model\":\"{model}\"}}}}\n")
}

/// A fresh directory for one test, removed when the test ends.
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "topgent-model-session-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn ms(time: SystemTime) -> u64 {
    u64::try_from(time.duration_since(UNIX_EPOCH).unwrap().as_millis()).unwrap()
}

#[test]
fn a_project_directory_is_named_the_way_claude_code_names_it() {
    assert_eq!(
        project_slug(Path::new("/home/user/Desktop/x.y z")),
        "-home-user-Desktop-x-y-z"
    );
    assert_eq!(
        project_slug(Path::new("/Users/u/Projects/topgent")),
        "-Users-u-Projects-topgent"
    );
}

#[test]
fn another_projects_transcript_does_not_name_this_session_model() {
    let home = Scratch::new("other");
    let started = SystemTime::now() - Duration::from_secs(60);
    let after = started + Duration::from_secs(10);
    // Sorted first, and the wrong project.
    write_at(
        &home.path().join(".claude/projects/-a-proj/s.jsonl"),
        &line("claude-other-project"),
        after,
    );
    write_at(
        &home.path().join(".claude/projects/-b-proj/s.jsonl"),
        &line("claude-this-session"),
        after,
    );
    let session = Session {
        pid: NO_PID,
        cwd: Some(Path::new("/b/proj")),
        started_at_ms: ms(started),
    };
    let found = detect(builtin().unwrap(), "claude-code", home.path(), &session).unwrap();
    assert_eq!(found.model, "claude-this-session");
    assert_eq!(found.certainty, Certainty::Observed);
}

#[test]
fn a_transcript_older_than_the_process_is_another_session() {
    let home = Scratch::new("older");
    let started = SystemTime::now() - Duration::from_secs(60);
    write_at(
        &home.path().join(".claude/projects/-b-proj/old.jsonl"),
        &line("claude-last-week"),
        started - Duration::from_secs(3_600),
    );
    write_at(
        &home.path().join(".claude/settings.json"),
        "{\"model\":\"claude-configured\"}",
        started,
    );
    let session = Session {
        pid: NO_PID,
        cwd: Some(Path::new("/b/proj")),
        started_at_ms: ms(started),
    };
    let found = detect(builtin().unwrap(), "claude-code", home.path(), &session).unwrap();
    assert_eq!(found.model, "claude-configured");
    assert_eq!(
        found.certainty,
        Certainty::Declared,
        "a configured model is an intention, and says so"
    );
}

#[test]
fn the_newest_transcript_in_the_project_wins_not_the_first_by_name() {
    let home = Scratch::new("newest");
    let started = SystemTime::now() - Duration::from_secs(60);
    let dir = home.path().join(".claude/projects/-b-proj");
    write_at(
        &dir.join("a.jsonl"),
        &line("claude-earlier"),
        started + Duration::from_secs(5),
    );
    write_at(
        &dir.join("z.jsonl"),
        &line("claude-latest"),
        started + Duration::from_secs(30),
    );
    let session = Session {
        pid: NO_PID,
        cwd: Some(Path::new("/b/proj")),
        started_at_ms: ms(started),
    };
    let found = detect(builtin().unwrap(), "claude-code", home.path(), &session).unwrap();
    assert_eq!(found.model, "claude-latest");
}

#[test]
fn without_a_working_directory_no_transcript_is_attributed() {
    let home = Scratch::new("nocwd");
    let started = SystemTime::now() - Duration::from_secs(60);
    write_at(
        &home.path().join(".claude/projects/-b-proj/s.jsonl"),
        &line("claude-someone"),
        started + Duration::from_secs(5),
    );
    let session = Session {
        pid: NO_PID,
        cwd: None,
        started_at_ms: ms(started),
    };
    assert_eq!(
        detect(builtin().unwrap(), "claude-code", home.path(), &session),
        None
    );
}

/// A transcript is append-only, so the current model is at the end. Only the
/// end is read, and only a bounded amount of it.
#[test]
fn a_large_transcript_is_read_from_its_end_and_no_further() {
    let home = Scratch::new("tail");
    let path = home.path().join("big.jsonl");
    let mut body = line("claude-first");
    let filler = "{\"type\":\"user\",\"message\":{\"content\":\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"}}\n";
    while body.len() < 20 * 1024 * 1024 {
        body.push_str(filler);
    }
    body.push_str(&line("claude-latest"));
    fs::write(&path, &body).unwrap();

    let read = read_bounded(&path, SourceKind::Jsonl).unwrap();
    assert!(
        read.len() as u64 <= TAIL_BYTES,
        "read {} bytes of a {} byte transcript",
        read.len(),
        body.len()
    );
    assert!(read.ends_with(&line("claude-latest")));
    // The cut lands mid-record; the partial first line is dropped, not parsed.
    assert!(read.starts_with('{'));
}

#[test]
fn a_config_file_is_read_from_its_start_and_no_further() {
    let home = Scratch::new("head");
    let path = home.path().join("settings.json");
    let body = format!(
        "{{\"model\":\"claude-configured\",\"padding\":\"{}\"}}",
        "x".repeat(2 * 1024 * 1024)
    );
    fs::write(&path, &body).unwrap();
    let read = read_bounded(&path, SourceKind::Json).unwrap();
    assert!(read.len() as u64 <= HEAD_BYTES, "read {} bytes", read.len());
    assert!(read.starts_with("{\"model\""));
}
