//! The event log, as the interface reads it.
//!
//! Severity is decided here rather than in the log, because the same kind of
//! entry can mean opposite things: a grade that moved down is the risk model
//! reporting improvement, and grading it like an escalation is what turned a
//! recovery into an alarm somebody had to investigate.

use serde_json::{Value, json};

pub(crate) fn event_json(event: &topgent_journal::Entry) -> Value {
    let (severity, evidence) = match event.kind {
        topgent_journal::Kind::Behaviour | topgent_journal::Kind::Recon => {
            ("critical", "deterministic host metadata · rising edge")
        }
        topgent_journal::Kind::CredentialExposed | topgent_journal::Kind::PolicyBreach => {
            ("critical", "deterministic host evidence · rising edge")
        }
        // A downgrade is the risk model reporting improvement. Grading it the
        // same as an escalation is what turned `CRITICAL to HIGH` into an
        // alarm the user had to investigate.
        topgent_journal::Kind::GradeChanged
            if event.direction == Some(topgent_journal::GradeMove::Downgraded) =>
        {
            ("info", "journalled state transition · downgrade")
        }
        topgent_journal::Kind::GradeChanged | topgent_journal::Kind::ModelDrift => {
            ("high", "journalled state transition")
        }
        topgent_journal::Kind::Action => ("medium", "Topgent action journal"),
        topgent_journal::Kind::Started | topgent_journal::Kind::Stopped => {
            ("info", "process lifecycle observation")
        }
    };
    let run = event.started_at.map_or_else(
        || event.pid.to_string(),
        |started_at| format!("{}@{}", event.pid, started_at.0),
    );
    json!({
        "id": format!("{}:{}:{}", event.at, event.kind.as_str(), run),
        "at": event.at,
        "kind": event.kind.as_str(),
        "pid": event.pid,
        "started_at": event.started_at.map(|started_at| started_at.0),
        "run": run,
        "agent": event.agent,
        "detail": event.detail,
        "direction": event.direction.map(topgent_journal::GradeMove::as_str),
        "severity": severity,
        "evidence": evidence,
    })
}
