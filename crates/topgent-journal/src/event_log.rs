//! One line per thing that changed, appended and never rewritten.
//!
//! Each entry names the exact agent run it happened to, so a reused pid cannot
//! inherit another process's history. A grade change carries the direction it
//! moved in, decided once from typed bands: reading direction out of the
//! sentence describing it is how a downgrade came to be reported as an
//! escalation.

use crate::sweep::SeenKey;
use serde_json::{Value, json};
use topgent_core::Grade;
use topgent_facts::UnixMillis;

/// What kind of change an entry records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// An agent was seen for the first time.
    Started,
    /// An agent is no longer running.
    Stopped,
    /// Its risk grade moved.
    GradeChanged,
    /// A credential came into reach that was not in reach before.
    CredentialExposed,
    /// It touched a resource its configuration does not grant.
    PolicyBreach,
    /// Its live connections started to look like scanning.
    Recon,
    /// A rogue-behaviour factor appeared on the rising edge.
    Behaviour,
    /// The model or provider changed for a running agent.
    ModelDrift,
    /// Topgent did something.
    Action,
}

/// Which way a risk grade moved.
///
/// A grade change is not inherently alarming. Reading the direction out of the
/// human detail string is how `CRITICAL to HIGH` was reported as an escalation,
/// so the direction is decided once, here, from typed bands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GradeMove {
    /// The grade moved up a band or more.
    Escalated,
    /// The grade moved down a band or more.
    Downgraded,
}

/// One line in the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Milliseconds since the epoch.
    pub at: u64,
    /// What happened.
    pub kind: Kind,
    /// Process id it happened to.
    pub pid: u32,
    /// Process start time, which with the pid is the exact run it happened to.
    ///
    /// `None` for an entry written before identity carried a start time, and
    /// for actions that are not about one running process.
    pub started_at: Option<UnixMillis>,
    /// Agent family, when known.
    pub agent: String,
    /// One line a person reads.
    pub detail: String,
    /// Which way the grade moved, on a grade change only.
    pub direction: Option<GradeMove>,
}

impl Kind {
    /// Stable machine-readable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Stopped => "stopped",
            Self::GradeChanged => "grade_changed",
            Self::CredentialExposed => "credential_exposed",
            Self::PolicyBreach => "policy_breach",
            Self::Recon => "recon",
            Self::Behaviour => "behaviour",
            Self::ModelDrift => "model_drift",
            Self::Action => "action",
        }
    }
}

impl GradeMove {
    /// Stable machine-readable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Escalated => "escalated",
            Self::Downgraded => "downgraded",
        }
    }

    /// The direction between two stored grade labels.
    ///
    /// `None` when either label is unrecognised or the bands are equal, so an
    /// unreadable record never becomes an alarm.
    #[must_use]
    pub fn between(was: &str, now: &str) -> Option<Self> {
        let was = Grade::from_label(was)?;
        let now = Grade::from_label(now)?;
        match now.cmp(&was) {
            std::cmp::Ordering::Greater => Some(Self::Escalated),
            std::cmp::Ordering::Less => Some(Self::Downgraded),
            std::cmp::Ordering::Equal => None,
        }
    }
}

impl Entry {
    /// One log line about an exact agent run.
    pub(crate) fn about(at: u64, kind: Kind, key: SeenKey, agent: &str, detail: String) -> Self {
        Self {
            at,
            kind,
            pid: key.pid,
            started_at: key.started_at,
            agent: agent.to_owned(),
            detail,
            direction: None,
        }
    }

    pub(crate) fn to_json(&self) -> Value {
        let mut value = json!({
            "at": self.at,
            "kind": self.kind.as_str(),
            "pid": self.pid,
            "agent": self.agent,
            "detail": self.detail,
        });
        if let (Some(object), Some(started_at)) = (value.as_object_mut(), self.started_at) {
            object.insert("started_at".to_owned(), json!(started_at.0));
        }
        if let (Some(object), Some(direction)) = (value.as_object_mut(), self.direction) {
            object.insert("direction".to_owned(), json!(direction.as_str()));
        }
        value
    }

    pub(crate) fn from_json(v: &Value) -> Option<Self> {
        let kind = match v.get("kind")?.as_str()? {
            "started" => Kind::Started,
            "stopped" => Kind::Stopped,
            "grade_changed" => Kind::GradeChanged,
            "credential_exposed" => Kind::CredentialExposed,
            "policy_breach" => Kind::PolicyBreach,
            "recon" => Kind::Recon,
            "behaviour" => Kind::Behaviour,
            "model_drift" => Kind::ModelDrift,
            "action" => Kind::Action,
            _ => return None,
        };
        Some(Self {
            at: v.get("at")?.as_u64()?,
            kind,
            pid: u32::try_from(v.get("pid")?.as_u64()?).ok()?,
            started_at: v.get("started_at").and_then(Value::as_u64).map(UnixMillis),
            agent: v.get("agent")?.as_str()?.to_owned(),
            detail: v.get("detail")?.as_str()?.to_owned(),
            direction: match v.get("direction").and_then(Value::as_str) {
                Some("escalated") => Some(GradeMove::Escalated),
                Some("downgraded") => Some(GradeMove::Downgraded),
                _ => None,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{Entry, GradeMove, Kind};
    use crate::sweep::SeenKey;
    use serde_json::json;
    use topgent_facts::UnixMillis;

    #[test]
    fn a_log_line_keeps_exact_identity_and_direction_across_a_round_trip() {
        let mut entry = Entry::about(
            5,
            Kind::GradeChanged,
            SeenKey::exact(18_246, UnixMillis(1_000)),
            "codex-cli",
            "HIGH to CRITICAL".to_owned(),
        );
        entry.direction = Some(GradeMove::Escalated);
        assert_eq!(Entry::from_json(&entry.to_json()), Some(entry));

        // Lines written before this contract carried neither field and must
        // still read back rather than being dropped from the log.
        let legacy = json!({
            "at": 5, "kind": "started", "pid": 42,
            "agent": "codex-cli", "detail": "started, graded LOW",
        });
        let parsed = Entry::from_json(&legacy).expect("a legacy line still parses");
        assert_eq!(parsed.started_at, None);
        assert_eq!(parsed.direction, None);
    }
}
