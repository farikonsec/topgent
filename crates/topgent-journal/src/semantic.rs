//! Optional semantic context supplied by an agent's own harness.
//!
//! Everything here is a claim by the subject rather than an observation of it,
//! so it is sanitized on the way in, bounded, and kept apart from host
//! evidence. Prompts, file contents, credential values and private keys never
//! become records: only the shape of what an agent said it was doing.

use crate::text::sanitize;
use serde_json::{Value, json};

/// Maximum retained optional semantic records.
pub const MAX_SEMANTIC_RECORDS: usize = 200;

/// Sanitized, provider-neutral context supplied by an agent harness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticRecord {
    /// Harness session or run identifier.
    pub session_id: String,
    /// Process identifier observed by the harness.
    pub pid: u32,
    /// Process start time, required to prevent PID-reuse attribution.
    pub started_at: u64,
    /// Harness or adapter that supplied this record.
    pub source: String,
    /// Sanitized one-line task summary; never a raw prompt.
    pub summary: String,
    /// Coarse objective category.
    pub objective: String,
    /// Coarse tool category.
    pub tool: String,
    /// Coarse outcome category.
    pub outcome: String,
    /// Model label, if supplied.
    pub model: String,
    /// Milliseconds since the epoch.
    pub observed_at: u64,
}

fn category(input: &str) -> &'static str {
    let lower = input.to_ascii_lowercase();
    if ["test", "spec", "regression", "verify"]
        .iter()
        .any(|word| lower.contains(word))
    {
        "testing"
    } else if ["review", "audit", "security", "vulnerability"]
        .iter()
        .any(|word| lower.contains(word))
    {
        "review"
    } else if ["deploy", "release", "publish", "ship"]
        .iter()
        .any(|word| lower.contains(word))
    {
        "deployment"
    } else if ["research", "investigate", "find", "compare"]
        .iter()
        .any(|word| lower.contains(word))
    {
        "research"
    } else if ["fix", "code", "implement", "build", "refactor", "edit"]
        .iter()
        .any(|word| lower.contains(word))
    {
        "development"
    } else {
        "general"
    }
}

fn tool_category(name: &str) -> &'static str {
    match name.to_ascii_lowercase().as_str() {
        "bash" | "shell" | "terminal" | "exec_command" => "shell",
        "read" | "write" | "edit" | "multiedit" | "apply_patch" => "filesystem",
        "webfetch" | "websearch" | "web" => "network",
        "task" | "agent" | "subagent" => "agent",
        "inference" | "generate" | "chat" => "inference",
        "" => "none",
        _ => "other",
    }
}

fn claude_record(
    value: &Value,
    pid: u32,
    started_at: u64,
    observed_at: u64,
) -> Option<SemanticRecord> {
    let session_id = sanitize(value.get("session_id")?.as_str()?, 128);
    let event = value.get("hook_event_name")?.as_str()?;
    let prompt = value
        .get("prompt")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let objective = category(prompt).to_owned();
    let (summary, outcome) = match event {
        "SessionStart" => ("Claude Code session started".to_owned(), "running"),
        "UserPromptSubmit" => (format!("Claude Code task ({objective})"), "running"),
        "PreToolUse" => ("Claude Code tool activity".to_owned(), "running"),
        "Stop" => ("Claude Code turn completed".to_owned(), "complete"),
        "SessionEnd" => ("Claude Code session ended".to_owned(), "ended"),
        _ => return None,
    };
    Some(SemanticRecord {
        session_id,
        pid,
        started_at,
        source: "claude-code-hook".to_owned(),
        summary,
        objective,
        tool: tool_category(
            value
                .get("tool_name")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        )
        .to_owned(),
        outcome: outcome.to_owned(),
        model: sanitize(
            value
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            96,
        ),
        observed_at,
    })
}

fn codex_record(
    value: &Value,
    pid: u32,
    started_at: u64,
    observed_at: u64,
) -> Option<SemanticRecord> {
    if value.get("type")?.as_str()? != "agent-turn-complete" {
        return None;
    }
    let session_id = sanitize(value.get("thread-id")?.as_str()?, 128);
    let input = value
        .get("input-messages")
        .map(Value::to_string)
        .unwrap_or_default();
    let objective = category(&input).to_owned();
    Some(SemanticRecord {
        session_id,
        pid,
        started_at,
        source: "codex-notify".to_owned(),
        summary: format!("Codex task ({objective})"),
        objective,
        tool: "agent".to_owned(),
        outcome: "complete".to_owned(),
        model: String::new(),
        observed_at,
    })
}

fn ollama_record(
    value: &Value,
    pid: u32,
    started_at: u64,
    observed_at: u64,
) -> Option<SemanticRecord> {
    let model = sanitize(value.get("model")?.as_str()?, 96);
    let session = value
        .get("session_id")
        .and_then(Value::as_str)
        .unwrap_or("ollama-runtime");
    Some(SemanticRecord {
        session_id: sanitize(session, 128),
        pid,
        started_at,
        source: "ollama-runtime".to_owned(),
        summary: "Ollama model inference".to_owned(),
        objective: "model-serving".to_owned(),
        tool: "inference".to_owned(),
        outcome: sanitize(
            value
                .get("outcome")
                .and_then(Value::as_str)
                .unwrap_or("running"),
            64,
        ),
        model,
        observed_at,
    })
}

impl SemanticRecord {
    /// Parse and sanitize one untrusted JSON object.
    ///
    /// Unknown fields, including raw prompts and tool payloads, are discarded.
    #[must_use]
    pub fn from_untrusted(value: &Value) -> Option<Self> {
        let text = |key: &str, max: usize| {
            value
                .get(key)
                .and_then(Value::as_str)
                .map(|value| sanitize(value, max))
        };
        Some(Self {
            session_id: text("session_id", 128)?,
            pid: u32::try_from(value.get("pid")?.as_u64()?).ok()?,
            started_at: value.get("started_at")?.as_u64()?,
            source: text("source", 64)?,
            summary: text("summary", 240)?,
            objective: text("objective", 64)?,
            tool: text("tool", 64)?,
            outcome: text("outcome", 64)?,
            model: value
                .get("model")
                .and_then(Value::as_str)
                .map_or_else(String::new, |text| sanitize(text, 96)),
            observed_at: value.get("observed_at")?.as_u64()?,
        })
    }

    /// Convert a native harness event without retaining its raw prompt or output.
    ///
    /// `pid` and `started_at` must identify the actual harness process found by
    /// the local process collector, not values claimed by the event payload.
    #[must_use]
    pub fn from_harness_event(
        harness: &str,
        value: &Value,
        pid: u32,
        started_at: u64,
        observed_at: u64,
    ) -> Option<Self> {
        match harness {
            "claude" => claude_record(value, pid, started_at, observed_at),
            "codex" => codex_record(value, pid, started_at, observed_at),
            "ollama" => ollama_record(value, pid, started_at, observed_at),
            _ => None,
        }
    }

    pub(crate) fn to_json(&self) -> Value {
        json!({
            "session_id": self.session_id, "pid": self.pid,
            "started_at": self.started_at, "source": self.source,
            "summary": self.summary, "objective": self.objective,
            "tool": self.tool, "outcome": self.outcome, "model": self.model,
            "observed_at": self.observed_at,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::SemanticRecord;
    use crate::MAX_SEMANTIC_RECORDS;
    use crate::journal::Journal;
    use crate::test_support::test_dir;
    use serde_json::json;

    fn semantic(at: u64) -> SemanticRecord {
        SemanticRecord {
            session_id: "run-1".to_owned(),
            pid: 42,
            started_at: 100,
            source: "test-adapter".to_owned(),
            summary: "Review code".to_owned(),
            objective: "development".to_owned(),
            tool: "shell".to_owned(),
            outcome: "running".to_owned(),
            model: "gpt-test".to_owned(),
            observed_at: at,
        }
    }

    #[test]
    fn semantic_parser_redacts_secrets_paths_controls_and_ignores_payloads() -> Result<(), String> {
        let record = SemanticRecord::from_untrusted(&json!({
            "session_id":"run\n1", "pid":42, "started_at":100,
            "source":"fixture", "summary":"Use sk-secret /Users/alice/key token=abc Bearer abc\nthen test",
            "objective":"development", "tool":"shell", "outcome":"running",
            "model":"gpt-test", "observed_at":200,
            "prompt":"raw prompt must not exist", "tool_payload":{"secret":"abc"}
        }))
        .ok_or_else(|| "valid fixture was rejected".to_owned())?;
        assert_eq!(record.session_id, "run 1");
        assert_eq!(
            record.summary,
            "Use [REDACTED] [REDACTED] [REDACTED] Bearer [REDACTED] then test"
        );
        assert!(!record.to_json().to_string().contains("raw prompt"));
        Ok(())
    }

    #[test]
    fn semantic_retention_is_bounded_deduplicated_and_clearable() -> std::io::Result<()> {
        let dir = test_dir("semantic");
        let journal = Journal::at(&dir);
        for at in 0..=MAX_SEMANTIC_RECORDS as u64 {
            journal.append_semantic(semantic(at))?;
        }
        journal.append_semantic(semantic(200))?;
        let records = journal.semantic_records()?;
        assert_eq!(records.len(), MAX_SEMANTIC_RECORDS);
        assert_eq!(records.first().map(|record| record.observed_at), Some(1));
        assert_eq!(records.last().map(|record| record.observed_at), Some(200));
        journal.clear_semantic()?;
        assert!(journal.semantic_records()?.is_empty());
        let _ = std::fs::remove_dir(dir);
        Ok(())
    }

    #[test]
    fn native_harness_adapters_never_persist_prompt_or_response_text() -> Result<(), String> {
        let claude = SemanticRecord::from_harness_event(
            "claude",
            &json!({
                "session_id":"claude-1", "hook_event_name":"UserPromptSubmit",
                "prompt":"Fix password=secret in /Users/alice/private.rs"
            }),
            10,
            100,
            1_000,
        )
        .ok_or_else(|| "claude event rejected".to_owned())?;
        assert_eq!(claude.objective, "development");
        assert_eq!(claude.summary, "Claude Code task (development)");
        assert!(!claude.to_json().to_string().contains("private.rs"));

        let codex = SemanticRecord::from_harness_event(
            "codex",
            &json!({
                "type":"agent-turn-complete", "thread-id":"codex-1",
                "input-messages":["Audit ghp_secret"],
                "last-assistant-message":"The secret was abc"
            }),
            11,
            101,
            1_001,
        )
        .ok_or_else(|| "codex event rejected".to_owned())?;
        assert_eq!(codex.objective, "review");
        assert!(!codex.to_json().to_string().contains("ghp_secret"));
        assert!(!codex.to_json().to_string().contains("secret was"));

        let ollama = SemanticRecord::from_harness_event(
            "ollama",
            &json!({
                "model":"qwen3-coder:latest", "prompt":"raw prompt", "outcome":"running"
            }),
            12,
            102,
            1_002,
        )
        .ok_or_else(|| "ollama event rejected".to_owned())?;
        assert_eq!(ollama.model, "qwen3-coder:latest");
        assert!(!ollama.to_json().to_string().contains("raw prompt"));
        Ok(())
    }

    #[test]
    fn native_adapters_reject_unknown_events_and_harnesses() {
        assert!(
            SemanticRecord::from_harness_event(
                "claude",
                &json!({
                    "session_id":"x", "hook_event_name":"FutureEvent", "prompt":"x"
                }),
                1,
                1,
                1
            )
            .is_none()
        );
        assert!(SemanticRecord::from_harness_event("unknown", &json!({}), 1, 1, 1).is_none());
    }
}
