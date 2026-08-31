//! Optional context an agent's own harness volunteered.
//!
//! Everything here is a claim by the subject rather than an observation of it,
//! so it is kept apart from host evidence and admitted only for an exact live
//! run. It is off unless the operator turns it on, and turning it off clears
//! what was retained.

use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use topgent_core::Agent;
use topgent_journal::Journal;

pub(crate) fn semantic_identity_matches(
    pid: u32,
    started_at: u64,
    identities: &[(u32, u64)],
) -> bool {
    identities.contains(&(pid, started_at))
}

fn semantic_json(enabled: bool, journal: &Journal, agents: &[Agent]) -> Vec<Value> {
    if !enabled {
        return Vec::new();
    }
    let identities = agents
        .iter()
        .map(|agent| (agent.id.pid, agent.id.started_at.0))
        .collect::<Vec<_>>();
    journal
        .semantic_records()
        .unwrap_or_default()
        .iter()
        .map(|record| {
            json!({
                "session_id": record.session_id, "pid": record.pid,
                "started_at": record.started_at, "source": record.source,
                "summary": record.summary, "objective": record.objective,
                "tool": record.tool, "outcome": record.outcome, "model": record.model,
                "observed_at": record.observed_at,
                "matched": semantic_identity_matches(record.pid, record.started_at, &identities),
                "provenance": "agent_supplied", "authority": "context_only",
            })
        })
        .collect()
}

pub(crate) fn ollama_models_from_body(body: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let mut models = value
        .get("models")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|model| model.get("name").or_else(|| model.get("model")))
        .filter_map(Value::as_str)
        .filter(|model| !model.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    models.sort();
    models.dedup();
    models
}

fn active_ollama_models() -> Vec<String> {
    let Some(address) = "127.0.0.1:11434"
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
    else {
        return Vec::new();
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(150)) else {
        return Vec::new();
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(200)));
    if stream
        .write_all(b"GET /api/ps HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return Vec::new();
    }
    let mut response = String::new();
    if stream.read_to_string(&mut response).is_err() || !response.starts_with("HTTP/1.1 200") {
        return Vec::new();
    }
    response
        .split_once("\r\n\r\n")
        .map_or_else(Vec::new, |(_, body)| ollama_models_from_body(body))
}

fn ollama_context(enabled: bool, agents: &[Agent], observed_at: u64) -> Vec<Value> {
    if !enabled {
        return Vec::new();
    }
    let Some(agent) = agents
        .iter()
        .find(|agent| agent.family.as_deref() == Some("ollama"))
    else {
        return Vec::new();
    };
    active_ollama_models()
        .into_iter()
        .map(|model| {
            json!({
                "session_id": format!("ollama:{model}"), "pid": agent.id.pid,
                "started_at": agent.id.started_at.0, "source": "ollama-runtime",
                "summary": "Ollama model loaded for inference", "objective": "model-serving",
                "tool": "inference", "outcome": "running", "model": model,
                "observed_at": observed_at, "matched": true,
                "provenance": "runtime_metadata", "authority": "context_only",
            })
        })
        .collect()
}

fn all_semantic_json(
    enabled: bool,
    journal: &Journal,
    agents: &[Agent],
    observed_at: u64,
) -> Vec<Value> {
    let mut records = semantic_json(enabled, journal, agents);
    records.extend(ollama_context(enabled, agents, observed_at));
    records
}

fn context_integrations(agents: &[Agent]) -> Value {
    let has_family = |family: &str| {
        agents.iter().any(|agent| {
            agent.family.as_deref() == Some(family)
                || agent
                    .extensions
                    .iter()
                    .any(|extension| extension.family == family)
        })
    };
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let configured = |relative: &str, marker: &str| {
        home.as_ref().is_some_and(|home| {
            std::fs::read_to_string(home.join(relative)).is_ok_and(|text| text.contains(marker))
        })
    };
    json!({
        "detection_families": ["claude-code", "codex-cli", "gemini-cli", "aider", "goose", "ollama", "amp", "opencode", "cursor", "lm-studio", "windsurf", "cline", "roo-code", "continue"],
        "adapters": [
            { "family":"claude-code", "detected":has_family("claude-code"), "mode":"native_hooks", "configured":configured(".claude/settings.json", "context hook claude") },
            { "family":"codex-cli", "detected":has_family("codex-cli"), "mode":"turn_complete_notify", "configured":configured(".codex/config.toml", "context\", \"hook\", \"codex") },
            { "family":"ollama", "detected":has_family("ollama"), "mode":"runtime_api", "configured":true },
        ]
    })
}

pub(crate) fn context_json(
    enabled: bool,
    journal: &Journal,
    agents: &[Agent],
    observed_at: u64,
) -> Value {
    json!({
        "enabled": enabled,
        "privacy": "sanitized summaries and categories only",
        "authority": "agent-supplied context; deterministic host evidence wins",
        "records": all_semantic_json(enabled, journal, agents, observed_at),
        "integrations": context_integrations(agents),
    })
}

#[cfg(test)]
mod tests {
    use super::{ollama_models_from_body, semantic_identity_matches};

    #[test]
    fn semantic_context_requires_pid_and_start_time_to_match() {
        let identities = [(42, 1_000), (43, 2_000)];
        assert!(semantic_identity_matches(42, 1_000, &identities));
        assert!(!semantic_identity_matches(42, 999, &identities));
        assert!(!semantic_identity_matches(99, 1_000, &identities));
    }

    #[test]
    fn ollama_runtime_parser_accepts_only_model_names_and_deduplicates() {
        assert_eq!(
            ollama_models_from_body(
                r#"{"models":[{"name":"qwen:7b","size":42},{"model":"qwen:7b"},{"name":"gemma:3b"}],"prompt":"never read"}"#
            ),
            ["gemma:3b", "qwen:7b"]
        );
        assert!(ollama_models_from_body("not json").is_empty());
    }
}
