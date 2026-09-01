//! Harness hooks: letting an agent's own tooling tell Topgent what it is doing.
//!
//! A hook is installed into the agent's configuration, not into Topgent, so
//! everything here writes files that belong to something else. Each write is
//! atomic and each install is idempotent — a half-written harness config is a
//! broken agent, and it would be Topgent that broke it.
//!
//! What a hook reports is a claim by the thing being watched. It is recorded as
//! context and never outranks what the host observed directly.

use crate::output::now_ms;
use std::io::Read;
use topgent_collect::process;
use topgent_journal::Journal;
use topgent_journal::SemanticRecord;

pub(crate) fn hooks_command(args: &[String]) -> i32 {
    match args.get(2).map(String::as_str) {
        Some("status") => {
            println!("{}", hook_status());
            0
        }
        Some("install") => match install_hooks() {
            Ok(value) => {
                println!("{value}");
                0
            }
            Err(error) => {
                eprintln!("topgent context hooks: {error}");
                1
            }
        },
        _ => {
            eprintln!("topgent context hooks status|install");
            2
        }
    }
}

pub(crate) fn hook_status() -> serde_json::Value {
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let claude = home.as_ref().is_some_and(|home| {
        std::fs::read_to_string(home.join(".claude/settings.json"))
            .is_ok_and(|text| text.contains("context hook claude"))
    });
    let codex = home.as_ref().is_some_and(|home| {
        std::fs::read_to_string(home.join(".codex/config.toml"))
            .is_ok_and(|text| text.contains("context\", \"hook\", \"codex"))
    });
    serde_json::json!({
        "claude_code": { "detected": command_exists("claude"), "hook": claude },
        "codex_cli": { "detected": command_exists("codex"), "hook": codex },
        "ollama": { "detected": command_exists("ollama"), "hook": "runtime_api", "endpoint": "127.0.0.1:11434/api/ps" },
    })
}

pub(crate) fn command_exists(name: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|path| path.join(name).is_file()))
}

pub(crate) fn install_hooks() -> std::io::Result<serde_json::Value> {
    // The path is written into the user's own agent config, never used for a trust
    // decision, and is rejected below if it contains quotes or newlines.
    let executable = std::env::current_exe()?; // nosemgrep: rust.lang.security.current-exe.current-exe
    let executable = executable
        .to_str()
        .ok_or_else(|| std::io::Error::other("Topgent executable path is not UTF-8"))?;
    if executable.contains(['\'', '"', '\n']) {
        return Err(std::io::Error::other(
            "Topgent executable path cannot be safely quoted",
        ));
    }
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| std::io::Error::other("HOME is not set"))?;
    let claude_path = home.join(".claude/settings.json");
    let codex_path = home.join(".codex/config.toml");
    install_claude_hooks(&claude_path, executable)?;
    install_codex_hook(&codex_path, executable)?;
    Ok(serde_json::json!({ "ok": true, "status": hook_status() }))
}

pub(crate) fn install_claude_hooks(
    path: &std::path::Path,
    executable: &str,
) -> std::io::Result<()> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|_| "{}".to_owned());
    let mut root = serde_json::from_str::<serde_json::Value>(&text)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let hooks = root
        .as_object_mut()
        .ok_or_else(|| std::io::Error::other("Claude settings root is not an object"))?
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}));
    let hooks = hooks
        .as_object_mut()
        .ok_or_else(|| std::io::Error::other("Claude hooks setting is not an object"))?;
    let command = format!("'{executable}' context hook claude");
    for event in [
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse",
        "Stop",
        "SessionEnd",
    ] {
        let entries = hooks.entry(event).or_insert_with(|| serde_json::json!([]));
        let entries = entries.as_array_mut().ok_or_else(|| {
            std::io::Error::other(format!("Claude {event} hooks are not an array"))
        })?;
        if entries
            .iter()
            .any(|entry| entry.to_string().contains("context hook claude"))
        {
            continue;
        }
        entries.push(serde_json::json!({
            "matcher": "",
            "hooks": [{ "type": "command", "command": command, "timeout": 5, "async": true }]
        }));
    }
    atomic_config_write(
        path,
        serde_json::to_string_pretty(&root)
            .unwrap_or_default()
            .as_bytes(),
    )
}

pub(crate) fn install_codex_hook(path: &std::path::Path, executable: &str) -> std::io::Result<()> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let notify = format!("notify = [\"{executable}\", \"context\", \"hook\", \"codex\"]");
    let mut found = false;
    let mut output = text
        .lines()
        .map(|line| {
            if !found && line.trim_start().starts_with("notify =") {
                found = true;
                notify.clone()
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>();
    if !found {
        let index = output
            .iter()
            .position(|line| line.trim_start().starts_with('['))
            .unwrap_or(output.len());
        output.insert(index, notify);
        output.insert(index + 1, String::new());
    }
    atomic_config_write(path, format!("{}\n", output.join("\n")).as_bytes())
}

pub(crate) fn atomic_config_write(path: &std::path::Path, content: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if path.exists() {
        let backup = path.with_extension(format!("topgent-backup-{}", now_ms()));
        std::fs::copy(path, backup)?;
    }
    let temporary = path.with_extension(format!("topgent-{}.tmp", std::process::id()));
    std::fs::write(&temporary, content)?;
    std::fs::rename(temporary, path)
}

pub(crate) fn harness_hook(args: &[String]) -> i32 {
    // Hooks are observability only and must never break or delay the harness.
    if !topgent_policy_enabled() {
        return 0;
    }
    let Some(harness) = args.get(2).map(String::as_str) else {
        return 0;
    };
    let input = if harness == "codex" {
        args.get(3).cloned().unwrap_or_default()
    } else {
        let mut input = String::new();
        if std::io::stdin().read_to_string(&mut input).is_err() {
            return 0;
        }
        input
    };
    let Ok(value) = serde_json::from_str(&input) else {
        return 0;
    };
    let Some((pid, started_at)) = harness_identity(harness) else {
        return 0;
    };
    let Some(record) =
        SemanticRecord::from_harness_event(harness, &value, pid, started_at, now_ms())
    else {
        return 0;
    };
    let _ = Journal::open_default().append_semantic(record);
    0
}

pub(crate) fn harness_identity(harness: &str) -> Option<(u32, u64)> {
    let family = match harness {
        "claude" => "claude-code",
        "codex" => "codex-cli",
        "ollama" => "ollama",
        _ => return None,
    };
    let processes = process::snapshot();
    if harness == "ollama" {
        return processes
            .iter()
            .find(|process| process.family == Some("ollama"))
            .map(|process| (process.pid, process.started_at.0));
    }
    let by_pid = processes
        .iter()
        .map(|process| (process.pid, process))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut cursor = std::process::id();
    for _ in 0..12 {
        let process = by_pid.get(&cursor)?;
        if process.family == Some(family) {
            return Some((process.pid, process.started_at.0));
        }
        cursor = process.parent?;
    }
    None
}

pub(crate) fn topgent_policy_enabled() -> bool {
    topgent_policy::Policy::load().semantic.enabled
}

#[cfg(test)]
mod hook_install_tests {
    use super::{install_claude_hooks, install_codex_hook};

    fn fixture(name: &str) -> std::path::PathBuf {
        // nosemgrep: rust.lang.security.temp-dir.temp-dir - test fixture, per-process name, not a trust boundary
        std::env::temp_dir().join(format!("topgent-hook-{name}-{}", std::process::id()))
    }

    #[test]
    fn claude_hook_install_is_additive_backed_up_and_idempotent() -> std::io::Result<()> {
        let path = fixture("claude.json");
        std::fs::write(&path, r#"{"theme":"dark","hooks":{"Stop":[]}}"#)?;
        install_claude_hooks(&path, "/opt/topgent")?;
        install_claude_hooks(&path, "/opt/topgent")?;
        let value: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
        assert_eq!(
            value.get("theme").and_then(serde_json::Value::as_str),
            Some("dark")
        );
        for event in [
            "SessionStart",
            "UserPromptSubmit",
            "PreToolUse",
            "Stop",
            "SessionEnd",
        ] {
            let matches = value
                .get("hooks")
                .and_then(|hooks| hooks.get(event))
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter(|entry| entry.to_string().contains("context hook claude"))
                .count();
            assert_eq!(matches, 1, "{event}");
        }
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn codex_hook_install_preserves_tables_and_replaces_previous_notify() -> std::io::Result<()> {
        let path = fixture("codex.toml");
        std::fs::write(
            &path,
            "notify = [\"old\"]\n\n[projects.x]\ntrust_level = \"trusted\"\n",
        )?;
        install_codex_hook(&path, "/opt/topgent")?;
        install_codex_hook(&path, "/opt/topgent")?;
        let text = std::fs::read_to_string(&path)?;
        assert_eq!(text.matches("notify =").count(), 1);
        assert!(text.contains("[projects.x]"));
        assert!(text.contains("context\", \"hook\", \"codex"));
        let _ = std::fs::remove_file(path);
        Ok(())
    }
}
