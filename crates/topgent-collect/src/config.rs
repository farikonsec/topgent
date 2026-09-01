//! The config collector.
//!
//! An agent's own configuration is the **declared** column: what it says it may
//! do. Reading it needs no privileges and no instrumentation, which is why
//! Topgent can answer the connector-allowlist question about an agent that has
//! never heard of it.
//!
//! Every value read here is data. A config naming a binary is a string, and
//! nothing in this module will ever run it.

use crate::{Clock, CollectError, Collector, emit};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use topgent_facts::{Access, Claim, Confidence, Fact, Subject, UnixMillis};

/// Emits declared permissions and connectors for recognised agent families.
#[derive(Debug, Default)]
pub struct ConfigCollector {
    /// Where to look for agent configuration. `None` means the real `HOME`.
    ///
    /// Injectable so an end-to-end test can stand up a whole fake estate — real
    /// processes, real config files, real credentials in reach — without
    /// touching the machine it runs on.
    pub home: Option<PathBuf>,
}

const ID: &str = "config";

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Read a JSON file, returning `None` for anything unreadable or malformed.
///
/// A hostile or broken config must not stop the sweep. It is untrusted input by
/// definition: agents write it, and so does anything that can write as the user.
fn read_json(path: &Path) -> Option<Value> {
    let bytes = std::fs::read(path).ok()?;
    // Cap what a config file can cost us. A 200 MB settings.json is not a
    // configuration, it is a denial of service.
    if bytes.len() > 8 * 1024 * 1024 {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

/// Turn one Claude Code permission rule into a path and an access.
///
/// Rules look like `Bash(cargo *)`, `Write(/path/**)` or a bare `Read`.
#[must_use]
pub fn parse_permission_rule(rule: &str) -> Option<(String, Access)> {
    let (tool, arg) = match rule.split_once('(') {
        Some((t, rest)) => (t, rest.strip_suffix(')').unwrap_or(rest)),
        None => (rule, "*"),
    };
    let access = match tool.trim() {
        "Bash" | "Execute" => Access::Execute,
        "Write" | "Edit" | "NotebookEdit" => Access::Write,
        "Read" | "Glob" | "Grep" => Access::Read,
        _ => return None,
    };
    // `Bash()` names no path. A bare `Bash` means every path and says so above;
    // empty parentheses are malformed, and the safe reading of a malformed
    // grant is no grant. Widening it to `*` would turn a typo into permission
    // over everything, which is the wrong direction to guess in.
    let arg = arg.trim();
    if arg.is_empty() {
        return None;
    }
    Some((arg.to_owned(), access))
}

fn claude_facts(subject: &Subject, clock: &dyn Clock, home: &Path, facts: &mut Vec<Fact>) {
    let settings = home.join(".claude/settings.json");
    let probe = format!("{}", settings.display());
    if let Some(v) = read_json(&settings) {
        for (key, granted) in [("allow", true), ("deny", false)] {
            let Some(rules) = v
                .pointer(&format!("/permissions/{key}"))
                .and_then(Value::as_array)
            else {
                continue;
            };
            for rule in rules.iter().filter_map(Value::as_str) {
                if let Some((path, access)) = parse_permission_rule(rule) {
                    facts.extend(emit(
                        ID,
                        &probe,
                        Confidence::Certain,
                        clock,
                        subject.clone(),
                        Claim::PermissionDeclared {
                            path,
                            access,
                            granted,
                        },
                    ));
                }
            }
        }
        // Hooks run arbitrary commands on events, so a config with hooks grants
        // execution whatever its permission list says.
        if v.get("hooks").is_some_and(|h| !h.is_null()) {
            facts.extend(emit(
                ID,
                &probe,
                Confidence::Certain,
                clock,
                subject.clone(),
                Claim::PermissionDeclared {
                    path: "<event hooks>".to_owned(),
                    access: Access::Execute,
                    granted: true,
                },
            ));
        }
    }

    // The model an agent is configured to use is stated in its own settings.
    // Reading it from traffic is not possible without decrypting TLS, and
    // Topgent does not do that, so config is the honest source.
    if let Some(v) = read_json(&settings)
        && let Some(model) = v.get("model").and_then(Value::as_str)
    {
        facts.extend(emit(
            ID,
            &probe,
            Confidence::Certain,
            clock,
            subject.clone(),
            Claim::ModelInUse {
                provider: "anthropic".to_owned(),
                model: model.to_owned(),
            },
        ));
    }

    for mcp in [
        home.join(".claude/.mcp.json"),
        home.join("Library/Application Support/Claude/claude_desktop_config.json"),
    ] {
        let probe = format!("{}", mcp.display());
        let Some(v) = read_json(&mcp) else { continue };
        let Some(servers) = v.get("mcpServers").and_then(Value::as_object) else {
            continue;
        };
        for name in servers.keys() {
            facts.extend(emit(
                ID,
                &probe,
                Confidence::Certain,
                clock,
                subject.clone(),
                Claim::ConnectorDeclared {
                    name: name.clone(),
                    // What a connector can do is only knowable by asking it.
                    // Until Topgent does, the honest answer is read.
                    access: Access::Read,
                },
            ));
        }
    }
}

fn codex_facts(subject: &Subject, clock: &dyn Clock, home: &Path, facts: &mut Vec<Fact>) {
    let cfg = home.join(".codex/config.toml");
    let Ok(text) = std::fs::read_to_string(&cfg) else {
        return;
    };
    let probe = format!("{}", cfg.display());
    // Only the sandbox line is read, and only as a string. No TOML dependency
    // for one key, and nothing here is evaluated.
    if let Some(model) = text
        .lines()
        .filter_map(|l| l.split_once('='))
        .find(|(k, _)| k.trim() == "model")
        .map(|(_, v)| v.trim().trim_matches('"').to_owned())
        .filter(|m| !m.is_empty())
    {
        facts.extend(emit(
            ID,
            &probe,
            Confidence::Certain,
            clock,
            subject.clone(),
            Claim::ModelInUse {
                provider: "openai".to_owned(),
                model,
            },
        ));
    }

    let sandboxed = text
        .lines()
        .filter_map(|l| l.split_once('='))
        .any(|(k, v)| k.trim() == "sandbox_mode" && !v.contains("danger"));
    if sandboxed {
        // Record that a sandbox was declared, as a denied grant on the marker
        // path. The core reads this to know the agent claims to be confined, so
        // any reach beyond it is an escape signal rather than normal behaviour.
        facts.extend(emit(
            ID,
            &probe,
            Confidence::Likely,
            clock,
            subject.clone(),
            Claim::PermissionDeclared {
                path: "<sandbox>".to_owned(),
                access: Access::Execute,
                granted: false,
            },
        ));
    } else {
        facts.extend(emit(
            ID,
            &probe,
            Confidence::Likely,
            clock,
            subject.clone(),
            Claim::PermissionDeclared {
                path: "*".to_owned(),
                access: Access::Execute,
                granted: true,
            },
        ));
    }
}

impl Collector for ConfigCollector {
    fn id(&self) -> &'static str {
        ID
    }

    fn collect(&self, clock: &dyn Clock) -> Result<Vec<Fact>, CollectError> {
        let Some(home) = self.home.clone().or_else(home) else {
            return Err(CollectError::Unavailable {
                what: "HOME is not set".to_owned(),
            });
        };

        // Config is per family, and it attaches to every live process of that
        // family: two Claude Code sessions share one settings.json.
        let by_family: BTreeMap<&'static str, Vec<(u32, UnixMillis)>> = crate::process::snapshot()
            .into_iter()
            .fold(BTreeMap::new(), |mut acc, p| {
                if let Some(f) = p.family {
                    acc.entry(f).or_default().push((p.pid, p.started_at));
                }
                acc
            });

        let mut facts = Vec::new();
        for (family, procs) in &by_family {
            for (pid, started_at) in procs {
                let subject = Subject::Process {
                    pid: *pid,
                    started_at: *started_at,
                };
                match *family {
                    "claude-code" => claude_facts(&subject, clock, &home, &mut facts),
                    "codex-cli" => codex_facts(&subject, clock, &home, &mut facts),
                    _ => {}
                }
            }
        }
        Ok(facts)
    }
}

#[cfg(test)]
mod permission_rules {
    use super::{Access, parse_permission_rule};

    /// `Bash()` names nothing. Reported by the `config` fuzz target, which
    /// asserts that no rule it accepts carries an empty path.
    #[test]
    fn a_rule_naming_no_path_is_refused() {
        for rule in ["Bash()", "Write()", "Read(  )", "Edit(\t)", "Glob()"] {
            assert!(
                parse_permission_rule(rule).is_none(),
                "{rule} names no path and must not become a grant"
            );
        }
    }

    /// The bare form is the one that means everything, and it still does.
    #[test]
    fn a_bare_tool_still_means_every_path() {
        assert_eq!(
            parse_permission_rule("Bash"),
            Some(("*".to_owned(), Access::Execute))
        );
    }

    #[test]
    fn ordinary_rules_are_unchanged() {
        assert_eq!(
            parse_permission_rule("Bash(cargo *)"),
            Some(("cargo *".to_owned(), Access::Execute))
        );
        assert_eq!(
            parse_permission_rule("Write(/tmp/**)"),
            Some(("/tmp/**".to_owned(), Access::Write))
        );
        assert!(parse_permission_rule("Unknown(x)").is_none());
    }
}
