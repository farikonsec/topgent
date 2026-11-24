//! The workspace-exfiltration rule's numbers and lists, read from
//! `data/workspace-exfiltration.json`.

use std::sync::OnceLock;

use serde_json::Value;

pub(super) const CONFIG_JSON: &str = include_str!("../../data/workspace-exfiltration.json");

/// The rule's numbers, read from `data/workspace-exfiltration.json`, where
/// `thresholds_explained` says the same in words for anyone tuning them.
///
/// They are shipped, not user settings, on purpose: the settings file sits in
/// the home folder the watched agent can write, and an agent that could raise
/// these could blind the rule to itself.
#[derive(Debug, Clone)]
pub(crate) struct Thresholds {
    /// How long after the read ends traffic is still linked to it for the
    /// burst and total tests. Later traffic is left to the whole-run test.
    pub window_ms: u64,
    /// Files read under one root before it counts as a harvested workspace.
    /// Below this the rule does not look at the run at all.
    pub harvest_files: u32,
    /// The same for files from `.git` history, which hold deleted secrets, so
    /// a smaller read of it is enough.
    pub harvest_history_files: u32,
    /// Bytes sent inside the window to places other than the agent's own
    /// service that fire on their own, whatever the workspace's size.
    pub egress_bytes: u64,
    /// Connection attempts to one place that count as retrying, when that
    /// place also received at least [`RETRY_UPLOAD_BYTES`](super::exfiltration::RETRY_UPLOAD_BYTES).
    pub egress_attempts: u32,
    /// A burst to any other owner of at least this percent of the
    /// workspace's size fires. Archives compress, so this is well under 100.
    pub burst_percent_other: u64,
    /// The same for the agent's own service, where prompts legitimately carry
    /// parts of files: only about the whole workspace at once fires.
    pub burst_percent_own: u64,
    /// No burst below this many bytes fires, however small the workspace.
    pub burst_floor_bytes: u64,
    /// No burst to the agent's own service below this fires. A long session
    /// re-sends its context to the vendor all day, so on a small repository
    /// 100% alone would creep to a false alarm. The cost, stated on the card:
    /// a small upload to the agent's own vendor does not fire.
    pub own_service_floor_bytes: u64,
    /// Whole-run test: bytes sent to one other owner over the run's whole life
    /// after the read began fire at this percent of the workspace. Catches a
    /// slow trickle and pieces sent after the window closed. Higher than the
    /// burst's percent because a whole run also carries ordinary traffic.
    pub run_percent_other: u64,
    /// No whole-run total below this fires, so hours of telemetry to one
    /// service stay quiet.
    pub run_floor_bytes: u64,
    /// After reading a secret, how long an outbound burst is still linked to
    /// it. A secret file is small and leaves in one request, so this is short.
    pub secret_egress_window_ms: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct Config {
    pub rule: String,
    pub summary: String,
    pub thresholds: Thresholds,
    pub model_services: Vec<String>,
    pub object_storage: Vec<String>,
}

/// The shipped configuration, or `None` when it does not parse.
pub(super) fn parse(text: &str) -> Option<Config> {
    let value: Value = serde_json::from_str(text).ok()?;
    let t = value.get("thresholds")?;
    let n = |f: &str| t.get(f).and_then(Value::as_u64);
    let list = |f: &str| -> Option<Vec<String>> {
        value
            .get(f)?
            .as_array()?
            .iter()
            .map(|v| v.as_str().map(str::to_ascii_lowercase))
            .collect()
    };
    Some(Config {
        rule: value.get("rule")?.as_str()?.to_owned(),
        summary: value.get("summary")?.as_str()?.to_owned(),
        thresholds: Thresholds {
            window_ms: n("window_ms")?,
            harvest_files: u32::try_from(n("harvest_files")?).ok()?,
            harvest_history_files: u32::try_from(n("harvest_history_files")?).ok()?,
            egress_bytes: n("egress_bytes")?,
            egress_attempts: u32::try_from(n("egress_attempts")?).ok()?,
            burst_percent_other: n("burst_percent_other")?,
            burst_percent_own: n("burst_percent_own")?,
            burst_floor_bytes: n("burst_floor_bytes")?,
            own_service_floor_bytes: n("own_service_floor_bytes")?,
            run_percent_other: n("run_percent_other")?,
            run_floor_bytes: n("run_floor_bytes")?,
            secret_egress_window_ms: n("secret_egress_window_ms").unwrap_or(600_000),
        },
        model_services: list("model_services")?,
        object_storage: list("object_storage")?,
    })
}

pub(crate) fn config() -> &'static Config {
    static CONFIG: OnceLock<Config> = OnceLock::new();
    CONFIG.get_or_init(|| {
        parse(CONFIG_JSON).unwrap_or_else(|| Config {
            // The shipped file is checked by a test; this is never reached
            // in a build that passed it, and is safe if it were: no service
            // is excluded and nothing is called object storage.
            rule: "WORKSPACE_EXFILTRATION".into(),
            summary: String::new(),
            thresholds: Thresholds {
                window_ms: 1_800_000,
                harvest_files: 500,
                harvest_history_files: 50,
                egress_bytes: 10 * 1024 * 1024,
                egress_attempts: 20,
                burst_percent_other: 20,
                burst_percent_own: 100,
                burst_floor_bytes: 256 * 1024,
                own_service_floor_bytes: 32_000_000,
                run_percent_other: 50,
                run_floor_bytes: 1024 * 1024,
                secret_egress_window_ms: 600_000,
            },
            model_services: Vec::new(),
            object_storage: Vec::new(),
        })
    })
}

/// Whether `name` is object storage by the configured patterns.
pub(crate) fn object_storage(name: &str, patterns: &[String]) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    patterns.iter().any(|pattern| {
        if let Some((prefix, suffix)) = pattern.split_once("*.") {
            let Some(head) = name.strip_suffix(&format!(".{suffix}")) else {
                return false;
            };
            head.split('.').any(|label| label.starts_with(prefix))
        } else {
            name == *pattern || name.ends_with(&format!(".{pattern}"))
        }
    })
}
