//! How long a guarded response waits before it may act on the same target.
//!
//! Two surfaces can decide to stop the same agent at the same moment, and a
//! response signalled twice is a response nobody asked for. The cooldown is
//! keyed on the exact run and the response scope, so a reused pid inherits
//! nothing and two different responses to one agent do not block each other.

use crate::text::bounded_metadata;
use serde_json::{Value, json};

/// Maximum retained guarded-response cooldown records.
pub const MAX_RESPONSE_COOLDOWNS: usize = 256;

/// One durable cooldown preventing repeated response attempts against the same
/// exact process identity during a bounded cooldown window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseCooldown {
    /// Target process identifier.
    pub pid: u32,
    /// Target process start time, preventing inheritance across PID reuse.
    pub started_at: u64,
    /// Sanitized response scope, such as `termination`.
    pub scope: String,
    /// Time at which Topgent recorded the response attempt.
    pub acquired_at: u64,
    /// Earliest time at which another attempt may acquire the same lease.
    pub retry_after: u64,
}

pub(crate) fn response_cooldown_json(record: &ResponseCooldown) -> Value {
    json!({
        "pid": record.pid,
        "started_at": record.started_at,
        "scope": record.scope,
        "acquired_at": record.acquired_at,
        "retry_after": record.retry_after,
    })
}

pub(crate) fn response_cooldown_from_json(value: &Value) -> Option<ResponseCooldown> {
    let scope = value.get("scope")?.as_str()?.to_owned();
    if scope.is_empty() || scope.chars().count() > 64 || bounded_metadata(&scope, 64) != scope {
        return None;
    }
    let acquired_at = value.get("acquired_at")?.as_u64()?;
    let retry_after = value.get("retry_after")?.as_u64()?;
    (retry_after > acquired_at).then_some(ResponseCooldown {
        pid: u32::try_from(value.get("pid")?.as_u64()?).ok()?,
        started_at: value.get("started_at")?.as_u64()?,
        scope,
        acquired_at,
        retry_after,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use crate::MAX_RESPONSE_COOLDOWNS;
    use crate::journal::Journal;
    use crate::test_support::test_dir;

    #[test]
    fn response_cooldown_is_durable_exact_identity_scoped_and_bounded() -> std::io::Result<()> {
        let dir = test_dir("response-cooldown");
        let journal = Journal::at(&dir);

        assert_eq!(
            journal.acquire_response_cooldown(42, 1_000, "termination", 2_000, 500)?,
            None
        );
        assert_eq!(
            Journal::at(&dir).acquire_response_cooldown(42, 1_000, "termination", 2_100, 500)?,
            Some(2_500),
            "a second journal instance must observe the durable cooldown"
        );
        assert_eq!(
            journal.acquire_response_cooldown(42, 1_001, "termination", 2_100, 500)?,
            None,
            "PID reuse must not inherit an earlier process cooldown"
        );
        assert_eq!(
            journal.acquire_response_cooldown(42, 1_000, "container-stop", 2_100, 500)?,
            None,
            "independent response scopes must not block one another"
        );
        assert_eq!(
            journal.acquire_response_cooldown(42, 1_000, "termination", 2_500, 500)?,
            None,
            "the boundary instant begins a new window"
        );

        std::fs::write(
            journal.response_cooldown_path(),
            r#"[{"pid":42,"started_at":1000,"scope":"termination","acquired_at":1,"retry_after":2},{"scope":"forged"}]"#,
        )?;
        assert_eq!(
            journal.acquire_response_cooldown(42, 1_000, "termination", 1, 500)?,
            Some(2),
            "malformed members are skipped without discarding valid cooldowns"
        );
        for index in 0..=MAX_RESPONSE_COOLDOWNS {
            journal.acquire_response_cooldown(
                u32::try_from(index).unwrap_or(u32::MAX),
                9_000,
                "termination",
                10_000 + u64::try_from(index).unwrap_or(u64::MAX),
                100_000,
            )?;
        }
        let retained = journal.response_cooldowns()?;
        assert_eq!(retained.len(), MAX_RESPONSE_COOLDOWNS);
        assert!(!retained.iter().any(|record| record.pid == 0));
        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }
}
