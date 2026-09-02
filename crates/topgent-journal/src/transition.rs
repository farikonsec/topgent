//! Rising and falling edges of a policy response.
//!
//! A rule that matches on every sweep is one finding, not one per sweep. These
//! records turn a stream of identical observations into the moments that
//! actually changed: triggered, suppressed, recovered, and a later retrigger
//! after a restart.

use crate::text::bounded_metadata;
use serde_json::{Value, json};

/// Maximum retained response-transition identities.
pub const MAX_RESPONSE_TRANSITIONS: usize = 512;

/// Durable rising-edge state for one exact agent/rule response decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseTransition {
    /// Stable bounded exact-agent and rule key.
    pub key: String,
    /// Whether the rule was matched in its latest evaluated sweep.
    pub active: bool,
    /// Latest evaluation time.
    pub last_seen_at: u64,
    /// Time at which active/inactive state last changed.
    pub last_changed_at: u64,
    /// Number of inactive-to-active transitions.
    pub trigger_count: u64,
}

pub(crate) fn response_transition_json(record: &ResponseTransition) -> Value {
    json!({
        "key": record.key,
        "active": record.active,
        "last_seen_at": record.last_seen_at,
        "last_changed_at": record.last_changed_at,
        "trigger_count": record.trigger_count,
    })
}

pub(crate) fn response_transition_from_json(value: &Value) -> Option<ResponseTransition> {
    let key = value.get("key")?.as_str()?.to_owned();
    if key.is_empty() || key.chars().count() > 512 || bounded_metadata(&key, 512) != key {
        return None;
    }
    let last_seen_at = value.get("last_seen_at")?.as_u64()?;
    let last_changed_at = value.get("last_changed_at")?.as_u64()?;
    if last_changed_at > last_seen_at {
        return None;
    }
    Some(ResponseTransition {
        key,
        active: value.get("active")?.as_bool()?,
        last_seen_at,
        last_changed_at,
        trigger_count: value.get("trigger_count")?.as_u64()?,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use crate::journal::Journal;
    use crate::test_support::test_dir;

    #[test]
    fn response_transitions_are_rising_edge_restart_and_recovery_safe() -> std::io::Result<()> {
        let dir = test_dir("response-transition");
        let journal = Journal::at(&dir);
        let key = "response:42:1000:0:alert:100:write:/tmp/canary";
        let (first, record) = journal.record_response_transition(key, true, 1_000)?;
        assert_eq!(first, "triggered");
        assert_eq!(record.trigger_count, 1);
        let (repeat, record) = Journal::at(&dir).record_response_transition(key, true, 2_000)?;
        assert_eq!(repeat, "suppressed");
        assert_eq!(record.last_changed_at, 1_000);
        assert_eq!(record.trigger_count, 1);
        let (recovered, record) = journal.record_response_transition(key, false, 3_000)?;
        assert_eq!(recovered, "recovered");
        assert_eq!(record.last_changed_at, 3_000);
        let (retriggered, record) = journal.record_response_transition(key, true, 4_000)?;
        assert_eq!(retriggered, "triggered");
        assert_eq!(record.trigger_count, 2);

        let changed_rule = format!("{key}:edited");
        assert_eq!(
            journal
                .record_response_transition(&changed_rule, true, 4_100)?
                .0,
            "triggered"
        );
        let changed_identity = key.replacen("42:1000", "42:2000", 1);
        assert_eq!(
            journal
                .record_response_transition(&changed_identity, true, 4_200)?
                .0,
            "triggered"
        );
        std::fs::write(
            journal.response_transition_path(),
            r#"[{"key":"forged","active":true,"last_seen_at":1,"last_changed_at":2,"trigger_count":1}]"#,
        )?;
        assert!(journal.response_transitions()?.is_empty());
        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }

    /// The finding: every journal writer named its scratch file
    /// `<record>.<pid>.tmp`, so two writers inside one process collided on it.
    /// Both created it, one renamed it away, and the other's rename failed with
    /// the file gone. The visible symptom was a response decision reported with
    /// transition `unknown` and `transition_persistent: false` — the audit log
    /// silently failing to record a state change — plus orphaned `.tmp` files.
    ///
    /// Surfaced on a Kali lab host, where two report tests running in parallel
    /// each drove a real sweep against the shared default journal, and did not
    /// reproduce on the faster development machine.
    #[test]
    fn concurrent_writers_in_one_process_do_not_lose_a_record() {
        let dir = test_dir("response-transition-concurrent");
        let journal = Journal::at(&dir);

        std::thread::scope(|scope| {
            for index in 0..8_u32 {
                let journal = &journal;
                scope.spawn(move || {
                    for round in 0..4_u64 {
                        journal
                            .record_response_transition(
                                &format!("response:{index}:1000:0:alert:100:write:/tmp/canary"),
                                round % 2 == 0,
                                1_000 + round,
                            )
                            .unwrap_or_else(|error| {
                                panic!("writer {index} lost a record: {error}")
                            });
                    }
                });
            }
        });

        let records = journal
            .response_transitions()
            .expect("the journal is readable");
        let keys = records
            .iter()
            .map(|record| record.key.clone())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(keys.len(), 8, "a writer's key vanished: {keys:?}");

        // Nothing left lying about in the state directory.
        let orphans = std::fs::read_dir(&dir)
            .expect("the directory exists")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp"))
            .collect::<Vec<_>>();
        assert!(orphans.is_empty(), "scratch files survived: {orphans:?}");

        let _ = std::fs::remove_dir_all(dir);
    }
}
