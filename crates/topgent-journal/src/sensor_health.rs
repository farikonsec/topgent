//! Collector health, kept across restarts.
//!
//! A sensor that failed once and recovered is a different thing from one that
//! has never worked, and a later failure must not erase the last time a sensor
//! did see something. The history holds both, along with genuine dropped-event
//! counters where the sensor supplies them and nothing where it does not.

use crate::text::bounded_metadata;
use serde_json::{Value, json};

/// Maximum retained collector-health identities.
pub const MAX_SENSOR_HEALTH_RECORDS: usize = 64;

/// Durable aggregate health for one stable collector identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensorHealthRecord {
    /// Stable collector ID.
    pub id: String,
    /// Most recently observed capability state.
    pub state: String,
    /// Most recent sweep timestamp.
    pub last_observed_at: u64,
    /// Most recent successful sweep, retained across later failures.
    pub last_success_at: Option<u64>,
    /// Most recent failed sweep.
    pub last_error_at: Option<u64>,
    /// Consecutive non-available runs.
    pub consecutive_failures: u64,
    /// Total persisted runs observed.
    pub total_runs: u64,
    /// Total admissible facts emitted across persisted runs.
    pub total_facts: u64,
    /// Latest genuine sensor-supplied cumulative dropped-event counter.
    pub dropped_events: Option<u64>,
    /// Sanitized latest failure detail.
    pub detail: Option<String>,
}

pub(crate) fn sensor_health_json(record: &SensorHealthRecord) -> Value {
    json!({
        "id": record.id,
        "state": record.state,
        "last_observed_at": record.last_observed_at,
        "last_success_at": record.last_success_at,
        "last_error_at": record.last_error_at,
        "consecutive_failures": record.consecutive_failures,
        "total_runs": record.total_runs,
        "total_facts": record.total_facts,
        "dropped_events": record.dropped_events,
        "detail": record.detail,
    })
}

pub(crate) fn sensor_health_from_json(value: &Value) -> Option<SensorHealthRecord> {
    let id = value.get("id")?.as_str()?.to_owned();
    if id.is_empty() || id.chars().count() > 96 || bounded_metadata(&id, 96) != id {
        return None;
    }
    let state = value.get("state")?.as_str()?.to_owned();
    if !matches!(
        state.as_str(),
        "available" | "unsupported" | "permission_required" | "error"
    ) {
        return None;
    }
    let last_observed_at = value.get("last_observed_at")?.as_u64()?;
    let last_success_at = value.get("last_success_at").and_then(Value::as_u64);
    let last_error_at = value.get("last_error_at").and_then(Value::as_u64);
    if last_success_at.is_some_and(|at| at > last_observed_at)
        || last_error_at.is_some_and(|at| at > last_observed_at)
    {
        return None;
    }
    Some(SensorHealthRecord {
        id,
        state,
        last_observed_at,
        last_success_at,
        last_error_at,
        consecutive_failures: value.get("consecutive_failures")?.as_u64()?,
        total_runs: value.get("total_runs")?.as_u64()?,
        total_facts: value.get("total_facts")?.as_u64()?,
        dropped_events: value.get("dropped_events").and_then(Value::as_u64),
        detail: value
            .get("detail")
            .and_then(Value::as_str)
            .map(|detail| bounded_metadata(detail, 512)),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use crate::MAX_SENSOR_HEALTH_RECORDS;
    use crate::journal::Journal;
    use crate::test_support::test_dir;

    #[test]
    fn sensor_health_survives_restart_and_preserves_success_and_drop_truth() -> std::io::Result<()>
    {
        let dir = test_dir("sensor-health");
        let journal = Journal::at(&dir);
        let healthy = journal.record_sensor_health(
            "filesystem_events",
            "available",
            1_000,
            3,
            Some(2),
            None,
        )?;
        assert_eq!(healthy.last_success_at, Some(1_000));
        assert_eq!(healthy.consecutive_failures, 0);

        let failed = Journal::at(&dir).record_sensor_health(
            "filesystem_events",
            "permission_required",
            2_000,
            0,
            None,
            Some("audit log denied\nsecret-looking detail"),
        )?;
        assert_eq!(failed.last_success_at, Some(1_000));
        assert_eq!(failed.last_error_at, Some(2_000));
        assert_eq!(failed.consecutive_failures, 1);
        assert_eq!(failed.total_runs, 2);
        assert_eq!(failed.total_facts, 3);
        assert_eq!(failed.dropped_events, Some(2));
        assert!(!failed.detail.as_deref().unwrap_or_default().contains('\n'));

        let recovered = journal.record_sensor_health(
            "filesystem_events",
            "available",
            3_000,
            1,
            Some(4),
            None,
        )?;
        assert_eq!(recovered.last_success_at, Some(3_000));
        assert_eq!(recovered.last_error_at, Some(2_000));
        assert_eq!(recovered.consecutive_failures, 0);
        assert_eq!(recovered.total_runs, 3);
        assert_eq!(recovered.total_facts, 4);
        assert_eq!(recovered.dropped_events, Some(4));

        for index in 0..=MAX_SENSOR_HEALTH_RECORDS {
            journal.record_sensor_health(
                &format!("fixture-{index:03}"),
                "available",
                4_000 + u64::try_from(index).unwrap_or(u64::MAX),
                0,
                None,
                None,
            )?;
        }
        assert_eq!(
            journal.sensor_health_records()?.len(),
            MAX_SENSOR_HEALTH_RECORDS
        );

        std::fs::write(
            journal.sensor_health_path(),
            r#"[{"id":"forged","state":"healthy"}]"#,
        )?;
        assert!(journal.sensor_health_records()?.is_empty());
        let _ = std::fs::remove_dir_all(dir);
        Ok(())
    }
}
