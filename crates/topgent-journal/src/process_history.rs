//! Process history kept between sweeps.
//!
//! A process that exits between two sweeps takes its place in its agent's
//! tree with it, unless something wrote that place down. This is where it is
//! written down: identity, parent, name and when it was seen. No arguments,
//! no environment, and program names without their paths.

use serde_json::{Value, json};
use topgent_core::lineage::{Lineage, ProcessKey, ProcessRecord};
use topgent_facts::UnixMillis;

use crate::text::{program_path, sanitize};

/// Most processes kept in history.
pub const MAX_PROCESS_HISTORY: usize = 2_048;

fn key_json(key: ProcessKey) -> Value {
    json!({ "pid": key.pid, "started_at": key.started_at.0 })
}

fn key_from(value: &Value) -> Option<ProcessKey> {
    Some(ProcessKey {
        pid: u32::try_from(value.get("pid")?.as_u64()?).ok()?,
        started_at: UnixMillis(value.get("started_at")?.as_u64()?),
    })
}

fn millis(value: &Value, name: &str) -> Option<UnixMillis> {
    value.get(name).and_then(Value::as_u64).map(UnixMillis)
}

pub(crate) fn process_history_json(lineage: &Lineage) -> Value {
    Value::Array(
        lineage
            .records()
            .map(|record| {
                json!({
                    "key": key_json(record.key),
                    "name": record.name,
                    "parent": record.parent.map(key_json),
                    "parent_pid": record.parent_pid,
                    "reparented": record.reparented,
                    "crossed_namespace": record.crossed_namespace,
                    "pid_namespace": record.pid_namespace,
                    "exe": record.exe,
                    "previous_exes": record.previous_exes,
                    "exec_generation": record.exec_generation,
                    "program_unread": record.program_unread,
                    "first_seen": record.first_seen.0,
                    "last_seen": record.last_seen.0,
                    "gone_after": record.gone_after.map(|at| at.0),
                    "exited_at": record.exited_at.map(|at| at.0),
                    "exit_code": record.exit_code,
                    "from_event": record.from_event,
                })
            })
            .collect(),
    )
}

fn record_from(value: &Value) -> Option<ProcessRecord> {
    let text = |name: &str| {
        value
            .get(name)
            .and_then(Value::as_str)
            .map(|s| sanitize(s, 255))
    };
    Some(ProcessRecord {
        key: key_from(value.get("key")?)?,
        name: text("name")?,
        parent: value.get("parent").and_then(key_from),
        parent_pid: value
            .get("parent_pid")
            .and_then(Value::as_u64)
            .and_then(|pid| u32::try_from(pid).ok()),
        reparented: value.get("reparented")?.as_bool()?,
        crossed_namespace: value.get("crossed_namespace")?.as_bool()?,
        pid_namespace: value.get("pid_namespace").and_then(Value::as_u64),
        exe: value
            .get("exe")
            .and_then(Value::as_str)
            .map(|s| program_path(s, 255)),
        previous_exes: value
            .get("previous_exes")?
            .as_array()?
            .iter()
            .filter_map(Value::as_str)
            .take(8)
            .map(|s| program_path(s, 255))
            .collect(),
        exec_generation: u32::try_from(value.get("exec_generation")?.as_u64()?).ok()?,
        program_unread: value
            .get("program_unread")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        first_seen: millis(value, "first_seen")?,
        last_seen: millis(value, "last_seen")?,
        gone_after: millis(value, "gone_after"),
        exited_at: millis(value, "exited_at"),
        exit_code: value
            .get("exit_code")
            .and_then(Value::as_u64)
            .and_then(|code| u32::try_from(code).ok()),
        // Absent in history written before S5, which had no kernel events.
        from_event: value
            .get("from_event")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

/// Rebuilds history from its stored form. Malformed records are dropped, and
/// the bound applies however many the file holds.
pub(crate) fn process_history_from_json(value: &Value) -> Lineage {
    let mut lineage = Lineage::new(MAX_PROCESS_HISTORY);
    for record in value
        .as_array()
        .into_iter()
        .flatten()
        .take(MAX_PROCESS_HISTORY * 2)
        .filter_map(record_from)
    {
        lineage.restore(record);
    }
    lineage.settle();
    lineage
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{MAX_PROCESS_HISTORY, process_history_from_json, process_history_json};
    use serde_json::json;
    use std::collections::BTreeSet;
    use topgent_core::lineage::{Lineage, Observation, ProcessKey};
    use topgent_facts::UnixMillis;

    fn seen(pid: u32, start: u64, parent: Option<u32>) -> Observation {
        Observation {
            key: ProcessKey {
                pid,
                started_at: UnixMillis(start),
            },
            parent_pid: parent,
            name: format!("p{pid}"),
            exe: Some("sh".to_owned()),
            pid_namespace: Some(4_026_531_836),
            at: UnixMillis(start),
            from_event: true,
        }
    }

    #[test]
    fn history_round_trips_with_parents_and_endings() {
        let mut lineage = Lineage::new(64);
        lineage.observe(seen(1, 10, None));
        lineage.observe(seen(2, 20, Some(1)));
        lineage.observe(seen(3, 30, Some(2)));
        lineage.missing(
            &BTreeSet::from([ProcessKey {
                pid: 1,
                started_at: UnixMillis(10),
            }]),
            UnixMillis(40),
        );
        let back = process_history_from_json(&process_history_json(&lineage));
        assert_eq!(
            back.records().cloned().collect::<Vec<_>>(),
            lineage.records().cloned().collect::<Vec<_>>()
        );
    }

    #[test]
    fn hostile_or_malformed_records_are_dropped_not_trusted() {
        let value = json!([
            {"key": {"pid": 1, "started_at": 10}, "name": "ok", "reparented": false,
             "crossed_namespace": false, "previous_exes": [], "exec_generation": 0,
             "first_seen": 10, "last_seen": 10},
            {"key": {"pid": 99_999_999_999_u64, "started_at": 10}, "name": "bad pid"},
            {"key": "not a key"},
            "not a record",
        ]);
        let back = process_history_from_json(&value);
        assert_eq!(back.len(), 1);
    }

    #[test]
    fn a_huge_file_is_bounded_on_load() {
        let records = (0..MAX_PROCESS_HISTORY as u64 + 500)
            .map(|n| {
                json!({"key": {"pid": n, "started_at": n}, "name": "x", "reparented": false,
                       "crossed_namespace": false, "previous_exes": [], "exec_generation": 0,
                       "first_seen": n, "last_seen": n, "exited_at": n})
            })
            .collect::<Vec<_>>();
        assert!(process_history_from_json(&json!(records)).len() <= MAX_PROCESS_HISTORY);
    }

    #[test]
    fn stored_executable_paths_are_kept_without_storing_arguments() {
        let value = json!([{
            "key": {"pid": 7, "started_at": 10},
            "name": "python3",
            "reparented": false,
            "crossed_namespace": false,
            "exe": "/usr/local/bin/python3",
            "previous_exes": ["/bin/sh"],
            "exec_generation": 1,
            "first_seen": 10,
            "last_seen": 10
        }]);
        let back = process_history_from_json(&value);
        let record = back.records().next().expect("stored process");
        assert_eq!(record.exe.as_deref(), Some("/usr/local/bin/python3"));
        assert_eq!(record.previous_exes, ["/bin/sh"]);
    }
}
