//! What Topgent can see on this host, and what it cannot.
//!
//! A green row is not the same as full coverage. Each sensor reports its state,
//! the permission it would need, what a healthy run still cannot supply here,
//! and genuine dropped-event counters where the sensor keeps them and nothing
//! where it does not. The binaries the sensors run are reported alongside them,
//! because a sensor is only as trustworthy as the program behind it.

use serde_json::{Value, json};
use topgent_collect::CollectorRun;
use topgent_journal::Journal;

pub(crate) fn sensor_health(
    runs: &[CollectorRun],
    generated_at: u64,
    journal: &Journal,
) -> Vec<Value> {
    let mut sensors = runs
        .iter()
        .map(|run| {
            let history = journal.record_sensor_health(
                run.collector,
                run.state.as_str(),
                generated_at,
                run.fact_count,
                run.dropped_events,
                run.detail.as_deref(),
            );
            let persistent = history.is_ok();
            let history = history.ok();
            json!({
                "id": run.collector,
                "state": run.state.as_str(),
                "fact_count": run.fact_count,
                "duration_ms": run.duration_ms,
                "detail": run.detail,
                "last_observed_at": history.as_ref().map_or(generated_at, |record| record.last_observed_at),
                "last_successful_sweep": history.as_ref().and_then(|record| record.last_success_at),
                "last_error_at": history.as_ref().and_then(|record| record.last_error_at),
                "consecutive_failures": history.as_ref().map_or(u64::from(run.state != topgent_collect::CapabilityState::Available), |record| record.consecutive_failures),
                "total_runs": history.as_ref().map_or(1, |record| record.total_runs),
                "total_facts": history.as_ref().map_or(u64::try_from(run.fact_count).unwrap_or(u64::MAX), |record| record.total_facts),
                "history_persistent": persistent,
                "permission": sensor_permission(run.collector, std::env::consts::OS),
                "dropped_events": history.as_ref().and_then(|record| record.dropped_events).or(run.dropped_events),
                // Available is not the same as complete: a healthy sensor that
                // the platform only lets see part of the picture says so here.
                "boundary": run.boundary,
                "version": env!("CARGO_PKG_VERSION"),
            })
        })
        .collect::<Vec<_>>();
    for (id, detail, permission) in [
        (
            "filesystem_events",
            "No filesystem event sensor is installed.",
            "optional enhanced sensor",
        ),
        (
            "network_events",
            "No connection-lifecycle sensor is installed; socket snapshots remain available.",
            "optional enhanced sensor",
        ),
        (
            "dns_events",
            "No per-process DNS event sensor is installed.",
            "optional enhanced sensor",
        ),
    ] {
        if sensors.iter().any(|sensor| sensor["id"] == id) {
            continue;
        }
        sensors.push(json!({
            "id": id, "state": "unsupported", "fact_count": 0, "duration_ms": 0,
            "detail": detail, "last_successful_sweep": Value::Null,
            "last_observed_at": Value::Null, "last_error_at": Value::Null,
            "consecutive_failures": 0, "total_runs": 0, "total_facts": 0,
            "history_persistent": true,
            "permission": permission, "dropped_events": Value::Null,
            "boundary": Value::Null,
            "version": env!("CARGO_PKG_VERSION"),
        }));
    }
    sensors
}

/// What Topgent can say about the binaries its own sensors run.
///
/// Every collector shells out to an operating-system tool. Resolving those
/// through `PATH` would let anything running as the user choose what Topgent
/// reads, so each one is bound to a location the operating system owns, and
/// what was found is reported here rather than assumed. A tool changing state
/// between sweeps is itself a finding, so the change survives a restart.
pub(crate) fn tool_attestations(generated_at: u64, journal: &Journal) -> Vec<Value> {
    topgent_collect::tool::attestations()
        .into_iter()
        .map(|attestation| {
            let history = journal
                .record_tool_attestation(
                    attestation.name,
                    attestation.state.as_str(),
                    attestation.path.as_deref(),
                    generated_at,
                )
                .ok();
            json!({
                "name": attestation.name,
                "state": attestation.state.as_str(),
                "path": attestation.path,
                "first_seen_at": history.as_ref().map(|record| record.first_seen_at),
                "previous_state": history.as_ref().and_then(|record| record.previous_state.clone()),
                "changed_at": history.as_ref().and_then(|record| record.changed_at),
                "history_persistent": history.is_some(),
            })
        })
        .collect()
}

pub(crate) fn sensor_permission(collector: &str, os: &str) -> &'static str {
    match (collector, os) {
        ("filesystem_events" | "network_events", "windows") => {
            "read access to Windows Security event log"
        }
        // Off by default, and Topgent never turns it on: enabling a log is the
        // operator's decision, not a monitor's.
        // Bound by an open descriptor the operating system reports, which
        // Windows does not expose to a standard user.
        ("editor_extensions", "linux" | "macos") => "standard user",
        ("editor_extensions", _) => "unsupported on this platform",
        ("dns_events", "windows") => {
            "Microsoft-Windows-DNS-Client/Operational enabled by an administrator"
        }
        ("filesystem_events" | "network_events" | "dns_events", "linux") => {
            "read access to Linux Audit log"
        }
        ("filesystem_events" | "network_events" | "dns_events", _) => "optional enhanced sensor",
        _ => "standard user",
    }
}

/// Which rules this machine can actually detect, and how well.
///
/// Read from the factor catalogue, so the coverage table and the legend cannot
/// list different rules. They previously carried separate hard-coded orderings
/// of the same twenty rules; the coverage table now follows the legend, which
/// is severity-first — a reader wants to know whether the worst rules are
/// covered before the routine ones.
pub(crate) fn detection_coverage(runs: &[CollectorRun]) -> Vec<Value> {
    let Ok(catalogue) = topgent_policy::catalogue::builtin() else {
        // A build that cannot read its own catalogue claims no coverage, which
        // is the truthful answer and the one that shows up as a problem.
        return Vec::new();
    };
    let collector_state = |id: &str| {
        runs.iter()
            .find(|run| run.collector == id)
            .map_or("unsupported", |run| run.state.as_str())
    };
    catalogue
        .factors
        .iter()
        .map(|factor| {
            let sensor = factor.sensor.as_str();
            let mut state = collector_state(sensor);
            // A factor can be capped below what its sensor reports, where the
            // sensor alone is not enough to show the factor working.
            if let Some(ceiling) = factor.coverage_ceiling.as_deref()
                && state == "available"
            {
                state = ceiling;
            }
            // Filesystem evidence has only ever been produced against captured
            // sensor output, so it says fixture when it is working at all.
            let verification = if sensor == "filesystem_events" {
                if state == "available" {
                    "fixture"
                } else {
                    "unavailable"
                }
            } else {
                factor.verification.as_str()
            };
            json!({
                "rule": factor.code, "sensor": sensor, "state": state,
                "verification": verification, "last_verified_at": Value::Null,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{detection_coverage, sensor_permission};

    #[test]
    fn coverage_lists_every_rule_the_legend_does_in_the_same_order() {
        // Two orderings of the same twenty rules is how a reader ends up
        // comparing the wrong row against the wrong sensor.
        let catalogue = topgent_policy::catalogue::builtin().expect("catalogue loads");
        let rows = detection_coverage(&[]);
        let listed: Vec<&str> = rows
            .iter()
            .filter_map(|row| row.get("rule").and_then(serde_json::Value::as_str))
            .collect();
        let declared: Vec<&str> = catalogue
            .factors
            .iter()
            .map(|factor| factor.code.as_str())
            .collect();
        assert_eq!(listed, declared);
    }

    #[test]
    fn a_rule_whose_sensor_never_ran_is_unsupported_rather_than_covered() {
        // The failure that matters: no sensor runs, so nothing is detectable,
        // and an empty coverage table would read as nothing being wrong.
        let rows = detection_coverage(&[]);
        assert_eq!(rows.len(), 20);
        for row in &rows {
            assert_eq!(
                row.get("state").and_then(serde_json::Value::as_str),
                Some("unsupported"),
                "{row}"
            );
        }
    }

    #[test]
    fn enhanced_sensor_permissions_are_platform_specific() {
        assert_eq!(
            sensor_permission("filesystem_events", "windows"),
            "read access to Windows Security event log"
        );
        assert_eq!(
            sensor_permission("network_events", "windows"),
            "read access to Windows Security event log"
        );
        assert_eq!(
            sensor_permission("network_events", "linux"),
            "read access to Linux Audit log"
        );
        assert_eq!(
            sensor_permission("dns_events", "macos"),
            "optional enhanced sensor"
        );
        // Off by default, and Topgent never turns it on: enabling a log is the
        // operator's decision, so the report asks rather than acts.
        assert_eq!(
            sensor_permission("dns_events", "windows"),
            "Microsoft-Windows-DNS-Client/Operational enabled by an administrator"
        );
        // Reading which process holds a log open needs no elevation where the
        // operating system will say, and cannot be done at all where it will
        // not.
        assert_eq!(
            sensor_permission("editor_extensions", "macos"),
            "standard user"
        );
        assert_eq!(
            sensor_permission("editor_extensions", "linux"),
            "standard user"
        );
        assert_eq!(
            sensor_permission("editor_extensions", "windows"),
            "unsupported on this platform"
        );
        assert_eq!(sensor_permission("process", "windows"), "standard user");
    }
}
