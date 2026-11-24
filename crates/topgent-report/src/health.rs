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

/// How this executable and its narrow Linux helpers are laid out on disk.
#[must_use]
pub fn deployment() -> Value {
    // Diagnostic only: adjacent helpers are independently checked before use.
    let executable = std::env::current_exe().ok(); // nosemgrep: rust.lang.security.current-exe.current-exe
    deployment_at(executable.as_deref(), std::env::consts::OS)
}

fn deployment_at(executable: Option<&std::path::Path>, os: &str) -> Value {
    let directory = executable.and_then(std::path::Path::parent);
    let mode = directory.map_or("unknown", |path| {
        let parts = path
            .components()
            .map(|part| part.as_os_str().to_string_lossy())
            .collect::<Vec<_>>();
        if parts.windows(2).any(|window| window == ["lib", "topgent"]) {
            "versioned_user_install"
        } else {
            "portable_or_source"
        }
    });
    let helpers = if os == "linux" {
        ["topgent-capture", "topgent-sensor"]
            .into_iter()
            .map(|name| {
                let path = directory.map(|directory| directory.join(name));
                let state = path.as_deref().map_or("missing", |path| {
                    if !path.is_file() {
                        "missing"
                    } else if !topgent_collect::capture::helper::safe_to_run(path) {
                        "unsafe_permissions"
                    } else if topgent_collect::capture::helper::runnable_by_others(path) {
                        "exposed_to_other_users"
                    } else {
                        "ready"
                    }
                });
                json!({"name": name, "state": state, "path": path})
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let kernel = (os == "linux")
        .then(|| std::fs::read_to_string("/proc/sys/kernel/osrelease").ok())
        .flatten()
        .map(|value| value.trim().to_owned());
    json!({
        "mode": mode,
        "executable": executable,
        "kernel": kernel,
        "helpers": helpers,
    })
}

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
                "dropped_events": run.dropped_events,
                "collection_coverage": crate::evidence::coverage_for(run).as_str(),
                "loss_accounting": loss_accounting(run.collector),
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
            "collection_coverage": "unsupported", "loss_accounting": "No sensor installed",
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
        ("capture", "linux") => "CAP_NET_RAW on the capture helper",
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

/// What a sensor's loss figure covers, in words.
fn loss_accounting(collector: &str) -> &'static str {
    match collector {
        "capture" => "Accumulator only; upstream loss is unmeasured",
        "process_events" => {
            "Per interval: kernel messages missing from each CPU's numbering, socket overflows \
             and this side's buffer. Time the sensor was not running, or ran \
             without reporting for over 3 s, makes that interval not continuous; it is not \
             counted as loss"
        }
        _ => "End-to-end loss is unmeasured",
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::indexing_slicing)]

    use super::{detection_coverage, sensor_permission};

    #[cfg(unix)]
    #[test]
    fn deployment_names_missing_and_exposed_helpers() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = crate::test_support::test_dir("deployment-health");
        let executable = dir.join("lib/topgent/1.0/topgent");
        std::fs::create_dir_all(executable.parent().expect("parent")).expect("directories");
        std::fs::write(&executable, b"binary").expect("executable");
        let capture = executable.parent().expect("parent").join("topgent-capture");
        std::fs::write(&capture, b"helper").expect("helper");
        std::fs::set_permissions(&capture, std::fs::Permissions::from_mode(0o755)).expect("mode");

        let result = super::deployment_at(Some(&executable), "linux");
        assert_eq!(result["mode"], "versioned_user_install");
        assert_eq!(result["helpers"][0]["state"], "exposed_to_other_users");
        assert_eq!(result["helpers"][1]["state"], "missing");
    }

    #[test]
    fn the_process_sensor_says_what_its_loss_figure_covers() {
        let text = super::loss_accounting("process_events");
        assert!(text.starts_with("Per interval"), "{text}");
        assert!(text.contains("not continuous"), "{text}");
        assert!(text.contains("3 s"), "a stalled sensor is named: {text}");
        assert_eq!(
            super::loss_accounting("socket"),
            "End-to-end loss is unmeasured"
        );
    }

    #[test]
    fn health_uses_current_loss_measurements_and_never_promotes_zero_to_complete() {
        let dir = crate::test_support::test_dir("coverage-health");
        let journal = topgent_journal::Journal::at(&dir);
        let mut run = topgent_collect::CollectorRun {
            collector: "capture",
            state: topgent_collect::CapabilityState::Available,
            fact_count: 7,
            duration_ms: 1,
            detail: None,
            dropped_events: Some(9),
            boundary: Some("Partial packet visibility"),
            continuous: None,
        };
        for (time, drops, expected) in [
            (1, Some(9), "loss_observed"),
            (2, None, "snapshot_only"),
            (3, Some(0), "snapshot_only"),
        ] {
            run.dropped_events = drops;
            let rows = super::sensor_health(&[run.clone()], time, &journal);
            let row = rows.first().expect("capture row");
            assert_eq!(row["collection_coverage"], expected);
            assert_eq!(row["dropped_events"], serde_json::json!(drops));
            assert_eq!(row["fact_count"], 7);
            assert!(
                row["loss_accounting"]
                    .as_str()
                    .expect("scope")
                    .contains("Accumulator only")
            );
            assert!(
                rows.iter()
                    .skip(1)
                    .all(|r| r["collection_coverage"] == "unsupported")
            );
        }
        let _ = std::fs::remove_dir_all(dir);
    }

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
            sensor_permission("capture", "linux"),
            "CAP_NET_RAW on the capture helper"
        );
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

/// The operating system by its own name and version, as the top of each
/// interface shows it: "Kali GNU/Linux Rolling", "macOS 26.1", "Windows
/// 11 (10.0.26100)". Read once per process; `None` when the system does not
/// say.
pub(crate) fn os_name() -> Option<String> {
    static NAME: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    NAME.get_or_init(read_os_name).clone()
}

#[cfg(target_os = "linux")]
fn read_os_name() -> Option<String> {
    let text = std::fs::read_to_string("/etc/os-release")
        .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
        .ok()?;
    os_release_name(&text)
}

/// `PRETTY_NAME` from an os-release file, else `NAME` with `VERSION`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn os_release_name(text: &str) -> Option<String> {
    let field = |key: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
            .map(|v| v.trim().trim_matches('"').to_owned())
            .filter(|v| !v.is_empty())
    };
    field("PRETTY_NAME")
        .or_else(|| {
            let name = field("NAME")?;
            Some(match field("VERSION") {
                Some(version) => format!("{name} {version}"),
                None => name,
            })
        })
        .map(|name| name.chars().filter(|c| !c.is_control()).take(80).collect())
}

#[cfg(target_os = "macos")]
fn read_os_name() -> Option<String> {
    let plist = std::fs::read_to_string("/System/Library/CoreServices/SystemVersion.plist").ok()?;
    let value = |key: &str| {
        let after = plist.split(&format!("<key>{key}</key>")).nth(1)?;
        let start = after.find("<string>")? + "<string>".len();
        let end = after.find("</string>")?;
        after.get(start..end).map(str::to_owned)
    };
    Some(format!(
        "{} {}",
        value("ProductName").unwrap_or_else(|| "macOS".to_owned()),
        value("ProductVersion")?
    ))
}

#[cfg(windows)]
fn read_os_name() -> Option<String> {
    // `ver` prints "Microsoft Windows [Version 10.0.26100.1234]".
    let output = std::process::Command::new("cmd")
        .args(["/c", "ver"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let version = text
        .split("Version ")
        .nth(1)?
        .trim()
        .trim_end_matches(']')
        .to_owned();
    let build: u32 = version.split('.').nth(2)?.parse().ok()?;
    // Windows 11 still reports 10.0; its builds start at 22000.
    let name = if build >= 22_000 {
        "Windows 11"
    } else {
        "Windows 10"
    };
    Some(format!("{name} ({version})"))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn read_os_name() -> Option<String> {
    None
}

#[cfg(test)]
mod os_name_tests {
    use super::os_release_name;

    #[test]
    fn a_pretty_name_is_taken_as_written_and_a_bare_one_is_built() {
        let kali =
            "NAME=\"Kali GNU/Linux\"\nPRETTY_NAME=\"Kali GNU/Linux Rolling\"\nVERSION=\"2026.3\"\n";
        assert_eq!(
            os_release_name(kali).as_deref(),
            Some("Kali GNU/Linux Rolling")
        );
        let bare = "NAME=Debian\nVERSION=\"13 (trixie)\"\n";
        assert_eq!(os_release_name(bare).as_deref(), Some("Debian 13 (trixie)"));
        assert_eq!(os_release_name("ID=x\n"), None);
    }
}
