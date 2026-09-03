//! Deterministic gates for one-family-at-a-time validation.
//!
//! This crate evaluates sanitized Topgent reports. It never installs, launches,
//! or removes third-party software; those lifecycle operations remain explicit
//! and scoped to a reviewed disposable lab directory.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod bench;
pub mod overclaim;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Expected live state for one validation checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedState {
    /// No process from this family may be running.
    Absent,
    /// Exactly one top-level process from this family must be running.
    Running,
}

/// One deterministic checkpoint request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRequest<'a> {
    /// Stable family ID from the signature catalogue.
    pub family: &'a str,
    /// Expected process state.
    pub state: ExpectedState,
    /// Optional TCP listener that must be attributed to the family.
    pub listener: Option<u16>,
}

/// Sanitized evidence returned by a checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckResult {
    /// Whether every requested assertion passed.
    pub passed: bool,
    /// Stable family ID.
    pub family: String,
    /// Requested state.
    pub expected_state: ExpectedState,
    /// Matching top-level agent count.
    pub matching_agents: usize,
    /// Matching process IDs, sorted numerically.
    pub pids: Vec<u32>,
    /// Expected listener, when requested.
    pub expected_listener: Option<u16>,
    /// Whether that listener was attributed to the family.
    pub listener_attributed: Option<bool>,
    /// Process collector capability state.
    pub process_sensor: String,
    /// Socket collector capability state.
    pub socket_sensor: String,
    /// Plain-language failed assertions; empty on success.
    pub failures: Vec<String>,
}

/// Evaluate one sanitized report against a checkpoint.
#[must_use]
pub fn evaluate(report: &Value, request: &CheckRequest<'_>) -> CheckResult {
    let agents = report
        .get("agents")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let mut pids = agents
        .iter()
        .filter(|agent| {
            agent.get("family").and_then(Value::as_str) == Some(request.family)
                || agent
                    .get("extensions")
                    .and_then(Value::as_array)
                    .is_some_and(|extensions| {
                        extensions.iter().any(|extension| {
                            extension.get("family").and_then(Value::as_str) == Some(request.family)
                        })
                    })
        })
        .filter_map(|agent| agent.get("pid").and_then(Value::as_u64))
        .filter_map(|pid| u32::try_from(pid).ok())
        .collect::<Vec<_>>();
    pids.sort_unstable();

    let sensor_state = |id: &str| {
        report
            .get("sensors")
            .and_then(Value::as_array)
            .and_then(|sensors| {
                sensors
                    .iter()
                    .find(|sensor| sensor.get("id").and_then(Value::as_str) == Some(id))
            })
            .and_then(|sensor| sensor.get("state"))
            .and_then(Value::as_str)
            .unwrap_or("missing")
            .to_owned()
    };
    let process_sensor = sensor_state("process");
    let socket_sensor = sensor_state("socket");
    let listener_attributed = request.listener.map(|port| {
        report
            .get("network")
            .and_then(Value::as_array)
            .is_some_and(|network| {
                network.iter().any(|endpoint| {
                    endpoint.get("agent_family").and_then(Value::as_str) == Some(request.family)
                        && endpoint.get("direction").and_then(Value::as_str) == Some("listening")
                        && endpoint.get("port").and_then(Value::as_u64) == Some(u64::from(port))
                })
            })
    });

    let mut failures = Vec::new();
    if process_sensor != "available" {
        failures.push(format!("process sensor is {process_sensor}"));
    }
    match request.state {
        ExpectedState::Absent if !pids.is_empty() => {
            failures.push(format!("expected no running agents, found {}", pids.len()));
        }
        ExpectedState::Running if pids.len() != 1 => {
            failures.push(format!(
                "expected exactly one running agent, found {}",
                pids.len()
            ));
        }
        ExpectedState::Absent | ExpectedState::Running => {}
    }
    if request.listener.is_some() && socket_sensor != "available" {
        failures.push(format!("socket sensor is {socket_sensor}"));
    }
    if listener_attributed == Some(false) {
        failures.push("expected listener was not attributed".to_owned());
    }

    CheckResult {
        passed: failures.is_empty(),
        family: request.family.to_owned(),
        expected_state: request.state,
        matching_agents: pids.len(),
        pids,
        expected_listener: request.listener,
        listener_attributed,
        process_sensor,
        socket_sensor,
        failures,
    }
}

#[cfg(test)]
mod tests {
    use super::{CheckRequest, ExpectedState, evaluate};
    use serde_json::{Value, json};

    #[allow(clippy::needless_pass_by_value)]
    fn report(agents: Value, network: Value, process: &str, socket: &str) -> Value {
        json!({
            "agents": agents,
            "network": network,
            "sensors": [
                {"id":"process","state":process},
                {"id":"socket","state":socket}
            ]
        })
    }

    #[test]
    fn absent_and_exactly_one_running_are_distinct_gates() {
        let empty = report(json!([]), json!([]), "available", "available");
        assert!(
            evaluate(
                &empty,
                &CheckRequest {
                    family: "goose",
                    state: ExpectedState::Absent,
                    listener: None
                }
            )
            .passed
        );
        assert!(
            !evaluate(
                &empty,
                &CheckRequest {
                    family: "goose",
                    state: ExpectedState::Running,
                    listener: None
                }
            )
            .passed
        );

        let one = report(
            json!([{"family":"goose","pid":42}]),
            json!([]),
            "available",
            "available",
        );
        assert!(
            evaluate(
                &one,
                &CheckRequest {
                    family: "goose",
                    state: ExpectedState::Running,
                    listener: None
                }
            )
            .passed
        );
    }

    #[test]
    fn duplicate_top_level_rows_fail_the_running_gate() {
        let duplicate = report(
            json!([{"family":"goose","pid":2},{"family":"goose","pid":1}]),
            json!([]),
            "available",
            "available",
        );
        let result = evaluate(
            &duplicate,
            &CheckRequest {
                family: "goose",
                state: ExpectedState::Running,
                listener: None,
            },
        );
        assert!(!result.passed);
        assert_eq!(result.pids, [1, 2]);
    }

    #[test]
    fn active_extension_matches_its_real_shared_host_once() {
        let shared_host = report(
            json!([{
                "family": null,
                "pid": 42,
                "extensions": [
                    {"family":"cline","extension_id":"saoudrizwan.claude-dev"},
                    {"family":"roo-code","extension_id":"rooveterinaryinc.roo-cline"}
                ]
            }]),
            json!([]),
            "available",
            "available",
        );
        let result = evaluate(
            &shared_host,
            &CheckRequest {
                family: "cline",
                state: ExpectedState::Running,
                listener: None,
            },
        );
        assert!(result.passed);
        assert_eq!(result.pids, [42]);
    }

    #[test]
    fn listeners_require_attribution_and_live_socket_coverage() {
        let live = report(
            json!([{"family":"goose","pid":42}]),
            json!([{"agent_family":"goose","direction":"listening","port":7777}]),
            "available",
            "available",
        );
        assert!(
            evaluate(
                &live,
                &CheckRequest {
                    family: "goose",
                    state: ExpectedState::Running,
                    listener: Some(7777)
                }
            )
            .passed
        );

        let unavailable = report(
            json!([{"family":"goose","pid":42}]),
            json!([]),
            "available",
            "permission_required",
        );
        let result = evaluate(
            &unavailable,
            &CheckRequest {
                family: "goose",
                state: ExpectedState::Running,
                listener: Some(7777),
            },
        );
        assert!(!result.passed);
        assert_eq!(result.listener_attributed, Some(false));
    }

    #[test]
    fn missing_or_unavailable_process_coverage_never_passes() {
        for state in ["missing", "permission_required", "error"] {
            let value = if state == "missing" {
                json!({"agents":[],"network":[],"sensors":[]})
            } else {
                report(json!([]), json!([]), state, "available")
            };
            assert!(
                !evaluate(
                    &value,
                    &CheckRequest {
                        family: "goose",
                        state: ExpectedState::Absent,
                        listener: None
                    }
                )
                .passed
            );
        }
    }
}
