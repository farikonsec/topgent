//! The report is the one contract three front ends depend on, so its shape is
//! pinned here. These run against the live machine — Topgent is a tool for
//! looking at the machine it runs on, and the report must hold together whatever
//! that machine happens to be running, including nothing.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use serde_json::Value;

fn assert_activity_shape(v: &Value) {
    for key in ["events", "links", "paths", "detectors"] {
        assert!(v["activity"].get(key).and_then(Value::as_array).is_some());
    }
    let activity_ids = v["activity"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["id"].as_str().expect("activity id"))
        .collect::<std::collections::BTreeSet<_>>();
    for event in v["activity"]["events"].as_array().unwrap() {
        for key in [
            "sequence",
            "agent_pid",
            "agent_started_at",
            "actor_pid",
            "at",
        ] {
            assert!(event.get(key).and_then(Value::as_u64).is_some(), "{key}");
        }
        for key in [
            "id",
            "kind",
            "title",
            "detail",
            "confidence",
            "collector",
            "probe",
        ] {
            assert!(event.get(key).and_then(Value::as_str).is_some(), "{key}");
        }
        assert!(event.get("network").is_some());
        assert!(event.get("parent_id").is_some());
    }
    for link in v["activity"]["links"].as_array().unwrap() {
        assert!(activity_ids.contains(link["from"].as_str().unwrap()));
        assert!(activity_ids.contains(link["to"].as_str().unwrap()));
        assert!(
            ["direct", "attributed", "correlated"].contains(&link["certainty"].as_str().unwrap())
        );
    }
    for path in v["activity"]["paths"].as_array().unwrap() {
        assert!(path["agent_started_at"].as_u64().is_some());
        assert_eq!(path["certainty"], "correlated");
        for event_id in path["events"].as_array().unwrap() {
            assert!(activity_ids.contains(event_id.as_str().unwrap()));
        }
    }
    let detector = &v["activity"]["detectors"][0];
    assert_eq!(detector["id"], "periodic_completed_connections");
    assert_eq!(detector["min_events"], 5);
    assert_eq!(detector["max_jitter_percent"], 20);
    assert_eq!(detector["risk_points"], 0);
}

fn assert_complete_legend(v: &Value) {
    let mut codes: Vec<&str> = v["legend"]
        .as_array()
        .expect("legend array")
        .iter()
        .map(|item| item["code"].as_str().expect("legend code"))
        .collect();
    codes.sort_unstable();
    assert_eq!(
        codes,
        [
            "AGENT_CHAIN",
            "ARBITRARY_EXECUTION",
            "BROAD_WRITE",
            "CREDENTIAL_ACCESS",
            "DECLARATION_DRIFT",
            "DISALLOWED_ASSET",
            "EXFILTRATION_PATH",
            "EXPOSED_LISTENER",
            "METADATA_SERVICE",
            "OFFENSIVE_TOOL",
            "PERSISTENCE_WRITE",
            "PRIVATE_PEER",
            "PROCESS_EXPLOSION",
            "RECON_FANOUT",
            "SANDBOX_ESCAPE",
            "SECRET_REACHABLE",
            "SELF_TAMPERING",
            "SUSPICIOUS_ENDPOINT",
            "UNRESTRICTED_NETWORK",
            "WATCHLIST",
        ]
    );
}

fn assert_health_shape(v: &Value) {
    assert!(v["platform"]["os"].as_str().is_some());
    assert!(v["platform"]["arch"].as_str().is_some());
    let sensors = v["sensors"].as_array().expect("sensor health array");
    for required in [
        "process",
        "socket",
        "config",
        "reach",
        "editor_extensions",
        "filesystem_events",
        "network_events",
        "dns_events",
    ] {
        assert_eq!(
            sensors
                .iter()
                .filter(|sensor| sensor["id"] == required)
                .count(),
            1,
            "{required} must have exactly one real or placeholder health row"
        );
    }
    for sensor in sensors {
        for key in ["id", "state", "permission", "version"] {
            assert!(sensor[key].as_str().is_some(), "{key}");
        }
        assert!(
            ["available", "unsupported", "permission_required", "error"]
                .contains(&sensor["state"].as_str().unwrap())
        );
        for key in [
            "last_observed_at",
            "last_successful_sweep",
            "last_error_at",
            "dropped_events",
        ] {
            assert!(sensor.get(key).is_some(), "{key}");
        }
        for key in ["consecutive_failures", "total_runs", "total_facts"] {
            assert!(sensor[key].as_u64().is_some(), "{key}");
        }
        assert!(sensor["history_persistent"].as_bool().is_some());
    }
    assert_eq!(
        sensors
            .iter()
            .filter(|sensor| sensor["id"] == "filesystem_events")
            .count(),
        1,
        "the real collector must replace, not duplicate, the enhanced-sensor placeholder"
    );
    let filesystem_state = sensors
        .iter()
        .find(|sensor| sensor["id"] == "filesystem_events")
        .and_then(|sensor| sensor["state"].as_str())
        .expect("filesystem sensor state");
    let coverage = v["coverage"].as_array().expect("coverage array");
    for entry in coverage
        .iter()
        .filter(|entry| entry["sensor"] == "filesystem_events")
    {
        assert_eq!(entry["state"], filesystem_state);
    }
    let rules = coverage
        .iter()
        .map(|entry| entry["rule"].as_str().expect("coverage rule"))
        .collect::<std::collections::BTreeSet<_>>();
    let legend = v["legend"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["code"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(rules, legend);
}

fn assert_response_shape(v: &Value) {
    let decisions = v["response"]["decisions"]
        .as_array()
        .expect("response decisions");
    for decision in decisions {
        assert!(decision.get("approval").is_some());
        assert!(
            ["triggered", "suppressed"].contains(
                &decision["transition"]
                    .as_str()
                    .expect("response transition")
            )
        );
        assert!(decision["transition_persistent"].as_bool().is_some());
        assert!(decision["trigger_count"].as_u64().is_some());
        assert!(decision["last_transition_at"].as_u64().is_some());
        if let Some(approval) = decision["approval"].as_object() {
            assert!(approval.get("id").and_then(Value::as_str).is_some());
            assert!(
                ["pending", "approved", "denied", "expired"].contains(
                    &approval
                        .get("state")
                        .and_then(Value::as_str)
                        .expect("approval state")
                )
            );
            assert!(approval.get("created_at").and_then(Value::as_u64).is_some());
            assert!(approval.get("expires_at").and_then(Value::as_u64).is_some());
            assert_eq!(
                approval.get("persistent").and_then(Value::as_bool),
                Some(true)
            );
        }
    }
    for key in ["observe", "alert", "intercept", "terminate"] {
        assert!(v["response"]["capability"][key].as_bool().is_some());
    }
    for rule in v["watchlist"].as_array().unwrap() {
        assert!(
            ["observe", "alert", "approval", "block", "kill"]
                .contains(&rule["response"].as_str().unwrap())
        );
    }
}

fn assert_context_shape(v: &Value) {
    let enabled = v["context"]["enabled"]
        .as_bool()
        .expect("context enabled flag");
    assert!(v["context"]["records"].as_array().is_some());
    if !enabled {
        assert_eq!(v["context"]["records"].as_array().map(Vec::len), Some(0));
    }
    assert!(
        v["context"]["authority"]
            .as_str()
            .is_some_and(|text| text.contains("host evidence wins"))
    );
    assert_eq!(
        v["context"]["integrations"]["detection_families"]
            .as_array()
            .map(Vec::len),
        Some(14)
    );
    assert_eq!(
        v["context"]["integrations"]["adapters"]
            .as_array()
            .map(Vec::len),
        Some(3)
    );
}

#[allow(clippy::too_many_lines)]
fn assert_report_shape(v: &Value) {
    assert!(v.get("version").and_then(Value::as_str).is_some());
    assert!(v.get("generated_at").and_then(Value::as_u64).is_some());
    assert!(v.get("fact_count").and_then(Value::as_u64).is_some());
    assert!(v.get("agents").and_then(Value::as_array).is_some());
    assert!(v.get("assets").and_then(Value::as_array).is_some());
    assert!(v.get("relationships").and_then(Value::as_array).is_some());
    assert_eq!(v["aibom"]["format"], "CycloneDX");
    assert_eq!(v["aibom"]["spec_version"], "1.6");
    assert!(v.get("network").and_then(Value::as_array).is_some());
    assert!(v.get("events").and_then(Value::as_array).is_some());
    assert!(v.get("failures").and_then(Value::as_array).is_some());

    assert_complete_legend(v);

    for agent in v["agents"].as_array().unwrap() {
        // Pin every field a front end reads so renderers never have to guess.
        for key in ["pid", "started_at", "score", "pips", "outbound"] {
            assert!(agent.get(key).and_then(Value::as_u64).is_some(), "{key}");
        }
        for key in [
            "asset_id",
            "asset_disposition",
            "identity",
            "grade",
            "discovery_confidence",
        ] {
            assert!(agent.get(key).and_then(Value::as_str).is_some(), "{key}");
        }
        for key in [
            "factors",
            "resources",
            "endpoints",
            "connectors",
            "invokes",
            "children",
        ] {
            assert!(agent.get(key).and_then(Value::as_array).is_some(), "{key}");
        }

        // Grade is one of the bands, never a raw number leaking through.
        // NOT EVALUATED joined the list when an agent owned by another account
        // stopped being graded LOW; this test only noticed once a machine
        // actually had one running.
        let grade = agent["grade"].as_str().unwrap();
        assert!(
            ["NOT EVALUATED", "LOW", "MEDIUM", "HIGH", "CRITICAL"].contains(&grade),
            "unexpected grade {grade}"
        );

        // Confidence uses the standard evidence words everywhere.
        let conf = agent["discovery_confidence"].as_str().unwrap();
        assert!(
            ["Confirmed", "Probable", "Possible"].contains(&conf),
            "unexpected confidence {conf}"
        );

        // No resource ever leaks contents: the schema only carries labels.
        for res in agent["resources"].as_array().unwrap() {
            assert!(res.get("path").is_some());
            assert!(res.get("declared").is_some());
            assert!(res.get("reachable").is_some());
            assert!(res.get("evidence").and_then(Value::as_array).is_some());
        }
    }

    let asset_ids = v["assets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|asset| asset["id"].as_str().expect("asset id"))
        .collect::<std::collections::BTreeSet<_>>();
    for asset in v["assets"].as_array().unwrap() {
        for key in ["id", "kind", "name", "confidence", "source", "disposition"] {
            assert!(asset.get(key).and_then(Value::as_str).is_some(), "{key}");
        }
    }
    for relationship in v["relationships"].as_array().unwrap() {
        assert!(asset_ids.contains(relationship["from"].as_str().unwrap()));
        assert!(asset_ids.contains(relationship["to"].as_str().unwrap()));
        assert!(relationship["agent_pid"].as_u64().is_some());
        for key in ["kind", "agent_family", "disposition"] {
            assert!(
                relationship.get(key).and_then(Value::as_str).is_some(),
                "{key}"
            );
        }
    }

    assert_activity_shape(v);
    assert_health_shape(v);
    assert_response_shape(v);
    assert_context_shape(v);
    assert!(v["network_baselines"].as_array().is_some());
    for record in v["network"].as_array().unwrap() {
        for key in [
            "agent_pid",
            "agent_started_at",
            "port",
            "first_seen",
            "last_seen",
            "observations",
            "last_visibility_change",
            "visibility_changes",
        ] {
            assert!(record.get(key).and_then(Value::as_u64).is_some(), "{key}");
        }
        for key in [
            "agent_family",
            "host",
            "direction",
            "verdict",
            "lifecycle_evidence",
        ] {
            assert!(record.get(key).and_then(Value::as_str).is_some(), "{key}");
        }
        assert!(record["risk_points"].as_u64().is_some());
        assert!(["none", "high", "critical"].contains(&record["alert_level"].as_str().unwrap()));
        assert!(record["first_seen"].as_u64() <= record["last_seen"].as_u64());
        assert!(
            record["observations"]
                .as_u64()
                .is_some_and(|count| count > 0)
        );
        assert!(record["first_seen_this_sweep"].as_bool().is_some());
        assert!(record["currently_observed"].as_bool().is_some());
        assert_eq!(record["lifecycle_evidence"], "socket_snapshot_visibility");
        assert_eq!(record["time_series"]["detector_version"], "1");
        assert_eq!(
            record["time_series"]["evidence"],
            "socket_snapshot_visibility"
        );
        assert!(record["time_series"]["retained_samples"].as_u64().is_some());
        assert!(record["time_series"]["max_samples"].as_u64().is_some());
        assert_eq!(
            record["time_series"]["retention_ms"],
            topgent_core::NETWORK_HISTORY_RETENTION_MS
        );
        assert!(record["time_series"]["patterns"].as_array().is_some());
        assert!(matches!(
            record["time_series"]["warmup"].as_str(),
            Some("collecting" | "ready")
        ));
        assert!(matches!(
            record["baseline"]["state"].as_str(),
            Some("collecting" | "ready" | "expired")
        ));
        assert_eq!(
            record["baseline"]["reset_identity"],
            "pid_and_process_start_time"
        );
        assert!(record["baseline"]["warmup_samples"].as_u64().is_some());
        assert!(record["baseline"]["expiry_ms"].as_u64().is_some());
        assert!(record["baseline"]["outside_baseline"].as_bool().is_some());
        assert!(record.get("bytes").is_some_and(Value::is_null));
        assert!(record.get("duration_ms").is_some_and(Value::is_null));
    }
    for event in v["events"].as_array().unwrap() {
        for key in ["id", "kind", "agent", "detail", "severity", "evidence"] {
            assert!(event[key].as_str().is_some(), "{key}");
        }
        for key in ["at", "pid"] {
            assert!(event[key].as_u64().is_some(), "{key}");
        }
        assert!(
            ["info", "medium", "high", "critical"].contains(&event["severity"].as_str().unwrap())
        );
    }
}

#[test]
fn cyclone_dx_export_uses_exactly_the_report_inventory_references() {
    let report = topgent_report::scan();
    let document = topgent_report::cyclonedx_from_report(&report).expect("valid export");
    let report_ids = report["assets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|asset| asset["id"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    let exported_ids = ["components", "services"]
        .into_iter()
        .flat_map(|key| document[key].as_array().unwrap().iter())
        .map(|asset| asset["bom-ref"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(report_ids, exported_ids);
    assert!(topgent_export::validate_cyclonedx(&document).is_ok());
}

#[test]
fn the_report_has_the_shape_every_front_end_expects() {
    assert_report_shape(&topgent_report::scan());
}

#[test]
fn two_scans_of_the_same_machine_agree_on_structure() {
    // The numbers can move between sweeps — that is the point of watching — but
    // the shape may not, or a live UI would break mid-poll.
    let a = topgent_report::scan();
    let b = topgent_report::scan();
    assert_report_shape(&a);
    assert_report_shape(&b);
    assert_eq!(a["version"], b["version"]);
}

#[test]
fn stopping_a_pid_that_is_not_there_is_refused_not_crashed() {
    // 0 is never a real target, and the guards must turn it into a clean refusal
    // rather than a panic or a stray signal.
    let out = topgent_report::stop(0);
    assert_eq!(out["ok"], Value::Bool(false));
    assert!(out["message"].as_str().unwrap().contains('0'));
}

#[test]
fn malformed_asset_policy_mutations_are_refused_before_writing() {
    let long_family = "x".repeat(129);
    for (id, family, disposition) in [
        ("not-an-asset", None, "approved"),
        ("urn:topgent:model:test", None, "invented"),
        (
            "urn:topgent:model:test",
            Some(long_family.as_str()),
            "approved",
        ),
    ] {
        let out = topgent_report::set_asset_disposition(id, family, disposition);
        assert_eq!(out["ok"], Value::Bool(false));
    }
}
