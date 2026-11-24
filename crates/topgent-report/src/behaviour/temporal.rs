//! Native, time-windowed behaviour rules over retained attributed actions.
//!
//! These rules answer a different question from the vendored F catalogue. F
//! evaluates one kernel event. A temporal rule joins two already-attributed
//! events from the same exact agent run. The join stays deterministic and
//! bounded by the action history; it does not infer payload transfer or intent.

use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::net::IpAddr;
use topgent_policy::locations::Sensitive;

/// Maximum gap between a sensitive read and a later connection attempt.
const CREDENTIAL_EGRESS_WINDOW_MS: u64 = 60_000;

fn text<'a>(row: &'a Value, field: &str) -> Option<&'a str> {
    row.get(field)?.as_str()
}

fn number(row: &Value, field: &str) -> Option<u64> {
    row.get(field)?.as_u64()
}

fn agent_identity(row: &Value) -> Option<(u64, u64)> {
    Some((number(row, "agent_pid")?, number(row, "agent_started_at")?))
}

fn successful_read(row: &Value) -> bool {
    matches!(text(row, "action"), Some("read" | "read_write"))
        && text(row, "result") == Some("succeeded")
}

fn connection_attempt(row: &Value) -> bool {
    matches!(text(row, "action"), Some("connect" | "send"))
        && matches!(text(row, "result"), Some("connected" | "in_progress"))
}

fn path_matches(target: &str, sensitive: &[Sensitive], home: Option<&str>) -> bool {
    sensitive.iter().any(|entry| {
        let path = entry.path.strip_prefix("~/").map_or_else(
            || {
                if entry.path.starts_with('/') {
                    entry.path.clone()
                } else {
                    home.map_or_else(
                        || entry.path.clone(),
                        |root| format!("{root}/{}", entry.path),
                    )
                }
            },
            |tail| home.map_or_else(|| entry.path.clone(), |root| format!("{root}/{tail}")),
        );
        target == path
    })
}

fn non_loopback_target(target: &str) -> bool {
    let host = target
        .strip_prefix('[')
        .and_then(|rest| rest.split_once("]:").map(|(host, _)| host))
        .or_else(|| target.rsplit_once(':').map(|(host, _)| host))
        .unwrap_or(target);
    host.parse::<IpAddr>().map_or(true, |ip| !ip.is_loopback())
}

/// Finds a sensitive read followed by non-loopback egress from the same exact
/// agent run within one minute.
///
/// The finding deliberately says "followed by" rather than "exfiltrated". No
/// payload is collected, so the sequence cannot establish that file contents
/// crossed the connection.
pub(crate) fn correlate(
    action_history: &Value,
    sensitive: &[Sensitive],
    home: Option<&str>,
) -> Vec<Value> {
    let rows = action_history["rows"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    let mut reads_by_agent: BTreeMap<(u64, u64), Vec<&Value>> = BTreeMap::new();
    for read in rows.iter().filter(|row| {
        successful_read(row)
            && text(row, "target").is_some_and(|path| path_matches(path, sensitive, home))
    }) {
        let Some(identity) = agent_identity(read) else {
            continue;
        };
        reads_by_agent.entry(identity).or_default().push(read);
    }
    for reads in reads_by_agent.values_mut() {
        reads.sort_by_key(|row| number(row, "at").unwrap_or(0));
    }

    let mut findings = Vec::new();
    for connect in rows.iter().filter(|row| connection_attempt(row)) {
        let (Some(connect_at), Some(identity)) = (number(connect, "at"), agent_identity(connect))
        else {
            continue;
        };
        if !text(connect, "target").is_some_and(non_loopback_target) {
            continue;
        }
        let Some(reads) = reads_by_agent.get(&identity) else {
            continue;
        };
        let insertion = reads.partition_point(|read| number(read, "at").unwrap_or(0) <= connect_at);
        let Some(read) = insertion.checked_sub(1).and_then(|index| reads.get(index)) else {
            continue;
        };
        let read_at = number(read, "at").unwrap_or(0);
        if connect_at.saturating_sub(read_at) > CREDENTIAL_EGRESS_WINDOW_MS {
            continue;
        }
        findings.push(json!({
                "rule": "Credential access followed by non-loopback connection",
                "maturity": "topgent",
                "priority": "WARNING",
                "tags": ["credential_access", "egress", "temporal"],
                "source": "topgent-temporal",
                "record": format!("{} -> {}", text(read, "record").unwrap_or("unknown"), text(connect, "record").unwrap_or("unknown")),
                "at": connect_at,
                "lineage_at": number(connect, "lineage_at").unwrap_or(connect_at),
                "actor_pid": number(connect, "actor_pid").unwrap_or(0),
                "actor_name": text(connect, "actor_name").unwrap_or("unknown"),
                "summary": crate::behaviour::summary_of("Credential access followed by non-loopback connection"),
                "target": text(connect, "target").unwrap_or("unknown"),
                "container": "",
                "agent_pid": number(connect, "agent_pid"),
                "agent_started_at": number(connect, "agent_started_at"),
                "actor_started_at": number(connect, "actor_started_at"),
                "chain": connect.get("chain").cloned().unwrap_or_else(|| json!([])),
                "explanation": format!(
                    "{} was opened, then this agent attempted {} {} ms later. This sequence does not establish that file contents were transferred.",
                    text(read, "target").unwrap_or("a sensitive path"),
                    text(connect, "target").unwrap_or("a non-loopback connection"),
                    connect_at.saturating_sub(read_at),
                ),
            }));
    }
    findings
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::needless_pass_by_value,
        clippy::unwrap_used
    )]

    use super::correlate;
    use serde::Deserialize;
    use serde_json::{Value, json};
    use std::collections::BTreeSet;
    use topgent_policy::locations::Sensitive;

    fn read(agent: u64, at: u64) -> Value {
        json!({"record":"1", "action":"read", "result":"succeeded", "target":"/home/test/.aws/credentials",
            "at":at, "lineage_at":at, "actor_pid":11, "actor_name":"cat", "actor_started_at":90,
            "agent_pid":agent, "agent_started_at":50, "chain":[11]})
    }

    fn connect(agent: u64, at: u64, target: &str, result: &str) -> Value {
        json!({"record":"2", "action":"connect", "result":result, "target":target,
            "at":at, "lineage_at":at, "actor_pid":12, "actor_name":"curl", "actor_started_at":95,
            "agent_pid":agent, "agent_started_at":50, "chain":[12]})
    }

    fn state(rows: Vec<Value>) -> Value {
        json!({"rows":rows})
    }

    fn sensitive() -> Vec<Sensitive> {
        vec![Sensitive {
            path: ".aws/credentials".into(),
            label: "AWS credentials".into(),
        }]
    }

    #[test]
    fn a_sensitive_read_then_non_loopback_connection_on_the_same_agent_fires() {
        let findings = correlate(
            &state(vec![
                connect(10, 1_500, "203.0.113.9:443", "connected"),
                read(10, 1_000),
            ]),
            &sensitive(),
            Some("/home/test"),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["agent_pid"], 10);
        assert!(
            findings[0]["explanation"]
                .as_str()
                .is_some_and(|s| s.contains("does not establish"))
        );
    }

    #[test]
    fn one_connection_uses_only_the_most_recent_qualifying_read() {
        let mut older = read(10, 1_000);
        older["record"] = json!("older");
        let mut newer = read(10, 1_400);
        newer["record"] = json!("newer");
        let findings = correlate(
            &state(vec![
                connect(10, 1_500, "203.0.113.9:443", "connected"),
                older,
                newer,
            ]),
            &sensitive(),
            Some("/home/test"),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["record"], "newer -> 2");
        assert!(
            findings[0]["explanation"]
                .as_str()
                .unwrap()
                .contains("100 ms")
        );
    }

    #[test]
    fn unrelated_late_failed_loopback_and_reverse_sequences_do_not_fire() {
        let controls = [
            state(vec![
                connect(20, 1_500, "203.0.113.9:443", "connected"),
                read(10, 1_000),
            ]),
            state(vec![
                connect(10, 62_000, "203.0.113.9:443", "connected"),
                read(10, 1_000),
            ]),
            state(vec![
                connect(10, 1_500, "203.0.113.9:443", "failed"),
                read(10, 1_000),
            ]),
            state(vec![
                connect(10, 1_500, "127.0.0.1:8000", "connected"),
                read(10, 1_000),
            ]),
            state(vec![
                read(10, 2_000),
                connect(10, 1_500, "203.0.113.9:443", "connected"),
            ]),
        ];
        for control in controls {
            assert!(correlate(&control, &sensitive(), Some("/home/test")).is_empty());
        }
    }

    #[derive(Deserialize)]
    struct Corpus {
        schema_version: u16,
        #[serde(rename = "corpus_id")]
        id: String,
        cases: Vec<Case>,
    }

    #[derive(Deserialize)]
    struct Case {
        id: String,
        environment: String,
        expected_findings: usize,
        rows: Vec<Value>,
    }

    #[test]
    fn fixed_workload_corpus_has_no_unexpected_temporal_findings() {
        let corpus: Corpus = serde_json::from_str(include_str!("testdata/s8-temporal-corpus.json"))
            .expect("S8 temporal corpus must be valid JSON");
        assert_eq!(corpus.schema_version, 1);
        assert_eq!(corpus.id, "s8-temporal-v1");
        assert_eq!(corpus.cases.len(), 10, "case removal changes the score");

        let environments = corpus
            .cases
            .iter()
            .map(|case| case.environment.as_str())
            .collect::<BTreeSet<_>>();
        for required in [
            "package-installation",
            "local-dev-server",
            "loopback-client",
            "repository-scan",
            "shell-and-build",
            "model-provider-traffic",
        ] {
            assert!(
                environments.contains(required),
                "missing {required} control"
            );
        }

        for case in corpus.cases {
            let actual = correlate(
                &json!({"rows": case.rows}),
                &sensitive(),
                Some("/home/test"),
            );
            assert_eq!(actual.len(), case.expected_findings, "{}", case.id);
        }
    }
}
