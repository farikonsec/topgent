//! The CI decision.
//!
//! Exit codes are the contract with a pipeline, so the mapping from findings to
//! codes lives in one place. A report the evaluator cannot parse is a failure
//! rather than a pass: a gate that opens when it cannot read the evidence is
//! worse than no gate.

use crate::contract::POLICY_RESULT_VERSION;
use crate::contract::REPORT_CONTRACT_VERSION;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Severity floor used by a CI policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeverityFloor {
    /// Fail only Critical agents or disallowed assets.
    Critical,
    /// Fail High or Critical agents and disallowed assets.
    High,
    /// Fail Medium, High, or Critical agents and disallowed assets.
    Medium,
    /// Fail every non-Low agent and every disallowed asset.
    Low,
}

impl SeverityFloor {
    /// Parse a stable lowercase CLI value.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "critical" => Some(Self::Critical),
            "high" => Some(Self::High),
            "medium" => Some(Self::Medium),
            "low" => Some(Self::Low),
            _ => None,
        }
    }

    fn matches(self, grade: &str) -> bool {
        let rank = |value| match value {
            "LOW" => 0,
            "MEDIUM" => 1,
            "HIGH" => 2,
            "CRITICAL" => 3,
            _ => -1,
        };
        let floor = match self {
            Self::Low => 0,
            Self::Medium => 1,
            Self::High => 2,
            Self::Critical => 3,
        };
        rank(grade) >= floor
    }
}

/// One deterministic CI policy violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violation {
    /// Stable violation category.
    pub code: String,
    /// Asset or agent identifier where available.
    pub subject: String,
    /// Human-readable evidence-based explanation.
    pub message: String,
}

/// Versioned machine-readable CI evaluation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyResult {
    /// Contract version.
    pub version: u32,
    /// Whether no violations were found and required coverage was present.
    pub passed: bool,
    /// Whether all required rule coverage was available.
    pub coverage_complete: bool,
    /// Deterministically ordered violations.
    pub violations: Vec<Violation>,
}

/// The text of a JSON document, without a byte-order mark.
///
/// PowerShell's default redirection writes UTF-8 with a byte-order mark, so a
/// Windows operator who saves a report the obvious way and feeds it to the CI
/// evaluator gets `expected value at line 1 column 1` and no idea why. The mark
/// is not part of the document, and refusing a file over it is refusing the
/// user's own tooling rather than anything wrong with their report.
#[must_use]
pub fn without_byte_order_mark(text: &str) -> &str {
    text.strip_prefix('\u{feff}').unwrap_or(text)
}

/// The sensor states a coverage entry is allowed to carry.
///
/// Read from the same vocabulary the collectors report, so a state nobody can
/// produce is a malformed report rather than an unrecognised-but-tolerated one.
const COVERAGE_STATES: [&str; 4] = [
    "available",
    "degraded",
    "permission_required",
    "unsupported",
];

/// The verifications a coverage entry is allowed to carry.
const COVERAGE_VERIFICATIONS: [&str; 5] =
    ["live", "automated", "fixture", "degraded", "unavailable"];

/// Whether the coverage table accounts for every rule, exactly once.
///
/// `coverage.iter().all(..)` was the whole test, and `all()` on an empty array
/// is true: a report with `"coverage": []` passed `--require-coverage`, so a
/// truncated upload, a crafted file, or a build whose catalogue failed to load
/// opened the gate rather than closing it. Requiring merely non-empty is no
/// better, because one entry would then stand in for twenty.
///
/// So the exact expected set is validated. Missing rules mean incomplete
/// coverage, which the gate may be configured to tolerate. A duplicate, an
/// unknown rule, or an entry whose fields are not from the vocabulary means the
/// input is not a Topgent report, which is an error and never a pass.
///
/// # Errors
///
/// Returns an explanation when the coverage table is malformed, or when this
/// build cannot read its own catalogue and therefore has nothing to check
/// against.
fn coverage_is_complete(coverage: &[Value]) -> Result<bool, String> {
    let catalogue = topgent_policy::catalogue::builtin()
        .map_err(|error| format!("this build cannot read its own risk catalogue: {error}"))?;
    let expected: std::collections::BTreeSet<&str> = catalogue
        .factors
        .iter()
        .map(|factor| factor.code.as_str())
        .collect();

    let mut seen = std::collections::BTreeSet::new();
    for entry in coverage {
        let rule = entry["rule"]
            .as_str()
            .ok_or("a coverage entry has no rule name")?;
        if !expected.contains(rule) {
            return Err(format!(
                "coverage names {rule}, which is not a rule in this build's catalogue"
            ));
        }
        if !seen.insert(rule) {
            return Err(format!("coverage lists {rule} more than once"));
        }
        let state = entry["state"]
            .as_str()
            .ok_or_else(|| format!("coverage entry {rule} has no state"))?;
        if !COVERAGE_STATES.contains(&state) {
            return Err(format!(
                "coverage entry {rule} carries unknown state {state}"
            ));
        }
        let verification = entry["verification"]
            .as_str()
            .ok_or_else(|| format!("coverage entry {rule} has no verification"))?;
        if !COVERAGE_VERIFICATIONS.contains(&verification) {
            return Err(format!(
                "coverage entry {rule} carries unknown verification {verification}"
            ));
        }
        if entry["sensor"].as_str().is_none_or(str::is_empty) {
            return Err(format!("coverage entry {rule} names no sensor"));
        }
    }

    // Every rule present and every one of them detectable. A rule the
    // catalogue declares and the report omits is missing coverage, not
    // coverage that happens to be fine.
    Ok(seen.len() == expected.len() && coverage.iter().all(|entry| entry["state"] == "available"))
}

/// Evaluate the same report contract used by the desktop UI.
///
/// # Errors
///
/// Returns an explanation when the report contract is missing or malformed.
pub fn evaluate_report(
    report: &Value,
    floor: SeverityFloor,
    require_coverage: bool,
) -> Result<PolicyResult, String> {
    if let Some(version) = report.get("contract_version") {
        let version = version
            .as_u64()
            .ok_or("input contract_version is not an unsigned integer")?;
        if version != REPORT_CONTRACT_VERSION {
            return Err(format!(
                "unsupported report contract version {version}; expected {REPORT_CONTRACT_VERSION}"
            ));
        }
    }
    let agents = report["agents"]
        .as_array()
        .ok_or("input has no agents array")?;
    let assets = report["assets"]
        .as_array()
        .ok_or("input has no assets array")?;
    let coverage = report["coverage"]
        .as_array()
        .ok_or("input has no coverage array")?;
    let coverage_complete = coverage_is_complete(coverage)?;
    let mut violations = Vec::new();
    // A report produced while the operator's policy was broken was scored
    // against built-in defaults, not against their rules. Passing it would be
    // passing a different check from the one CI asked for. Absent from an older
    // report means the field did not exist yet, which is not a failure.
    if let Some(health) = report.get("policy_health")
        && health.get("operator_rules_in_force") == Some(&Value::Bool(false))
    {
        violations.push(Violation {
            code: "POLICY_NOT_IN_FORCE".to_owned(),
            subject: health
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or("policy")
                .to_owned(),
            message: format!(
                "the policy could not be loaded, so this report was scored against built-in \
                 defaults rather than the configured rules: {}",
                health
                    .get("detail")
                    .and_then(Value::as_str)
                    .unwrap_or("no detail recorded")
            ),
        });
    }
    for agent in agents {
        let grade = agent["grade"].as_str().ok_or("agent has no valid grade")?;
        if floor.matches(grade) {
            let asset_id = agent["asset_id"].as_str().unwrap_or("unknown-agent");
            let subject = agent["pid"].as_u64().map_or_else(
                || asset_id.to_owned(),
                |pid| format!("{asset_id}#pid={pid}"),
            );
            violations.push(Violation {
                code: "RISK_THRESHOLD".to_owned(),
                subject,
                message: format!("agent risk grade {grade} meets the configured failure threshold"),
            });
        }
    }
    for asset in assets
        .iter()
        .filter(|asset| asset["disposition"] == "disallowed")
    {
        violations.push(Violation {
            code: "DISALLOWED_ASSET".to_owned(),
            subject: asset["id"]
                .as_str()
                .ok_or("asset has no valid id")?
                .to_owned(),
            message: format!(
                "disallowed {} is present",
                asset["kind"].as_str().unwrap_or("asset")
            ),
        });
    }
    violations
        .sort_by(|left, right| (&left.code, &left.subject).cmp(&(&right.code, &right.subject)));
    Ok(PolicyResult {
        version: POLICY_RESULT_VERSION,
        passed: violations.is_empty() && (!require_coverage || coverage_complete),
        coverage_complete,
        violations,
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::unwrap_used
    )]
    use super::*;
    use serde_json::json;

    /// A coverage table with every rule this build's catalogue declares.
    ///
    /// Written from the catalogue rather than by hand, so it cannot drift out
    /// of step with the rule set the gate checks against.
    fn full_coverage(state: &str) -> Vec<Value> {
        topgent_policy::catalogue::builtin()
            .expect("the built-in catalogue loads")
            .factors
            .iter()
            .map(|factor| {
                json!({
                    "rule": factor.code,
                    "sensor": factor.sensor,
                    "state": state,
                    "verification": "automated",
                })
            })
            .collect()
    }

    #[test]
    fn evaluator_separates_violations_from_missing_coverage() {
        let report = json!({
            "agents": [{"asset_id":"urn:topgent:agent:a", "grade":"HIGH"}],
            "assets": [{"id":"urn:topgent:model:m", "kind":"model", "disposition":"disallowed"}],
            // Was a single `{"state":"unsupported"}` entry, which the gate had
            // no way to tell from a complete table. Every rule is now named.
            "coverage": full_coverage("unsupported")
        });
        let result = evaluate_report(&report, SeverityFloor::High, true)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!result.passed);
        assert!(!result.coverage_complete);
        assert_eq!(result.violations.len(), 2);
    }

    /// The finding: `coverage.iter().all(..)` is true on an empty array, so a
    /// report carrying no coverage at all passed `--require-coverage`. A
    /// truncated upload or a crafted file opened the gate.
    #[test]
    fn an_empty_coverage_table_is_not_complete_coverage() {
        let report = json!({"agents": [], "assets": [], "coverage": []});
        let result = evaluate_report(&report, SeverityFloor::High, true)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!result.coverage_complete);
        assert!(!result.passed, "an empty coverage table opened the gate");
        // Without --require-coverage the same report still has no violations.
        let lenient = evaluate_report(&report, SeverityFloor::High, false)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(lenient.passed);
    }

    #[test]
    fn one_available_rule_does_not_stand_in_for_the_whole_catalogue() {
        let mut coverage = full_coverage("available");
        coverage.truncate(1);
        let report = json!({"agents": [], "assets": [], "coverage": coverage});
        let result = evaluate_report(&report, SeverityFloor::High, true)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!result.coverage_complete);
        assert!(!result.passed);
    }

    #[test]
    fn a_rule_the_catalogue_declares_and_the_report_omits_is_missing_coverage() {
        let mut coverage = full_coverage("available");
        coverage.pop();
        let report = json!({"agents": [], "assets": [], "coverage": coverage});
        let result = evaluate_report(&report, SeverityFloor::High, true)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!result.coverage_complete);
    }

    #[test]
    fn a_complete_table_of_available_rules_passes() {
        let report = json!({
            "agents": [], "assets": [], "coverage": full_coverage("available")
        });
        let result = evaluate_report(&report, SeverityFloor::High, true)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(result.coverage_complete);
        assert!(result.passed);
    }

    /// A table that is not a Topgent coverage table is bad input, which is a
    /// different outcome from incomplete coverage: the caller is told the
    /// report could not be read rather than that the host is short a sensor.
    #[test]
    fn a_malformed_coverage_table_is_an_error_rather_than_a_quiet_failure() {
        let duplicated = {
            let mut coverage = full_coverage("available");
            coverage.push(coverage[0].clone());
            json!({"agents": [], "assets": [], "coverage": coverage})
        };
        assert!(
            evaluate_report(&duplicated, SeverityFloor::High, true)
                .is_err_and(|error| error.contains("more than once"))
        );

        let unknown_rule = {
            let mut coverage = full_coverage("available");
            coverage.push(json!({
                "rule": "NOT_A_RULE", "sensor": "process",
                "state": "available", "verification": "automated"
            }));
            json!({"agents": [], "assets": [], "coverage": coverage})
        };
        assert!(
            evaluate_report(&unknown_rule, SeverityFloor::High, true)
                .is_err_and(|error| error.contains("not a rule in this build's catalogue"))
        );

        for broken in [
            json!({"sensor": "process", "state": "available", "verification": "automated"}),
            json!({"rule": "SANDBOX_ESCAPE", "sensor": "process", "verification": "automated"}),
            json!({"rule": "SANDBOX_ESCAPE", "sensor": "process", "state": "fine",
                   "verification": "automated"}),
            json!({"rule": "SANDBOX_ESCAPE", "sensor": "process", "state": "available",
                   "verification": "vibes"}),
            json!({"rule": "SANDBOX_ESCAPE", "sensor": "", "state": "available",
                   "verification": "automated"}),
        ] {
            let report = json!({"agents": [], "assets": [], "coverage": [broken.clone()]});
            assert!(
                evaluate_report(&report, SeverityFloor::High, true).is_err(),
                "a malformed entry was tolerated: {broken}"
            );
        }
    }

    /// A report scored against built-in defaults because the operator's policy
    /// would not load is not the check CI asked for, so it fails rather than
    /// passing quietly.
    #[test]
    fn a_report_scored_without_the_operators_policy_fails_the_gate() {
        let report = json!({
            "agents": [], "assets": [], "coverage": full_coverage("available"),
            "policy_health": {
                "state": "malformed",
                "detail": "the policy is not valid JSON",
                "digest": Value::Null,
                "operator_rules_in_force": false,
                "path": "/home/someone/.config/topgent/policy.json",
            }
        });
        let result = evaluate_report(&report, SeverityFloor::Critical, false)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!result.passed);
        assert_eq!(result.violations[0].code, "POLICY_NOT_IN_FORCE");

        // Recovered from the last-known-good copy is still the operator's rules.
        let recovered = json!({
            "agents": [], "assets": [], "coverage": full_coverage("available"),
            "policy_health": {"state": "recovered", "operator_rules_in_force": true}
        });
        assert!(
            evaluate_report(&recovered, SeverityFloor::Critical, false)
                .unwrap_or_else(|error| panic!("{error}"))
                .passed
        );

        // An older report has no such field, and that is not a failure.
        let legacy = json!({
            "agents": [], "assets": [], "coverage": full_coverage("available")
        });
        assert!(
            evaluate_report(&legacy, SeverityFloor::Critical, false)
                .unwrap_or_else(|error| panic!("{error}"))
                .passed
        );
    }

    #[test]
    fn evaluator_accepts_legacy_and_current_reports_but_rejects_unknown_contracts() {
        let legacy = json!({"agents":[], "assets":[], "coverage":[]});
        assert!(evaluate_report(&legacy, SeverityFloor::High, true).is_ok());
        let current = json!({
            "contract_version": REPORT_CONTRACT_VERSION,
            "agents":[], "assets":[], "coverage":[]
        });
        assert!(evaluate_report(&current, SeverityFloor::High, true).is_ok());
        let future = json!({
            "contract_version": REPORT_CONTRACT_VERSION + 1,
            "agents":[], "assets":[], "coverage":[]
        });
        assert!(
            evaluate_report(&future, SeverityFloor::High, true)
                .is_err_and(|error| error.contains("unsupported report contract version"))
        );
        let malformed = json!({
            "contract_version": "1", "agents":[], "assets":[], "coverage":[]
        });
        assert!(
            evaluate_report(&malformed, SeverityFloor::High, true)
                .is_err_and(|error| error.contains("not an unsigned integer"))
        );
    }

    #[test]
    fn a_byte_order_mark_is_not_a_reason_to_refuse_someones_report() {
        // PowerShell's default redirection writes UTF-8 with a mark, so the
        // obvious way to save a report on Windows produced
        // "expected value at line 1 column 1" and no clue why.
        let document = r#"{"contract_version":1}"#;
        let marked = format!("\u{feff}{document}");
        assert_eq!(super::without_byte_order_mark(&marked), document);
        assert_eq!(super::without_byte_order_mark(document), document);
        assert!(serde_json::from_str::<serde_json::Value>(&marked).is_err());
        assert!(
            serde_json::from_str::<serde_json::Value>(super::without_byte_order_mark(&marked))
                .is_ok()
        );

        // Only a leading mark, and only one: a mark in the middle of a document
        // is part of its content and is left exactly where it is.
        let inside = "{\"name\":\"a\u{feff}b\"}";
        assert_eq!(super::without_byte_order_mark(inside), inside);
        let doubled = format!("\u{feff}\u{feff}{document}");
        assert_eq!(
            super::without_byte_order_mark(&doubled),
            format!("\u{feff}{document}")
        );
        assert_eq!(super::without_byte_order_mark(""), "");
    }
}
