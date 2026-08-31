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
    let coverage_complete = coverage.iter().all(|entry| entry["state"] == "available");
    let mut violations = Vec::new();
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
    #[test]
    fn evaluator_separates_violations_from_missing_coverage() {
        let report = json!({
            "agents": [{"asset_id":"urn:topgent:agent:a", "grade":"HIGH"}],
            "assets": [{"id":"urn:topgent:model:m", "kind":"model", "disposition":"disallowed"}],
            "coverage": [{"state":"unsupported"}]
        });
        let result = evaluate_report(&report, SeverityFloor::High, true)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!result.passed);
        assert!(!result.coverage_complete);
        assert_eq!(result.violations.len(), 2);
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
