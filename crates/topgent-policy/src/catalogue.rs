//! The risk factor catalogue.
//!
//! Every factor's points, its sentence, its remedy and its ATLAS mapping live
//! in `data/risk-factors.json`. They used to live in four places — the enum in
//! `topgent-core`, the default weights here, and the descriptions and technique
//! mapping in `topgent-report` — with nothing forcing them to agree. Adding a
//! factor meant editing four files and hoping.
//!
//! Rust still owns the vocabulary. `FactorCode` remains an enum, because a
//! scorer that matches exhaustively on findings is a compile-time guarantee
//! worth more than the flexibility of a string, and because a data file that
//! could invent a new kind of finding would be a data file that could talk the
//! scorer into a verdict. The file supplies the *attributes* of codes Rust
//! already knows.
//!
//! # Failing closed
//!
//! The catalogue is compiled into the binary with `include_str!`, so it cannot
//! be swapped, edited or removed on a running machine. The only way to break it
//! is to edit it wrongly here, which [`builtin`] refuses and the tests catch
//! before a build ships. Validation is strict on purpose: an unknown code, a
//! duplicate, a missing sentence or a zero-point factor is an error rather than
//! something quietly skipped, because a scoring table that silently drops a row
//! produces a lower score, and a lower score reads as safety.

use serde::Deserialize;
use std::collections::BTreeSet;
use std::sync::OnceLock;

const SCHEMA_VERSION: u16 = 1;
const BUILTIN_JSON: &str = include_str!("../data/risk-factors.json");
static BUILTIN: OnceLock<Result<Catalogue, String>> = OnceLock::new();

/// Every code the scorer knows, in the order the catalogue must declare them.
///
/// The list is here rather than derived from the file because it is the
/// contract: the file describes these codes and may not introduce others.
pub const KNOWN_CODES: [&str; 20] = [
    "SANDBOX_ESCAPE",
    "RECON_FANOUT",
    "ARBITRARY_EXECUTION",
    "BROAD_WRITE",
    "UNRESTRICTED_NETWORK",
    "SECRET_REACHABLE",
    "EXFILTRATION_PATH",
    "AGENT_CHAIN",
    "DECLARATION_DRIFT",
    "WATCHLIST",
    "EXPOSED_LISTENER",
    "OFFENSIVE_TOOL",
    "PROCESS_EXPLOSION",
    "SUSPICIOUS_ENDPOINT",
    "PRIVATE_PEER",
    "METADATA_SERVICE",
    "CREDENTIAL_ACCESS",
    "PERSISTENCE_WRITE",
    "SELF_TAMPERING",
    "DISALLOWED_ASSET",
];

/// Everything known about one factor.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactorEntry {
    /// Stable machine-readable name, matching the `FactorCode` variant.
    pub code: String,
    /// Points the factor contributes by default.
    pub points: u32,
    /// Points for each occurrence after the first, where a factor can recur.
    #[serde(default)]
    pub subsequent_points: Option<u32>,
    /// Whether an operator may change the points in their own policy.
    ///
    /// Two factors are fixed: a sandbox escape and a critical watchlist match
    /// both mean the agent is doing something it said it would not, and being
    /// able to tune that down would defeat the point of declaring it.
    #[serde(default = "yes")]
    pub tunable: bool,
    /// One sentence explaining the factor, as the interface shows it.
    pub description: String,
    /// What to do about it.
    pub remedy: String,
    /// Where to do it.
    pub remedy_where: String,
    /// MITRE ATLAS or ATT&CK technique id, or empty where none applies.
    pub atlas_id: String,
    /// What that technique is, in a few words.
    pub atlas_description: String,
    /// Which sensor has to be working for this factor to be detectable at all.
    pub sensor: String,
    /// How the factor was last shown to work.
    ///
    /// `live` means against a real agent on a real host, `automated` against a
    /// deterministic test, `fixture` against captured sensor output, and
    /// `unavailable` means the sensor it needs does not exist on this platform.
    /// `degraded` is the honest fifth answer: the factor works, but it has
    /// never been shown working end to end, so the report does not claim it
    /// has been.
    pub verification: String,
    /// The best coverage this factor can claim even with its sensor healthy.
    ///
    /// Two factors need evidence the sensor alone cannot supply — a watchlist
    /// match depends on rules the operator wrote, and a sandbox escape depends
    /// on a declaration Topgent did not verify. Reporting either as fully
    /// covered would overstate what is actually being watched.
    #[serde(default)]
    pub coverage_ceiling: Option<String>,
}

const fn yes() -> bool {
    true
}

/// The validated catalogue.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalogue {
    /// Schema version this file claims to be.
    pub schema_version: u16,
    /// Where the catalogue came from.
    pub source: String,
    /// Every factor, in the order the legend presents them.
    pub factors: Vec<FactorEntry>,
}

impl Catalogue {
    /// The entry for one code, or `None` if the catalogue does not describe it.
    #[must_use]
    pub fn entry(&self, code: &str) -> Option<&FactorEntry> {
        self.factors.iter().find(|factor| factor.code == code)
    }
}

/// The catalogue compiled into this build.
///
/// # Errors
///
/// Returns the validation failure if the built-in catalogue is malformed. That
/// is a build-time mistake rather than a runtime condition: the file is part of
/// the binary.
pub fn builtin() -> Result<&'static Catalogue, &'static str> {
    match BUILTIN.get_or_init(|| parse_and_validate(BUILTIN_JSON)) {
        Ok(catalogue) => Ok(catalogue),
        Err(error) => Err(error.as_str()),
    }
}

fn parse_and_validate(source: &str) -> Result<Catalogue, String> {
    let catalogue: Catalogue = serde_json::from_str(source)
        .map_err(|error| format!("risk catalogue is invalid: {error}"))?;
    if catalogue.schema_version != SCHEMA_VERSION {
        return Err(format!(
            "risk catalogue schema {} is not the {SCHEMA_VERSION} this build understands",
            catalogue.schema_version
        ));
    }
    if catalogue.source.trim().is_empty() {
        return Err("risk catalogue names no source".to_owned());
    }

    let mut seen = BTreeSet::new();
    for factor in &catalogue.factors {
        if !KNOWN_CODES.contains(&factor.code.as_str()) {
            return Err(format!(
                "risk catalogue describes {}, which the scorer does not know",
                factor.code
            ));
        }
        if !seen.insert(factor.code.as_str()) {
            return Err(format!("risk catalogue lists {} twice", factor.code));
        }
        if factor.points == 0 {
            return Err(format!("{} scores nothing", factor.code));
        }
        if factor.description.trim().is_empty()
            || factor.remedy.trim().is_empty()
            || factor.remedy_where.trim().is_empty()
        {
            return Err(format!("{} cannot explain itself", factor.code));
        }
        if factor.subsequent_points.is_some_and(|points| points == 0) {
            return Err(format!("{} scores nothing after the first", factor.code));
        }
        if factor.sensor.trim().is_empty() || factor.verification.trim().is_empty() {
            return Err(format!(
                "{} names no sensor or no verification",
                factor.code
            ));
        }
    }
    for code in KNOWN_CODES {
        if !seen.contains(code) {
            return Err(format!("risk catalogue says nothing about {code}"));
        }
    }
    Ok(catalogue)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn the_built_in_catalogue_describes_every_factor_the_scorer_knows() {
        let catalogue = builtin().expect("the built-in catalogue must validate");
        assert_eq!(catalogue.factors.len(), KNOWN_CODES.len());
        for code in KNOWN_CODES {
            let entry = catalogue.entry(code).expect("every code is described");
            assert!(entry.points > 0, "{code} scores nothing");
            assert!(!entry.remedy.is_empty(), "{code} has no remedy");
        }
    }

    #[test]
    fn the_catalogue_declares_factors_in_the_order_the_legend_presents_them() {
        // The legend is read top to bottom by someone deciding what to look at,
        // so the order is part of what the interface promises. Reordering the
        // file reorders the screen, which is why the contract is stated twice
        // and checked rather than left to whoever edits the JSON.
        let catalogue = builtin().expect("the built-in catalogue must validate");
        let declared: Vec<&str> = catalogue
            .factors
            .iter()
            .map(|factor| factor.code.as_str())
            .collect();
        assert_eq!(declared, KNOWN_CODES.to_vec());
    }

    #[test]
    fn the_two_fixed_factors_are_the_ones_an_agent_broke_its_own_promise_to_earn() {
        // Everything else is a judgement call an operator may retune. These two
        // mean the agent did something it declared it would not, and a policy
        // that could discount that would defeat the point of declaring it.
        let catalogue = builtin().expect("the built-in catalogue must validate");
        let fixed: Vec<&str> = catalogue
            .factors
            .iter()
            .filter(|factor| !factor.tunable)
            .map(|factor| factor.code.as_str())
            .collect();
        assert_eq!(fixed, vec!["SANDBOX_ESCAPE", "WATCHLIST"]);
    }

    #[test]
    fn every_factor_names_the_sensor_that_has_to_be_working_for_it() {
        // Coverage is what makes an empty panel mean something. A factor with
        // no named sensor cannot be reported as uncovered when its sensor is
        // down, which is exactly when someone needs to be told.
        let catalogue = builtin().expect("the built-in catalogue must validate");
        for factor in &catalogue.factors {
            assert!(!factor.sensor.is_empty(), "{} names no sensor", factor.code);
            assert!(
                ["live", "automated", "fixture", "degraded", "unavailable"]
                    .contains(&factor.verification.as_str()),
                "{} claims verification {}",
                factor.code,
                factor.verification
            );
        }
    }

    #[test]
    fn a_catalogue_that_forgets_a_factor_is_refused_rather_than_scored_lower() {
        // The failure that matters. A dropped row is a lower score, and a lower
        // score reads as safety, so silence is the one thing this must not do.
        let source = BUILTIN_JSON.replace(
            r#"      "code": "CREDENTIAL_ACCESS","#,
            r#"      "code": "CREDENTIAL_ACCESS_TYPO","#,
        );
        let error = parse_and_validate(&source).expect_err("an unknown code is refused");
        assert!(error.contains("CREDENTIAL_ACCESS_TYPO"), "{error}");
    }

    #[test]
    fn a_factor_worth_nothing_is_a_mistake_not_a_setting() {
        let source = BUILTIN_JSON.replace(r#""points": 70,"#, r#""points": 0,"#);
        let error = parse_and_validate(&source).expect_err("a zero-point factor is refused");
        assert!(error.contains("scores nothing"), "{error}");
    }

    #[test]
    fn a_factor_that_cannot_explain_itself_is_refused() {
        let source = BUILTIN_JSON.replace(
            r#""remedy": "Rotate the credential and remove the agent's access","#,
            r#""remedy": "  ","#,
        );
        let error = parse_and_validate(&source).expect_err("an unexplained factor is refused");
        assert!(error.contains("cannot explain itself"), "{error}");
    }

    #[test]
    fn a_schema_this_build_does_not_understand_is_refused() {
        let source = BUILTIN_JSON.replace(r#""schema_version": 1,"#, r#""schema_version": 2,"#);
        let error = parse_and_validate(&source).expect_err("an unknown schema is refused");
        assert!(error.contains("schema 2"), "{error}");
    }

    #[test]
    fn a_field_nobody_recognises_is_refused_rather_than_ignored() {
        // A misspelled key that parses as "absent" is how a tuned weight
        // silently stops applying.
        let source = BUILTIN_JSON.replace(r#""points": 100,"#, r#""points": 100, "pointz": 5,"#);
        let error = parse_and_validate(&source).expect_err("an unknown field is refused");
        assert!(error.contains("invalid"), "{error}");
    }
}
