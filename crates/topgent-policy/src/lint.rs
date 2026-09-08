//! What is wrong with a catalogue, said out loud.
//!
//! A rule file has two ways of being wrong. It can fail to parse, which is
//! loud and already handled. Or it can parse perfectly and describe a factor
//! that cannot fire on this host, which is silent: the report shows no finding,
//! and a host with nothing wrong looks exactly like a host nobody was watching.
//!
//! Everything here is about the second kind. A warning never stops a catalogue
//! loading, because a factor that cannot fire is still better than no rules at
//! all. It is reported so an operator can tell the two situations apart.
//!
//! Each warning carries three strings on purpose: a stable code to grep for, a
//! short label to put in a table, and a sentence saying what it means for the
//! results. A warning that only prints a code makes the reader guess.

use crate::Thresholds;
use crate::catalogue::Catalogue;

/// What kind of problem was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WarningCode {
    /// The condition can never hold, whatever the agent does.
    UnsatisfiableCondition,
    /// The sensor this factor needs is not working on this host.
    SensorUnavailableHere,
    /// The factor contributes no points, so it cannot change a score.
    ScoresNothing,
    /// The factor claims no ATLAS or ATT&CK technique.
    NoTechniqueMapping,
    /// The factor has never been shown working end to end.
    Unproven,
    /// The factor is not stable, so a fresh install does not load it.
    NotOnByDefault,
    /// The factor is on its way out.
    Deprecated,
}

impl WarningCode {
    /// A stable identifier, for grepping and for machine readers.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsatisfiableCondition => "POLICY_UNSATISFIABLE_CONDITION",
            Self::SensorUnavailableHere => "POLICY_SENSOR_UNAVAILABLE_HERE",
            Self::ScoresNothing => "POLICY_SCORES_NOTHING",
            Self::NoTechniqueMapping => "POLICY_NO_TECHNIQUE_MAPPING",
            Self::Unproven => "POLICY_UNPROVEN",
            Self::NotOnByDefault => "POLICY_NOT_ON_BY_DEFAULT",
            Self::Deprecated => "POLICY_DEPRECATED",
        }
    }

    /// A few words, for a table.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::UnsatisfiableCondition => "condition can never hold",
            Self::SensorUnavailableHere => "sensor unavailable on this host",
            Self::ScoresNothing => "contributes no points",
            Self::NoTechniqueMapping => "no technique mapping",
            Self::Unproven => "never shown working end to end",
            Self::NotOnByDefault => "not loaded on a fresh install",
            Self::Deprecated => "on its way out",
        }
    }

    /// What it means for the results, which is the part that matters.
    #[must_use]
    pub const fn impact(self) -> &'static str {
        match self {
            Self::UnsatisfiableCondition => {
                "This factor cannot fire for any agent. A report with no such finding says \
                 nothing about the host, and reads identically to a host where the condition \
                 was checked and did not hold."
            }
            Self::SensorUnavailableHere => {
                "The evidence this factor needs is not being collected on this host, so its \
                 absence from a report is a gap in coverage rather than a clean result."
            }
            Self::ScoresNothing => {
                "A factor worth zero points appears in the catalogue but can never change a \
                 grade, so tuning it has no effect and its presence is misleading."
            }
            Self::NoTechniqueMapping => {
                "The finding cannot be tied to a published technique, so it cannot be \
                 correlated with anything outside Topgent."
            }
            Self::Unproven => {
                "The factor is believed to work but has not been demonstrated against a real \
                 agent, so a finding from it carries less weight than one that has."
            }
            Self::NotOnByDefault => {
                "This factor's maturity is below stable, so nothing on a fresh install \
                 evaluates it. Its absence from a report says nothing about the host until \
                 an operator opts that maturity in."
            }
            Self::Deprecated => {
                "The factor is kept for compatibility and will be removed, so anything built \
                 on it will stop working."
            }
        }
    }
}

/// One problem, with the factor it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    /// What kind of problem.
    pub code: WarningCode,
    /// The factor code it concerns.
    pub factor: String,
    /// Where in the catalogue, one-based, so a reader can find it in the file.
    pub index: usize,
    /// The specific detail, such as which sensor is missing.
    pub detail: String,
}

impl core::fmt::Display for Warning {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} factor {} (#{}): {} — {}",
            self.code.as_str(),
            self.factor,
            self.index,
            self.code.label(),
            self.detail
        )
    }
}

/// Everything wrong with a catalogue that is not a parse error.
///
/// `working_sensors` is the set of sensor names this host is actually
/// collecting from, as `topgent doctor` reports them. Pass an empty slice to
/// skip the host-specific check; passing an empty slice as though it meant
/// "everything works" is exactly the mistake this signature is shaped to
/// prevent.
#[must_use]
pub fn lint(
    catalogue: &Catalogue,
    thresholds: &Thresholds,
    working_sensors: Option<&[String]>,
) -> Vec<Warning> {
    let mut out = Vec::new();
    for (position, entry) in catalogue.factors.iter().enumerate() {
        let index = position + 1;
        let warn = |code: WarningCode, detail: String| Warning {
            code,
            factor: entry.code.clone(),
            index,
            detail,
        };

        for (which, condition) in [("firing", &entry.firing), ("requires", &entry.requires)] {
            if let Some(condition) = condition
                && !condition.is_satisfiable(thresholds)
            {
                out.push(warn(
                    WarningCode::UnsatisfiableCondition,
                    format!("its `{which}` condition is false for every agent"),
                ));
            }
        }

        if entry.points == 0 {
            out.push(warn(
                WarningCode::ScoresNothing,
                "points is zero".to_owned(),
            ));
        }

        // A deliberate absence is not a gap. A factor that says why it maps to
        // nothing has been thought about; one that is silently blank has not.
        if entry.atlas_id.trim().is_empty() && entry.technique_absent_reason.is_none() {
            out.push(warn(
                WarningCode::NoTechniqueMapping,
                "atlas_id is empty and no reason is given".to_owned(),
            ));
        }

        if !entry.maturity.on_by_default() {
            out.push(warn(
                WarningCode::NotOnByDefault,
                format!("maturity is `{}`", entry.maturity.as_str()),
            ));
        }

        if entry.maturity == crate::Maturity::Deprecated {
            out.push(warn(
                WarningCode::Deprecated,
                "scheduled for removal".to_owned(),
            ));
        }

        if matches!(entry.verification.as_str(), "degraded" | "unavailable") {
            out.push(warn(
                WarningCode::Unproven,
                format!("verification is `{}`", entry.verification),
            ));
        }

        if let Some(working) = working_sensors
            && !entry.sensor.trim().is_empty()
            && !working.iter().any(|name| name == &entry.sensor)
        {
            out.push(warn(
                WarningCode::SensorUnavailableHere,
                format!(
                    "needs the `{}` sensor, which is not collecting",
                    entry.sensor
                ),
            ));
        }
    }
    out
}
