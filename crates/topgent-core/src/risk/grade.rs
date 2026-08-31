//! Turning a total into a word.
//!
//! The ceiling exists so that a very long list of small findings cannot present
//! as more urgent than a single decisive one. A grade is a summary for a person
//! deciding what to look at first, and it is never the evidence itself.

use super::factor::Factor;

/// Risk band.
///
/// Always shown with the score and the factors, never alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Grade {
    /// Nothing notable.
    Low,
    /// Worth knowing about.
    Medium,
    /// Worth acting on.
    High,
    /// Act now.
    Critical,
}

impl Grade {
    /// Band for a score.
    #[must_use]
    pub const fn from_score(score: u32) -> Self {
        if score >= 80 {
            Self::Critical
        } else if score >= 60 {
            Self::High
        } else if score >= 35 {
            Self::Medium
        } else {
            Self::Low
        }
    }

    /// Display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }

    /// The band a stored label came from.
    ///
    /// Round-trips with `label`, so a record written by an older build is read
    /// back as the same band rather than compared as text. Comparing grades as
    /// strings is how a downgrade gets reported as an escalation.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        match label.to_ascii_uppercase().as_str() {
            "LOW" => Some(Self::Low),
            "MEDIUM" => Some(Self::Medium),
            "HIGH" => Some(Self::High),
            "CRITICAL" => Some(Self::Critical),
            _ => None,
        }
    }

    /// How many of four marks are filled, so the band reads without colour.
    #[must_use]
    pub const fn pips(self) -> u8 {
        match self {
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }
}

/// The whole assessment of one agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Risk {
    /// Total, capped at 100.
    pub score: u32,
    /// Band derived from the total.
    pub grade: Grade,
    /// Contributions, highest first, ties broken by code so the order is stable.
    pub factors: Vec<Factor>,
    /// The identity multiplier that was applied, as a percentage.
    pub identity_multiplier: u32,
}

/// Ceiling on the score. Beyond this the number stops carrying information.
pub(super) const MAX_SCORE: u32 = 100;
