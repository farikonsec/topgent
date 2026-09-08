//! Accepting a finding, on the record and with an end date.
//!
//! Every monitor eventually meets a finding its operator has looked at and
//! decided to live with. Without somewhere to put that decision it goes into
//! the only place available: someone stops reading the output. An exception is
//! that decision written down, so the tool keeps evaluating and the acceptance
//! is visible instead of implicit.
//!
//! # Why every field is required
//!
//! An exception is a hole in the thing that is supposed to be watching. Each
//! field closes a way that hole becomes permanent and anonymous:
//!
//! - **name** so it can be discussed, and so two of them are distinguishable.
//! - **reason** so a reader six months later knows what was accepted and why.
//! - **`created_by`** so the decision has an owner.
//! - **`expires_at`**, and there is no "never". An acceptance that outlives the
//!   circumstances that justified it is the failure mode this whole type
//!   exists to prevent, and an optional expiry would be left empty every time.
//!
//! # Scope
//!
//! An exception names one factor and narrows from there. A rule that suppressed
//! everything for a process, or every finding of a kind everywhere, would be
//! indistinguishable from switching the monitor off for that case, so the
//! narrowing is on the shape of the type rather than left to discipline.
//!
//! # Time
//!
//! Expiry is checked against the moment being scored, never against the clock.
//! Replaying a bundle from last month must produce the answer that was correct
//! last month, and an exception that had not yet expired then must still apply.

use serde::{Deserialize, Serialize};

/// One accepted finding, scoped and dated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exception {
    /// What this acceptance is called.
    pub name: String,
    /// The factor code it suppresses, such as `SECRET_REACHABLE`.
    pub factor: String,
    /// Agent family it applies to. `None` means any family.
    #[serde(default)]
    pub family: Option<String>,
    /// Substring the finding's subject must contain. `None` means any subject.
    ///
    /// A path fragment, a host, or a resource name. Matching on a substring
    /// rather than an exact value is deliberate: the thing an operator accepts
    /// is usually a directory or a domain, and forcing exact values produces
    /// either a hundred exceptions or one that is too wide.
    #[serde(default)]
    pub target: Option<String>,
    /// Why this was accepted.
    pub reason: String,
    /// Who accepted it.
    pub created_by: String,
    /// When it was accepted, in Unix milliseconds.
    pub created_at: u64,
    /// When it stops applying, in Unix milliseconds. There is no "never".
    pub expires_at: u64,
}

/// Why an exception was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExceptionError {
    /// A required field was blank.
    Blank {
        /// Which field.
        field: &'static str,
    },
    /// The expiry is not after the creation time.
    NotDated {
        /// When it was created.
        created_at: u64,
        /// When it claims to expire.
        expires_at: u64,
    },
    /// The factor code is not one this build knows.
    UnknownFactor {
        /// The code as written.
        factor: String,
    },
    /// The window is longer than [`MAX_WINDOW_MS`].
    TooLong {
        /// How many days were asked for.
        days: u64,
    },
}

impl core::fmt::Display for ExceptionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Blank { field } => write!(f, "exception field `{field}` is blank"),
            Self::NotDated {
                created_at,
                expires_at,
            } => write!(
                f,
                "exception expires at {expires_at}, which is not after {created_at}"
            ),
            Self::UnknownFactor { factor } => {
                write!(f, "exception names factor `{factor}`, which does not exist")
            }
            Self::TooLong { days } => write!(
                f,
                "exception runs for {days} days, over the {} day limit",
                MAX_WINDOW_MS / 86_400_000
            ),
        }
    }
}

impl core::error::Error for ExceptionError {}

/// The longest an acceptance may run before someone looks again: one year.
///
/// A cap rather than a policy choice. An exception that can be written for a
/// decade is a permanent one with extra steps.
pub const MAX_WINDOW_MS: u64 = 365 * 86_400_000;

impl Exception {
    /// Checks everything that must be true for this to be usable.
    ///
    /// # Errors
    ///
    /// Returns [`ExceptionError`] for a blank required field, an expiry that
    /// is not after creation, a window over [`MAX_WINDOW_MS`], or a factor
    /// code this build does not know.
    pub fn validate(&self) -> Result<(), ExceptionError> {
        for (field, value) in [
            ("name", &self.name),
            ("factor", &self.factor),
            ("reason", &self.reason),
            ("created_by", &self.created_by),
        ] {
            if value.trim().is_empty() {
                return Err(ExceptionError::Blank { field });
            }
        }
        if self.expires_at <= self.created_at {
            return Err(ExceptionError::NotDated {
                created_at: self.created_at,
                expires_at: self.expires_at,
            });
        }
        let window = self.expires_at.saturating_sub(self.created_at);
        if window > MAX_WINDOW_MS {
            return Err(ExceptionError::TooLong {
                days: window / 86_400_000,
            });
        }
        if !crate::catalogue::KNOWN_CODES.contains(&self.factor.as_str()) {
            return Err(ExceptionError::UnknownFactor {
                factor: self.factor.clone(),
            });
        }
        Ok(())
    }

    /// Whether this exception is in force at one moment.
    ///
    /// `as_of` is the moment being scored, not the clock. See the module note.
    #[must_use]
    pub const fn active_at(&self, as_of: u64) -> bool {
        as_of >= self.created_at && as_of < self.expires_at
    }

    /// Whether it covers one finding.
    ///
    /// All three tests must pass. A family or target of `None` matches
    /// anything, which is the widest an exception can be, and the widest is
    /// still scoped to one factor code.
    #[must_use]
    pub fn covers(&self, factor: &str, family: Option<&str>, subject: &str) -> bool {
        if self.factor != factor {
            return false;
        }
        if let Some(wanted) = &self.family
            && family != Some(wanted.as_str())
        {
            return false;
        }
        if let Some(wanted) = &self.target
            && !subject.contains(wanted.as_str())
        {
            return false;
        }
        true
    }
}

/// One finding an exception stopped, kept so the suppression is visible.
///
/// A suppressed finding that left no trace would make an exception
/// indistinguishable from the finding never having occurred, which is exactly
/// the confusion the whole mechanism is supposed to remove.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Suppression {
    /// The exception that applied.
    pub exception: String,
    /// The factor it suppressed.
    pub factor: String,
    /// The finding's own sentence, kept verbatim.
    pub title: String,
    /// Points that did not reach the score.
    pub points: u32,
    /// When this exception stops applying.
    pub expires_at: u64,
}
