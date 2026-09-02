//! How the policy on disk was read.
//!
//! The policy is not a preferences file. It carries the watchlist rules, the
//! response modes, the asset dispositions, the thresholds and the weights, so
//! losing it silently downgrades every finding on the host at once.
//!
//! `load_from` used to be `read_to_string().ok().and_then(parse).ok()
//! .unwrap_or_default()`, which turns a crash mid-write, a full disk, a
//! concurrent writer and a mistyped key into exactly the same outcome as a
//! fresh install: built-in defaults, no message, and a report that looks fine.
//!
//! Four states replace that one. Three of them are good news and one is a
//! failure a person has to see.

use serde::{Deserialize, Serialize};

/// What Topgent can say about the policy behind this run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PolicyHealth {
    /// No policy file exists. The built-in defaults apply, which is the normal
    /// state of a fresh install and is not a fault.
    Absent,
    /// The file was read and parsed. The digest identifies which policy
    /// produced a given report, so two runs can be compared without trusting
    /// that nobody edited the file in between.
    Valid {
        /// Lowercase hex SHA-256 of the exact bytes read.
        digest: String,
    },
    /// The file could not be read or parsed, and the last-known-good copy was
    /// loaded instead. Detection continues on the older rules, and the report
    /// says which rules those are.
    Recovered {
        /// What was wrong with the current file.
        detail: String,
        /// Digest of the last-known-good copy that was loaded.
        digest: String,
    },
    /// The file could not be read or parsed and there is no last-known-good
    /// copy. Built-in defaults are in force, and the operator's rules are not.
    Malformed {
        /// What was wrong with the file.
        detail: String,
    },
}

impl PolicyHealth {
    /// Stable report label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Valid { .. } => "valid",
            Self::Recovered { .. } => "recovered",
            Self::Malformed { .. } => "malformed",
        }
    }

    /// Whether the rules in force are the ones the operator wrote.
    ///
    /// `Absent` is true: nobody wrote any rules, so the defaults are what was
    /// asked for. `Malformed` is false, because rules exist and are not being
    /// applied. Enforcement and the CI gate fail closed on false.
    #[must_use]
    pub const fn rules_are_the_operators(&self) -> bool {
        match self {
            Self::Absent | Self::Valid { .. } | Self::Recovered { .. } => true,
            Self::Malformed { .. } => false,
        }
    }

    /// What went wrong, when something did.
    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Absent | Self::Valid { .. } => None,
            Self::Recovered { detail, .. } | Self::Malformed { detail } => Some(detail),
        }
    }

    /// The digest of the bytes actually in force, when there are any.
    #[must_use]
    pub fn digest(&self) -> Option<&str> {
        match self {
            Self::Valid { digest } | Self::Recovered { digest, .. } => Some(digest),
            Self::Absent | Self::Malformed { .. } => None,
        }
    }
}

/// Lowercase hex SHA-256 of some bytes.
#[must_use]
pub fn digest_of(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

#[cfg(test)]
mod tests {
    use super::{PolicyHealth, digest_of};

    #[test]
    fn the_digest_is_sha256() {
        // The published vector, so a swap of the hash function is visible.
        assert_eq!(
            digest_of(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(digest_of(b"").len(), 64);
    }

    /// The finding: losing the operator's rules looked exactly like never
    /// having had any. Only one of the four states may fail closed, and only
    /// one of them is silent.
    #[test]
    fn only_a_malformed_policy_with_no_backup_withholds_the_operators_rules() {
        assert!(PolicyHealth::Absent.rules_are_the_operators());
        assert!(
            PolicyHealth::Valid {
                digest: digest_of(b"{}")
            }
            .rules_are_the_operators()
        );
        assert!(
            PolicyHealth::Recovered {
                detail: "truncated".to_owned(),
                digest: digest_of(b"{}"),
            }
            .rules_are_the_operators()
        );
        assert!(
            !PolicyHealth::Malformed {
                detail: "truncated".to_owned()
            }
            .rules_are_the_operators()
        );
    }

    #[test]
    fn every_state_says_what_it_is_and_only_the_failures_carry_a_reason() {
        assert_eq!(PolicyHealth::Absent.as_str(), "absent");
        assert_eq!(PolicyHealth::Absent.detail(), None);
        assert_eq!(PolicyHealth::Absent.digest(), None);
        let malformed = PolicyHealth::Malformed {
            detail: "expected value at line 1".to_owned(),
        };
        assert_eq!(malformed.as_str(), "malformed");
        assert_eq!(malformed.detail(), Some("expected value at line 1"));
        assert_eq!(malformed.digest(), None, "no bytes are in force");
    }
}
