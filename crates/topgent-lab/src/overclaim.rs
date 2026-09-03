//! The M0 overclaim lint.
//!
//! `docs/NORMATIVE-CLAIMS.md` fixes what Topgent is allowed to say about its
//! own findings. A monitor rarely fails by printing a wrong number; it fails by
//! printing a right number under a verb the evidence does not support. This
//! module is the mechanical half of that document: pure text in, findings out,
//! no I/O, so the rules can be tested without a filesystem.
//!
//! The rules are deliberately biased toward false positives. An allowlist entry
//! costs one line and a reviewer's attention. A shipped overclaim costs the
//! credibility of every other claim in the report.

/// Marker that exempts a line from every rule.
///
/// Placed on the offending line itself, with a reason after it.
pub const ALLOW_MARKER: &str = "overclaim-ok";

/// Strong claims that may appear only beside an explicit quality or coverage.
const RESERVED: &[&str] = &[
    "proves",
    "guarantees",
    "ensures",
    "prevents",
    "blocks",
    "detects all",
    "every file",
    "all connections",
    "always",
    "never misses",
    "complete",
    "full visibility",
    "confirms",
    "verified",
];

/// Phrases no qualifier rescues, because no platform can support them.
const BANNED: &[&str] = &[
    "knows everything",
    "cannot be evaded",
    "tamper-proof",
    "tamperproof",
    "tamper proof",
];

/// Quality and coverage tokens, matched with their original casing.
///
/// Case matters. Lowercase `unknown` and `strong` are ordinary English and
/// would let almost any sentence qualify itself by accident.
const QUALIFIERS: &[&str] = &[
    "Exact",
    "Strong",
    "Weak",
    "Unknown",
    "Contradicted",
    "CompleteForWindow",
    "LossObserved",
    "CollectorDegraded",
    "SnapshotOnly",
    "Unsupported",
    "`exact`",
    "`strong`",
    "`weak`",
    "`unknown`",
    "`contradicted`",
    "`complete_for_window`",
    "`loss_observed`",
    "`collector_degraded`",
    "`snapshot_only`",
    "`unsupported`",
];

/// Constructions that deny the claim rather than make it.
const DENIALS: &[&str] = &[
    "not ",
    "never",
    "cannot",
    "can not",
    "without",
    "rather than",
    "instead of",
    "no claim",
    "nothing",
    "must only",
    "only ever",
];

/// Words that name the integrity mechanism.
const SIGNATURE_WORDS: &[&str] = &["signature", "signatures", "signed", "signing", "ed25519"];

/// Words that turn integrity into a claim about truth or completeness.
const TRUTH_WORDS: &[&str] = &[
    "proves",
    "guarantees",
    "ensures",
    "proof that",
    "means that",
];

/// Which rule a finding violates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// A reserved strong claim with no quality or coverage beside it.
    Unqualified(&'static str),
    /// A phrase that is wrong under every qualifier.
    Banned(&'static str),
    /// Integrity described as proof of truth or of completeness.
    SignatureOverclaim,
    /// A confidence percentage no benchmark produced.
    UncalibratedPercentage,
}

impl Rule {
    /// One line explaining why the rule exists, for the failure message.
    #[must_use]
    pub fn reason(self) -> String {
        match self {
            Self::Unqualified(phrase) => {
                format!("`{phrase}` needs an attribution quality or collection coverage beside it")
            }
            Self::Banned(phrase) => {
                format!("`{phrase}` is banned outright; no qualifier makes it true")
            }
            Self::SignatureOverclaim => {
                "signing establishes integrity, not that the sensor was truthful or complete"
                    .to_owned()
            }
            Self::UncalibratedPercentage => {
                "a confidence percentage is only permitted from benchmark output".to_owned()
            }
        }
    }
}

/// One rule violation, located.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// One-based line number.
    pub line: usize,
    /// The rule that fired.
    pub rule: Rule,
    /// The offending line, trimmed.
    pub text: String,
}

/// Audits one document or source file.
///
/// Returns every violation in order. An empty result is a pass.
#[must_use]
pub fn audit(text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        if raw.contains(ALLOW_MARKER) {
            continue;
        }
        let line = index + 1;
        let lower = raw.to_lowercase();
        let trimmed = raw.trim().to_owned();

        for phrase in BANNED {
            if lower.contains(phrase) && !denied_around(&lower, phrase) {
                findings.push(Finding {
                    line,
                    rule: Rule::Banned(phrase),
                    text: trimmed.clone(),
                });
            }
        }

        if !qualified(raw) {
            for phrase in RESERVED {
                if contains_word(&lower, phrase) && !denied_around(&lower, phrase) {
                    findings.push(Finding {
                        line,
                        rule: Rule::Unqualified(phrase),
                        text: trimmed.clone(),
                    });
                }
            }
        }

        if signature_overclaim(&lower) {
            findings.push(Finding {
                line,
                rule: Rule::SignatureOverclaim,
                text: trimmed.clone(),
            });
        }

        if uncalibrated_percentage(&lower) {
            findings.push(Finding {
                line,
                rule: Rule::UncalibratedPercentage,
                text: trimmed,
            });
        }
    }
    findings
}

/// Whether the line carries a quality or coverage token.
fn qualified(raw: &str) -> bool {
    QUALIFIERS.iter().any(|token| raw.contains(token))
}

/// Whether the line denies the claim instead of making it.
fn denied(lower: &str) -> bool {
    DENIALS.iter().any(|token| lower.contains(token))
}

/// Whether the rest of the line denies the phrase that fired.
///
/// The phrase is removed before the denial words are looked for, because
/// several of them carry their own. `never misses` contains `never` and
/// `cannot be evaded` contains `cannot`, so a line-wide search would let the
/// two strongest claims in the list excuse themselves.
fn denied_around(lower: &str, phrase: &str) -> bool {
    denied(&lower.replace(phrase, " "))
}

/// Whether integrity is being described as truth or completeness.
fn signature_overclaim(lower: &str) -> bool {
    SIGNATURE_WORDS.iter().any(|word| lower.contains(word))
        && TRUTH_WORDS.iter().any(|word| lower.contains(word))
        && !denied(lower)
}

/// Whether a confidence percentage appears outside benchmark output.
fn uncalibrated_percentage(lower: &str) -> bool {
    lower.contains('%') && lower.contains("confiden") && !lower.contains("benchmark")
}

/// Substring match that respects word boundaries.
///
/// Without this, `complete` fires on `completeness` and `blocks` fires on
/// `blocks_read`, which trains reviewers to ignore the lint.
fn contains_word(haystack: &str, needle: &str) -> bool {
    haystack.match_indices(needle).any(|(at, found)| {
        let before = haystack.get(..at).and_then(|head| head.chars().next_back());
        let after = haystack
            .get(at.saturating_add(found.len())..)
            .and_then(|tail| tail.chars().next());
        !before.is_some_and(is_word_char) && !after.is_some_and(is_word_char)
    })
}

/// Whether a character continues a word.
fn is_word_char(character: char) -> bool {
    character.is_alphanumeric() || character == '_' || character == '-'
}

/// Audits Rust source, ignoring comments.
///
/// The lint governs what Topgent tells a user, not how its authors reason with
/// each other. A layout comment saying a label is "always drawn" is not a claim
/// about a finding, and treating it as one trains reviewers to skip the lint.
/// Line numbers are preserved so a finding still points at the right line.
#[must_use]
pub fn audit_rust(source: &str) -> Vec<Finding> {
    let masked: String = source
        .lines()
        .map(|line| if is_comment(line) { "" } else { line })
        .collect::<Vec<_>>()
        .join("\n");
    audit(&masked)
}

/// Whether a line is wholly a comment.
fn is_comment(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*")
}
