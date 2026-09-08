//! Behavioural scenarios, run against the artefact that ships.
//!
//! A unit test proves the source tree is right. It says nothing about the file
//! somebody downloads, which is built by a different toolchain, stripped,
//! archived, extracted and run under a different loader. Every step there has
//! shipped a broken binary for somebody at some point, and the source tests
//! stayed green throughout.
//!
//! A scenario is therefore a black box: it names a command line, the input, and
//! what must and must not appear in the output. The harness spawns the binary
//! under test and compares. Nothing here links against the crates being tested.
//!
//! # The safeguards matter more than the scenarios
//!
//! A suite that silently runs nothing passes. So the file declares how many
//! scenarios it holds, the harness refuses a suite where that number is wrong,
//! refuses a run where nothing executed, and refuses a platform where every
//! applicable case was skipped. Each of those is a way a green tick can mean
//! "we did not look".
//!
//! Every scenario also carries at least one negative assertion. A detector that
//! matched everything would satisfy every positive expectation ever written.

use serde::Deserialize;

/// A suite of scenarios, as one file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suite {
    /// Schema version of this file.
    pub schema_version: u16,
    /// How many scenarios this file holds.
    ///
    /// Written down and checked. A suite that lost half its cases to a bad
    /// merge would otherwise pass with the half that remained.
    pub expected_scenarios: usize,
    /// The scenarios.
    pub scenarios: Vec<Scenario>,
}

/// One black-box case.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    /// Stable identifier, used in output and in skip reports.
    pub id: String,
    /// What this case is checking, in a sentence.
    pub description: String,
    /// Platforms it applies to: `macos`, `linux`, `windows`.
    pub platforms: Vec<String>,
    /// Arguments to the binary under test. The binary itself is not named here,
    /// because the point is to run whichever artefact is being validated.
    pub args: Vec<String>,
    /// Exit code the command must return, where the command has a fixed one.
    ///
    /// Absent means the exit code is not part of what this case checks. That
    /// is not laxity: some commands report something about the *host* in their
    /// exit code rather than something about themselves. `doctor` exits
    /// non-zero when the machine lacks a sensor it needs, which is true of
    /// plenty of perfectly good build machines, and a case about the content
    /// of its output has no business asserting that the host is healthy.
    ///
    /// Every case still has to assert something, which [`Suite::validate`]
    /// enforces through `must_not_appear`.
    #[serde(default)]
    pub expect_exit: Option<i32>,
    /// Substrings that must all appear in standard output.
    #[serde(default)]
    pub expect_stdout: Vec<String>,
    /// Substrings that must not appear anywhere in the output.
    ///
    /// Required to be non-empty by [`Suite::validate`]: a case with no negative
    /// assertion is satisfied by a tool that prints everything.
    pub must_not_appear: Vec<String>,
}

/// Why a suite could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuiteError {
    /// The file claims a different number of scenarios than it holds.
    Miscounted {
        /// What the file declared.
        declared: usize,
        /// What it holds.
        found: usize,
    },
    /// A scenario has no negative assertion.
    NoNegativeControl {
        /// Which scenario.
        id: String,
    },
    /// A scenario names no platform, so it can never run.
    NoPlatform {
        /// Which scenario.
        id: String,
    },
    /// Two scenarios share an identifier.
    DuplicateId {
        /// The identifier.
        id: String,
    },
    /// A scenario names a platform this build does not know.
    UnknownPlatform {
        /// Which scenario.
        id: String,
        /// The platform as written.
        platform: String,
    },
}

impl core::fmt::Display for SuiteError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Miscounted { declared, found } => write!(
                f,
                "suite declares {declared} scenarios and holds {found}; \
                 a suite that lost cases must not pass with the ones that remain"
            ),
            Self::NoNegativeControl { id } => write!(
                f,
                "scenario `{id}` asserts nothing negative; a tool that printed \
                 everything would satisfy it"
            ),
            Self::NoPlatform { id } => {
                write!(f, "scenario `{id}` names no platform, so it never runs")
            }
            Self::DuplicateId { id } => write!(f, "two scenarios share the id `{id}`"),
            Self::UnknownPlatform { id, platform } => write!(
                f,
                "scenario `{id}` names platform `{platform}`, which this build \
                 does not know; a typo here silently skips the case"
            ),
        }
    }
}

impl core::error::Error for SuiteError {}

/// Platforms a scenario may name.
pub const PLATFORMS: [&str; 3] = ["macos", "linux", "windows"];

/// The platform this build is running on, in scenario spelling.
#[must_use]
pub const fn current_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    }
}

impl Suite {
    /// Everything that must be true before a suite is worth running.
    ///
    /// # Errors
    ///
    /// Returns [`SuiteError`] for a miscount, a duplicate id, a scenario with
    /// no platform, an unknown platform, or a scenario with no negative
    /// assertion.
    pub fn validate(&self) -> Result<(), SuiteError> {
        if self.expected_scenarios != self.scenarios.len() {
            return Err(SuiteError::Miscounted {
                declared: self.expected_scenarios,
                found: self.scenarios.len(),
            });
        }
        let mut seen: Vec<&str> = Vec::new();
        for scenario in &self.scenarios {
            if seen.contains(&scenario.id.as_str()) {
                return Err(SuiteError::DuplicateId {
                    id: scenario.id.clone(),
                });
            }
            seen.push(&scenario.id);
            if scenario.platforms.is_empty() {
                return Err(SuiteError::NoPlatform {
                    id: scenario.id.clone(),
                });
            }
            for platform in &scenario.platforms {
                if !PLATFORMS.contains(&platform.as_str()) {
                    return Err(SuiteError::UnknownPlatform {
                        id: scenario.id.clone(),
                        platform: platform.clone(),
                    });
                }
            }
            if scenario.must_not_appear.is_empty() {
                return Err(SuiteError::NoNegativeControl {
                    id: scenario.id.clone(),
                });
            }
        }
        Ok(())
    }

    /// Scenarios that apply to one platform.
    #[must_use]
    pub fn applicable(&self, platform: &str) -> Vec<&Scenario> {
        self.scenarios
            .iter()
            .filter(|scenario| scenario.platforms.iter().any(|name| name == platform))
            .collect()
    }
}

/// What one scenario did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Which scenario.
    pub id: String,
    /// Whether every expectation held.
    pub passed: bool,
    /// Why it failed, empty when it passed.
    pub failures: Vec<String>,
}

/// The first line of a stream, for a message that has to stay one line.
fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or("")
}

/// Enough of a command's output to say why it failed, and no more.
///
/// Bounded, because a scenario's output can be a whole report and a test
/// failure that scrolls off the screen is a test failure nobody reads.
fn evidence(stdout: &str) -> String {
    const MAX: usize = 600;
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return "(nothing)".to_owned();
    }
    let mut out: String = trimmed.chars().take(MAX).collect();
    if trimmed.chars().count() > MAX {
        out.push_str("...");
    }
    out.replace('\n', " ")
}

/// Compares one command's result against what the scenario expected.
///
/// Pure, so the comparison can be tested without spawning anything. The
/// harness supplies the exit code and the output it observed.
#[must_use]
pub fn judge(scenario: &Scenario, exit: i32, stdout: &str, stderr: &str) -> Outcome {
    let mut failures = Vec::new();
    if scenario
        .expect_exit
        .is_some_and(|expected| exit != expected)
    {
        // The output too, not only the code. A scenario that failed on a
        // machine nobody can log into is worth nothing if all it says is a
        // number: this one failed on a build runner for four rounds while the
        // same command passed on every machine here, and each round cost a
        // push to learn nothing. Whatever the command printed is the evidence.
        failures.push(format!(
            "exit {exit}, expected {:?}; stderr: {}; stdout: {}",
            scenario.expect_exit,
            first_line(stderr),
            evidence(stdout)
        ));
    }
    for wanted in &scenario.expect_stdout {
        if !stdout.contains(wanted.as_str()) {
            failures.push(format!("stdout does not contain {wanted:?}"));
        }
    }
    for banned in &scenario.must_not_appear {
        if stdout.contains(banned.as_str()) || stderr.contains(banned.as_str()) {
            failures.push(format!("output contains {banned:?}, which it must not"));
        }
    }
    Outcome {
        id: scenario.id.clone(),
        passed: failures.is_empty(),
        failures,
    }
}
