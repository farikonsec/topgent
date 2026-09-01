//! Where Topgent's own sensors come from.
//!
//! Every collector here shells out to an operating-system tool, and until now
//! each one named it and let the loader find it. `PATH` is writable by anything
//! running as the user, and the whole premise of this product is that agents
//! run as the user. A monitor that resolves its own sensors through `PATH` can
//! be handed fabricated telemetry by anything that can drop a file in a
//! directory listed ahead of the real one, and it would report that telemetry
//! with full confidence.
//!
//! So tools are resolved to an absolute path in a location the operating system
//! owns. A tool found only on `PATH` is refused rather than used, because a
//! sensor Topgent cannot vouch for is worse than a sensor it does not have: the
//! first lies quietly and the second is visible in Sensor Health.

use crate::CollectError;
use std::path::{Path, PathBuf};
use std::process::Command;

/// What Topgent could establish about the binary behind a sensor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolState {
    /// Found at a path the operating system owns.
    Trusted,
    /// Present on this host, but only somewhere anything could have put it.
    Untrusted,
    /// Not found at any expected location.
    Missing,
}

impl ToolState {
    /// Stable report label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Untrusted => "untrusted",
            Self::Missing => "missing",
        }
    }
}

/// What Topgent can say about one sensor's binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolAttestation {
    /// The tool's short name.
    pub name: &'static str,
    /// The absolute path used, when one was accepted.
    pub path: Option<String>,
    /// What could be established.
    pub state: ToolState,
}

/// An operating-system tool and the only places it is accepted from.
#[derive(Debug, Clone, Copy)]
pub struct SystemTool {
    /// Short name, used in reports and errors.
    pub name: &'static str,
    /// Absolute paths this tool is accepted from, in order.
    pub candidates: &'static [&'static str],
}

impl SystemTool {
    /// The first accepted path that exists on this host.
    #[must_use]
    pub fn resolve(&self) -> Option<PathBuf> {
        self.candidates
            .iter()
            .map(Path::new)
            .find(|candidate| candidate.is_file())
            .map(Path::to_path_buf)
    }

    /// What Topgent can say about this tool right now.
    #[must_use]
    pub fn attest(&self) -> ToolAttestation {
        match self.resolve() {
            Some(path) => ToolAttestation {
                name: self.name,
                path: Some(path.to_string_lossy().into_owned()),
                state: ToolState::Trusted,
            },
            // Deliberately does not fall back to a `PATH` lookup to fill this
            // in. Reporting where an unaccepted copy lives would invite reading
            // it, and the point is that it is not read.
            None => ToolAttestation {
                name: self.name,
                path: None,
                state: ToolState::Missing,
            },
        }
    }

    /// A command bound to the accepted absolute path.
    ///
    /// # Errors
    ///
    /// Returns [`CollectError::Unavailable`] when the tool is not present at
    /// any accepted location. The caller must not reach for `PATH` instead.
    pub fn command(&self) -> Result<Command, CollectError> {
        let path = self.resolve().ok_or_else(|| CollectError::Unavailable {
            what: format!(
                "{} was not found at any operating-system location Topgent accepts, so this \
                 sensor is not run; a copy elsewhere on PATH is deliberately not used",
                self.name
            ),
        })?;
        let mut command = Command::new(path);
        no_console_window(&mut command);
        Ok(command)
    }
}

/// Keep a spawned tool from opening a console window.
///
/// Every sensor on Windows runs through `powershell.exe` or `netstat`, and a
/// GUI process spawning a console application gets a console window for it.
/// The desktop app therefore flashed a black window several times per sweep,
/// which looks like the tool doing something it will not explain.
///
/// `CREATE_NO_WINDOW` is 0x0800_0000. The constant is written here rather than
/// pulled from a Windows crate because it is one number and this is the only
/// place that needs it.
#[cfg(windows)]
fn no_console_window(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    command.creation_flags(0x0800_0000);
}

/// Nothing to suppress anywhere else.
#[cfg(not(windows))]
fn no_console_window(_command: &mut Command) {}

/// The Windows shell every Windows event query runs through.
pub const POWERSHELL: SystemTool = SystemTool {
    name: "powershell.exe",
    candidates: &[
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe",
    ],
};

/// The Windows socket table tool.
pub const NETSTAT: SystemTool = SystemTool {
    name: "netstat",
    candidates: &[r"C:\Windows\System32\NETSTAT.EXE"],
};

/// The Windows process-termination tool.
///
/// Used only after a preflight that has already established identity, owner and
/// that the target is not something Windows depends on.
pub const TASKKILL: SystemTool = SystemTool {
    name: "taskkill",
    candidates: &[r"C:\Windows\System32\taskkill.exe"],
};

/// The Linux socket table tool.
pub const SS: SystemTool = SystemTool {
    name: "ss",
    candidates: &["/usr/sbin/ss", "/usr/bin/ss", "/sbin/ss", "/bin/ss"],
};

/// The macOS open-file and socket tool.
pub const LSOF: SystemTool = SystemTool {
    name: "lsof",
    candidates: &["/usr/sbin/lsof", "/usr/bin/lsof"],
};

/// Reverse-lookup helpers, used only to label an address for a person to read.
pub const DIG: SystemTool = SystemTool {
    name: "dig",
    candidates: &["/usr/bin/dig", "/usr/local/bin/dig"],
};

/// Reverse-lookup fallback.
pub const HOST: SystemTool = SystemTool {
    name: "host",
    candidates: &["/usr/bin/host", "/usr/local/bin/host"],
};

/// The container runtime client.
///
/// This one both reads container identity and performs a guarded stop, so a
/// substituted binary would not merely lie about the estate: it would be handed
/// a termination request. Package-manager locations are accepted because that
/// is where the real client is installed; a copy anywhere else is not.
pub const DOCKER: SystemTool = SystemTool {
    name: "docker",
    candidates: &[
        "/usr/bin/docker",
        "/usr/local/bin/docker",
        "/opt/homebrew/bin/docker",
        r"C:\Program Files\Docker\Docker\resources\bin\docker.exe",
    ],
};

/// Every tool a sweep may reach for on this platform, for the health report.
#[must_use]
pub fn attestations() -> Vec<ToolAttestation> {
    #[cfg(windows)]
    let tools = [POWERSHELL, NETSTAT, TASKKILL, DOCKER];
    #[cfg(target_os = "linux")]
    let tools = [SS, DIG, HOST, DOCKER];
    #[cfg(target_os = "macos")]
    let tools = [LSOF, DIG, HOST, DOCKER];
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    let tools: [SystemTool; 0] = [];
    tools.iter().map(SystemTool::attest).collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{DOCKER, SystemTool, ToolState, attestations};

    #[test]
    fn every_accepted_location_is_absolute_and_specific() {
        // A relative candidate would be resolved against the working
        // directory, which is exactly the class of hijack this module exists
        // to remove.
        for tool in [
            super::POWERSHELL,
            super::NETSTAT,
            super::TASKKILL,
            super::SS,
            super::LSOF,
            super::DIG,
            super::HOST,
            super::DOCKER,
        ] {
            assert!(!tool.name.is_empty());
            assert!(
                !tool.candidates.is_empty(),
                "{} has nowhere to come from",
                tool.name
            );
            for candidate in tool.candidates {
                // `Path::is_absolute` answers for the platform the test is
                // running on, so a unix path looks relative on Windows and a
                // drive path looks relative on unix. The property being
                // asserted is about the string, not about this host.
                let rooted = candidate.starts_with('/')
                    || candidate
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_alphabetic)
                        && candidate.get(1..3) == Some(r":\");
                assert!(
                    rooted,
                    "{} accepts a location that is not rooted: {candidate}",
                    tool.name
                );
                assert!(
                    !candidate.contains(".."),
                    "{} accepts a traversable location: {candidate}",
                    tool.name
                );
            }
        }
    }

    #[test]
    fn a_tool_that_is_not_where_it_should_be_is_refused_not_hunted_for() {
        // The failure mode this prevents: finding a planted copy on PATH and
        // reporting its output as operating-system truth.
        let absent = SystemTool {
            name: "nowhere",
            candidates: &["/topgent/definitely/not/here"],
        };
        let attestation = absent.attest();
        assert_eq!(attestation.state, ToolState::Missing);
        assert_eq!(
            attestation.path, None,
            "an unaccepted copy is not even named"
        );

        let error = absent.command().expect_err("a missing tool cannot be run");
        let message = error.to_string();
        assert!(message.contains("nowhere"), "{message}");
        assert!(message.contains("PATH"), "the refusal says why: {message}");
    }

    #[test]
    fn a_tool_found_where_it_belongs_is_bound_to_that_exact_path() {
        // Something every unix host has, used only to prove the binding.
        let present = SystemTool {
            name: "sh",
            candidates: &["/bin/sh", r"C:\Windows\System32\cmd.exe"],
        };
        let attestation = present.attest();
        assert_eq!(attestation.state, ToolState::Trusted);
        let path = attestation.path.expect("a trusted tool names its path");
        assert!(
            present.candidates.contains(&path.as_str()),
            "bound to a path nobody accepted: {path}"
        );
        assert!(present.command().is_ok());
    }

    #[test]
    fn the_health_report_covers_this_platforms_tools_without_duplicates() {
        let all = attestations();
        assert!(
            !all.is_empty(),
            "some tool is used on every supported platform"
        );
        let mut names: Vec<&str> = all.iter().map(|tool| tool.name).collect();
        names.sort_unstable();
        let mut unique = names.clone();
        unique.dedup();
        assert_eq!(names, unique, "a tool is attested twice");
        assert!(all.iter().any(|tool| tool.name == DOCKER.name));
        #[cfg(windows)]
        assert!(all.iter().any(|tool| tool.name == super::POWERSHELL.name));
    }
}
