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
///
/// This used to be a boolean dressed as three variants: `resolve` took the
/// first candidate path for which `is_file()` returned true and `attest`
/// reported `Trusted`, so the accepted locations — `/usr/local/bin` and
/// `/opt/homebrew/bin` among them, which are owned by the logged-in user on
/// most developer machines — proved only that *a* file existed at *a* string.
/// The threat model says sensors resolve to operating-system-owned locations.
/// The code did not check.
///
/// Trust is now a state rather than a verdict, and the uncomfortable answer is
/// reported rather than rounded up: a Homebrew Docker client is `UserManaged`,
/// because the account being monitored can replace it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolState {
    /// Owned by the operating system and not writable by the monitored user,
    /// along its whole resolved path.
    SystemTrusted,
    /// Present and usable, but replaceable by the account being watched —
    /// either the file itself or a directory on the way to it.
    UserManaged,
    /// Found, but this platform has no ownership check in this build, so
    /// nothing is claimed either way.
    Unverified,
    /// Found and refused: not a regular file, or its path could not be resolved.
    Rejected,
    /// Not found at any accepted location.
    Missing,
}

impl ToolState {
    /// Stable report label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SystemTrusted => "system_trusted",
            Self::UserManaged => "user_managed",
            Self::Unverified => "unverified",
            Self::Rejected => "rejected",
            Self::Missing => "missing",
        }
    }

    /// Whether the tool can be run at all.
    ///
    /// Trust decides how much its output is worth, not whether the sensor
    /// exists. A refused or absent tool is not run; a `UserManaged` one is run
    /// and its findings carry the state alongside them.
    #[must_use]
    pub const fn is_usable(self) -> bool {
        matches!(
            self,
            Self::SystemTrusted | Self::UserManaged | Self::Unverified
        )
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
    /// The first accepted path that exists on this host, and what it is worth.
    ///
    /// Candidates are tried in order and the first usable one wins, so a client
    /// installed in an operating-system location is preferred over the same
    /// client in a user-writable one. A candidate that resolves to something
    /// other than a regular file is refused rather than skipped quietly.
    #[must_use]
    pub fn resolve_checked(&self) -> (Option<PathBuf>, ToolState) {
        let mut refused = false;
        for candidate in self.candidates.iter().map(Path::new) {
            if !candidate.exists() {
                continue;
            }
            // The canonical path is what gets executed, so it is what gets
            // judged: a symlink from an accepted location into a user-writable
            // one is exactly the substitution being guarded against.
            let Ok(real) = candidate.canonicalize() else {
                refused = true;
                continue;
            };
            if !real.is_file() {
                refused = true;
                continue;
            }
            let state = trust_of(&real);
            if state.is_usable() {
                return (Some(displayable(real)), state);
            }
            refused = true;
        }
        // Deliberately does not fall back to a `PATH` lookup. Reporting where
        // an unaccepted copy lives would invite reading it, and the point is
        // that it is not read.
        (
            None,
            if refused {
                ToolState::Rejected
            } else {
                ToolState::Missing
            },
        )
    }

    /// The first accepted path that can be run on this host.
    #[must_use]
    pub fn resolve(&self) -> Option<PathBuf> {
        self.resolve_checked().0
    }

    /// What Topgent can say about this tool right now.
    #[must_use]
    pub fn attest(&self) -> ToolAttestation {
        let (path, state) = self.resolve_checked();
        ToolAttestation {
            name: self.name,
            path: path.map(|path| path.to_string_lossy().into_owned()),
            state,
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

/// The canonical path, without the prefix Windows adds to it.
///
/// `canonicalize` on Windows returns the extended-length verbatim form,
/// `\\?\C:\Windows\System32\NETSTAT.EXE`. It is the same path and it is what
/// gets executed, but printing it in a report reads as something having gone
/// wrong. Stripped only for the recorded path; the value actually run is the
/// canonical one either way, because Windows resolves both to the same file.
fn displayable(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(rest) = path.to_string_lossy().strip_prefix(r"\\?\") {
            return PathBuf::from(rest);
        }
    }
    path
}

/// Whether the operating system owns this file and everything on the way to it.
///
/// A binary owned by the monitored account at mode 0755 is replaceable by that
/// account, and so is one inside a directory the account can write, however
/// well-protected the file itself is. Both are checked, because either alone is
/// enough to substitute the sensor.
///
/// Mode bits are not a complete answer — they say nothing about a signature or
/// about package provenance, so a *system-owned* binary is still only as
/// trustworthy as whatever put it there. The state says what was checked, and
/// nothing more.
#[cfg(unix)]
fn trust_of(path: &Path) -> ToolState {
    use std::os::unix::fs::MetadataExt as _;

    // Root, and on macOS the `wheel` and `admin` groups, own the locations a
    // standard account cannot write. Anything else is the monitored user's.
    let owned_by_system = |metadata: &std::fs::Metadata| {
        let group_writable = metadata.mode() & 0o020 != 0;
        let other_writable = metadata.mode() & 0o002 != 0;
        metadata.uid() == 0 && !group_writable && !other_writable
    };

    let Ok(metadata) = std::fs::metadata(path) else {
        return ToolState::Rejected;
    };
    if !metadata.is_file() {
        return ToolState::Rejected;
    }
    if !owned_by_system(&metadata) {
        return ToolState::UserManaged;
    }
    // Every directory on the resolved path. `/opt/homebrew/bin` is owned by the
    // logged-in user on a default install, so a root-owned binary sitting in it
    // can still be moved aside and replaced.
    let mut cursor = path.parent();
    while let Some(directory) = cursor {
        let Ok(metadata) = std::fs::metadata(directory) else {
            return ToolState::Rejected;
        };
        if !owned_by_system(&metadata) {
            return ToolState::UserManaged;
        }
        cursor = directory.parent();
    }
    ToolState::SystemTrusted
}

/// Windows has no mode bits, and the equivalent answer needs an access-control
/// query this build does not make. Saying `Unverified` is the honest answer;
/// saying `SystemTrusted` because the path starts with `C:\Windows` would be a
/// claim about an access-control list nobody read.
#[cfg(not(unix))]
fn trust_of(path: &Path) -> ToolState {
    if path.is_file() {
        ToolState::Unverified
    } else {
        ToolState::Rejected
    }
}

/// Keep a spawned tool from opening a console window.
///
/// Every sensor on Windows runs through `powershell.exe` or `netstat`, and a
/// GUI process spawning a console application gets a console window for it.
/// The desktop app therefore flashed a black window several times per sweep,
/// which looks like the tool doing something it will not explain.
///
/// `CREATE_NO_WINDOW` is `0x0800_0000`. The constant is written here rather than
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
    fn a_tool_found_where_it_belongs_is_bound_to_a_real_path() {
        // Something every host has, used only to prove the binding. The bound
        // path is the canonical one, which on macOS resolves /bin/sh through
        // no links and on some Linux distributions resolves it into /usr/bin.
        let present = SystemTool {
            name: "sh",
            candidates: &["/bin/sh", r"C:\Windows\System32\cmd.exe"],
        };
        let attestation = present.attest();
        assert!(
            attestation.state.is_usable(),
            "the platform shell was refused: {:?}",
            attestation.state
        );
        #[cfg(unix)]
        assert_eq!(
            attestation.state,
            ToolState::SystemTrusted,
            "the platform shell is not owned by the operating system"
        );
        let path = attestation.path.expect("a resolved tool names its path");
        assert!(std::path::Path::new(&path).is_absolute(), "{path}");
        assert!(present.command().is_ok());
    }

    /// The finding: `resolve` took the first candidate for which `is_file()`
    /// was true and `attest` called it trusted. `/usr/local/bin` and
    /// `/opt/homebrew/bin` are accepted locations and are owned by the logged-in
    /// user on most developer machines, so the monitored account could replace
    /// the binary whose output Topgent reports as operating-system truth.
    #[cfg(unix)]
    #[test]
    fn a_binary_the_watched_account_can_replace_is_not_system_trusted() {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;

        // nosemgrep: rust.lang.security.temp-dir.temp-dir - test fixture, per-process and per-thread name, not a trust boundary
        let dir = std::env::temp_dir().join(format!("topgent-tool-trust-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let planted = dir.join("sensor");
        let mut file = std::fs::File::create(&planted).expect("a scratch file");
        file.write_all(b"#!/bin/sh\nexit 0\n").expect("write");
        drop(file);
        std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o755))
            .expect("mode 0755");

        let leaked = Box::leak(planted.to_string_lossy().into_owned().into_boxed_str());
        let tool = SystemTool {
            name: "planted",
            candidates: std::slice::from_ref(Box::leak(Box::new(&*leaked))),
        };
        let attestation = tool.attest();
        assert_eq!(
            attestation.state,
            ToolState::UserManaged,
            "a binary at 0755 owned by the current user was called trusted"
        );
        // Still usable: trust decides what the output is worth, not whether the
        // sensor runs at all.
        assert!(attestation.state.is_usable());
        assert!(tool.command().is_ok());

        // A directory Topgent will not follow to a file is refused, not skipped.
        let missing = SystemTool {
            name: "gone",
            candidates: &["/topgent/definitely/not/here"],
        };
        assert_eq!(missing.attest().state, ToolState::Missing);

        // A path that is not a regular file is refused rather than run.
        let directory = SystemTool {
            name: "a-directory",
            candidates: &["/tmp"],
        };
        assert_eq!(directory.attest().state, ToolState::Rejected);
        assert!(directory.command().is_err());

        std::fs::remove_dir_all(&dir).expect("clean up");
    }

    /// `canonicalize` on Windows returns the extended-length verbatim form, and
    /// a sensor path printed as `\\?\C:\Windows\System32\NETSTAT.EXE` reads as
    /// something having gone wrong. Seen in a live report from the lab host.
    #[test]
    fn a_reported_path_carries_no_verbatim_prefix() {
        for attestation in attestations() {
            let Some(path) = attestation.path else {
                continue;
            };
            assert!(
                !path.starts_with(r"\\?\"),
                "{} is reported as {path}",
                attestation.name
            );
            assert!(
                std::path::Path::new(&path).is_absolute(),
                "{} lost its root: {path}",
                attestation.name
            );
        }
    }

    #[test]
    fn every_state_has_a_stable_label_and_says_whether_it_runs() {
        for (state, label, usable) in [
            (ToolState::SystemTrusted, "system_trusted", true),
            (ToolState::UserManaged, "user_managed", true),
            (ToolState::Unverified, "unverified", true),
            (ToolState::Rejected, "rejected", false),
            (ToolState::Missing, "missing", false),
        ] {
            assert_eq!(state.as_str(), label);
            assert_eq!(state.is_usable(), usable, "{label}");
        }
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
