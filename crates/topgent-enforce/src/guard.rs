//! What Topgent will not touch, whatever a rule says.
//!
//! The guard runs before any signal and answers one question: may this process
//! be stopped by this installation, on this host, at all. It refuses itself and
//! the session it runs inside, anything the operating system stands on, and
//! anything owned by another account, because Topgent takes no privilege it was
//! not given. An owner the system will not state is never assumed to be its
//! own: unknown matches nothing, including another unknown.

use crate::Refusal;
use topgent_collect::process;

/// What may never be signalled.
///
/// Held as a struct rather than read from the environment at signal time, so a
/// test can construct one and the guard logic is exercised without a real kill.
#[derive(Debug, Clone)]
pub struct Guard {
    /// This process.
    pub own_pid: u32,
    /// The process that launched Topgent, if it is worth protecting.
    pub parent_pid: Option<u32>,
    /// The account Topgent runs as. Anything else is out of bounds.
    pub own_owner: process::Owner,
}

/// Windows executables whose termination stops the operating system.
///
/// Matched on the whole executable name, never as a substring: an agent called
/// `lsass-notreally.exe` has not earned the protection Windows gives `lsass`.
#[cfg(any(windows, test))]
/// Windows processes whose loss takes the operating system with them.
///
/// Deliberately not a data file, unlike the risk factors and detection signals.
/// Those lists are additive: adding an entry makes Topgent notice more. This
/// one is subtractive — removing an entry makes Topgent willing to stop
/// something it currently refuses — so a file able to edit it would be a way to
/// talk the guard out of a refusal. Refusals stay in code.
///
/// Matched by name before ownership is consulted, because a standard user can
/// own a process with one of these names and the answer is still no.
pub(crate) const WINDOWS_CRITICAL: [&str; 8] = [
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "lsaiso.exe",
    "system",
];

impl Guard {
    /// The guard for the process calling this.
    #[must_use]
    pub fn current() -> Self {
        let own_pid = std::process::id();
        let procs = process::snapshot();
        let me = procs.iter().find(|p| p.pid == own_pid);
        Self {
            own_pid,
            parent_pid: me.and_then(|p| p.parent),
            own_owner: process::owner_of(own_pid),
        }
    }

    /// Whether this process may be signalled, and why not when it may not.
    ///
    /// # Errors
    ///
    /// Returns [`Refusal::Protected`] for anything Topgent will not touch.
    pub fn check(&self, target: &process::ProcInfo) -> Result<(), Refusal> {
        if target.pid == self.own_pid {
            return Err(Refusal::Protected {
                why: "that is Topgent itself",
            });
        }
        if Some(target.pid) == self.parent_pid {
            return Err(Refusal::Protected {
                why: "that is the session Topgent is running inside",
            });
        }
        if target.pid <= 1 {
            return Err(Refusal::Protected {
                why: "pid 1 runs the machine",
            });
        }
        if let Some(why) = protected_system_process(target) {
            return Err(Refusal::Protected { why });
        }
        if matches!(self.own_owner, process::Owner::Unknown)
            || matches!(target.owner, process::Owner::Unknown)
        {
            return Err(Refusal::Protected {
                why: "the operating system did not say who owns this process, and an owner \
                      Topgent cannot establish is never assumed to be its own",
            });
        }
        if !target.owner.is_same_account_as(&self.own_owner) {
            return Err(Refusal::Protected {
                why: "it belongs to another user, and Topgent takes no privilege it was not given",
            });
        }
        Ok(())
    }
}

/// Processes the operating system itself depends on.
///
/// On Windows several of these do not merely matter, they are load-bearing:
/// terminating `csrss`, `wininit`, `services`, `lsass` or `smss` stops the
/// machine with a bug check. A response that can take the host down is not a
/// response, so they are refused before ownership is even consulted.
#[must_use]
pub fn protected_system_process(target: &process::ProcInfo) -> Option<&'static str> {
    #[cfg(windows)]
    {
        // Pid 4 is the kernel's own process and pid 0 is the idle process.
        if matches!(target.pid, 0 | 4) {
            return Some("that is the Windows kernel process");
        }
        let name = target
            .name
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(&target.name)
            .to_ascii_lowercase();
        if WINDOWS_CRITICAL.contains(&name.as_str()) {
            return Some("stopping it would stop Windows itself");
        }
    }
    #[cfg(not(windows))]
    let _ = target;
    None
}

#[cfg(test)]
mod protected_tests {
    use super::WINDOWS_CRITICAL;

    #[test]
    fn the_protected_list_never_shrinks_without_someone_noticing() {
        // The floor, restated. Every name here is a process whose loss stops
        // Windows, and this test exists so that removing one is a deliberate
        // act with a failing test attached rather than a quiet edit.
        for name in [
            "smss.exe",
            "csrss.exe",
            "wininit.exe",
            "winlogon.exe",
            "services.exe",
            "lsass.exe",
            "lsaiso.exe",
            "system",
        ] {
            assert!(
                WINDOWS_CRITICAL.contains(&name),
                "{name} is no longer protected"
            );
        }
    }

    #[test]
    fn every_protected_name_is_lowercase_so_it_can_actually_match() {
        // Comparison is case-folded before it reaches the list. An entry with a
        // capital letter would look like protection and provide none.
        for name in WINDOWS_CRITICAL {
            assert_eq!(name, name.to_ascii_lowercase(), "{name} could never match");
        }
    }
}
