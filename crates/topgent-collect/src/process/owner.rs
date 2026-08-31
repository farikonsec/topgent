//! Who a process runs as.
//!
//! Ownership is typed per platform rather than flattened to a number, because a
//! Windows security identifier is not a Unix uid and comparing them as integers
//! would authorise a stop across accounts. An owner the system will not state
//! is `Unknown`, and `Unknown` matches nothing — including another `Unknown`.

use super::table::ProcInfo;
#[cfg(unix)]
use super::table::snapshot;

/// Who a process runs as, in whatever terms the platform actually uses.
///
/// Unix compares numeric user ids. Windows has no equivalent and identifies
/// accounts by security identifier, so until now every Windows process carried
/// uid zero, which is indistinguishable from root and had to be refused. A
/// typed owner lets each platform say what it means, and lets `Unknown` mean
/// exactly that rather than being mistaken for a privileged account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Owner {
    /// Unix numeric user id.
    Uid(u32),
    /// Windows security identifier.
    Sid(String),
    /// The platform would not say who owns this process.
    Unknown,
}

impl Owner {
    /// Whether two owners are the same account.
    ///
    /// An unknown owner matches nothing, including another unknown owner: two
    /// processes Topgent cannot identify are not thereby the same user.
    #[must_use]
    pub fn is_same_account_as(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Uid(left), Self::Uid(right)) => left == right,
            (Self::Sid(left), Self::Sid(right)) => {
                !left.is_empty() && left.eq_ignore_ascii_case(right)
            }
            _ => false,
        }
    }

    /// Stable label for reports and refusals.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Uid(uid) => format!("uid {uid}"),
            Self::Sid(sid) => sid.clone(),
            Self::Unknown => "unknown".to_owned(),
        }
    }
}

/// The same process, with its owner established if it was not already.
///
/// Called on the few processes a response is about, never on the whole table.
#[must_use]
pub fn with_resolved_owner(mut process: ProcInfo) -> ProcInfo {
    if matches!(process.owner, Owner::Unknown) {
        process.owner = owner_of(process.pid);
    }
    process
}

/// Who owns this process, asked of the operating system now.
///
/// Deliberately resolved on demand rather than collected for every process on
/// every sweep. Ownership only decides whether a response may proceed, and a
/// response is a rare deliberate act, so the cost belongs there and not in the
/// hot path.
#[must_use]
pub fn owner_of(pid: u32) -> Owner {
    #[cfg(unix)]
    {
        snapshot()
            .into_iter()
            .find(|process| process.pid == pid)
            .map_or(Owner::Unknown, |process| process.owner)
    }
    #[cfg(windows)]
    {
        windows_owner_sid(pid)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        Owner::Unknown
    }
}

/// Ask Windows for one process's owning account.
///
/// Fixed script, one pid, no interpolation of anything discovered: the pid is
/// formatted as a number and nothing else crosses the boundary.
#[cfg(windows)]
fn windows_owner_sid(pid: u32) -> Owner {
    let script = format!(
        "$ErrorActionPreference='Stop'; $p=Get-CimInstance Win32_Process -Filter \"ProcessId={pid}\" -ErrorAction Stop; if (-not $p) {{exit 1}}; (Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid).Sid"
    );
    let Ok(mut command) = crate::tool::POWERSHELL.command() else {
        return Owner::Unknown;
    };
    let Ok(output) = command
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
    else {
        return Owner::Unknown;
    };
    if !output.status.success() {
        return Owner::Unknown;
    }
    let sid = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if valid_windows_sid(&sid) {
        Owner::Sid(sid)
    } else {
        Owner::Unknown
    }
}

/// Whether a string is shaped like a Windows security identifier.
///
/// Anything that is not is treated as no answer rather than as an account,
/// because an owner Topgent cannot parse must never compare equal to its own.
#[cfg(any(windows, test))]
#[must_use]
pub fn valid_windows_sid(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("S-1-") else {
        return false;
    };
    if value.len() > 184 || rest.is_empty() {
        return false;
    }
    let mut parts = 0_usize;
    for part in rest.split('-') {
        if part.is_empty() || part.len() > 20 || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
        parts += 1;
    }
    parts >= 2
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    #[test]
    fn the_owner_of_the_process_asking_is_established_where_it_is_free() {
        // Measured, not assumed. Linux returns no user id unless the sweep asks
        // for one, and the sweep did not: every process then carried uid zero,
        // which is root's real id, so "Topgent could not tell" and "the same
        // account as Topgent" became the same answer and the guard would have
        // authorised stopping anything on the host.
        //
        // Windows has no numeric owner and asking costs a query per process, so
        // the sweep deliberately leaves it unstated and the response path
        // establishes it for the few processes it is about. Unknown must stay
        // unknown there rather than becoming a value that could compare equal.
        use super::Owner;
        let processes = crate::process::snapshot();
        let current = processes
            .iter()
            .find(|process| process.pid == std::process::id())
            .expect("this process is in the process table");

        #[cfg(unix)]
        {
            assert!(
                matches!(current.owner, Owner::Uid(_)),
                "the process table did not say who owns the process asking: {:?}",
                current.owner
            );
            assert!(
                !current.user.is_empty() && current.user != "0",
                "the owner fell back to a numeric placeholder: {}",
                current.user
            );
            assert!(current.owner.is_same_account_as(&Owner::Uid(current.uid)));
        }
        #[cfg(windows)]
        {
            assert_eq!(
                current.owner,
                Owner::Unknown,
                "the sweep paid for an owner it does not need"
            );
            // Resolved on demand, it is a real account and not a placeholder.
            let resolved = super::owner_of(std::process::id());
            assert!(
                matches!(&resolved, Owner::Sid(sid) if super::valid_windows_sid(sid)),
                "the response path could not establish an owner: {resolved:?}"
            );
            assert!(!resolved.is_same_account_as(&Owner::Unknown));
        }
    }

    #[test]
    fn an_owner_nobody_established_matches_nothing_including_another_unknown() {
        use super::Owner;
        // Windows carried uid zero for every process, which is indistinguishable
        // from root. "Topgent could not tell" and "the same account" must never
        // be the same answer, in either direction.
        assert!(Owner::Uid(501).is_same_account_as(&Owner::Uid(501)));
        assert!(!Owner::Uid(501).is_same_account_as(&Owner::Uid(0)));
        assert!(!Owner::Unknown.is_same_account_as(&Owner::Unknown));
        assert!(!Owner::Unknown.is_same_account_as(&Owner::Uid(501)));
        assert!(!Owner::Uid(501).is_same_account_as(&Owner::Unknown));
        // A uid and a security identifier are not comparable, so they are not
        // compared: nothing about them can be shown to be the same account.
        assert!(!Owner::Uid(0).is_same_account_as(&Owner::Sid("S-1-5-18".to_owned())));

        // Windows compares account identifiers case-insensitively.
        assert!(
            Owner::Sid("S-1-5-21-1-2-3-1001".to_owned())
                .is_same_account_as(&Owner::Sid("s-1-5-21-1-2-3-1001".to_owned()))
        );
        assert!(
            !Owner::Sid("S-1-5-21-1-2-3-1001".to_owned())
                .is_same_account_as(&Owner::Sid("S-1-5-21-1-2-3-1002".to_owned()))
        );
        // An empty identifier is not an account either.
        assert!(!Owner::Sid(String::new()).is_same_account_as(&Owner::Sid(String::new())));
    }

    #[test]
    fn only_something_shaped_like_an_account_identifier_becomes_one() {
        // An owner Topgent cannot parse must be no answer rather than a value
        // that could compare equal to its own.
        for good in [
            "S-1-5-18",
            "S-1-5-21-1004336348-1177238915-682003330-512",
            "S-1-0-0",
        ] {
            assert!(
                super::valid_windows_sid(good),
                "rejected a real sid: {good}"
            );
        }
        for bad in [
            "",
            "S-1-5",
            "S-1-",
            "not-a-sid",
            "s-1-5-18",
            "S-1-5-18-",
            "S-1-5-x",
            "S-1-5-18 && whoami",
            "S-1-5-99999999999999999999999",
        ] {
            assert!(!super::valid_windows_sid(bad), "accepted a non-sid: {bad}");
        }
        // Absurdly long input is refused before it is parsed.
        let long = format!("S-1-5-{}", "1-".repeat(200));
        assert!(!super::valid_windows_sid(&long));
    }

    #[cfg(windows)]
    #[test]
    fn windows_does_not_invent_a_unix_uid_for_the_current_process() -> Result<(), String> {
        let current = crate::process::snapshot()
            .into_iter()
            .find(|process| process.pid == std::process::id())
            .ok_or("current Windows process is not visible")?;
        assert_eq!(current.uid, 0);
        assert!(!current.user.trim().is_empty());
        Ok(())
    }
}
