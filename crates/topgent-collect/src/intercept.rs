//! Whether this host can stop an action before it happens.
//!
//! Every response Topgent can currently make is retrospective: it observes
//! something, then stops the process that did it. Preventing the action itself
//! needs a point where the operating system pauses the request and asks. Such
//! points exist, and none of them is available to an ordinary user process, so
//! this module's job is to say precisely which one applies here and what it
//! would take rather than to claim the capability or to deny it flatly.
//!
//! The distinction matters because `Block` and `Approval` are already in the
//! response ladder. Until now they refused on every host with the same answer,
//! which reads as "this product does not do that" when the truth is "this
//! installation is one privilege away from doing that".

/// What an interception point would need on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Interception {
    /// A usable interception point is available to this process now.
    Available {
        /// The mechanism in the operating system's own terms.
        mechanism: &'static str,
    },
    /// The platform provides one, and this process is not allowed to use it.
    PrivilegeRequired {
        /// The mechanism in the operating system's own terms.
        mechanism: &'static str,
        /// What the operator would have to grant, in words they can act on.
        needs: &'static str,
    },
    /// Nothing on this platform offers an interception point Topgent can use.
    Unsupported {
        /// Why not, in words a user can act on.
        why: &'static str,
    },
}

impl Interception {
    /// Whether an action can actually be stopped before it happens.
    #[must_use]
    pub const fn is_available(&self) -> bool {
        matches!(self, Self::Available { .. })
    }

    /// Stable report label.
    #[must_use]
    pub const fn state(&self) -> &'static str {
        match self {
            Self::Available { .. } => "available",
            Self::PrivilegeRequired { .. } => "privilege_required",
            Self::Unsupported { .. } => "unsupported",
        }
    }

    /// One line a person can act on.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::Available { mechanism } => {
                format!("{mechanism} is available to this process")
            }
            Self::PrivilegeRequired { mechanism, needs } => {
                format!("{mechanism} is supported by this host but needs {needs}")
            }
            Self::Unsupported { why } => (*why).to_owned(),
        }
    }
}

/// Linux capability bit for `CAP_SYS_ADMIN`.
#[cfg(any(target_os = "linux", test))]
const CAP_SYS_ADMIN: u32 = 21;

/// The interception point available on this host, established now.
#[must_use]
pub fn probe() -> Interception {
    #[cfg(target_os = "linux")]
    {
        linux_interception(
            &std::fs::read_to_string(kernel_config_path()).unwrap_or_default(),
            &std::fs::read_to_string("/proc/self/status").unwrap_or_default(),
        )
    }
    #[cfg(target_os = "macos")]
    {
        // Endpoint Security can hold an operation open for an authorization
        // answer, and the entitlement for it is granted by Apple to a
        // requesting developer account, not by the person running the app.
        Interception::Unsupported {
            why: "macOS pauses an operation for an answer only through Endpoint Security, whose \
                  client entitlement Apple grants to a developer account; Topgent does not carry \
                  one, so nothing here can hold an action open",
        }
    }
    #[cfg(windows)]
    {
        // A filesystem minifilter or a WFP callout can hold an operation, and
        // both are kernel components that must be signed and installed.
        Interception::Unsupported {
            why: "Windows pauses an operation for an answer only from a kernel component, a \
                  filesystem minifilter or a Filtering Platform callout, which must be signed \
                  and installed as a driver; Topgent ships no driver",
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        Interception::Unsupported {
            why: "no interception point is known for this platform",
        }
    }
}

/// Where this kernel's build configuration is published.
#[cfg(target_os = "linux")]
fn kernel_config_path() -> String {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_owned();
    format!("/boot/config-{release}")
}

/// Decide from the kernel's own configuration and this process's capabilities.
///
/// Split out from the reading so both answers can be tested without a Linux
/// host, and so neither is inferred: the kernel says whether it was built with
/// permission events, and `/proc/self/status` says whether this process may use
/// them. A missing or unreadable configuration is not evidence of absence, and
/// is reported as the unknown it is rather than as an unsupported host.
#[cfg(any(target_os = "linux", test))]
#[must_use]
pub fn linux_interception(kernel_config: &str, process_status: &str) -> Interception {
    const MECHANISM: &str = "fanotify permission events (FAN_OPEN_PERM)";
    if !kernel_config.is_empty()
        && !kernel_config
            .lines()
            .any(|line| line.trim() == "CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y")
    {
        return Interception::Unsupported {
            why: "this kernel was built without CONFIG_FANOTIFY_ACCESS_PERMISSIONS, so nothing \
                  here can hold a file operation open for an answer",
        };
    }
    if effective_capabilities(process_status).is_some_and(|caps| caps & (1 << CAP_SYS_ADMIN) != 0) {
        return Interception::Available {
            mechanism: MECHANISM,
        };
    }
    Interception::PrivilegeRequired {
        mechanism: MECHANISM,
        needs: "CAP_SYS_ADMIN, which an ordinary user process does not hold; it belongs in a \
                separately installed privileged helper rather than in the desktop application",
    }
}

/// The effective capability set from `/proc/self/status`.
#[cfg(any(target_os = "linux", test))]
fn effective_capabilities(process_status: &str) -> Option<u64> {
    process_status.lines().find_map(|line| {
        line.strip_prefix("CapEff:")
            .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
    })
}

#[cfg(test)]
mod tests {
    use super::{linux_interception, probe};

    const PERMISSIVE_KERNEL: &str = "CONFIG_FANOTIFY=y\nCONFIG_FANOTIFY_ACCESS_PERMISSIONS=y\n";

    #[test]
    fn a_capable_kernel_without_the_privilege_says_what_it_would_take() {
        // Observed on Kali 6.19.14 aarch64: the kernel is built for permission
        // events and an ordinary shell holds no capabilities at all, so
        // fanotify_init returns EPERM. Reporting that as "unsupported" would
        // tell the operator the product cannot do this, when the truth is that
        // this installation is one privilege away from doing it.
        let unprivileged = "Name:\tbash\nCapEff:\t0000000000000000\n";
        let state = linux_interception(PERMISSIVE_KERNEL, unprivileged);
        assert_eq!(state.state(), "privilege_required");
        assert!(!state.is_available());
        let detail = state.detail();
        assert!(detail.contains("CAP_SYS_ADMIN"), "{detail}");
        assert!(detail.contains("privileged helper"), "{detail}");
    }

    #[test]
    fn holding_the_privilege_is_the_only_thing_that_makes_it_available() {
        // CAP_SYS_ADMIN is bit 21. Only that bit counts: a process with every
        // other capability still cannot open a permission group.
        let admin = format!("CapEff:\t{:016x}\n", 1_u64 << 21);
        assert!(linux_interception(PERMISSIVE_KERNEL, &admin).is_available());

        let everything_else = format!("CapEff:\t{:016x}\n", u64::MAX ^ (1_u64 << 21));
        assert_eq!(
            linux_interception(PERMISSIVE_KERNEL, &everything_else).state(),
            "privilege_required"
        );

        // A status file that does not say cannot be read as though it did.
        for silent in ["", "Name:\tbash\n", "CapEff:\tnot-a-number\n"] {
            assert_eq!(
                linux_interception(PERMISSIVE_KERNEL, silent).state(),
                "privilege_required",
                "read an unstated capability as held: {silent:?}"
            );
        }
    }

    #[test]
    fn a_kernel_built_without_permission_events_cannot_be_privileged_into_them() {
        let plain = "CONFIG_FANOTIFY=y\n";
        let admin = format!("CapEff:\t{:016x}\n", 1_u64 << 21);
        let state = linux_interception(plain, &admin);
        assert_eq!(state.state(), "unsupported");
        assert!(
            state
                .detail()
                .contains("CONFIG_FANOTIFY_ACCESS_PERMISSIONS")
        );

        // An unreadable configuration is not evidence of absence. It falls
        // through to the capability question rather than declaring the host
        // incapable of something it may well support.
        assert_eq!(
            linux_interception("", &admin).state(),
            "available",
            "an unreadable kernel configuration became a verdict"
        );
    }

    #[test]
    fn every_platform_answers_and_says_why() {
        let state = probe();
        assert!(!state.state().is_empty());
        assert!(
            state.detail().len() > 20,
            "an answer nobody can act on: {}",
            state.detail()
        );
        // Nothing is available without a privilege or a driver, so a bare
        // process claiming it can hold an action open is a bug.
        #[cfg(not(target_os = "linux"))]
        assert!(!state.is_available());
    }
}
