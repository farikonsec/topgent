//! What each operating system wants before it will let a program see packets.
//!
//! Three different mechanisms, three different answers, and one shape. Each
//! `probe` asks the smallest question that settles it, and every failure is a
//! state rather than an error: a check that could not run reports
//! [`super::State::Unknown`] and never reports the capability as present.

#[cfg(any(target_os = "linux", windows))]
use super::Remedy;
use super::State;

/// What is being asked for on this platform, in the system's own words.
#[cfg(target_os = "linux")]
pub const PRIVILEGE: &str =
    "the CAP_NET_RAW capability on the Topgent binary, granted once, not root";

/// See the Linux note.
#[cfg(target_os = "macos")]
pub const PRIVILEGE: &str =
    "read access to the packet-capture devices /dev/bpf*, through group membership, not root";

/// See the Linux note.
#[cfg(windows)]
pub const PRIVILEGE: &str = "the Npcap driver, installed by its own signed installer";

/// See the Linux note.
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub const PRIVILEGE: &str = "nothing: this build cannot capture packets on this platform";

/// Whether this host will let Topgent see packets, and what is missing if not.
///
/// # Linux
///
/// A raw socket needs `CAP_NET_RAW`. The honest test is to try opening one:
/// reading `/proc/self/status` would say what the process was granted, and a
/// permission can be present and still refused by a sandbox, a container
/// policy or `seccomp`. Asking the kernel is the only answer that cannot be
/// wrong.
#[cfg(target_os = "linux")]
#[must_use]
pub fn probe() -> State {
    // `/proc/self/status` is read only to explain the answer, never to decide
    // it. The decision below is the kernel's.
    let effective = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                line.strip_prefix("CapEff:")
                    .map(str::trim)
                    .map(str::to_owned)
            })
        });

    // The helper answers first where there is one, because it is the process
    // that will do the capturing. Asking whether *this* process can open a raw
    // socket is the wrong question once the privilege lives somewhere else: a
    // correctly installed and granted system reported "restart to enable"
    // forever, and restarting would never have helped, because the interface
    // is never meant to hold the capability again.
    //
    // There is no restart state here either. A file capability applies at the
    // next exec, and the helper is exec'd fresh every time it starts, so a
    // grant is in force the moment it is made.
    // A helper that exists and cannot be trusted is its own answer. Silently
    // falling through to the in-process test would report the interface's
    // capability for a machine whose helper is the thing that is wrong.
    if let Some(unsafe_helper) = installed_helper()
        && !super::helper::safe_to_run(&unsafe_helper)
    {
        return State::Unsupported {
            reason: format!(
                "{} is writable by an account other than its owner, so Topgent will not \
                 run it. Restore it with: chmod 755 {}",
                unsafe_helper.display(),
                unsafe_helper.display()
            ),
        };
    }
    if let Some(helper) = helper_path() {
        return if has_capability(&helper) {
            State::Available
        } else {
            State::NeedsGrant {
                missing: format!(
                    "{} does not hold CAP_NET_RAW, and it is the only part of Topgent \
                     that needs it",
                    helper.display()
                ),
                remedy: grant_remedy(&helper.display().to_string()),
            }
        };
    }

    match raw_socket_permitted() {
        Ok(true) => State::Available,
        // The capability may already be on the binary and simply not in force
        // for this process. That is a grant that worked, not one that failed.
        Ok(false) if binary_has_capability() => State::NeedsRestart {
            detail: "granted on the binary; restart Topgent to use it, because file \
                     capabilities take effect at the next start"
                .to_owned(),
        },
        Ok(false) => State::NeedsGrant {
            missing: match effective {
                Some(caps) => format!(
                    "opening a raw socket was refused; this process holds CapEff {caps}, \
                     which does not include CAP_NET_RAW"
                ),
                None => "opening a raw socket was refused".to_owned(),
            },
            remedy: grant_remedy(&grant_target()),
        },
        Err(detail) => State::Unknown { detail },
    }
}

/// Asks the kernel directly, by opening a packet socket and dropping it.
///
/// No packets are read and nothing is captured: the socket is opened to learn
/// whether it can be opened, and closed at the end of the expression.
///
/// This used to read the capability mask out of `/proc/self/status` and call
/// that the answer, because nothing in the build could open a packet socket
/// without unsafe code. It can now, and the difference is not cosmetic: a
/// capability can be present on the process and still refused by a container
/// policy, a sandbox or a `seccomp` filter. The mask would have said available
/// and the capture would then have failed, which is the one answer this module
/// promises never to give.
///
/// The mask is still read, but only to explain a refusal.
#[cfg(target_os = "linux")]
fn raw_socket_permitted() -> Result<bool, String> {
    match super::wire::Wire::open() {
        Ok(socket) => {
            drop(socket);
            Ok(true)
        }
        Err(crate::CollectError::Denied { .. }) => Ok(false),
        Err(other) => Err(other.to_string()),
    }
}

/// The one step that grants capture, for whichever binary needs it.
#[cfg(target_os = "linux")]
fn grant_remedy(target: &str) -> Remedy {
    Remedy::Command {
        command: format!("sudo setcap cap_net_raw,cap_net_admin+eip {target}"),
        effect: "grants that one binary the ability to open raw sockets. Topgent still \
                 runs as your user and gains nothing else."
            .to_owned(),
        undo: "sudo setcap -r <the same path>".to_owned(),
    }
}

/// Which binary the capability should go on.
///
/// The capture helper where there is one, and this binary otherwise. This is
/// the whole point of having a helper: it does nothing but read frames, so it
/// is a far smaller thing to grant a privilege to than an interface with a
/// window, a policy engine and a journal in it. Wireshark grants `dumpcap` and
/// not Wireshark for exactly this reason.
#[cfg(target_os = "linux")]
pub(super) fn grant_target() -> String {
    helper_path().map_or_else(
        || {
            // Printed in a command for a person to run. Nothing executes it here.
            // nosemgrep: rust.lang.security.current-exe.current-exe
            std::env::current_exe().map_or_else(
                |_| "/path/to/topgent".to_owned(),
                |p| p.display().to_string(),
            )
        },
        |path| path.display().to_string(),
    )
}

/// The capture helper beside this binary, whether or not it is safe to run.
#[cfg(target_os = "linux")]
fn installed_helper() -> Option<std::path::PathBuf> {
    // nosemgrep: rust.lang.security.current-exe.current-exe
    let path = std::env::current_exe()
        .ok()?
        .parent()?
        .join("topgent-capture");
    path.is_file().then_some(path)
}

/// The capture helper beside this binary, if it is installed and safe to run.
#[cfg(target_os = "linux")]
fn helper_path() -> Option<std::path::PathBuf> {
    // The path locates a sibling file; that file is checked before it is run.
    // nosemgrep: rust.lang.security.current-exe.current-exe
    let path = std::env::current_exe()
        .ok()?
        .parent()?
        .join("topgent-capture");
    // The same check that decides whether it will be run. Without this the
    // probe answered "available" for a helper the runtime then refused, which
    // is the one thing this module promises never to do: report a capability
    // that will not work.
    (path.is_file() && super::helper::safe_to_run(&path)).then_some(path)
}

/// Whether the capability is on the binary itself.
///
/// Asked only here, on the grant path, never during a sweep. `setcap` writes a
/// `security.capability` extended attribute, and reading an xattr from Rust
/// needs either a crate or `unsafe`, which this workspace forbids, so the
/// system's own reader is used from a fixed absolute path.
#[cfg(target_os = "linux")]
fn binary_has_capability() -> bool {
    // Asks getcap about this process's own file. Nothing runs on the answer.
    // nosemgrep: rust.lang.security.current-exe.current-exe
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    has_capability(&exe)
}

/// Whether one binary carries the capture capability.
///
/// `setcap` writes a `security.capability` extended attribute, and reading an
/// xattr from Rust needs either a crate or `unsafe`, which this workspace
/// forbids, so the system's own reader is used from a fixed absolute path.
#[cfg(target_os = "linux")]
fn has_capability(exe: &std::path::Path) -> bool {
    let Ok(mut command) = crate::tool::GETCAP.command() else {
        return false;
    };
    let Ok(output) = command.arg(exe).output() else {
        return false;
    };
    String::from_utf8_lossy(&output.stdout).contains("cap_net_raw")
}

/// # macOS
///
/// Two questions, and both have to be yes. The operating system's is whether
/// `/dev/bpf*` can be opened, which the `access_bpf` group that Wireshark's
/// `ChmodBPF` helper creates is the established way to arrange. The build's is
/// whether it has a capture backend for this platform, and today it does not.
///
/// Answering only the first is how this reported `available` on a Mac where
/// the devices were readable and nothing could capture a single packet. The
/// permission being in place is not the feature being present, which is the
/// same mistake, one layer up, as reporting a granted capability as a running
/// capture.
#[cfg(target_os = "macos")]
#[must_use]
pub fn probe() -> State {
    // Asked first, because it is the one that decides. A backend that cannot
    // exist here makes the state of the devices a detail rather than an answer.
    if let Err(reason) = super::wire::Wire::open() {
        return State::Unsupported {
            reason: format!("{reason}. {}", bpf_state()),
        };
    }
    State::Available
}

/// What the operating system's half of the answer is, in words.
///
/// Kept although nothing decides on it yet: it is what turns "this build
/// cannot" into "this build cannot, and here is what the machine is ready
/// for", and it is what the grant path will need the day there is a backend.
#[cfg(target_os = "macos")]
fn bpf_state() -> String {
    let mut last = None;
    for index in 0..4 {
        let device = format!("/dev/bpf{index}");
        match std::fs::File::open(&device) {
            Ok(_) => {
                return "The packet-capture devices on this machine are readable, so \
                        nothing but the build stands in the way"
                    .to_owned();
            }
            Err(error) => {
                if error.kind() == std::io::ErrorKind::NotFound {
                    continue;
                }
                last = Some(format!("{device}: {error}"));
            }
        }
    }
    match last {
        Some(detail) => format!(
            "The packet-capture devices are also unreadable ({detail}), which the \
             ChmodBPF helper shipped with Wireshark is the usual way to change"
        ),
        None => "No packet-capture device was found either".to_owned(),
    }
}

/// # Windows
///
/// Capture needs a driver, and a driver cannot be granted by a permission
/// change. `wpcap.dll` in the system directory is what every capture library
/// loads, so its presence is the question.
#[cfg(windows)]
#[must_use]
pub fn probe() -> State {
    // See the macOS note: the driver being installed is not this build being
    // able to use it, and reporting the first as the second is the lie this
    // module exists to avoid.
    if let Err(reason) = super::wire::Wire::open() {
        return State::Unsupported {
            reason: reason.to_string(),
        };
    }
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_owned());
    for relative in ["System32\\Npcap\\wpcap.dll", "System32\\wpcap.dll"] {
        if std::path::Path::new(&root).join(relative).exists() {
            return State::Available;
        }
    }
    State::NeedsGrant {
        missing: "wpcap.dll was not found, so no packet-capture driver is installed".to_owned(),
        remedy: Remedy::Install {
            what: "Npcap".to_owned(),
            source: "https://npcap.com, installed by its own signed installer. Topgent \
                     will not install a driver on your behalf."
                .to_owned(),
        },
    }
}

/// Everything else says so rather than guessing.
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
#[must_use]
pub fn probe() -> State {
    State::Unsupported {
        reason: "this build has no packet-capture path for this platform".to_owned(),
    }
}
