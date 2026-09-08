//! Deeper network visibility, and what it costs to switch on.
//!
//! # What this is for
//!
//! Topgent runs unprivileged and says so. There is one capability it cannot
//! have at that privilege level and which changes what it can see, so rather
//! than either taking the privilege quietly or pretending the gap does not
//! exist, it is offered as a single, scoped, user-initiated grant: one button,
//! one operating-system prompt, one capability.
//!
//! # What it actually adds, stated honestly
//!
//! The socket tables show TCP connections that exist at the moment of a sweep.
//! They do not show UDP peers, ICMP at all, or a connection that opened and
//! closed between two sweeps. Packet capture shows all three, and shows a port
//! scan as it happens rather than never.
//!
//! It does **not** give content. Agent traffic is TLS and stays TLS; Topgent
//! decrypts nothing and this does not change that. It does **not** improve
//! attribution either: a packet carries no process id, so the owning process
//! still comes from the socket table, exactly as it did before. Sniffnet is
//! often credited with fast per-process attribution and does not do it either
//! — it reads the local port off the packet and asks the operating system.
//!
//! Being clear about that is the point. A capability sold on what it cannot do
//! is a capability nobody can consent to.
//!
//! # Nothing here fails
//!
//! Every function returns a state. A missing driver, a refused device, an
//! unreadable file and an unsupported platform are all ordinary answers with
//! their own text. There is no path through this module that panics, and none
//! that reports a capability as present because a check could not be run.

use std::fmt;

/// Whether deeper visibility is available, and if not, why not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// The capability is present and capture would work now.
    Available,
    /// Granted on disk, and not yet in effect.
    ///
    /// File capabilities take effect at the next `exec`, so a process that was
    /// already running when the grant happened still cannot capture. Reporting
    /// that as "still unavailable" told people their successful grant had
    /// failed, which is the worst answer of the four.
    NeedsRestart {
        /// What was granted, and what has to happen now.
        detail: String,
    },
    /// The platform supports it, and it has not been granted.
    ///
    /// This is the only state where the button does anything.
    NeedsGrant {
        /// What is missing, in one sentence a person can act on.
        missing: String,
        /// The exact step that grants it.
        remedy: Remedy,
    },
    /// This build cannot do it on this platform.
    Unsupported {
        /// Why not.
        reason: String,
    },
    /// The check itself could not be completed.
    ///
    /// Deliberately not folded into `NeedsGrant`. "We asked and the answer was
    /// no" and "we could not ask" are different, and a monitor that reports the
    /// second as the first is guessing.
    Unknown {
        /// What went wrong while checking.
        detail: String,
    },
}

impl State {
    /// The short word a report or a badge prints.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::NeedsRestart { .. } => "needs_restart",
            Self::NeedsGrant { .. } => "needs_grant",
            Self::Unsupported { .. } => "unsupported",
            Self::Unknown { .. } => "unknown",
        }
    }

    /// The words a persistent indicator shows.
    ///
    /// [`Self::Available`] says the permission is present, not that packets
    /// are being read. Whether they are is a separate question with a separate
    /// answer, and [`indicator`] is what joins the two: an indicator saying
    /// capture was running when it was not would be the most misleading string
    /// in the interface.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Available => "Packet capture: permitted",
            Self::NeedsRestart { .. } => "Packet capture: restart to enable",
            Self::NeedsGrant { .. } => "Packet capture: off",
            Self::Unsupported { .. } => "Packet capture: unavailable here",
            Self::Unknown { .. } => "Packet capture: could not check",
        }
    }

    /// Whether pressing the indicator has anything to say.
    ///
    /// Every state opens the dialog except one that cannot be acted on at all,
    /// because "why is this off" is a question worth answering even when the
    /// answer is that this platform cannot do it.
    #[must_use]
    pub const fn is_actionable(&self) -> bool {
        !matches!(self, Self::Unsupported { .. })
    }

    /// Whether the button should be offered at all.
    #[must_use]
    pub const fn is_grantable(&self) -> bool {
        matches!(self, Self::NeedsGrant { .. })
    }
}

/// How a grant is obtained, and by whom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Remedy {
    /// A command the operator runs, which will prompt for elevation itself.
    ///
    /// Topgent never runs this silently and never holds the privilege: the
    /// operating system prompts, the change is made once, and Topgent goes on
    /// running as an ordinary user.
    Command {
        /// The command, exactly as it should be typed.
        command: String,
        /// What it changes, in one sentence.
        effect: String,
        /// How to undo it.
        undo: String,
    },
    /// Software the operator must install, which Topgent will not do for them.
    Install {
        /// What to install.
        what: String,
        /// Where it comes from.
        source: String,
    },
}

/// Everything the dialog needs to explain itself.
///
/// Held as data rather than written into the interface, so the command line and
/// the window say the same thing and neither can drift from what the code
/// actually does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    /// Current state on this host.
    pub state: State,
    /// What granting it would let Topgent see.
    pub gains: &'static [&'static str],
    /// What it would still not see, said before it is granted rather than
    /// discovered afterwards.
    pub limits: &'static [&'static str],
    /// What is being asked for, in the operating system's own terms.
    pub privilege: &'static str,
}

/// What capture adds. Every line is something the socket tables cannot show.
const GAINS: &[&str] = &[
    "UDP peers. The socket collector reports TCP only and says so in its own boundary text.",
    "ICMP. A process holding a raw socket can reach any host on the network, and no socket listing names where it went.",
    "Connections that open and close between two sweeps, which a snapshot cannot catch by construction.",
    "A port scan while it is happening. Its refused connections leave no socket for any \
     snapshot to find, so most of them are counted rather than tied to a process; the \
     traffic is visible either way, where today it is not visible at all.",
];

/// What it does not add. Listed first in the dialog, on purpose.
const LIMITS: &[&str] = &[
    "No content. Agent traffic is TLS and stays TLS; nothing here decrypts anything.",
    "No better attribution. A packet carries no process id, so the owning process still comes from the socket table.",
    "No history. Capture starts when it is switched on and sees nothing that happened before.",
];

impl fmt::Display for Offer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "deeper network visibility: {}", self.state.as_str())?;
        writeln!(f, "  asks for: {}", self.privilege)?;
        writeln!(f, "  it would show:")?;
        for line in self.gains {
            writeln!(f, "    - {line}")?;
        }
        writeln!(f, "  it would still not show:")?;
        for line in self.limits {
            writeln!(f, "    - {line}")?;
        }
        match &self.state {
            State::NeedsGrant { missing, remedy } => {
                writeln!(f, "  missing: {missing}")?;
                match remedy {
                    Remedy::Command {
                        command,
                        effect,
                        undo,
                    } => {
                        writeln!(f, "  run: {command}")?;
                        writeln!(f, "    which: {effect}")?;
                        write!(f, "    undo: {undo}")
                    }
                    Remedy::Install { what, source } => {
                        writeln!(f, "  install: {what}")?;
                        write!(f, "    from: {source}")
                    }
                }
            }
            State::NeedsRestart { detail } => write!(f, "  {detail}"),
            State::Unsupported { reason } => write!(f, "  reason: {reason}"),
            State::Unknown { detail } => write!(f, "  could not check: {detail}"),
            State::Available => write!(f, "  nothing to grant"),
        }
    }
}

/// How a status reads at a glance, before anybody has read the words.
///
/// Held here rather than in the window for the same reason the dialog's text
/// is: one control, one meaning, and no chance of the colour and the sentence
/// disagreeing. These are deliberately not the risk grades. Capture being off
/// is a choice and not a finding, and colouring it like a problem would train
/// people to ignore the colours that are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    /// Working now.
    Active,
    /// It will work, and not yet.
    Pending,
    /// Not on, and nothing is wrong.
    Inactive,
    /// Nothing can be done here.
    Unavailable,
    /// The answer is not known, which is not the same as no.
    Unknown,
}

/// What the persistent indicator says, and how it reads at a glance.
///
/// Two facts, joined here so neither can be shown without the other: whether
/// the permission is present, and whether a capture is actually reading. The
/// permission being granted is not the capture running, and the interface used
/// to imply it was.
#[must_use]
pub fn indicator() -> (String, Tone) {
    let state = probe();
    match state {
        State::Available => match live::status().as_str() {
            "running" => ("Packet capture: on".to_owned(), Tone::Active),
            // Switched off by somebody, which is a choice and not a fault.
            "off" => ("Packet capture: off".to_owned(), Tone::Inactive),
            "not started" => (
                "Packet capture: permitted, starting at next sweep".to_owned(),
                Tone::Pending,
            ),
            // A session that started and stopped. Reported as unknown rather
            // than off: something went wrong and the words say what.
            other => (format!("Packet capture: {other}"), Tone::Unknown),
        },
        State::NeedsRestart { .. } => (state.label().to_owned(), Tone::Pending),
        State::NeedsGrant { .. } => (state.label().to_owned(), Tone::Inactive),
        State::Unsupported { .. } => (state.label().to_owned(), Tone::Unavailable),
        State::Unknown { .. } => (state.label().to_owned(), Tone::Unknown),
    }
}

/// What this host can offer, and on what terms.
#[must_use]
pub fn offer() -> Offer {
    Offer {
        state: probe(),
        gains: GAINS,
        limits: LIMITS,
        privilege: PRIVILEGE,
    }
}

pub mod flows;
pub mod handoff;
pub mod helper;
pub mod live;
pub mod locals;
pub mod packet;
mod platform;
pub mod ports;
pub mod session;
pub mod wire;

pub use platform::{PRIVILEGE, probe};

/// What happened when a grant was attempted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Granted {
    /// The capability is now present, rechecked rather than assumed.
    Yes,
    /// The operator was asked and declined, or the prompt was dismissed.
    Declined,
    /// The step ran and the capability is still absent.
    ///
    /// Separate from `Declined` on purpose: a command that succeeded and
    /// changed nothing is a different problem from a person saying no.
    NoChange {
        /// What the step said, trimmed.
        detail: String,
    },
    /// Nothing was attempted, and why.
    NotAttempted {
        /// The reason, in one sentence.
        reason: String,
    },
}

impl Granted {
    /// The short word a status line prints.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Yes => "granted",
            Self::Declined => "declined",
            Self::NoChange { .. } => "no_change",
            Self::NotAttempted { .. } => "not_attempted",
        }
    }
}

/// Hands the capability back, through the operating system's own prompt.
///
/// The mirror of [`grant`], and it exists because a capability that is easier
/// to switch on than off is a bad bargain. Stopping the capture is instant and
/// needs no password; this is the stronger step, which removes the permission
/// from the binary so nothing can start it again without asking.
///
/// Only ever runs where a command granted it in the first place. macOS grants
/// through group membership and Windows through an installed driver, and
/// neither is Topgent's to take away.
#[must_use]
pub fn revoke() -> Granted {
    let Some(command) = revoke_command() else {
        return Granted::NotAttempted {
            reason: "on this platform the permission was not granted by Topgent, so it is \
                     not Topgent's to remove"
                .to_owned(),
        };
    };
    match elevate(&command) {
        Ok(output) => {
            // Rechecked, never assumed, exactly as the grant is. A command
            // that exits zero and changes nothing must not be reported as a
            // capability that has gone.
            if matches!(
                probe(),
                State::NeedsGrant { .. } | State::Unsupported { .. }
            ) {
                Granted::Yes
            } else {
                Granted::NoChange { detail: output }
            }
        }
        Err(reason) => {
            if reason.declined {
                Granted::Declined
            } else {
                Granted::NotAttempted {
                    reason: reason.detail,
                }
            }
        }
    }
}

/// The command that hands the capability back, for a dialog to show.
///
/// `None` where the permission was not Topgent's to give and so is not its to
/// take: macOS grants through group membership, Windows through an installed
/// driver.
#[must_use]
pub fn revoke_step() -> Option<String> {
    revoke_command()
}

/// The step that hands the capability back, where there is one.
///
/// Built from the same place the grant is, so the two can never drift into
/// pointing at different binaries.
#[cfg(target_os = "linux")]
#[expect(
    clippy::unnecessary_wraps,
    reason = "matches the other platforms, which have nothing to return"
)]
fn revoke_command() -> Option<String> {
    Some(format!("sudo setcap -r {}", platform::grant_target()))
}

/// See the Linux note. Nothing here was granted by Topgent.
#[cfg(not(target_os = "linux"))]
const fn revoke_command() -> Option<String> {
    None
}

/// Asks the operating system to grant the capability, through its own prompt.
///
/// Topgent does not elevate itself and does not hold the privilege. It asks
/// the platform's standard elevation helper to run one fixed command, the
/// operating system does the asking, and the result is rechecked rather than
/// assumed. A step that succeeded and changed nothing is reported as such.
///
/// Only ever runs for a [`State::NeedsGrant`] carrying a [`Remedy::Command`].
/// An install is the operator's to do, and this refuses rather than trying to
/// put a driver on somebody's machine.
#[must_use]
pub fn grant() -> Granted {
    let State::NeedsGrant { remedy, .. } = probe() else {
        return Granted::NotAttempted {
            reason: "there is nothing to grant on this host".to_owned(),
        };
    };
    let Remedy::Command { command, .. } = remedy else {
        return Granted::NotAttempted {
            reason: "this platform needs software installed, which Topgent will not do \
                     on your behalf"
                .to_owned(),
        };
    };
    match elevate(&command) {
        Ok(output) => {
            // Rechecked, never assumed. A command can exit zero and change
            // nothing, and a monitor that took the exit code as the answer
            // would then report a capability it does not have.
            // A grant that landed on the binary counts as success even though
            // this process cannot use it yet: file capabilities take effect at
            // the next exec. Calling that "no change" told people a successful
            // grant had failed.
            match probe() {
                State::Available | State::NeedsRestart { .. } => Granted::Yes,
                _ => Granted::NoChange { detail: output },
            }
        }
        Err(reason) => {
            if reason.declined {
                Granted::Declined
            } else {
                Granted::NotAttempted {
                    reason: reason.detail,
                }
            }
        }
    }
}

/// Why an elevation did not happen.
struct Refused {
    /// Whether the person said no, as opposed to the machine failing.
    declined: bool,
    /// What to report.
    detail: String,
}

/// Runs one fixed command through the platform's own elevation prompt.
///
/// The command comes from [`probe`] and nothing discovered anywhere in Topgent
/// is interpolated into it. There is no path here that builds a command line
/// out of anything a watched agent could influence.
#[cfg(target_os = "linux")]
fn elevate(command: &str) -> Result<String, Refused> {
    // `pkexec` is the desktop elevation helper and shows a graphical prompt.
    // `sudo` is not used: it wants a terminal, and there is not one behind a
    // button.
    let parts: Vec<&str> = command.split_whitespace().skip(1).collect();
    let output = std::process::Command::new("/usr/bin/pkexec")
        .args(&parts)
        .output()
        .map_err(|error| Refused {
            declined: false,
            detail: format!("pkexec could not be run: {error}"),
        })?;
    // 126 is pkexec's own code for a dismissed or refused authorisation.
    if output.status.code() == Some(126) {
        return Err(Refused {
            declined: true,
            detail: String::new(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stderr).trim().to_owned())
}

/// See the Linux note. macOS prompts through its own authorisation dialog.
#[cfg(target_os = "macos")]
fn elevate(_command: &str) -> Result<String, Refused> {
    // Deliberately not implemented. The macOS remedy is an install, not a
    // command, so this is unreachable through `grant`, and adding an
    // `osascript` elevation path that nothing calls would be a privileged code
    // path kept alive for no reason.
    Err(Refused {
        declined: false,
        detail: "macOS needs the capture helper installed rather than a permission \
                 changed, and Topgent will not install software on your behalf"
            .to_owned(),
    })
}

/// See the Linux note.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn elevate(_command: &str) -> Result<String, Refused> {
    Err(Refused {
        declined: false,
        detail: "this platform has no elevation path in this build".to_owned(),
    })
}
