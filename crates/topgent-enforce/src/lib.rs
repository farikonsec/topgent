//! Enforcement.
//!
//! The only crate in Topgent that changes anything. Everything else observes.
//!
//! Four rules hold here, and each one exists because of a specific way tools
//! like this get people hurt:
//!
//! 1. **Typed operations only.** There is no `execute(command)` behind this
//!    boundary and there never will be. The whole surface is [`Action`], and
//!    adding to it is a deliberate act with its own review.
//! 2. **Identity is re-checked at the moment of the signal.** A pid is not an
//!    identity — the kernel reuses them. Every operation carries the process
//!    start time it was authorised against, and refuses if the process now on
//!    that pid is a different one. Without that check a stale UI row could kill
//!    a database that happened to inherit the number.
//! 3. **Topgent never kills Topgent, or anything it cannot own.** Self, the
//!    session that launched it, pid 1, and any process belonging to another user
//!    are all refused before a signal is sent.
//! 4. **Every outcome writes a fact**, success or failure. An action taken reads
//!    the same shape in the log as an action observed, so one timeline covers
//!    both and nobody has to reconcile two formats after an incident.

#![forbid(unsafe_code)]
//!
//! # Layout
//!
//! | Module | What lives there |
//! |---|---|
//! | [`action`] | The operations Topgent will perform, and the refusals it gives instead. |
//! | [`guard`] | Who may be touched: self, session, init, other accounts, critical system processes. |
//! | [`ladder`] | Which rung an operator has earned — observe, ask, close, stop. |
//! | [`signal`] | Sending the signal itself, and what a platform without signals can honestly do. |
//! | [`execute`] | Running one authorised action: guard, recheck identity, signal, record. |
//! | [`container`] | The same discipline applied to a container runtime rather than a pid. |

#![deny(missing_docs)]

pub(crate) mod action;
pub(crate) mod container;
pub(crate) mod execute;
pub(crate) mod guard;
pub(crate) mod ladder;
pub(crate) mod signal;

pub use action::{Action, Executed, Outcome, Refusal};
pub use container::{
    ContainerAction, ContainerController, SystemDockerController, execute_container,
};
pub use execute::execute;
pub use guard::{Guard, protected_system_process};
pub use ladder::{ApprovalState, DecisionOutcome, EnforcementCapability, decide_response};
pub use signal::{GRACE, Signal, Signaller, SystemSignaller};

/// Sensor identity written into every fact this crate emits.
pub(crate) const ID: &str = "enforce";
