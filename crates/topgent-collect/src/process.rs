//! The process collector.
//!
//! Everything else anchors to a process, so this runs first. It needs no
//! privileges: on macOS an unprivileged process can enumerate every process on
//! the box, and can read the executable path, owner, start time and parent of
//! any process belonging to the same user. That covers every local coding agent,
//! because they all run as you.
//!
//! # Layout
//!
//! | Module | What lives there |
//! |---|---|
//! | [`table`] | One process as Topgent sees it, and the sweep that reads them all. |
//! | [`owner`] | Who a process runs as, in each platform's own terms. |
//! | [`launcher`] | Recovering the real program when a runtime is running someone else's script. |
//! | [`collector`] | Turning the table into facts, and deciding what counts as a new agent. |

mod collector;
mod launcher;
mod owner;
mod table;

pub use collector::ProcessCollector;
// The launcher work only exists where a runtime is launched that way, and in
// tests, which exercise the parser on every platform.
#[cfg(any(windows, test))]
pub use launcher::{SCRIPT_RUNTIMES, is_script_runtime, parse_windows_launchers};
#[cfg(any(windows, test))]
pub use owner::valid_windows_sid;
pub use owner::{Owner, owner_of, with_resolved_owner};
pub use table::{ProcInfo, family_of, snapshot};
