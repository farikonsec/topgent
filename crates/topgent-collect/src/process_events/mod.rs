//! Process lifecycle as it happens, from the kernel, through `topgent-sensor`.
//!
//! A sweep sees the processes that are running at the moment it looks. Most of
//! what an agent runs (a `cat`, a `curl`, a compiler pass) starts and ends
//! between two sweeps and was never seen at all. `topgent-sensor` holds the
//! kernel's process connector and writes one JSON line per fork, exec and
//! exit, plus a health line every second. This module starts it, reads it on a
//! thread, and hands each sweep what arrived since the last.
//!
//! # What is trusted
//!
//! The helper's path, found beside this binary and checked the same way the
//! capture helper is. Its output is parsed as hostile anyway: bounded lines,
//! bounded names, numbers checked.
//!
//! # What is counted rather than hidden
//!
//! Messages the kernel dropped (gaps in its per-CPU numbering), a full socket
//! buffer, lines this side could not keep up with, and every stretch of time
//! the helper was not running. A continuous sensor that goes quiet is either
//! seeing a quiet host or not seeing at all, and the counters are how the two
//! are told apart.
//!
//! # Layout
//!
//! - [`line`]: the helper's line format, read as hostile input.
//! - [`accounting`]: what one interval's coverage claim rests on: loss,
//!   restarts and silence, counted per interval.
//! - `supervisor`: starting the helper beside this binary, restarting it when
//!   it stops, and handing each sweep what arrived.

mod accounting;
mod line;
mod supervisor;

pub use accounting::{MAX_PENDING, Pending, STALL_MS, interval_covered};
pub use line::{HelperHealth, LifecycleEvent, LifecycleKind, Line, SensorCall, parse_line};
pub use supervisor::{ProcessEventCollector, take_drained};
