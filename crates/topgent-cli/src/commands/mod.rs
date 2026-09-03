//! One module per subcommand.
//!
//! Each takes the raw argument list and returns the process exit code, so a
//! command can be read end to end without tracing dispatch, and adding one is
//! a new file rather than an edit to a growing match.

pub(crate) mod approval;
pub(crate) mod asset;
pub(crate) mod benchmark;
pub(crate) mod context;
pub(crate) mod doctor;
pub(crate) mod events;
pub(crate) mod evidence;
pub(crate) mod export;
pub(crate) mod lab;
pub(crate) mod network;
pub(crate) mod policy;
pub(crate) mod rule;
pub(crate) mod stop;
