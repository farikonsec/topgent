//! One report, three front ends.
//!
//! The CLI, the development viewer and the desktop app must never disagree
//! about what Topgent found, so the sweep-fold-score-journal sequence and the
//! JSON shape it produces live here once. Each front end is a thin skin over
//! [`scan`] and the operations in `actions`.
//!
//! Everything sensitive stays out of the report. It carries the fact that a
//! credential is reachable, never its contents, because the fact vocabulary
//! cannot carry contents in the first place.
//!
//! # Layout
//!
//! `scan` runs one sweep and assembles the report. Every other module owns
//! one section of it and answers for what that section may honestly claim:
//!
//! | Module | Section |
//! |---|---|
//! | `agents` | one row per agent, and the evidence behind its identity |
//! | `activity` | the causal timeline |
//! | `network` | retained endpoint metadata and baselines |
//! | `events` | the event log, with severity decided by direction |
//! | `health` | what the sensors can see here, and what they cannot |
//! | `response` | what a rule would do, and what it is waiting on |
//! | `legend` | every risk factor, its cost and its ATLAS mapping |
//! | `context` | optional context an agent's own harness volunteered |
//! | `actions` | the operations that change the machine or the policy |

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub(crate) mod actions;
pub(crate) mod activity;
pub(crate) mod agents;
pub(crate) mod context;
pub(crate) mod events;
pub(crate) mod health;
pub(crate) mod legend;
pub(crate) mod network;
pub(crate) mod response;
pub(crate) mod scan;
#[cfg(test)]
mod test_support;

pub use actions::{
    add_rule, clear_semantic_context, export_session, remove_rule, reset_network_baseline,
    resolve_termination_approval, set_asset_disposition, set_rule_response, set_semantic_enabled,
    stop,
};
pub use scan::{cyclonedx_from_report, cyclonedx_scan, now_ms, scan};
pub use topgent_journal::state_dir;
