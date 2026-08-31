//! The risk model.
//!
//! A bare number is not a finding. Every score here is the sum of named factors,
//! and every factor carries the observation that produced it and how much that
//! observation is worth. If a factor cannot print its source, it does not exist.
//!
//! The shape is `capability × resource sensitivity × identity`:
//!
//! - **Capability** sets the base points. Running commands outranks writing files,
//!   which outranks reading them.
//! - **Sensitivity** decides whether a factor applies at all. A reachable path is
//!   only a factor when something worth taking is behind it.
//! - **Identity** scales the whole thing. Shell under a borrowed human account is
//!   worse than shell under a service account, because the audit trail then names
//!   a person for what the agent did.
//!
//! # Layout
//!
//! | Module | What lives there |
//! |---|---|
//! | [`factor`] | The vocabulary of findings: every code, its points, and what it means. |
//! | [`grade`] | Turning a total into a word, and the ceiling on the total. |
//! | [`classify`] | Small predicates about hosts, paths and executable names. |
//! | [`watchlist`] | Matching an agent against the operator's own rules. |
//! | [`factors`] | Deciding which factors an agent has actually earned. |
//! | [`assess`] | Scoring one agent, start to finish. |
//! | [`remediation`] | What to do about a factor, in the operator's terms. |

mod assess;
mod classify;
mod factor;
mod factors;
mod grade;
mod remediation;
mod watchlist;

pub use assess::{assess, assess_with, identity_order};
pub use factor::{Factor, FactorCode};
pub use grade::{Grade, Risk};
pub use remediation::{Remediation, remediations};
pub use watchlist::matched_watchlist_rules;
