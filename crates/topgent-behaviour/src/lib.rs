//! Runtime behaviour rules for agents, evaluated on Topgent's own events.
//!
//! The rules are the F catalogue, vendored verbatim under `data/f` at a pinned
//! commit: 95 rules, 355 macros and 165 lists describing what a process does
//! at runtime that deserves a second look. Nothing external runs. Topgent
//! parses the catalogue's condition language itself and evaluates each rule
//! against the file, exec and connect records its own sensors produce,
//! joined to process history.
//!
//! # Crate map
//!
//! - [`lang`]: the condition language: tokens, syntax tree and parser.
//! - [`event`]: what an event can say about a field, including "not collected".
//! - [`eval`]: three-valued evaluation, so a field Topgent does not collect
//!   leaves a rule undecided instead of passing or failing it.
//! - [`catalogue`]: loading the pinned catalogue and resolving every rule's
//!   macros and lists into one condition.
//! - [`fields`]: the fields Topgent supplies, which decide which rules can
//!   fire on its own events.

pub mod catalogue;
pub mod eval;
pub mod event;
pub mod fields;
pub mod index;
pub mod lang;
pub mod summaries;
