//! Stable external projections of Topgent's internal evidence model.
//!
//! Everything here is a projection outward. `CycloneDX` is an export format
//! and never Topgent's domain model, and the CI gate consumes the same report
//! fields the interface renders — so what a person sees on screen and what a
//! pipeline decides on cannot disagree.
//!
//! # Layout
//!
//! | Module | What lives there |
//! |---|---|
//! | [`contract`] | The version numbers other people's tooling depends on. |
//! | [`bom`] | The `CycloneDX` bill of materials, and its validator. |
//! | [`html`] | The same bill of materials as a page someone can read. |
//! | [`gate`] | The CI decision: what counts as a violation, and what exit code says so. |

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod bom;
mod contract;
mod gate;
mod html;
mod session;

pub use bom::{cyclonedx, validate_cyclonedx};
pub use contract::{CYCLONEDX_SPEC_VERSION, POLICY_RESULT_VERSION, REPORT_CONTRACT_VERSION};
pub use gate::{PolicyResult, SeverityFloor, Violation, evaluate_report, without_byte_order_mark};
pub use html::cyclonedx_html;
pub use session::{Detail, session_html, session_json};
