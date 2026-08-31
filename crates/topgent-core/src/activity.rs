//! Deterministic activity timelines and conservative attack-path correlation.
//!
//! A timeline event is an observation, not a claim about intent. Direct process
//! relationships are labelled direct; sequences joined only by agent identity
//! and time are labelled correlated. This prevents the UI from turning temporal
//! proximity into invented causality.
//!
//! # Layout
//!
//! | Module | What lives there |
//! |---|---|
//! | [`model`] | The timeline vocabulary: events, links, paths, and how certain a link is. |
//! | [`draft`] | Turning one fact into one candidate event, and giving it a stable identity. |
//! | [`paths`] | The two correlations Topgent is willing to draw, and their thresholds. |
//! | [`build`] | Assembling a timeline, and merging it with what was already retained. |

mod build;
mod draft;
mod model;
mod paths;

pub use build::{ACTIVITY_RETENTION_MS, MAX_ACTIVITY_EVENTS, build, merge_activity_history};
pub use model::{
    Activity, ActivityEvent, ActivityKind, ActivityLink, ActivityNetwork, ActivityPath,
    LinkCertainty, NetworkActivityPhase,
};
pub use paths::{
    LIFECYCLE_PERIODIC_MAX_INTERVAL_MS, LIFECYCLE_PERIODIC_MAX_JITTER_PERCENT,
    LIFECYCLE_PERIODIC_MIN_EVENTS, LIFECYCLE_PERIODIC_MIN_INTERVAL_MS,
};
