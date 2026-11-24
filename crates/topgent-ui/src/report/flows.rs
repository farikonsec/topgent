//! Agent flows: what one agent run read, and where its data went.
//!
//! The same record the browser viewer's Files tab reads. The core has already
//! done the counting — distinct files, their sizes at read time, the folders
//! read most, anything that looked like a secret, and, for each destination,
//! the files read in the minutes before its largest burst. The interface
//! renders these and derives nothing. Bytes sent are encrypted, so a flow
//! never claims the files were what went out, only what was open when it sent.

use serde::Deserialize;

use super::nullable;

/// One agent run's reads and transfers.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AgentFlow {
    /// Which run this belongs to.
    #[serde(deserialize_with = "nullable")]
    pub agent: FlowAgent,
    /// The workspace root it read under.
    #[serde(deserialize_with = "nullable")]
    pub workspace: String,
    /// Distinct files read under the root.
    #[serde(deserialize_with = "nullable")]
    pub files_read: u64,
    /// The size of those files as they were when first read.
    #[serde(deserialize_with = "nullable")]
    pub bytes_read: u64,
    /// Of the files, version-control history.
    #[serde(deserialize_with = "nullable")]
    pub history_files: u64,
    /// Whether the read is large enough to state a burst as a share of it.
    #[serde(deserialize_with = "nullable")]
    pub large_read: bool,
    /// `bytes read` or `workspace size`: what the shares are taken against.
    #[serde(deserialize_with = "nullable")]
    pub compared_with: String,
    /// The subdirectories read most.
    pub folders: Vec<FlowFolder>,
    /// Files read whose names look like credentials or keys.
    pub sensitive: Vec<String>,
    /// The burst window, in minutes.
    #[serde(deserialize_with = "nullable")]
    pub burst_window_minutes: u64,
    /// Where its data went.
    pub destinations: Vec<FlowDestination>,
}

/// Which run a flow is about.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct FlowAgent {
    /// Its process id.
    #[serde(deserialize_with = "nullable")]
    pub pid: u32,
    /// When the run started, in the report's time base.
    #[serde(deserialize_with = "nullable")]
    pub started_at: u64,
    /// What to call it.
    #[serde(deserialize_with = "nullable")]
    pub name: String,
    /// The agent family, when recognised.
    pub family: Option<String>,
}

/// A subdirectory and how many of its files were read.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct FlowFolder {
    /// The subdirectory.
    #[serde(deserialize_with = "nullable")]
    pub directory: String,
    /// Distinct files read in it.
    #[serde(deserialize_with = "nullable")]
    pub files: u64,
}

/// One place an agent sent data.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct FlowDestination {
    /// Address literal, or empty for a socket whose connect was not seen.
    #[serde(deserialize_with = "nullable")]
    pub address: String,
    /// Port, zero when unknown.
    #[serde(deserialize_with = "nullable")]
    pub port: u16,
    /// A name for the address, when one is known.
    #[serde(deserialize_with = "nullable")]
    pub name: String,
    /// Who owns the address, when that is known.
    #[serde(deserialize_with = "nullable")]
    pub owner: String,
    /// Whether this is the agent's own model service.
    #[serde(deserialize_with = "nullable")]
    pub own_service: bool,
    /// Bytes written to it in total.
    #[serde(deserialize_with = "nullable")]
    pub bytes: u64,
    /// The most bytes within any one burst window.
    #[serde(deserialize_with = "nullable")]
    pub burst_bytes: u64,
    /// That burst as a share of the basis, once the read is large; else absent.
    pub burst_percent_of_workspace: Option<u64>,
    /// Whether that burst crossed the rule's own threshold.
    #[serde(deserialize_with = "nullable")]
    pub over_threshold: bool,
    /// Files read in the window that ended with the burst. Never the contents.
    pub files_before_burst: Vec<String>,
}
