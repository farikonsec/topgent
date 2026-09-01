//! What Topgent can say about the binaries its own sensors run.
//!
//! A sensor's binary changing state is itself a security event: the evidence
//! behind every finding from that sensor has changed underneath the findings.
//! Noticing that only within one process would miss exactly the case that
//! matters, so attestations are journaled with their previous state and the
//! moment they changed.

/// Persisted attestation of one sensor binary.
///
/// A sensor's binary changing state is itself a security event. A tool that was
/// where the operating system keeps it and is now gone, or has moved, means the
/// evidence behind every finding from that sensor has changed underneath the
/// findings, and that has to survive a restart to be noticed at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolAttestationRecord {
    /// Tool short name.
    pub name: String,
    /// Latest observed state.
    pub state: String,
    /// Absolute path accepted, when one was.
    pub path: Option<String>,
    /// First sweep that saw this tool at all.
    pub first_seen_at: u64,
    /// Most recent sweep that looked.
    pub last_seen_at: u64,
    /// The state before the most recent change, when there has been one.
    pub previous_state: Option<String>,
    /// When the state last changed.
    pub changed_at: Option<u64>,
}

/// Largest number of retained tool attestations.
pub const MAX_TOOL_ATTESTATIONS: usize = 32;

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use crate::MAX_TOOL_ATTESTATIONS;
    use crate::journal::Journal;
    use crate::test_support::test_dir;

    #[test]
    fn a_sensor_binary_moving_is_remembered_across_a_restart() {
        // The sensors are the evidence behind every finding. A tool that was
        // where the operating system keeps it and is now gone means that
        // evidence changed underneath the findings, and noticing only within
        // one process would miss exactly the case that matters.
        let dir = test_dir("tool-attestation");
        let _ = std::fs::remove_dir_all(&dir);
        let journal = Journal::at(&dir);

        let first = journal
            .record_tool_attestation("docker", "trusted", Some("/usr/bin/docker"), 1_000)
            .expect("the first sighting persists");
        assert_eq!(first.first_seen_at, 1_000);
        assert_eq!(first.previous_state, None, "nothing has changed yet");
        assert_eq!(first.changed_at, None);

        // An unchanged sweep is not a change.
        let same = journal
            .record_tool_attestation("docker", "trusted", Some("/usr/bin/docker"), 2_000)
            .expect("an unchanged sighting persists");
        assert_eq!(same.previous_state, None);
        assert_eq!(same.last_seen_at, 2_000);
        assert_eq!(same.first_seen_at, 1_000, "first sighting is not rewritten");

        // A fresh journal over the same directory is the restart.
        let restarted = Journal::at(&dir);
        let moved = restarted
            .record_tool_attestation("docker", "missing", None, 3_000)
            .expect("the change persists");
        assert_eq!(moved.previous_state.as_deref(), Some("trusted"));
        assert_eq!(moved.changed_at, Some(3_000));
        assert_eq!(moved.path, None);
        assert_eq!(moved.first_seen_at, 1_000);

        // Same state, different path, is still a change worth recording.
        let relocated = restarted
            .record_tool_attestation("docker", "missing", Some("/opt/docker"), 4_000)
            .expect("a path change persists");
        assert_eq!(relocated.previous_state.as_deref(), Some("missing"));
        assert_eq!(relocated.changed_at, Some(4_000));

        let all = restarted.tool_attestations().expect("history reads back");
        assert_eq!(all.len(), 1, "one tool, one record");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tool_attestation_history_is_bounded_and_skips_unreadable_members() {
        let dir = test_dir("tool-bounds");
        let _ = std::fs::remove_dir_all(&dir);
        let journal = Journal::at(&dir);
        for index in 0..MAX_TOOL_ATTESTATIONS + 12 {
            journal
                .record_tool_attestation(&format!("tool{index:03}"), "trusted", None, 1_000)
                .expect("each sighting persists");
        }
        assert_eq!(
            journal
                .tool_attestations()
                .expect("history reads back")
                .len(),
            MAX_TOOL_ATTESTATIONS
        );

        // A hand-edited or truncated file is an empty history, not a panic.
        std::fs::write(dir.join("tool-attestations.json"), "{ not an array")
            .expect("the file is writable");
        assert!(
            journal
                .tool_attestations()
                .expect("a broken file reads as empty")
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
