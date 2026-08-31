//! What one sweep saw, and what changed since the last.
//!
//! The baseline is keyed on pid plus process start time, because a pid on its
//! own is not an identity: the operating system reuses it. A sweep that
//! resolves less of the same exact run is recorded as degraded rather than as
//! a change, and one surface at a time advances the baseline so two of them
//! watching the same host cannot re-report each other's findings.

use crate::event_log::{Entry, GradeMove, Kind};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use topgent_core::{Agent, Risk};
use topgent_facts::UnixMillis;

/// How long a sweep lock is honoured before it is treated as abandoned.
///
/// A surface killed mid-sweep must not stop every later sweep from journaling.
pub const SWEEP_LOCK_STALE_MS: u64 = 30_000;

/// Exclusive right to advance the sweep baseline, released on drop.
pub(crate) struct SweepLock {
    path: PathBuf,
}

/// A snapshot of what an agent looked like last sweep.
///
/// Just enough to tell what changed, and nothing that would be sensitive if the
/// file were read by someone else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    /// Agent family, or `unclassified`.
    pub agent: String,
    /// Risk grade label.
    pub grade: String,
    /// Credentials in reach and untouched.
    pub credentials: Vec<String>,
    /// Resources touched outside policy.
    pub breaches: Vec<String>,
    /// Whether its connections currently look like scanning.
    pub scanning: bool,
    /// Model/provider label at this sweep.
    pub model: Option<String>,
    /// Active metadata-only rogue-behaviour factors.
    pub behaviours: Vec<String>,
    /// Whether this record was carried over because the latest sweep of the
    /// same exact run saw less than an earlier one did.
    ///
    /// A degraded sweep contributes no change. It only records that Topgent
    /// briefly could not see what it had already confirmed.
    pub degraded: bool,
}

/// The label used when no family could be recognised.
pub const UNCLASSIFIED: &str = "unclassified";

/// Exact identity of one observed agent run.
///
/// A pid on its own is not an identity: the operating system reuses it, and two
/// different runs sharing one number were compared as the same agent, so a
/// reused pid could be reported as a grade change on a process that never
/// existed when the earlier grade was recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SeenKey {
    /// Process id.
    pub pid: u32,
    /// Process start time.
    ///
    /// `None` only for a record written before the baseline carried a start
    /// time. Such a record is matched by pid once and then rewritten exactly.
    pub started_at: Option<UnixMillis>,
}

/// The earlier record for an exact run, if the baseline holds one.
///
/// Falls back to a start-time-free record for the same pid exactly once, so
/// upgrading from an older baseline does not report every running agent as
/// newly started.
fn prior(before: &BTreeMap<SeenKey, Seen>, key: SeenKey) -> Option<(SeenKey, &Seen)> {
    if let Some(found) = before.get(&key) {
        return Some((key, found));
    }
    let legacy = SeenKey::legacy(key.pid);
    before.get(&legacy).map(|found| (legacy, found))
}

/// Carry a confirmed identity across a sweep that saw less.
///
/// Less visibility of the same exact run is not evidence that the run changed.
/// Without this, a sweep that could not read the executable replaced
/// `codex-cli / CRITICAL` with `unclassified / HIGH`, and the next sweep put it
/// back, so an unchanged process alternated identity and grade forever.
#[must_use]
pub fn reconcile(
    before: &BTreeMap<SeenKey, Seen>,
    observed: BTreeMap<SeenKey, Seen>,
) -> BTreeMap<SeenKey, Seen> {
    observed
        .into_iter()
        .map(|(key, now)| {
            let retained = prior(before, key).and_then(|(_, was)| {
                (now.agent == UNCLASSIFIED && was.agent != UNCLASSIFIED).then(|| Seen {
                    degraded: true,
                    ..was.clone()
                })
            });
            (key, retained.unwrap_or(now))
        })
        .collect()
}

/// Build the comparable shape of the current sweep.
#[must_use]
pub fn snapshot(scored: &[(Agent, Risk)]) -> BTreeMap<SeenKey, Seen> {
    scored
        .iter()
        .map(|(a, r)| {
            (
                SeenKey::exact(a.id.pid, a.id.started_at),
                Seen {
                    degraded: false,
                    agent: a.family.clone().unwrap_or_else(|| UNCLASSIFIED.to_owned()),
                    grade: r.grade.label().to_owned(),
                    credentials: a
                        .latent_secrets()
                        .into_iter()
                        .map(|s| s.path.clone())
                        .collect(),
                    breaches: a.drift().into_iter().map(|d| d.path.clone()).collect(),
                    scanning: r
                        .factors
                        .iter()
                        .any(|f| f.code == topgent_core::FactorCode::ReconFanout),
                    model: a.model.as_ref().map(|(p, m)| format!("{p}/{m}")),
                    behaviours: r
                        .factors
                        .iter()
                        .filter_map(|f| match f.code {
                            topgent_core::FactorCode::ExposedListener
                            | topgent_core::FactorCode::OffensiveTool
                            | topgent_core::FactorCode::ProcessExplosion
                            | topgent_core::FactorCode::SuspiciousEndpoint
                            | topgent_core::FactorCode::PrivatePeer
                            | topgent_core::FactorCode::MetadataService
                            | topgent_core::FactorCode::CredentialAccess
                            | topgent_core::FactorCode::PersistenceWrite
                            | topgent_core::FactorCode::SelfTampering => {
                                Some(f.code.as_str().to_owned())
                            }
                            _ => None,
                        })
                        .collect(),
                },
            )
        })
        .collect()
}

/// Everything that changed between two sweeps.
///
/// Pure: the same pair of snapshots always yields the same entries, which is
/// what lets the diff be tested without a filesystem.
#[must_use]
pub fn diff(
    before: &BTreeMap<SeenKey, Seen>,
    after: &BTreeMap<SeenKey, Seen>,
    at: u64,
) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut matched: BTreeSet<SeenKey> = BTreeSet::new();

    for (key, now) in after {
        let Some((prior_key, was)) = prior(before, *key) else {
            out.push(Entry::about(
                at,
                Kind::Started,
                *key,
                &now.agent,
                format!("started, graded {}", now.grade),
            ));
            continue;
        };
        matched.insert(prior_key);

        // A retained record is the earlier observation, unchanged. The sweep
        // that produced it saw less, and seeing less is not an event.
        if now.degraded {
            continue;
        }

        if was.grade != now.grade {
            let mut entry = Entry::about(
                at,
                Kind::GradeChanged,
                *key,
                &now.agent,
                format!("{} to {}", was.grade, now.grade),
            );
            entry.direction = GradeMove::between(&was.grade, &now.grade);
            out.push(entry);
        }
        for path in &now.credentials {
            if !was.credentials.contains(path) {
                out.push(Entry::about(
                    at,
                    Kind::CredentialExposed,
                    *key,
                    &now.agent,
                    format!("{path} came into reach"),
                ));
            }
        }
        for path in &now.breaches {
            if !was.breaches.contains(path) {
                out.push(Entry::about(
                    at,
                    Kind::PolicyBreach,
                    *key,
                    &now.agent,
                    format!("{path} touched but not granted"),
                ));
            }
        }
        // The rising edge only: alert once when scanning begins, not on
        // every sweep while it continues.
        if now.scanning && !was.scanning {
            out.push(Entry::about(
                at,
                Kind::Recon,
                *key,
                &now.agent,
                "connection pattern started to look like scanning".to_owned(),
            ));
        }
        if was.model != now.model && was.model.is_some() && now.model.is_some() {
            out.push(Entry::about(
                at,
                Kind::ModelDrift,
                *key,
                &now.agent,
                format!(
                    "model changed from {} to {}",
                    was.model.as_deref().unwrap_or("unknown"),
                    now.model.as_deref().unwrap_or("unknown")
                ),
            ));
        }
        for behaviour in &now.behaviours {
            if !was.behaviours.contains(behaviour) {
                out.push(Entry::about(
                    at,
                    Kind::Behaviour,
                    *key,
                    &now.agent,
                    format!("{behaviour} detected from metadata"),
                ));
            }
        }
    }

    for (key, was) in before {
        if !matched.contains(key) {
            out.push(Entry::about(
                at,
                Kind::Stopped,
                *key,
                &was.agent,
                "no longer running".to_owned(),
            ));
        }
    }

    out.sort_by_key(|e| (e.kind, e.pid));
    out
}

impl SweepLock {
    /// Take the lock, reclaiming one abandoned more than
    /// [`SWEEP_LOCK_STALE_MS`] ago.
    ///
    /// `None` means another surface holds it right now.
    pub(crate) fn acquire(path: &Path, at: u64) -> Option<Self> {
        if Self::claim(path, at) {
            return Some(Self {
                path: path.to_path_buf(),
            });
        }
        let held_at = std::fs::read_to_string(path)
            .ok()
            .and_then(|text| text.trim().parse::<u64>().ok());
        // An unreadable or unparsable holder is abandoned: it cannot be shown
        // to be live, and refusing forever would silence the journal.
        let stale = held_at.is_none_or(|held| at.saturating_sub(held) >= SWEEP_LOCK_STALE_MS);
        if !stale {
            return None;
        }
        std::fs::remove_file(path).ok()?;
        Self::claim(path, at).then(|| Self {
            path: path.to_path_buf(),
        })
    }

    pub(crate) fn claim(path: &Path, at: u64) -> bool {
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .is_ok_and(|mut file| write!(file, "{at}").is_ok())
    }
}

impl SeenKey {
    /// An exact identity.
    #[must_use]
    pub const fn exact(pid: u32, started_at: UnixMillis) -> Self {
        Self {
            pid,
            started_at: Some(started_at),
        }
    }

    /// A record from a baseline written before start times were kept.
    #[must_use]
    pub const fn legacy(pid: u32) -> Self {
        Self {
            pid,
            started_at: None,
        }
    }

    pub(crate) fn encode(self) -> String {
        self.started_at.map_or_else(
            || self.pid.to_string(),
            |at| format!("{}@{}", self.pid, at.0),
        )
    }

    pub(crate) fn decode(text: &str) -> Option<Self> {
        match text.split_once('@') {
            Some((pid, started_at)) => Some(Self::exact(
                pid.parse().ok()?,
                UnixMillis(started_at.parse().ok()?),
            )),
            None => Some(Self::legacy(text.parse().ok()?)),
        }
    }
}

impl Drop for SweepLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{SWEEP_LOCK_STALE_MS, Seen, SeenKey, SweepLock, UNCLASSIFIED, diff, reconcile};
    use crate::event_log::{GradeMove, Kind};
    use crate::journal::Journal;
    use crate::test_support::test_dir;
    use std::collections::BTreeMap;
    use topgent_facts::UnixMillis;

    fn key(pid: u32) -> SeenKey {
        SeenKey::exact(pid, UnixMillis(u64::from(pid) * 1_000))
    }

    fn seen(model: Option<&str>, behaviours: &[&str]) -> Seen {
        Seen {
            degraded: false,
            agent: "codex".to_owned(),
            grade: "MEDIUM".to_owned(),
            credentials: Vec::new(),
            breaches: Vec::new(),
            scanning: false,
            model: model.map(ToOwned::to_owned),
            behaviours: behaviours.iter().map(ToString::to_string).collect(),
        }
    }

    fn identified(agent: &str, grade: &str) -> Seen {
        Seen {
            degraded: false,
            agent: agent.to_owned(),
            grade: grade.to_owned(),
            credentials: Vec::new(),
            breaches: Vec::new(),
            scanning: false,
            model: None,
            behaviours: Vec::new(),
        }
    }

    #[test]
    fn a_reused_pid_is_a_different_run_not_a_grade_change() {
        // The operating system hands the same number to an unrelated process.
        // Compared on the pid alone, a fresh Critical agent inheriting the
        // number of an exited Low one was reported as an escalation of a
        // process that no longer existed.
        let before = BTreeMap::from([(
            SeenKey::exact(42, UnixMillis(1_000)),
            identified("opencode", "LOW"),
        )]);
        let after = BTreeMap::from([(
            SeenKey::exact(42, UnixMillis(9_000)),
            identified("aider", "CRITICAL"),
        )]);
        let events = diff(&before, &after, 5);

        assert!(!events.iter().any(|event| event.kind == Kind::GradeChanged));
        assert!(events.iter().any(|event| event.kind == Kind::Stopped
            && event.agent == "opencode"
            && event.started_at == Some(UnixMillis(1_000))));
        assert!(events.iter().any(|event| event.kind == Kind::Started
            && event.agent == "aider"
            && event.started_at == Some(UnixMillis(9_000))));
    }

    #[test]
    fn a_baseline_without_start_times_upgrades_without_restarting_everything() {
        // Records written before identity carried a start time match by pid
        // exactly once, so upgrading does not announce every running agent as
        // new, and the next save rewrites them exactly.
        let before = BTreeMap::from([(SeenKey::legacy(42), identified("codex-cli", "HIGH"))]);
        let after = BTreeMap::from([(
            SeenKey::exact(42, UnixMillis(9_000)),
            identified("codex-cli", "CRITICAL"),
        )]);
        let events = diff(&before, &after, 5);

        assert!(!events.iter().any(|event| event.kind == Kind::Started));
        assert!(!events.iter().any(|event| event.kind == Kind::Stopped));
        let change = events
            .iter()
            .find(|event| event.kind == Kind::GradeChanged)
            .expect("the grade still moved");
        assert_eq!(change.direction, Some(GradeMove::Escalated));
        assert_eq!(change.started_at, Some(UnixMillis(9_000)));
    }

    #[test]
    fn a_sweep_that_sees_less_does_not_erase_a_confirmed_identity() {
        // The PID 18246 signature. One sweep resolves the executable, the next
        // does not. Losing visibility of the same exact run is not a change,
        // and must not be reported as one in either direction.
        let key = SeenKey::exact(18_246, UnixMillis(1_000));
        let before = BTreeMap::from([(key, identified("codex-cli", "CRITICAL"))]);
        let observed = BTreeMap::from([(key, identified(UNCLASSIFIED, "HIGH"))]);

        let after = reconcile(&before, observed);
        let retained = after.get(&key).expect("the run is still present");
        assert_eq!(retained.agent, "codex-cli");
        assert_eq!(retained.grade, "CRITICAL");
        assert!(retained.degraded);
        assert!(diff(&before, &after, 5).is_empty());
    }

    #[test]
    fn recovering_visibility_takes_the_new_observation_without_an_alarm() {
        let key = SeenKey::exact(18_246, UnixMillis(1_000));
        let degraded = BTreeMap::from([(
            key,
            Seen {
                degraded: true,
                ..identified("codex-cli", "CRITICAL")
            },
        )]);
        let observed = BTreeMap::from([(key, identified("codex-cli", "CRITICAL"))]);

        let after = reconcile(&degraded, observed);
        let recovered = after.get(&key).expect("the run is still present");
        assert!(!recovered.degraded);
        assert_eq!(recovered.agent, "codex-cli");
        assert!(diff(&degraded, &after, 5).is_empty());
    }

    #[test]
    fn an_unclassified_run_that_was_never_identified_is_left_alone() {
        // Retention carries a confirmed identity forward. It must not invent
        // one for a process that has never been recognised.
        let key = SeenKey::exact(7, UnixMillis(1_000));
        let before = BTreeMap::from([(key, identified(UNCLASSIFIED, "LOW"))]);
        let observed = BTreeMap::from([(key, identified(UNCLASSIFIED, "HIGH"))]);

        let after = reconcile(&before, observed);
        let now = after.get(&key).expect("the run is still present");
        assert_eq!(now.agent, UNCLASSIFIED);
        assert!(!now.degraded);
        assert_eq!(
            diff(&before, &after, 5)
                .iter()
                .find(|event| event.kind == Kind::GradeChanged)
                .and_then(|event| event.direction),
            Some(GradeMove::Escalated)
        );
    }

    #[test]
    fn grade_direction_is_decided_from_bands_not_from_the_detail_string() {
        assert_eq!(
            GradeMove::between("HIGH", "CRITICAL"),
            Some(GradeMove::Escalated)
        );
        // The downgrade the UI read as an escalation because the sentence it
        // was given contained the word CRITICAL.
        assert_eq!(
            GradeMove::between("CRITICAL", "HIGH"),
            Some(GradeMove::Downgraded)
        );
        assert_eq!(GradeMove::between("LOW", "LOW"), None);
        assert_eq!(GradeMove::between("CRITICAL", "not a grade"), None);
        assert_eq!(GradeMove::between("", "CRITICAL"), None);

        let downgrade = BTreeMap::from([(
            SeenKey::exact(1, UnixMillis(1)),
            identified("codex-cli", "HIGH"),
        )]);
        let critical = BTreeMap::from([(
            SeenKey::exact(1, UnixMillis(1)),
            identified("codex-cli", "CRITICAL"),
        )]);
        let event = diff(&critical, &downgrade, 5)
            .into_iter()
            .find(|event| event.kind == Kind::GradeChanged)
            .expect("the grade moved");
        assert_eq!(event.direction, Some(GradeMove::Downgraded));
        assert_eq!(event.detail, "CRITICAL to HIGH");
    }

    #[test]
    fn the_saved_baseline_round_trips_exact_identity_and_degradation() {
        let dir = test_dir("sweep");
        let journal = Journal::at(&dir);
        let exact = SeenKey::exact(18_246, UnixMillis(1_000));
        let saved = BTreeMap::from([
            (
                exact,
                Seen {
                    degraded: true,
                    ..identified("codex-cli", "CRITICAL")
                },
            ),
            (
                SeenKey::exact(7, UnixMillis(2_000)),
                identified("aider", "LOW"),
            ),
        ]);
        journal.save_sweep(&saved).expect("the baseline saves");

        let read = journal.last_sweep().expect("the baseline reads back");
        assert_eq!(read, saved);
        assert!(read.get(&exact).is_some_and(|seen| seen.degraded));
        assert!(!read.contains_key(&SeenKey::legacy(18_246)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_one_surface_at_a_time_advances_the_sweep_baseline() {
        // The desktop app, the CLI and the development viewer sweep the same
        // host into the same journal. A second surface sweeping concurrently
        // must not re-report changes the first has already recorded.
        let dir = test_dir("sweep-lock");
        let _ = std::fs::remove_dir_all(&dir);
        let journal = Journal::at(&dir);
        std::fs::create_dir_all(&dir).expect("the journal directory is created");
        let lock_path = dir.join("sweep.lock");

        let held = SweepLock::acquire(&lock_path, 1_000).expect("the first surface takes the lock");
        assert!(SweepLock::acquire(&lock_path, 1_000).is_none());
        let (entries, applied) = journal
            .advance_sweep(&[], 1_000)
            .expect("a blocked sweep is not an error");
        assert!(!applied, "the second surface must not advance the baseline");
        assert!(entries.is_empty());
        assert!(!dir.join("last-sweep.json").exists());

        drop(held);
        let (_, applied) = journal
            .advance_sweep(&[], 1_000)
            .expect("the lock is free again");
        assert!(applied);
        assert!(!lock_path.exists(), "the lock is released after the sweep");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_abandoned_sweep_lock_is_reclaimed_and_never_silences_the_journal() {
        // A surface killed mid-sweep leaves the file behind. Refusing forever
        // would mean a security log that quietly stops recording.
        let dir = test_dir("sweep-stale");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the journal directory is created");
        let lock_path = dir.join("sweep.lock");

        let abandoned = SweepLock::acquire(&lock_path, 1_000).expect("the lock is taken");
        std::mem::forget(abandoned);
        assert!(SweepLock::acquire(&lock_path, 1_000 + SWEEP_LOCK_STALE_MS - 1).is_none());
        let reclaimed = SweepLock::acquire(&lock_path, 1_000 + SWEEP_LOCK_STALE_MS)
            .expect("an abandoned lock is reclaimed at the boundary");
        drop(reclaimed);

        // A holder whose timestamp cannot be read cannot be shown to be live.
        std::fs::write(&lock_path, "not a timestamp").expect("the lock file is written");
        let reclaimed =
            SweepLock::acquire(&lock_path, 1_000).expect("an unreadable holder is abandoned");
        drop(reclaimed);
        assert!(!lock_path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reports_model_drift_only_between_two_known_models() {
        let before = BTreeMap::from([(key(42), seen(Some("openai/gpt-5"), &[]))]);
        let after = BTreeMap::from([(key(42), seen(Some("openai/gpt-6"), &[]))]);
        let events = diff(&before, &after, 7);
        assert!(events.iter().any(|event| {
            event.kind == Kind::ModelDrift
                && event.detail == "model changed from openai/gpt-5 to openai/gpt-6"
        }));

        let unknown = BTreeMap::from([(key(42), seen(None, &[]))]);
        assert!(
            !diff(&unknown, &after, 7)
                .iter()
                .any(|event| event.kind == Kind::ModelDrift)
        );
    }

    #[test]
    fn reports_behaviour_on_the_rising_edge_only() {
        let before = BTreeMap::from([(key(42), seen(None, &["PRIVATE_PEER"]))]);
        let after = BTreeMap::from([(key(42), seen(None, &["PRIVATE_PEER", "OFFENSIVE_TOOL"]))]);
        let events = diff(&before, &after, 9);

        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == Kind::Behaviour)
                .count(),
            1
        );
        assert!(events.iter().any(|event| {
            event.kind == Kind::Behaviour && event.detail == "OFFENSIVE_TOOL detected from metadata"
        }));
        assert!(
            !diff(&after, &after, 10)
                .iter()
                .any(|event| event.kind == Kind::Behaviour)
        );
    }
}
