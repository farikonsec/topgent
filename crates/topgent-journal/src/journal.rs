//! The journal itself: where every record is read and written.
//!
//! One directory holds them all, and each kind of record is its own file so a
//! corrupt or hand-edited one cannot take the others with it. Every write is
//! atomic — a temporary file named for this process, then a rename — because a
//! half-written security record is worse than a missing one. A file that cannot
//! be parsed reads as empty history rather than as a failure, and a malformed
//! member is skipped without discarding its neighbours.

use crate::MAX_BYTES;
use crate::activity_history::{activity_from_json, activity_json};
use crate::approval::{
    ApprovalRecord, ApprovalRecordState, MAX_APPROVAL_RECORDS, approval_id,
    approval_record_from_json, approval_record_json,
};
use crate::attestation::{MAX_TOOL_ATTESTATIONS, ToolAttestationRecord};
use crate::cooldown::{
    MAX_RESPONSE_COOLDOWNS, ResponseCooldown, response_cooldown_from_json, response_cooldown_json,
};
use crate::event_log::{Entry, Kind};
use crate::network::{network_record_from_json, network_record_json};
use crate::semantic::{MAX_SEMANTIC_RECORDS, SemanticRecord};
use crate::sensor_health::{
    MAX_SENSOR_HEALTH_RECORDS, SensorHealthRecord, sensor_health_from_json, sensor_health_json,
};
use crate::sweep::{Seen, SeenKey, SweepLock, diff, reconcile, snapshot};
use crate::text::bounded_metadata;
use crate::transition::{
    MAX_RESPONSE_TRANSITIONS, ResponseTransition, response_transition_from_json,
    response_transition_json,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions, create_dir_all};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use topgent_core::{Activity, Agent, NetworkRecord, Risk};

/// Where everything Topgent keeps between runs lives.
///
/// `$XDG_STATE_HOME/topgent`, or the home directory's `.local/state/topgent`,
/// or the system temp directory if there is no home to speak of.
///
/// The home directory is not read from `HOME` alone. Windows does not set it
/// outside a shell that supplies it, so a desktop launch fell back to the temp
/// directory and lost the journal between runs. The same defect once made
/// credential reachability report nothing on Windows.
#[must_use]
pub fn state_dir() -> PathBuf {
    if let Some(explicit) = std::env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(explicit).join("topgent");
    }
    home_directory()
        .map_or_else(std::env::temp_dir, |home| home.join(".local/state"))
        .join("topgent")
}

fn home_directory() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("HOME") {
        return Some(PathBuf::from(home));
    }
    if cfg!(windows) {
        if let Some(profile) = std::env::var_os("USERPROFILE") {
            return Some(PathBuf::from(profile));
        }
        if let (Some(drive), Some(path)) =
            (std::env::var_os("HOMEDRIVE"), std::env::var_os("HOMEPATH"))
        {
            let mut joined = PathBuf::from(drive);
            joined.push(PathBuf::from(path));
            return Some(joined);
        }
    }
    None
}

/// Where the log and the last snapshot live.
#[derive(Debug, Clone)]
pub struct Journal {
    dir: PathBuf,
}

/// Exclusive right to rewrite one journal record file, released on drop.
///
/// Deliberately not [`SweepLock`], whose staleness test reads the timestamp the
/// holder wrote *into* the file. Between a holder's `create_new` and its write
/// the file is empty, and an empty file reads as abandoned — so under real
/// contention a second writer reclaimed a live lock and both proceeded. That is
/// tolerable once per sweep and not tolerable once per record.
///
/// Abandonment is judged by the filesystem's own timestamp instead, which
/// exists from the moment the file does.
struct RecordLock {
    path: PathBuf,
}

/// How long a record lock may sit untouched before it is treated as abandoned.
///
/// Deliberately not [`crate::SWEEP_LOCK_STALE_MS`]. A sweep is long, so thirty
/// seconds is a reasonable guess at "that process is gone". A record write is a
/// read, a serialise, and an atomic replace: milliseconds. Borrowing the sweep
/// figure meant a writer killed mid-record silenced every other writer for
/// thirty seconds, and they gave up inside the first two.
const RECORD_LOCK_STALE_MS: u64 = 2_000;

/// How long a writer waits for the lock before reporting that it could not get in.
///
/// Longer than [`RECORD_LOCK_STALE_MS`] on purpose. A waiter blocked by a dead
/// holder must still be waiting when the lock becomes reclaimable, or it gives
/// up on a lock nobody holds. Under live contention this is the drain time, and
/// bounded because a hang in a monitor is an outage.
const RECORD_LOCK_WAIT_MS: u64 = 5_000;

impl RecordLock {
    fn acquire(path: &Path) -> Option<Self> {
        match OpenOptions::new().create_new(true).write(true).open(path) {
            Ok(_) => Some(Self {
                path: path.to_path_buf(),
            }),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let abandoned = std::fs::metadata(path)
                    .and_then(|metadata| metadata.modified())
                    .ok()
                    .and_then(|modified| modified.elapsed().ok())
                    .is_some_and(|age| age.as_millis() >= u128::from(RECORD_LOCK_STALE_MS));
                if abandoned {
                    let _ = std::fs::remove_file(path);
                }
                None
            }
            Err(_) => None,
        }
    }
}

impl Drop for RecordLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// How long to sleep before trying the lock again.
///
/// The jitter is the point, not the backoff. Without it every contender sleeps
/// the same interval, wakes together, and races again: eight writers convoy,
/// and the unlucky one can lose every race until its budget runs out. That is
/// what failed on the Windows runner, where each critical section is slow
/// enough for the convoy to persist. Spreading the wake-ups breaks it.
///
/// The jitter source is the clock rather than a random number generator, so
/// this stays a dependency-free crate.
fn backoff(attempt: u32) -> std::time::Duration {
    let base = u64::from(attempt.min(8)).saturating_add(1);
    let jitter = u64::from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.subsec_nanos()),
    ) % base.saturating_mul(2).max(1);
    std::time::Duration::from_millis(base.saturating_add(jitter))
}

impl Journal {
    /// Open the journal at the default location.
    #[must_use]
    pub fn open_default() -> Self {
        Self::at(&state_dir())
    }

    /// Open the journal in a specific directory.
    #[must_use]
    pub fn at(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }

    /// The log file.
    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.dir.join("events.jsonl")
    }

    pub(crate) fn state_path(&self) -> PathBuf {
        self.dir.join("last-sweep.json")
    }

    pub(crate) fn network_path(&self) -> PathBuf {
        self.dir.join("network-history.json")
    }

    pub(crate) fn semantic_path(&self) -> PathBuf {
        self.dir.join("semantic-context.json")
    }

    pub(crate) fn activity_path(&self) -> PathBuf {
        self.dir.join("activity-history.json")
    }

    pub(crate) fn approval_path(&self) -> PathBuf {
        self.dir.join("approvals.json")
    }

    pub(crate) fn response_cooldown_path(&self) -> PathBuf {
        self.dir.join("response-cooldowns.json")
    }

    pub(crate) fn sensor_health_path(&self) -> PathBuf {
        self.dir.join("sensor-health.json")
    }

    pub(crate) fn tool_attestation_path(&self) -> PathBuf {
        self.dir.join("tool-attestations.json")
    }

    /// Persist one sensor-binary attestation and report whether it moved.
    ///
    /// Returns the record, whose `previous_state` and `changed_at` are set only
    /// when this sweep saw something different from the last one.
    ///
    /// # Errors
    ///
    /// Returns read or atomic persistence failures.
    pub fn record_tool_attestation(
        &self,
        name: &str,
        state: &str,
        path: Option<&str>,
        observed_at: u64,
    ) -> std::io::Result<ToolAttestationRecord> {
        self.with_record_lock("tool-attestations", || {
            let name = bounded_metadata(name, 64);
            let state = bounded_metadata(state, 32);
            let path = path.map(|value| bounded_metadata(value, 512));
            let mut records = self.tool_attestations()?;
            let record = if let Some(record) = records.iter_mut().find(|record| record.name == name)
            {
                if record.state != state || record.path != path {
                    record.previous_state = Some(record.state.clone());
                    record.changed_at = Some(observed_at);
                }
                record.state.clone_from(&state);
                record.path.clone_from(&path);
                record.last_seen_at = observed_at;
                record.clone()
            } else {
                let record = ToolAttestationRecord {
                    name,
                    state,
                    path,
                    first_seen_at: observed_at,
                    last_seen_at: observed_at,
                    previous_state: None,
                    changed_at: None,
                };
                records.push(record.clone());
                record
            };
            records.sort_by(|left, right| left.name.cmp(&right.name));
            if records.len() > MAX_TOOL_ATTESTATIONS {
                records.drain(..records.len() - MAX_TOOL_ATTESTATIONS);
            }
            let value = Value::Array(
                records
                    .iter()
                    .map(|record| {
                        json!({
                            "name": record.name,
                            "state": record.state,
                            "path": record.path,
                            "first_seen_at": record.first_seen_at,
                            "last_seen_at": record.last_seen_at,
                            "previous_state": record.previous_state,
                            "changed_at": record.changed_at,
                        })
                    })
                    .collect::<Vec<_>>(),
            );
            self.replace_atomically(&self.tool_attestation_path(), &value)?;
            Ok(record)
        })
    }

    /// Every retained sensor-binary attestation.
    ///
    /// # Errors
    ///
    /// Returns read failures. A missing file is an empty history.
    pub fn tool_attestations(&self) -> std::io::Result<Vec<ToolAttestationRecord>> {
        let Ok(text) = std::fs::read_to_string(self.tool_attestation_path()) else {
            return Ok(Vec::new());
        };
        let Ok(Value::Array(values)) = serde_json::from_str::<Value>(&text) else {
            return Ok(Vec::new());
        };
        Ok(values
            .iter()
            .filter_map(|value| {
                Some(ToolAttestationRecord {
                    name: value.get("name")?.as_str()?.to_owned(),
                    state: value.get("state")?.as_str()?.to_owned(),
                    path: value
                        .get("path")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                    first_seen_at: value.get("first_seen_at")?.as_u64()?,
                    last_seen_at: value.get("last_seen_at")?.as_u64()?,
                    previous_state: value
                        .get("previous_state")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                    changed_at: value.get("changed_at").and_then(Value::as_u64),
                })
            })
            .collect())
    }

    pub(crate) fn response_transition_path(&self) -> PathBuf {
        self.dir.join("response-transitions.json")
    }

    /// Persist one response decision and classify its state transition.
    ///
    /// Returns `triggered`, `suppressed`, `recovered`, or `inactive`. Repeated
    /// active scans are suppressed across process restarts.
    ///
    /// # Errors
    ///
    /// Returns read or atomic persistence failures.
    pub fn record_response_transition(
        &self,
        key: &str,
        active: bool,
        now: u64,
    ) -> std::io::Result<(&'static str, ResponseTransition)> {
        self.with_record_lock("response-transitions", || {
            let key = bounded_metadata(key, 512);
            let mut records = self.response_transitions()?;
            let (label, record) =
                if let Some(record) = records.iter_mut().find(|item| item.key == key) {
                    let label = match (record.active, active) {
                        (false, true) => "triggered",
                        (true, true) => "suppressed",
                        (true, false) => "recovered",
                        (false, false) => "inactive",
                    };
                    if record.active != active {
                        record.last_changed_at = now;
                    }
                    if !record.active && active {
                        record.trigger_count = record.trigger_count.saturating_add(1);
                    }
                    record.active = active;
                    record.last_seen_at = now;
                    (label, record.clone())
                } else {
                    let record = ResponseTransition {
                        key,
                        active,
                        last_seen_at: now,
                        last_changed_at: now,
                        trigger_count: u64::from(active),
                    };
                    let label = if active { "triggered" } else { "inactive" };
                    records.push(record.clone());
                    (label, record)
                };
            records.sort_by_key(|item| item.last_seen_at);
            if records.len() > MAX_RESPONSE_TRANSITIONS {
                records.drain(..records.len() - MAX_RESPONSE_TRANSITIONS);
            }
            self.save_response_transitions(&records)?;
            Ok((label, record))
        })
    }

    /// Run a read-modify-write against one journal file under an exclusive lock.
    ///
    /// An atomic replace stops a reader seeing half a file. It does not stop two
    /// writers each reading the whole record set, each adding their own entry,
    /// and the second overwriting the first — which loses records silently,
    /// with no error anywhere. Eight threads writing eight keys left two.
    ///
    /// The lock is an exclusive create, reclaimed after
    /// [`crate::SWEEP_LOCK_STALE_MS`] so a surface killed mid-write cannot
    /// silence the journal forever. It holds across processes as well as
    /// threads, which matters because the desktop application and the command
    /// line write the same files.
    fn with_record_lock<T>(
        &self,
        name: &str,
        work: impl FnOnce() -> std::io::Result<T>,
    ) -> std::io::Result<T> {
        create_dir_all(&self.dir)?;
        let path = self.dir.join(format!("{name}.lock"));
        // Bounded by wall clock rather than by a retry count. An attempt count
        // is a wait whose length depends on how fast the machine is, which is
        // how this passed everywhere and failed on the slowest Windows runner.
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_millis(RECORD_LOCK_WAIT_MS);
        let mut attempt = 0_u32;
        while std::time::Instant::now() < deadline {
            if let Some(_lock) = RecordLock::acquire(&path) {
                return work();
            }
            std::thread::sleep(backoff(attempt));
            attempt = attempt.saturating_add(1);
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            format!(
                "another writer held the {name} journal lock for {RECORD_LOCK_WAIT_MS}ms"
            ),
        ))
    }

    /// Replace one journal file with `value`, atomically.
    ///
    /// Nine call sites each rolled their own, and every one named the temporary
    /// file `<record>.<pid>.tmp`. Two writers *inside one process* therefore
    /// collided on the same scratch file: both created it, one renamed it away,
    /// and the other's rename failed with the file gone. The visible symptom was
    /// a response decision reported with transition `unknown` and
    /// `transition_persistent: false` — the journal, which is the audit log,
    /// silently failing to record a state change. It also left orphaned `.tmp`
    /// files behind.
    ///
    /// The scratch name now carries the thread and a monotonic counter as well
    /// as the pid, so no two writers can pick the same one, and a failed write
    /// cleans up after itself rather than accumulating.
    fn replace_atomically(&self, target: &Path, value: &Value) -> std::io::Result<()> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static ATTEMPT: AtomicU64 = AtomicU64::new(0);

        create_dir_all(&self.dir)?;
        let name = target.file_name().map_or_else(
            || "journal".to_owned(),
            |name| name.to_string_lossy().into_owned(),
        );
        let scratch = self.dir.join(format!(
            "{name}.{}.{}.tmp",
            std::process::id(),
            ATTEMPT.fetch_add(1, Ordering::Relaxed)
        ));
        let outcome = (|| -> std::io::Result<()> {
            let mut file = File::create(&scratch)?;
            file.write_all(value.to_string().as_bytes())?;
            file.flush()?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&scratch, target)
        })();
        if outcome.is_err() {
            let _ = std::fs::remove_file(&scratch);
        }
        outcome
    }

    pub(crate) fn response_transitions(&self) -> std::io::Result<Vec<ResponseTransition>> {
        let text = match std::fs::read_to_string(self.response_transition_path()) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let Ok(values) = serde_json::from_str::<Vec<Value>>(&text) else {
            return Ok(Vec::new());
        };
        Ok(values
            .iter()
            .filter_map(response_transition_from_json)
            .collect())
    }

    fn save_response_transitions(&self, records: &[ResponseTransition]) -> std::io::Result<()> {
        let values = records
            .iter()
            .map(response_transition_json)
            .collect::<Vec<_>>();
        self.replace_atomically(&self.response_transition_path(), &Value::Array(values))
    }

    /// Read durable sensor-health aggregates.
    ///
    /// Missing or malformed files are empty and malformed members are skipped.
    ///
    /// # Errors
    ///
    /// Returns non-absence read errors.
    pub fn sensor_health_records(&self) -> std::io::Result<Vec<SensorHealthRecord>> {
        let text = match std::fs::read_to_string(self.sensor_health_path()) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let Ok(values) = serde_json::from_str::<Vec<Value>>(&text) else {
            return Ok(Vec::new());
        };
        Ok(values.iter().filter_map(sensor_health_from_json).collect())
    }

    /// Merge one collector sweep into durable health aggregates.
    ///
    /// A failure never erases the last successful timestamp. Dropped-event
    /// counters advance only when a sensor supplies a genuine value.
    ///
    /// # Errors
    ///
    /// Returns read or atomic persistence failures.
    pub fn record_sensor_health(
        &self,
        id: &str,
        state: &str,
        observed_at: u64,
        fact_count: usize,
        dropped_events: Option<u64>,
        detail: Option<&str>,
    ) -> std::io::Result<SensorHealthRecord> {
        self.with_record_lock("sensor-health", || {
            let id = bounded_metadata(id, 96);
            let state = bounded_metadata(state, 32);
            let available = state == "available";
            let mut records = self.sensor_health_records()?;
            let record = if let Some(record) = records.iter_mut().find(|record| record.id == id) {
                record.state.clone_from(&state);
                record.last_observed_at = observed_at;
                record.total_runs = record.total_runs.saturating_add(1);
                record.total_facts = record
                    .total_facts
                    .saturating_add(u64::try_from(fact_count).unwrap_or(u64::MAX));
                record.detail = detail.map(|value| bounded_metadata(value, 512));
                if let Some(dropped) = dropped_events {
                    record.dropped_events = Some(dropped);
                }
                if available {
                    record.last_success_at = Some(observed_at);
                    record.consecutive_failures = 0;
                } else {
                    record.last_error_at = Some(observed_at);
                    record.consecutive_failures = record.consecutive_failures.saturating_add(1);
                }
                record.clone()
            } else {
                let record = SensorHealthRecord {
                    id,
                    state,
                    last_observed_at: observed_at,
                    last_success_at: available.then_some(observed_at),
                    last_error_at: (!available).then_some(observed_at),
                    consecutive_failures: u64::from(!available),
                    total_runs: 1,
                    total_facts: u64::try_from(fact_count).unwrap_or(u64::MAX),
                    dropped_events,
                    detail: detail.map(|value| bounded_metadata(value, 512)),
                };
                records.push(record.clone());
                record
            };
            records.sort_by(|left, right| left.id.cmp(&right.id));
            if records.len() > MAX_SENSOR_HEALTH_RECORDS {
                records.drain(..records.len() - MAX_SENSOR_HEALTH_RECORDS);
            }
            self.save_sensor_health(&records)?;
            Ok(record)
        })
    }

    fn save_sensor_health(&self, records: &[SensorHealthRecord]) -> std::io::Result<()> {
        let values = records.iter().map(sensor_health_json).collect::<Vec<_>>();
        self.replace_atomically(&self.sensor_health_path(), &Value::Array(values))
    }

    /// Record a durable response cooldown for one exact identity and scope.
    ///
    /// Returns `Some(retry_after)` when an unelapsed duplicate exists, or
    /// `None` after atomically persisting a new cooldown. PID reuse
    /// cannot inherit a cooldown because process start time is part of the key.
    /// Malformed persisted members are ignored independently.
    ///
    /// # Errors
    ///
    /// Returns read or atomic persistence failures.
    pub fn acquire_response_cooldown(
        &self,
        pid: u32,
        started_at: u64,
        scope: &str,
        now: u64,
        cooldown_ms: u64,
    ) -> std::io::Result<Option<u64>> {
        let scope = bounded_metadata(scope, 64);
        let mut records = self.response_cooldowns()?;
        if let Some(existing) = records.iter().find(|record| {
            record.pid == pid
                && record.started_at == started_at
                && record.scope == scope
                && now < record.retry_after
        }) {
            return Ok(Some(existing.retry_after));
        }
        records.retain(|record| now < record.retry_after);
        records.push(ResponseCooldown {
            pid,
            started_at,
            scope,
            acquired_at: now,
            retry_after: now.saturating_add(cooldown_ms.max(1)),
        });
        records.sort_by_key(|record| record.acquired_at);
        if records.len() > MAX_RESPONSE_COOLDOWNS {
            records.drain(..records.len() - MAX_RESPONSE_COOLDOWNS);
        }
        self.save_response_cooldowns(&records)?;
        Ok(None)
    }

    pub(crate) fn response_cooldowns(&self) -> std::io::Result<Vec<ResponseCooldown>> {
        let text = match std::fs::read_to_string(self.response_cooldown_path()) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let Ok(values) = serde_json::from_str::<Vec<Value>>(&text) else {
            return Ok(Vec::new());
        };
        Ok(values
            .iter()
            .filter_map(response_cooldown_from_json)
            .collect())
    }

    fn save_response_cooldowns(&self, records: &[ResponseCooldown]) -> std::io::Result<()> {
        let values = records
            .iter()
            .map(response_cooldown_json)
            .collect::<Vec<_>>();
        self.replace_atomically(&self.response_cooldown_path(), &Value::Array(values))
    }

    /// Read approval records, expiring elapsed pending requests fail closed.
    ///
    /// Missing or malformed files are empty. Invalid members are skipped.
    /// When a deadline elapses, the expired state is atomically persisted.
    ///
    /// # Errors
    ///
    /// Returns non-absence read errors or persistence errors while recording
    /// newly expired requests.
    pub fn approval_records(&self, now: u64) -> std::io::Result<Vec<ApprovalRecord>> {
        let text = match std::fs::read_to_string(self.approval_path()) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let Ok(values) = serde_json::from_str::<Vec<Value>>(&text) else {
            return Ok(Vec::new());
        };
        let mut records = values
            .iter()
            .filter_map(approval_record_from_json)
            .collect::<Vec<_>>();
        let mut changed = false;
        for record in &mut records {
            if record.state == ApprovalRecordState::Pending && now >= record.expires_at {
                record.state = ApprovalRecordState::Expired;
                record.resolved_at = Some(record.expires_at);
                changed = true;
            }
        }
        if changed {
            self.save_approval_records(&records)?;
        }
        Ok(records)
    }

    /// Create one pending request, or return its existing unexpired duplicate.
    ///
    /// Identity plus scope produce a stable request ID. Repeated scans therefore
    /// cannot create duplicate prompts. A resolved or expired request is not
    /// silently reset; a later workflow must explicitly create a new scope.
    ///
    /// # Errors
    ///
    /// Returns approval read or atomic persistence failures.
    pub fn request_approval(
        &self,
        pid: u32,
        started_at: u64,
        scope: &str,
        now: u64,
        ttl_ms: u64,
    ) -> std::io::Result<ApprovalRecord> {
        self.with_record_lock("approvals", || {
            let scope = bounded_metadata(scope, 256);
            let id = approval_id(pid, started_at, &scope);
            let mut records = self.approval_records(now)?;
            if let Some(existing) = records.iter().find(|record| record.id == id) {
                return Ok(existing.clone());
            }
            let record = ApprovalRecord {
                id,
                pid,
                started_at,
                scope,
                state: ApprovalRecordState::Pending,
                created_at: now,
                expires_at: now.saturating_add(ttl_ms.max(1)),
                resolved_at: None,
            };
            records.push(record.clone());
            records.sort_by_key(|item| item.created_at);
            if records.len() > MAX_APPROVAL_RECORDS {
                records.drain(..records.len() - MAX_APPROVAL_RECORDS);
            }
            self.save_approval_records(&records)?;
            Ok(record)
        })
    }

    /// Resolve one unexpired request for the same exact process identity.
    ///
    /// Only `Approved` and `Denied` are accepted as human decisions. Replays,
    /// stale identities, unknown IDs, and elapsed requests return `None`
    /// without modifying persistence.
    ///
    /// # Errors
    ///
    /// Returns approval read or atomic persistence failures.
    pub fn resolve_approval(
        &self,
        id: &str,
        pid: u32,
        started_at: u64,
        decision: ApprovalRecordState,
        now: u64,
    ) -> std::io::Result<Option<ApprovalRecord>> {
        self.with_record_lock("approvals", || {
            if !matches!(
                decision,
                ApprovalRecordState::Approved | ApprovalRecordState::Denied
            ) {
                return Ok(None);
            }
            let mut records = self.approval_records(now)?;
            let Some(record) = records.iter_mut().find(|record| {
                record.id == id
                    && record.pid == pid
                    && record.started_at == started_at
                    && record.state == ApprovalRecordState::Pending
                    && now < record.expires_at
            }) else {
                return Ok(None);
            };
            record.state = decision;
            record.resolved_at = Some(now);
            let resolved = record.clone();
            self.save_approval_records(&records)?;
            Ok(Some(resolved))
        })
    }

    fn save_approval_records(&self, records: &[ApprovalRecord]) -> std::io::Result<()> {
        let values = records.iter().map(approval_record_json).collect::<Vec<_>>();
        self.replace_atomically(&self.approval_path(), &Value::Array(values))
    }

    /// Read bounded metadata-only activity history.
    ///
    /// Missing or malformed files are empty history. Malformed members and
    /// relationships with missing event references are discarded.
    ///
    /// # Errors
    ///
    /// Returns non-absence file read errors.
    pub fn activity_history(&self) -> std::io::Result<Activity> {
        let text = match std::fs::read_to_string(self.activity_path()) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Activity::default());
            }
            Err(error) => return Err(error),
        };
        let Ok(value) = serde_json::from_str::<Value>(&text) else {
            return Ok(Activity::default());
        };
        Ok(activity_from_json(&value))
    }

    /// Atomically replace bounded metadata-only activity history.
    ///
    /// # Errors
    ///
    /// Returns directory, write, flush, sync, or atomic rename failures.
    pub fn save_activity_history(&self, activity: &Activity) -> std::io::Result<()> {
        self.replace_atomically(&self.activity_path(), &activity_json(activity))
    }

    /// Read bounded sanitized semantic context. Malformed records are skipped.
    ///
    /// # Errors
    ///
    /// Returns non-absence file read errors.
    pub fn semantic_records(&self) -> std::io::Result<Vec<SemanticRecord>> {
        let text = match std::fs::read_to_string(self.semantic_path()) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let Ok(values) = serde_json::from_str::<Vec<Value>>(&text) else {
            return Ok(Vec::new());
        };
        Ok(values
            .iter()
            .filter_map(SemanticRecord::from_untrusted)
            .collect())
    }

    /// Add one sanitized record with deduplication and bounded retention.
    ///
    /// # Errors
    ///
    /// Returns directory, write, flush, sync, or atomic rename failures.
    pub fn append_semantic(&self, record: SemanticRecord) -> std::io::Result<()> {
        let mut records = self.semantic_records()?;
        records.retain(|existing| {
            !(existing.session_id == record.session_id
                && existing.observed_at == record.observed_at
                && existing.pid == record.pid)
        });
        records.push(record);
        records.sort_by_key(|item| item.observed_at);
        if records.len() > MAX_SEMANTIC_RECORDS {
            records.drain(..records.len() - MAX_SEMANTIC_RECORDS);
        }
        let values = records
            .iter()
            .map(SemanticRecord::to_json)
            .collect::<Vec<_>>();
        self.replace_atomically(&self.semantic_path(), &Value::Array(values))
    }

    /// Delete every locally retained semantic record.
    ///
    /// # Errors
    ///
    /// Returns deletion errors other than an already-absent file.
    pub fn clear_semantic(&self) -> std::io::Result<()> {
        match std::fs::remove_file(self.semantic_path()) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Read bounded metadata-only network history.
    ///
    /// Unknown or malformed records are skipped independently so one damaged
    /// entry cannot make the dashboard lose all usable history.
    ///
    /// # Errors
    ///
    /// A missing or malformed file is treated as empty history. Other read
    /// errors are returned.
    pub fn network_history(&self) -> std::io::Result<Vec<NetworkRecord>> {
        let text = match std::fs::read_to_string(self.network_path()) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let Ok(values) = serde_json::from_str::<Vec<Value>>(&text) else {
            return Ok(Vec::new());
        };
        Ok(values.iter().filter_map(network_record_from_json).collect())
    }

    /// Atomically replace bounded metadata-only network history.
    ///
    /// # Errors
    ///
    /// Returns directory, write, flush, or rename failures.
    pub fn save_network_history(&self, records: &[NetworkRecord]) -> std::io::Result<()> {
        let values = records.iter().map(network_record_json).collect::<Vec<_>>();
        self.replace_atomically(&self.network_path(), &Value::Array(values))
    }

    /// Remove network history for one exact process instance.
    ///
    /// The process start time is part of the selector so a stale request cannot
    /// erase history belonging to a recycled PID. Other agents and older or
    /// newer instances of the same PID are preserved.
    ///
    /// # Errors
    ///
    /// Returns history read, directory, write, flush, sync, or rename failures.
    pub fn reset_network_baseline(&self, pid: u32, started_at: u64) -> std::io::Result<usize> {
        let mut records = self.network_history()?;
        let before = records.len();
        records.retain(|record| record.agent_pid != pid || record.agent_started_at != started_at);
        let removed = before.saturating_sub(records.len());
        if removed > 0 {
            self.save_network_history(&records)?;
        }
        Ok(removed)
    }

    /// Append entries, creating the directory if it is not there yet.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error. A journal that cannot be written is
    /// reported rather than silently dropped: a security log that fails quietly
    /// is worse than none, because it is trusted.
    pub fn append(&self, entries: &[Entry]) -> std::io::Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        create_dir_all(&self.dir)?;
        self.rotate_if_large()?;
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path())?;
        for e in entries {
            writeln!(f, "{}", e.to_json())?;
        }
        f.flush()
    }

    /// The most recent entries, newest first.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error, except that a missing log is an empty
    /// log rather than a failure.
    pub fn tail(&self, limit: usize) -> std::io::Result<Vec<Entry>> {
        let Ok(f) = File::open(self.path()) else {
            return Ok(Vec::new());
        };
        let mut all: Vec<Entry> = BufReader::new(f)
            .lines()
            .map_while(Result::ok)
            .filter_map(|l| serde_json::from_str::<Value>(&l).ok())
            .filter_map(|v| Entry::from_json(&v))
            .collect();
        all.reverse();
        all.truncate(limit);
        Ok(all)
    }

    /// Read the previous sweep's shape.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error. A missing or unreadable state file is
    /// an empty snapshot, which makes the next sweep report everything as new.
    pub fn last_sweep(&self) -> std::io::Result<BTreeMap<SeenKey, Seen>> {
        let Ok(text) = std::fs::read_to_string(self.state_path()) else {
            return Ok(BTreeMap::new());
        };
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            return Ok(BTreeMap::new());
        };
        let Some(map) = v.as_object() else {
            return Ok(BTreeMap::new());
        };
        Ok(map
            .iter()
            .filter_map(|(pid, entry)| {
                let strings = |key: &str| -> Vec<String> {
                    entry
                        .get(key)
                        .and_then(Value::as_array)
                        .map(|a| {
                            a.iter()
                                .filter_map(Value::as_str)
                                .map(ToOwned::to_owned)
                                .collect()
                        })
                        .unwrap_or_default()
                };
                Some((
                    SeenKey::decode(pid)?,
                    Seen {
                        degraded: entry
                            .get("degraded")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                        agent: entry.get("agent")?.as_str()?.to_owned(),
                        grade: entry.get("grade")?.as_str()?.to_owned(),
                        credentials: strings("credentials"),
                        breaches: strings("breaches"),
                        scanning: entry
                            .get("scanning")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                        model: entry
                            .get("model")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        behaviours: strings("behaviours"),
                    },
                ))
            })
            .collect())
    }

    /// Record this sweep's shape for the next one to compare against.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error.
    pub fn save_sweep(&self, snap: &BTreeMap<SeenKey, Seen>) -> std::io::Result<()> {
        create_dir_all(&self.dir)?;
        let obj: serde_json::Map<String, Value> = snap
            .iter()
            .map(|(key, s)| {
                (
                    key.encode(),
                    json!({
                        "agent": s.agent,
                        "grade": s.grade,
                        "credentials": s.credentials,
                        "breaches": s.breaches,
                        "scanning": s.scanning,
                        "model": s.model,
                        "behaviours": s.behaviours,
                        "degraded": s.degraded,
                    }),
                )
            })
            .collect();
        std::fs::write(self.state_path(), Value::Object(obj).to_string())
    }

    pub(crate) fn sweep_lock_path(&self) -> PathBuf {
        self.dir.join("sweep.lock")
    }

    /// Compare this sweep with the last one and journal what moved.
    ///
    /// The desktop app, the CLI and the development viewer all sweep the same
    /// host into the same journal. Without exclusion they read one another's
    /// half-written baseline and each report the other's changes again, so one
    /// unchanged process produced repeated alerts from different surfaces. One
    /// surface at a time advances the timeline; the others render the same host
    /// and journal nothing, which is correct because the change has already
    /// been recorded once.
    ///
    /// Returns the entries written, and whether this call was the one that
    /// advanced the baseline.
    ///
    /// # Errors
    ///
    /// Returns read, append or atomic persistence failures.
    pub fn advance_sweep(
        &self,
        scored: &[(Agent, Risk)],
        at: u64,
    ) -> std::io::Result<(Vec<Entry>, bool)> {
        create_dir_all(&self.dir)?;
        let Some(_lock) = SweepLock::acquire(&self.sweep_lock_path(), at) else {
            return Ok((Vec::new(), false));
        };
        let before = self.last_sweep().unwrap_or_default();
        let after = reconcile(&before, snapshot(scored));
        let entries = diff(&before, &after, at);
        self.append(&entries)?;
        self.save_sweep(&after)?;
        Ok((entries, true))
    }

    /// Record something Topgent did.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error.
    pub fn record_action(
        &self,
        at: u64,
        pid: u32,
        agent: &str,
        detail: &str,
    ) -> std::io::Result<()> {
        self.append(&[Entry {
            at,
            kind: Kind::Action,
            pid,
            started_at: None,
            agent: agent.to_owned(),
            detail: detail.to_owned(),
            direction: None,
        }])
    }

    /// Drop the oldest half once the log passes [`MAX_BYTES`].
    ///
    /// Truncating on a line boundary, so a partial record can never be read back
    /// as a whole one.
    fn rotate_if_large(&self) -> std::io::Result<()> {
        let path = self.path();
        let Ok(meta) = std::fs::metadata(&path) else {
            return Ok(());
        };
        if meta.len() < MAX_BYTES {
            return Ok(());
        }
        let text = std::fs::read_to_string(&path)?;
        let lines: Vec<&str> = text.lines().collect();
        let keep = lines.split_at(lines.len() / 2).1.join("\n");
        std::fs::write(&path, format!("{keep}\n"))
    }
}
