//! Where each run's data went, shown whether or not a rule fired, so a silent
//! verdict can still be checked against the numbers.

use serde_json::{Value, json};
use topgent_collect::observed::tally::DestTotals;

use super::config::Config;
use super::destinations::Destinations;
use super::exfiltration::basis;
use super::{Merged, Run};

/// Where one run sent data, and what it read first: every real destination
/// with its total and largest burst, the files read, the folders read most,
/// anything that looked like a secret, and — for each burst — the files read
/// in the minutes before it. Shown whether or not anything fired, so a person
/// can see where an agent's data goes and what it touched. A burst is compared
/// with the bytes the agent actually read, and only once the read is large
/// enough to mean something; below that the comparison is left out rather than
/// turned into an alarming percentage of a handful of files.
pub(super) fn flow(
    run: &Run,
    merged: &Merged,
    destinations: &mut dyn Destinations,
    cfg: &Config,
) -> Option<Value> {
    let t = &cfg.thresholds;
    let mut dests: Vec<&DestTotals> = merged
        .destinations
        .values()
        .filter(|d| d.port != 0 && d.port != 53 && d.bytes > 0)
        .collect();
    if dests.is_empty() {
        return None;
    }
    dests.sort_by_key(|d| std::cmp::Reverse(d.bytes));
    let root = merged.roots.values().max_by_key(|r| r.files);
    let workspace = root.and_then(|r| destinations.workspace(&r.root));
    // The read is "large" once it crosses the harvest thresholds: only then is
    // a burst worth stating as a share of it.
    let large_read = root
        .is_some_and(|r| r.files >= t.harvest_files || r.history_files >= t.harvest_history_files);
    let (basis, basis_is_read) = root.map_or((None, false), |r| basis(r, workspace));
    let basis = basis.unwrap_or(0);
    let window = topgent_collect::observed::tally::BURST_WINDOW_MS;
    let rows: Vec<Value> = dests
        .into_iter()
        .take(10)
        .map(|d| {
            let name = (!d.host.is_empty())
                .then(|| destinations.name(&d.host))
                .flatten();
            let own = !d.host.is_empty() && destinations.model_service(&d.host);
            let percent =
                (large_read && basis > 0).then(|| d.burst_bytes.saturating_mul(100) / basis);
            // The files read in the window that ended with this burst: not what
            // was sent (the bytes are encrypted), but what the agent had just
            // opened when it sent.
            let before: Vec<&str> = if d.burst_bytes > 0 {
                merged
                    .recent
                    .iter()
                    .filter(|(_, at)| *at <= d.burst_at && *at >= d.burst_at.saturating_sub(window))
                    .rev()
                    .take(12)
                    .map(|(path, _)| path.as_str())
                    .collect()
            } else {
                Vec::new()
            };
            json!({
                "address": d.host,
                "port": d.port,
                "name": name,
                "owner": name.as_deref().and_then(topgent_collect::resolve::owner_of),
                "own_service": own,
                "bytes": d.bytes,
                "burst_bytes": d.burst_bytes,
                // Only once the read is large and sized: a share of a real read.
                "burst_percent_of_workspace": percent,
                // The rule's own verdict, so no interface keeps a copy of the
                // thresholds.
                "over_threshold": percent.is_some_and(|pct| pct >= if own {
                    t.burst_percent_own
                } else {
                    t.burst_percent_other
                }) && d.burst_bytes >= if own {
                    t.burst_floor_bytes.max(t.own_service_floor_bytes)
                } else {
                    t.burst_floor_bytes
                },
                "files_before_burst": before,
            })
        })
        .collect();
    let folders: Vec<Value> = root
        .map(|r| {
            r.top
                .iter()
                .take(8)
                .map(|(dir, files)| json!({"directory": dir, "files": files}))
                .collect()
        })
        .unwrap_or_default();
    // Secrets first, oldest first: the names, never the contents.
    let mut sensitive: Vec<(&String, &(u64, u64, String))> = merged.sensitive.iter().collect();
    sensitive.sort_by_key(|(_, (at, _, _))| *at);
    let sensitive: Vec<&str> = sensitive
        .into_iter()
        .take(20)
        .map(|(p, _)| p.as_str())
        .collect();
    Some(json!({
        "agent": {"pid": run.key.pid, "started_at": run.key.started_at.0, "name": run.name, "family": run.family},
        "workspace": root.map(|r| r.root.clone()),
        "workspace_files": workspace.map(|(files, _)| files),
        "workspace_bytes": workspace.map(|(_, size)| size),
        "files_read": root.map_or(0, |r| r.files),
        "bytes_read": root.map_or(0, |r| r.read_bytes),
        "history_files": root.map_or(0, |r| r.history_files),
        "large_read": large_read,
        "compared_with": if basis_is_read { "bytes read" } else { "workspace size" },
        "folders": folders,
        "sensitive": sensitive,
        "burst_window_minutes": window / 60_000,
        "destinations": rows,
    }))
}
