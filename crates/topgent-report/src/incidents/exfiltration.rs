//! The workspace-exfiltration rule: a run read most of a workspace, then sent
//! about that much somewhere, kept retrying, or added up to it over the run.

use serde_json::{Value, json};
use topgent_collect::observed::tally::{DestTotals, RootTotals};

use super::config::{Config, object_storage};
use super::destinations::Destinations;
use super::format::{bytes, count, duration, plural};
use super::{Merged, Run};
use crate::egress_groups::{Group, group};

/// Data a retrying destination must have received for its retries to count:
/// enough to be an upload, not a heartbeat.
pub(super) const RETRY_UPLOAD_BYTES: u64 = 1024 * 1024;

/// What a burst is compared with, and whether that is the bytes read.
///
/// The bytes the agent read, when the sensor sized (nearly) every file: an
/// agent that writes 60 MB into its workspace has still only read what it
/// read. When many files could not be sized (deleted since, or named by a
/// path from another mount namespace), the sized total is only a floor, and a
/// floor would make an ordinary prompt look like a large share; the larger of
/// it and the workspace as it is now is used instead.
pub(super) fn basis(root: &RootTotals, workspace: Option<(u64, u64)>) -> (Option<u64>, bool) {
    let size = workspace.map(|(_, size)| size);
    let nearly_all_sized =
        u64::from(root.unsized_files).saturating_mul(50) <= u64::from(root.files);
    if root.read_bytes > 0 && nearly_all_sized {
        return (Some(root.read_bytes), true);
    }
    match size {
        Some(size) if size >= root.read_bytes => (Some(size), false),
        _ if root.read_bytes > 0 => (Some(root.read_bytes), true),
        _ => (None, false),
    }
}

/// Evaluates the rule on one run. `None` when it does not hold.
#[allow(clippy::too_many_lines)]
pub(super) fn evaluate(
    run: &Run,
    merged: &Merged,
    tools: &[String],
    destinations: &mut dyn Destinations,
    cfg: &Config,
) -> Option<Value> {
    let t = &cfg.thresholds;
    let harvest = merged
        .roots
        .values()
        .filter(|r| r.files >= t.harvest_files || r.history_files >= t.harvest_history_files)
        .max_by_key(|r| (r.files, r.history_files))?;
    let workspace = destinations.workspace(&harvest.root);
    let (basis, basis_is_read) = basis(harvest, workspace);
    let mut outbound: Vec<(DestTotals, Option<String>)> = Vec::new();
    // The agent's own services: not exempt, held to the burst test instead.
    let mut own: Vec<(DestTotals, Option<String>)> = Vec::new();
    // Other places first reached after the window: only the whole-run test
    // looks at these.
    let mut later: Vec<(DestTotals, Option<String>)> = Vec::new();
    for dest in merged.destinations.values() {
        // Name lookups (port 53) and the port-0 connects a resolver makes to
        // rank addresses carry no workspace. Counting them turned one night of
        // ZCode's DNS into 340 "attempts".
        if dest.port == 0 || dest.port == 53 {
            continue;
        }
        // Only what happened while the harvest was under way or after it.
        if dest.last_at < harvest.first_at {
            continue;
        }
        let in_window = dest.first_at <= harvest.last_at.saturating_add(t.window_ms);
        if !dest.host.is_empty() && destinations.model_service(&dest.host) {
            if in_window {
                own.push((dest.clone(), None));
            }
        } else if in_window {
            outbound.push((dest.clone(), None));
        } else {
            later.push((dest.clone(), None));
        }
    }
    // Names decide owners, so the places that received data are named before
    // grouping. Lookups are cached; the bound keeps a chatty run cheap, and
    // anything past it is grouped by network instead.
    {
        let mut sending: Vec<&mut (DestTotals, Option<String>)> = outbound
            .iter_mut()
            .chain(later.iter_mut())
            .filter(|(d, _)| d.bytes > 0 && !d.host.is_empty())
            .collect();
        sending.sort_by_key(|(d, _)| std::cmp::Reverse(d.bytes));
        for (dest, name) in sending.into_iter().take(32) {
            *name = destinations.name(&dest.host);
        }
    }
    // A burst: about the size of the workspace to one owner within minutes.
    // Judged against the workspace this agent read, so a 3 MB repository and
    // a 300 MB one are held to the same shape, not the same number. The
    // agent's own service also needs `own_service_floor_bytes`.
    let needed = |own: bool| {
        let percent = if own {
            t.burst_percent_own
        } else {
            t.burst_percent_other
        };
        let floor = if own {
            t.burst_floor_bytes.max(t.own_service_floor_bytes)
        } else {
            t.burst_floor_bytes
        };
        basis.map(|size| (size.saturating_mul(percent) / 100).max(floor))
    };
    let burst: Option<Group> = group(&outbound, false)
        .into_iter()
        .chain(group(&own, true))
        .filter(|g| needed(g.own).is_some_and(|need| g.burst_bytes >= need))
        .max_by_key(|g| g.burst_bytes);
    // The whole-run ledger: everything sent to one other owner since the read
    // began, however slowly and however late. Own services are left out: a
    // long session's conversation with its vendor adds up by design.
    let run_need =
        basis.map(|size| (size.saturating_mul(t.run_percent_other) / 100).max(t.run_floor_bytes));
    let whole_run: Vec<(DestTotals, Option<String>)> =
        outbound.iter().chain(later.iter()).cloned().collect();
    let trickle: Option<Group> = group(&whole_run, false)
        .into_iter()
        .filter(|g| run_need.is_some_and(|need| g.bytes >= need))
        .max_by_key(|g| g.bytes);
    let sent: u64 = outbound.iter().map(|(d, _)| d.bytes).sum();
    // Retries are judged per destination, and only when data moved: an
    // upload that keeps retrying sends, a telemetry ping does not. Summing
    // attempts across nineteen hosts made a chatty app look like a retry storm.
    let retrying = outbound
        .iter()
        .any(|(d, _)| d.attempts >= t.egress_attempts && d.bytes >= RETRY_UPLOAD_BYTES);
    if sent < t.egress_bytes && !retrying && burst.is_none() && trickle.is_none() {
        return None;
    }
    // A trickle's later places are part of what the card shows.
    if trickle.is_some() {
        outbound.extend(later);
    }
    let sent_total: u64 = outbound.iter().map(|(d, _)| d.bytes).sum();
    let attempts: u64 = outbound.iter().map(|(d, _)| u64::from(d.attempts)).sum();
    outbound.sort_by(|a, b| {
        b.0.bytes
            .cmp(&a.0.bytes)
            .then_with(|| b.0.attempts.cmp(&a.0.attempts))
    });
    for (dest, name) in outbound.iter_mut().take(8) {
        if !dest.host.is_empty() && name.is_none() {
            *name = destinations.name(&dest.host);
        }
    }
    let failed: u64 = outbound.iter().map(|(d, _)| u64::from(d.failed)).sum();
    let storage = outbound.iter().any(|(_, name)| {
        name.as_deref()
            .is_some_and(|n| object_storage(n, &cfg.object_storage))
    });
    let place = |dest: &DestTotals, name: &Option<String>| -> String {
        if dest.host.is_empty() {
            return "a connection Topgent saw used but not opened".to_owned();
        }
        match name {
            Some(name) => format!("{name} ({}:{})", dest.host, dest.port),
            None => format!("{}:{}", dest.host, dest.port),
        }
    };
    let where_to = match outbound.first() {
        Some((top, top_name)) if outbound.len() > 1 => format!(
            "{} and {} other {}",
            place(top, top_name),
            outbound.len() - 1,
            if outbound.len() == 2 {
                "destination"
            } else {
                "destinations"
            }
        ),
        Some((top, top_name)) => place(top, top_name),
        None => String::new(),
    };
    let total = workspace.map(|(files, _)| files);
    let share = total.filter(|n| *n > 0).map(|n| {
        let pct = (u64::from(harvest.files) * 100 / n).min(100);
        format!(" ({pct}% of the {} files there)", count(n))
    });
    let history = if harvest.history_files > 0 {
        format!(
            ", including {} from its git history",
            count(u64::from(harvest.history_files))
        )
    } else {
        String::new()
    };
    let read = format!(
        "{} read {} from {}{}{}",
        run.name,
        plural(u64::from(harvest.files), "file", "files"),
        harvest.root,
        share.unwrap_or_default(),
        history
    );
    // Where a group went, in words: one address as before, several as their
    // owner with the busiest address named.
    let group_place = |g: &Group, top_name: &Option<String>| -> String {
        match g.members.as_slice() {
            [(only, _)] => place(only, top_name),
            [(top, _), ..] => format!(
                "{} ({} addresses, most to {}:{})",
                g.label,
                g.members.len(),
                top.host,
                top.port
            ),
            [] => g.label.clone(),
        }
    };
    let burst_name = burst.as_ref().and_then(|g| {
        let (top, known) = g.members.first()?;
        known.clone().or_else(|| {
            (!top.host.is_empty())
                .then(|| destinations.name(&top.host))
                .flatten()
        })
    });
    let share_of = |n: u64| {
        n.saturating_mul(100)
            .checked_div(basis.unwrap_or(0))
            .unwrap_or(0)
    };
    let compared = if basis_is_read {
        "it read"
    } else {
        "workspace"
    };
    let tried = if let Some(g) = burst
        .as_ref()
        .filter(|_| sent < t.egress_bytes && !retrying)
    {
        format!(
            "then sent {} to {}{} within {} minutes, about {}% of the {} {}",
            bytes(g.burst_bytes),
            group_place(g, &burst_name),
            if g.own && g.members.len() == 1 {
                ", its own service,"
            } else {
                ""
            },
            topgent_collect::observed::tally::BURST_WINDOW_MS / 60_000,
            share_of(g.burst_bytes),
            bytes(basis.unwrap_or(0)),
            compared
        )
    } else if sent >= t.egress_bytes {
        format!(
            "then sent {} to {} over {}",
            bytes(sent),
            where_to,
            plural(attempts, "connection attempt", "connection attempts")
        )
    } else if let Some(g) = trickle.as_ref().filter(|_| !retrying) {
        let top_name = g.members.first().and_then(|(_, n)| n.clone());
        format!(
            "then sent {} to {} across the run, over {}, about {}% of the {} {}",
            bytes(g.bytes),
            group_place(g, &top_name),
            duration(g.last_at.saturating_sub(g.first_at)),
            share_of(g.bytes),
            bytes(basis.unwrap_or(0)),
            compared
        )
    } else {
        format!(
            "then tried to reach {} {} and sent {}",
            where_to,
            if attempts == 1 {
                "once".to_owned()
            } else {
                format!("{} times", count(attempts))
            },
            bytes(sent)
        )
    };
    let failed_note = if failed > 0 {
        format!(" ({} failed)", count(failed))
    } else {
        String::new()
    };
    let packed = if tools.is_empty() {
        String::new()
    } else {
        ", after packing it with an encryption tool".to_owned()
    };
    let headline = format!("{read}, {tried}{failed_note}{packed}.");

    let mut why = vec![format!(
        "None of these addresses belongs to a model service{} uses.",
        if run.family.is_some() {
            format!(" {}", run.name)
        } else {
            " an agent".to_owned()
        }
    )];
    if storage {
        why.push("The destination is cloud object storage.".to_owned());
    }
    if harvest.history_files >= t.harvest_history_files {
        why.push("Git history holds every past version of the code, including secrets that were later deleted.".to_owned());
    }
    if let Some(tool) = tools.first() {
        why.push(format!("Encryption tool ran during the upload: {tool}."));
    }
    if failed >= u64::from(t.egress_attempts) {
        why.push(format!(
            "Retried after {} failed connections.",
            count(failed)
        ));
    }
    if burst.as_ref().is_some_and(|g| g.own) {
        why.push(
            "Destination is its own model service. Volume matches the full workspace.".to_owned(),
        );
    }
    if let Some(g) = burst.as_ref().filter(|g| g.members.len() > 1 && !g.own) {
        why.push(format!(
            "{} addresses, one owner ({}). Counted together.",
            g.members.len(),
            g.label
        ));
    }
    if let Some(g) = trickle.as_ref().filter(|_| burst.is_none()) {
        why.push(format!(
            "Sent in parts over {}. Totals cover the full run.",
            duration(g.last_at.saturating_sub(g.first_at))
        ));
    }
    if run.family.is_none() {
        why.push(format!(
            "Topgent does not recognise {} as an AI agent. It is reported because of what it did.",
            run.name
        ));
    }

    let burst_elsewhere = burst.as_ref().is_some_and(|g| !g.own) || trickle.is_some();
    let severity = if (sent >= t.egress_bytes || burst_elsewhere)
        && (storage || harvest.history_files >= t.harvest_history_files)
    {
        "critical"
    } else {
        "high"
    };
    let mut actions = vec![json!({
        "label": format!("Stop {}", run.name),
        "command": format!("topgent stop {}", run.key.pid),
    })];
    if let Some(host) = outbound
        .iter()
        .map(|(d, _)| d.host.as_str())
        .find(|h| !h.is_empty())
    {
        actions.push(json!({
            "label": format!("Block {host} at the firewall"),
            "command": if cfg!(target_os = "linux") {
                format!("sudo nft add rule inet filter output ip{} daddr {host} drop",
                    if host.contains(':') { "6" } else { "" })
            } else {
                String::new()
            },
        }));
    }
    actions.push(json!({
        "label": format!("Treat {} as disclosed: rotate the keys and tokens in it", harvest.root),
        "command": "",
    }));
    actions.push(json!({
        "label": format!("Watch {} from now on", harvest.root),
        "command": format!("topgent rule add {} observed critical", harvest.root),
    }));

    let burst_json = burst.as_ref().map(|g| {
        let top = g.members.first().map(|(d, _)| d);
        json!({
            "address": top.map(|d| d.host.clone()),
            "port": top.map(|d| d.port),
            "name": burst_name,
            "owner": g.label,
            "addresses": g.members.len(),
            "own_service": g.own,
            "bytes": g.burst_bytes,
            "window_minutes": topgent_collect::observed::tally::BURST_WINDOW_MS / 60_000,
            "percent_of_workspace": share_of(g.burst_bytes),
            "compared_with": if basis_is_read { "bytes read" } else { "workspace size" },
            "at": g.burst_at,
        })
    });
    let run_json = trickle.as_ref().map(|g| {
        json!({
            "owner": g.label,
            "addresses": g.members.len(),
            "bytes": g.bytes,
            "percent_of_workspace": share_of(g.bytes),
            "compared_with": if basis_is_read { "bytes read" } else { "workspace size" },
            "first_at": g.first_at,
            "last_at": g.last_at,
        })
    });
    let first_at = harvest.first_at.min(
        outbound
            .iter()
            .map(|(d, _)| d.first_at)
            .min()
            .unwrap_or(u64::MAX),
    );
    let last_at = harvest
        .last_at
        .max(outbound.iter().map(|(d, _)| d.last_at).max().unwrap_or(0));

    Some(json!({
        "id": format!("{}:{}", run.key.pid, run.key.started_at.0),
        "rule": cfg.rule,
        "kind": "workspace_exfiltration",
        "name": "Workspace Exfiltration",
        "severity": severity,
        "headline": headline,
        "why": why,
        "actions": actions,
        "agent": {
            "pid": run.key.pid,
            "started_at": run.key.started_at.0,
            "name": run.name,
            "family": run.family,
            "recognised": run.family.is_some(),
        },
        "numbers": {
            "files_read": harvest.files,
            "history_files_read": harvest.history_files,
            "files_in_root": total,
            "workspace_bytes": workspace.map(|(_, size)| size),
            "bytes_read": harvest.read_bytes,
            "bytes_sent": sent_total,
            "connection_attempts": attempts,
            "failed_attempts": failed,
            "destinations": outbound.len(),
            "duration_ms": last_at.saturating_sub(first_at),
            "duration": duration(last_at.saturating_sub(first_at)),
            "encrypted": !tools.is_empty(),
        },
        "evidence": {
            "workspace": {
                "root": harvest.root,
                "files": harvest.files,
                "history_files": harvest.history_files,
                "uncounted": harvest.uncounted,
                "top_directories": harvest.top.iter().map(|(d, n)| json!({"directory": d, "files": n})).collect::<Vec<_>>(),
                "first_at": harvest.first_at,
                "last_at": harvest.last_at,
            },
            "other_roots": merged.roots.values()
                .filter(|r| r.root != harvest.root && r.files >= 20)
                .take(5)
                .map(|r| json!({"root": r.root, "files": r.files, "history_files": r.history_files}))
                .collect::<Vec<_>>(),
            "destinations": outbound.iter().take(20).map(|(d, name)| json!({
                "address": d.host,
                "port": d.port,
                "name": name,
                "owner": name.as_deref().and_then(topgent_collect::resolve::owner_of),
                "object_storage": name.as_deref().is_some_and(|n| object_storage(n, &cfg.object_storage)),
                "attempts": d.attempts,
                "connected": d.connected,
                "in_progress": d.in_progress,
                "failed": d.failed,
                "bytes": d.bytes,
                "burst_bytes": d.burst_bytes,
                "first_at": d.first_at,
                "last_at": d.last_at,
            })).collect::<Vec<_>>(),
            "burst": burst_json,
            "whole_run": run_json,
            "processes": merged.actors.iter().collect::<Vec<_>>(),
            "encryption_tools": tools,
        },
        "first_at": first_at,
        "last_at": last_at,
        "limits": [
            "Topgent counts files opened for reading and bytes written to the network. It reads neither, so it cannot show that the bytes sent were these files.",
            "Bytes are counted on internet sockets opened while Topgent was running. Data sent by sendfile or splice is not counted, so the real amount can be higher.",
            "Encryption is reported only when a separate tool was run. A program that encrypts inside its own process would upload ciphertext all the same, and Topgent would not see that step.",
            format!("An upload to the agent's own model service is reported only from {} in one burst, so a smaller upload to its own vendor is not.", bytes(t.own_service_floor_bytes)),
            format!("A read is remembered for {} after the process that made it goes quiet, so an upload later than that is not linked to it.", duration(topgent_collect::observed::tally::READER_QUIET_MS)),
        ],
    }))
}
