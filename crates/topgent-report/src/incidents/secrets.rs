//! Cards about secrets a run read: a credential store opened at all, and a
//! secret read shortly before data left.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::config::Config;
use super::destinations::Destinations;
use super::format::plural;
use super::{Merged, Run};

/// Incidents about secrets this run read: a credential store opened at all, and
/// a secret read shortly before data left the machine.
///
/// A secret file is small, so the bulk tests in [`evaluate`](super::exfiltration::evaluate) never see it. These
/// key on *which* file was read, and on whether bytes left within a short window
/// after. They never claim the bytes sent were the secret: Topgent counts reads
/// and bytes, not contents, so a card says what was read and that data then
/// left, and its limits say it cannot show the two are the same bytes.
/// One real destination of a run, for [`secret_incidents`].
struct Dst {
    host: String,
    port: u16,
    name: Option<String>,
    own: bool,
    minutes: Vec<(u64, u64)>,
    bytes: u64,
}

#[allow(clippy::too_many_lines)]
pub(super) fn secret_incidents(
    run: &Run,
    merged: &Merged,
    destinations: &mut dyn Destinations,
    cfg: &Config,
) -> Vec<Value> {
    if merged.sensitive.is_empty() {
        return Vec::new();
    }
    let window_min = cfg.thresholds.secret_egress_window_ms / 60_000;
    // Each real destination: its own-service flag, and its per-minute bytes.
    let dests: Vec<Dst> = merged
        .destinations
        .values()
        .filter(|d| d.port != 0 && d.port != 53 && d.bytes > 0)
        .map(|d| Dst {
            own: !d.host.is_empty() && destinations.model_service(&d.host),
            name: (!d.host.is_empty())
                .then(|| destinations.name(&d.host))
                .flatten(),
            host: d.host.clone(),
            port: d.port,
            minutes: d.minutes.clone(),
            bytes: d.bytes,
        })
        .collect();
    // Bytes a destination received in the window that began with a read.
    let after = |dst: &Dst, read_at: u64| -> u64 {
        let from = read_at / 60_000;
        dst.minutes
            .iter()
            .filter(|(m, _)| *m >= from && *m <= from + window_min)
            .map(|(_, b)| *b)
            .sum()
    };

    let mut secrets: Vec<(&String, u64, u64, &String)> = merged
        .sensitive
        .iter()
        .map(|(path, (at, size, class))| (path, *at, *size, class))
        .collect();
    secrets.sort_by_key(|(_, at, _, _)| *at);

    // Which destinations received bytes after any secret read, split by kind.
    let mut to_other: BTreeSet<(String, u16)> = BTreeSet::new();
    let mut to_own: BTreeSet<(String, u16)> = BTreeSet::new();
    for (_, at, _, _) in &secrets {
        for dst in &dests {
            if after(dst, *at) > 0 {
                if dst.own {
                    to_own.insert((dst.host.clone(), dst.port));
                } else {
                    to_other.insert((dst.host.clone(), dst.port));
                }
            }
        }
    }

    let secret_line = |path: &str, size: u64, class: &str| -> Value {
        json!({
            "path": path,
            "name": path.rsplit('/').next().unwrap_or(path),
            "class": class,
            "class_name": topgent_collect::sensitive::display(class),
            "bytes": size,
        })
    };
    let secret_rows: Vec<Value> = secrets
        .iter()
        .take(20)
        .map(|(p, _, size, class)| secret_line(p, *size, class))
        .collect();
    let dest_rows = |keys: &BTreeSet<(String, u16)>| -> Vec<Value> {
        dests
            .iter()
            .filter(|d| keys.contains(&(d.host.clone(), d.port)))
            .take(10)
            .map(|d| {
                json!({
                    "address": d.host,
                    "port": d.port,
                    "name": d.name,
                    "owner": d.name.as_deref().and_then(topgent_collect::resolve::owner_of),
                    "own_service": d.own,
                    "bytes": d.bytes,
                })
            })
            .collect()
    };
    let first_at = secrets.first().map_or(0, |(_, at, _, _)| *at);
    let last_at = secrets.last().map_or(first_at, |(_, at, _, _)| *at);
    let kinds: BTreeSet<&str> = secrets.iter().map(|(_, _, _, c)| c.as_str()).collect();
    let agent = |name: &str| {
        json!({
            "pid": run.key.pid, "started_at": run.key.started_at.0,
            "name": run.name, "family": run.family, "recognised": run.family.is_some(),
            "kind_name": name,
        })
    };
    let mut out = Vec::new();

    // A credential store opened at all: a vault or a browser's saved passwords
    // holds many secrets, so reading one is worth stating on its own.
    let stores: Vec<&(&String, u64, u64, &String)> = secrets
        .iter()
        .filter(|(_, _, _, c)| topgent_collect::sensitive::is_store(c))
        .collect();
    if !stores.is_empty() {
        let names: Vec<&str> = stores
            .iter()
            .map(|(_, _, _, c)| topgent_collect::sensitive::display(c))
            .collect();
        let sent = !to_other.is_empty();
        out.push(json!({
            "id": format!("secret_store:{}:{}", run.key.pid, run.key.started_at.0),
            "kind": "credential_store_opened",
            "rule": "credential_store_opened",
            "name": "Credential Store Access",
            "severity": if sent { "critical" } else { "high" },
            "headline": format!(
                "{} accessed a {}{}",
                run.name,
                dedup_join(&names),
                if sent { ", then sent data out" } else { "" }
            ),
            "why": [
                "A password vault, a browser's saved passwords or a keychain holds many credentials at once.",
                "Coding tasks do not need to open one.",
            ],
            "actions": [
                {"label": "Check the Files tab for this agent: which store it opened and where its data went after."},
                {"label": "If anything left the machine, treat every credential in that store as exposed and rotate it."},
            ],
            "agent": agent("Credential store opened"),
            "numbers": {"stores": stores.len(), "secrets": secrets.len()},
            "evidence": {
                "secrets": stores.iter().map(|(p, _, size, class)| secret_line(p, *size, class)).collect::<Vec<_>>(),
                "sent_to": dest_rows(&to_other),
            },
            "first_at": first_at,
            "last_at": last_at,
            "limits": [
                "Topgent sees that the file was opened for reading, never its contents.",
                "Bytes sent are counted, not their contents.",
            ],
        }));
    }

    // A secret read, then data left to somewhere that is not the agent's model
    // service, within the window.
    if !to_other.is_empty() {
        out.push(json!({
            "id": format!("secret_egress:{}:{}", run.key.pid, run.key.started_at.0),
            "kind": "secret_exfiltration",
            "rule": "secret_exfiltration",
            "name": "Credential Exfiltration",
            "severity": "critical",
            "headline": format!(
                "{} read {}, then sent data to {} within {} min",
                run.name,
                plural(secrets.len() as u64, "secret file", "secret files"),
                place_count(&to_other),
                window_min
            ),
            "why": [
                "Keys, tokens and passwords are what someone needs to act as you on other systems.",
                "Data left the machine shortly after they were read, to somewhere that is not this agent's model service.",
            ],
            "actions": [
                {"label": "Rotate every credential listed here now."},
                {"label": "Check the Files tab and Network tab for this agent: what it read and where the data went."},
            ],
            "agent": agent("Credential Exfiltration"),
            "numbers": {"secrets": secrets.len(), "classes": kinds.len()},
            "evidence": {"secrets": secret_rows.clone(), "sent_to": dest_rows(&to_other)},
            "first_at": first_at,
            "last_at": last_at,
            "limits": [
                "Topgent counts files opened for reading and bytes written to the network. It reads neither, so it cannot show that the bytes sent were these secrets.",
                "The link is timing: a secret was read, then data left within the window. A read and an unrelated upload close together would look the same.",
            ],
        }));
    } else if !to_own.is_empty() {
        // Sent only to the agent's own model service: routine for a `.env` that
        // a prompt pulls in, but still the secret's value reaching the vendor.
        out.push(json!({
            "id": format!("secret_to_model:{}:{}", run.key.pid, run.key.started_at.0),
            "kind": "secret_to_model",
            "rule": "secret_to_model",
            "name": "Credential Exposure",
            "severity": "high",
            "headline": format!(
                "{} read {}, then sent data to its model within {} min",
                run.name,
                plural(secrets.len() as u64, "secret file", "secret files"),
                window_min
            ),
            "why": [
                "A secret read just before a turn is often pulled into the prompt and sent to the model provider.",
                "The value is now held by the provider.",
            ],
            "actions": [
                {"label": "Check whether the agent needed the secret for the task."},
                {"label": "If it was sent to the provider unintentionally, rotate it and exclude it from the agent's context."},
            ],
            "agent": agent("Credential Exposure"),
            "numbers": {"secrets": secrets.len(), "classes": kinds.len()},
            "evidence": {"secrets": secret_rows.clone(), "sent_to": dest_rows(&to_own)},
            "first_at": first_at,
            "last_at": last_at,
            "limits": [
                "Reads and bytes are counted, not their contents.",
                "The link is timing only.",
            ],
        }));
    }
    out
}

/// `KeePass vault and 2 others`, de-duplicating repeats.
pub(super) fn dedup_join(names: &[&str]) -> String {
    let mut seen = Vec::new();
    for n in names {
        if !seen.contains(n) {
            seen.push(*n);
        }
    }
    match seen.as_slice() {
        [] => "credential store".to_owned(),
        [one] => (*one).to_owned(),
        [first, rest @ ..] => format!("{first} and {} other", rest.len()),
    }
}

/// `one place` / `3 places`.
pub(super) fn place_count(keys: &BTreeSet<(String, u16)>) -> String {
    match keys.len() {
        1 => "one place".to_owned(),
        n => format!("{n} places"),
    }
}
