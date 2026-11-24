//! The card a honeytoken read raises: one per run, listing every decoy it
//! opened. Built from the reads the collector recorded by name, so it needs no
//! history of its own beyond the incident rows every card shares.

use serde_json::{Value, json};

use super::{Manifest, data};
use crate::incidents::Run;

/// One recorded read: path, when, size then, class.
pub(crate) type Read = (String, u64, u64, String);

/// Splits `reads` into the ones of planted decoys and the rest.
pub(crate) fn split(
    reads: impl IntoIterator<Item = Read>,
    manifest: &Manifest,
) -> (Vec<Read>, Vec<Read>) {
    reads
        .into_iter()
        .partition(|(path, ..)| manifest.get(path).is_some())
}

/// The card for `run` having opened the decoys in `reads`, or `None` when it
/// opened none.
pub(crate) fn card(run: &Run, reads: &[Read], manifest: &Manifest) -> Option<Value> {
    let first_at = reads.iter().map(|(_, at, ..)| *at).min()?;
    let last_at = reads
        .iter()
        .map(|(_, at, ..)| *at)
        .max()
        .unwrap_or(first_at);
    let card = &data().card;
    let names: Vec<&str> = reads
        .iter()
        .map(|(path, ..)| path.rsplit('/').next().unwrap_or(path))
        .collect();
    let headline = format!(
        "{} opened {} {}: {}.",
        run.name,
        reads.len(),
        if reads.len() == 1 {
            "honeytoken"
        } else {
            "honeytokens"
        },
        names.join(", ")
    );
    Some(json!({
        "id": format!("honeytoken:{}:{}", run.key.pid, run.key.started_at.0),
        "rule": "HONEYTOKEN_ACCESSED",
        "kind": card.kind,
        "name": card.name,
        "severity": card.severity,
        "headline": headline,
        "why": card.why(run),
        "actions": card.actions(run),
        "agent": crate::incidents::card::agent(run),
        "numbers": {"honeytokens_read": reads.len()},
        "evidence": {
            "honeytokens": reads.iter().map(|(path, at, _, class)| json!({
                "path": path,
                "class": class,
                "class_name": topgent_collect::sensitive::display(class),
                "read_at": at,
                "planted_at": manifest.get(path).map(|t| t.planted_at),
            })).collect::<Vec<_>>(),
        },
        "first_at": first_at,
        "last_at": last_at,
        "limits": card.limits,
    }))
}
