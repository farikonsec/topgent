//! Honeytokens: decoy secrets whose only use is to be noticed when read.
//!
//! The egress rules need a read to be large, or data to leave, before they can
//! say anything, and a stolen `.env` is a few hundred bytes. A decoy closes that:
//! no task has a reason to open it, so one read is the whole signal, with no
//! size, destination or content test.
//!
//! It fits the OS-level model. The collector already records reads of files
//! whose names are in the sensitive-file catalogue, by path, without opening
//! them; a decoy is planted under such a name, and a read of a path in the
//! manifest becomes a card. Topgent never reads a decoy back.
//!
//! # Layout
//!
//! - `data/honeytokens.json`: the decoys and the card's words.
//! - `manifest`: planting, listing and removing decoys, and the manifest of
//!   what was planted where (paths, classes, sizes and times, never values).
//! - `incident`: the card a read raises.

pub(crate) mod incident;
pub(crate) mod manifest;

use std::sync::OnceLock;

use serde_json::Value;

use crate::incidents::card::Words;

pub use manifest::{Manifest, list_honeytokens, plant_honeytokens, remove_honeytokens};

const DATA: &str = include_str!("../../data/honeytokens.json");

/// One decoy to plant.
#[derive(Debug)]
pub(crate) struct Decoy {
    /// Where, relative to the folder it is planted in.
    pub path: String,
    /// The catalogue class its name must match.
    pub class: String,
    /// What it holds, with placeholders.
    pub content: String,
}

#[derive(Debug)]
pub(crate) struct Data {
    pub decoys: Vec<Decoy>,
    pub card: Words,
}

/// The decoys and card in `text`, or `None` when it does not parse.
fn parse(text: &str) -> Option<Data> {
    let value: Value = serde_json::from_str(text).ok()?;
    let text_of = |v: &Value, f: &str| v.get(f)?.as_str().map(str::to_owned);
    let decoys = value
        .get("decoys")?
        .as_array()?
        .iter()
        .map(|d| {
            Some(Decoy {
                path: text_of(d, "path")?,
                class: text_of(d, "class")?,
                content: text_of(d, "content")?,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(Data {
        decoys,
        card: Words::parse(value.get("card")?)?,
    })
}

/// The shipped decoys and card. The file is checked by a test, so a build
/// that passed it always parses; if it did not, nothing is planted and a read
/// still raises a bare card.
pub(crate) fn data() -> &'static Data {
    static PARSED: OnceLock<Data> = OnceLock::new();
    PARSED.get_or_init(|| {
        parse(DATA).unwrap_or_else(|| Data {
            decoys: Vec::new(),
            card: Words::bare("honeytoken_accessed", "Honeytoken Accessed", "critical"),
        })
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn the_shipped_file_parses_and_every_decoy_is_caught_by_its_name() {
        let parsed = parse(DATA).unwrap();
        assert!(!parsed.decoys.is_empty());
        for decoy in &parsed.decoys {
            let planted = format!("/home/u/project/{}", decoy.path);
            assert_eq!(
                topgent_collect::sensitive::classify(&planted),
                Some(decoy.class.as_str()),
                "{} must classify as {}",
                decoy.path,
                decoy.class
            );
        }
        assert_eq!(parsed.card.severity, "critical");
    }
}
