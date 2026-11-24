//! Files encrypted or destroyed: one run deleted or renamed away many files it
//! had just read, or rewrote many after running an encryption program.
//!
//! Built from the collector's change counters
//! ([`topgent_collect::observed::changes`]), which count a change only when the
//! same process read the file first. The numbers and the card's words are in
//! `data/files-destroyed.json`.

use std::sync::OnceLock;

use serde_json::{Value, json};
use topgent_collect::observed::tally::{BURST_WINDOW_MS, RootTotals};

use super::card::{self, Words};
use super::format::{count, plural};
use super::{Merged, Run};

const DATA: &str = include_str!("../../data/files-destroyed.json");

/// The rule's numbers and words.
#[derive(Debug)]
pub(super) struct Destruction {
    pub rule: String,
    /// Deletes and renames must fall within this long to be one event.
    pub window_ms: u64,
    /// Read files deleted or renamed away within the window that fire.
    pub destroyed_files: usize,
    /// Read files rewritten in place that fire alongside an encryption tool.
    pub rewritten_files: u32,
    pub words: Words,
}

/// The rule in `text`, or `None` when it does not parse.
pub(super) fn parse(text: &str) -> Option<Destruction> {
    let value: Value = serde_json::from_str(text).ok()?;
    let t = value.get("thresholds")?;
    let n = |f: &str| t.get(f).and_then(Value::as_u64);
    Some(Destruction {
        rule: value.get("rule")?.as_str()?.to_owned(),
        window_ms: n("window_ms")?,
        destroyed_files: usize::try_from(n("destroyed_files")?).ok()?,
        rewritten_files: u32::try_from(n("rewritten_files")?).ok()?,
        words: Words::parse(value.get("card")?)?,
    })
}

/// The shipped rule. Checked by a test; if it did not parse, the bars are set
/// out of reach so nothing fires rather than everything.
pub(super) fn destroyed() -> &'static Destruction {
    static PARSED: OnceLock<Destruction> = OnceLock::new();
    PARSED.get_or_init(|| {
        parse(DATA).unwrap_or_else(|| Destruction {
            rule: "FILES_DESTROYED".into(),
            window_ms: BURST_WINDOW_MS,
            destroyed_files: usize::MAX,
            rewritten_files: u32::MAX,
            words: Words::bare(
                "files_destroyed",
                "Files Encrypted or Destroyed",
                "critical",
            ),
        })
    })
}

/// The most of `times` (sorted) within `window_ms`, and when they began and
/// ended.
fn densest(times: &[u64], window_ms: u64) -> (usize, u64, u64) {
    let mut best = (0, 0, 0);
    let mut from = 0;
    for (to, at) in times.iter().enumerate() {
        while times
            .get(from)
            .is_some_and(|first| at.saturating_sub(*first) > window_ms)
        {
            from += 1;
        }
        let n = to + 1 - from;
        if n > best.0 {
            best = (n, times.get(from).copied().unwrap_or(*at), *at);
        }
    }
    best
}

/// What a run did that the rule fires on.
struct Found<'a> {
    root: &'a RootTotals,
    /// Read files deleted or renamed away in the densest window, and when.
    burst: (usize, u64, u64),
    /// Whether it fired on rewrites alongside an encryption tool.
    rewrites_fire: bool,
}

/// The verdict for `merged`, by `rule`'s numbers. `tools` are encryption
/// programs the run ran.
fn detect<'a>(merged: &'a Merged, tools: &[String], rule: &Destruction) -> Option<Found<'a>> {
    merged
        .roots
        .values()
        .map(|root| Found {
            root,
            burst: densest(&root.changes.times, rule.window_ms),
            rewrites_fire: !tools.is_empty() && root.changes.rewritten >= rule.rewritten_files,
        })
        .filter(|f| f.burst.0 >= rule.destroyed_files || f.rewrites_fire)
        .max_by_key(|f| (f.burst.0, f.root.changes.rewritten))
}

/// The card for `run`, or `None` when it did not destroy files.
pub(super) fn card(
    run: &Run,
    merged: &Merged,
    tools: &[String],
    rule: &Destruction,
) -> Option<Value> {
    let Found {
        root,
        burst,
        rewrites_fire,
    } = detect(merged, tools, rule)?;
    let c = &root.changes;
    let (n, from, to) = burst;
    let minutes = rule.window_ms / 60_000;
    let tool = tools
        .first()
        .map(|t| format!(", after running {t}"))
        .unwrap_or_default();
    let headline = if n >= rule.destroyed_files {
        let suffix = c
            .suffixes
            .first()
            .map(|(s, k)| format!("; {} renamed to *{s}", count(u64::from(*k))))
            .unwrap_or_default();
        format!(
            "{} deleted or renamed away {} it had read in {} within {minutes} minutes ({} renamed, {} deleted{suffix}){tool}.",
            run.name,
            plural(n as u64, "file", "files"),
            root.root,
            count(u64::from(c.renamed)),
            count(u64::from(c.deleted)),
        )
    } else {
        format!(
            "{} rewrote {} it had read in {}{tool}.",
            run.name,
            plural(u64::from(c.rewritten), "file", "files"),
            root.root,
        )
    };
    let mut why = rule.words.why(run);
    if rewrites_fire {
        why.push(format!(
            "It rewrote {} it had read while an encryption program ran.",
            plural(u64::from(c.rewritten), "file", "files")
        ));
    }
    let (first_at, last_at) = if n > 0 {
        (from, to)
    } else {
        (root.first_at, root.last_at)
    };
    Some(json!({
        "id": format!("destroyed:{}:{}", run.key.pid, run.key.started_at.0),
        "rule": rule.rule,
        "kind": rule.words.kind,
        "name": rule.words.name,
        "severity": rule.words.severity,
        "headline": headline,
        "why": why,
        "actions": rule.words.actions(run),
        "agent": card::agent(run),
        "numbers": {
            "files_read": root.files,
            "destroyed_in_window": n,
            "renamed": c.renamed,
            "deleted": c.deleted,
            "rewritten": c.rewritten,
        },
        "evidence": {
            "root": root.root,
            "new_suffixes": c.suffixes.iter().map(|(s, k)| json!({"suffix": s, "files": k})).collect::<Vec<_>>(),
            "encryption_tools": tools,
            "window_minutes": minutes,
        },
        "first_at": first_at,
        "last_at": last_at,
        "limits": rule.words.limits,
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use topgent_collect::observed::changes::ChangeTotals;
    use topgent_core::lineage::ProcessKey;
    use topgent_facts::UnixMillis;

    use super::*;

    fn run() -> Run {
        Run {
            key: ProcessKey {
                pid: 42,
                started_at: UnixMillis(1),
            },
            name: "python3".into(),
            family: None,
        }
    }

    fn merged(changes: ChangeTotals) -> Merged {
        let mut m = Merged::default();
        m.roots.insert(
            "/lab/repo".into(),
            RootTotals {
                root: "/lab/repo".into(),
                files: 200,
                changes,
                ..RootTotals::default()
            },
        );
        m
    }

    fn renamed(n: u32, every_ms: u64) -> ChangeTotals {
        ChangeTotals {
            renamed: n,
            times: (0..u64::from(n)).map(|i| 1_000 + i * every_ms).collect(),
            suffixes: vec![(".locked".into(), n)],
            ..ChangeTotals::default()
        }
    }

    #[test]
    fn the_shipped_rule_parses() {
        let rule = parse(DATA).unwrap();
        assert_eq!(rule.destroyed_files, 50);
        assert_eq!(rule.words.severity, "critical");
    }

    #[test]
    fn two_hundred_read_files_renamed_to_locked_is_one_card() {
        let card = card(&run(), &merged(renamed(200, 500)), &[], destroyed()).unwrap();
        assert_eq!(card["kind"], "files_destroyed");
        assert_eq!(
            card["headline"],
            "python3 deleted or renamed away 200 files it had read in /lab/repo within 5 minutes (200 renamed, 0 deleted; 200 renamed to *.locked)."
        );
        // With a separate encryption program it says so.
        let tools = vec!["openssl".to_owned()];
        let card = super::card(&run(), &merged(renamed(200, 500)), &tools, destroyed()).unwrap();
        assert!(
            card["headline"]
                .as_str()
                .unwrap()
                .ends_with(", after running openssl.")
        );
    }

    #[test]
    fn rewrites_fire_only_beside_an_encryption_program() {
        let formatter = ChangeTotals {
            rewritten: 200,
            ..ChangeTotals::default()
        };
        assert!(card(&run(), &merged(formatter.clone()), &[], destroyed()).is_none());
        let tools = vec!["gpg".to_owned()];
        let card = card(&run(), &merged(formatter), &tools, destroyed()).unwrap();
        assert_eq!(
            card["headline"],
            "python3 rewrote 200 files it had read in /lab/repo, after running gpg."
        );
    }

    #[test]
    fn a_few_or_a_slow_trickle_stays_silent() {
        assert!(card(&run(), &merged(renamed(49, 500)), &[], destroyed()).is_none());
        // 200 renames, one every 10 seconds: at most 31 in any 5 minutes.
        assert!(card(&run(), &merged(renamed(200, 10_000)), &[], destroyed()).is_none());
    }
}
