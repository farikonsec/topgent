//! Network scanning: one run tried many ports on one host, or many hosts,
//! within minutes, and sent nothing to them.
//!
//! Built from the per-destination counts the collector already keeps
//! (attempts by outcome, bytes written, first and last activity). A *probe* is
//! a destination connected to, or tried, that received no bytes: a scanner
//! checks what answers, a client sends a request. The numbers and the card's
//! words are in `data/network-scanning.json`.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde_json::{Value, json};
use topgent_collect::observed::tally::{BURST_WINDOW_MS, DestTotals};

use super::card::{self, Words};
use super::format::{count, plural};
use super::{Merged, Run};

const DATA: &str = include_str!("../../data/network-scanning.json");

/// The rule's numbers and words.
#[derive(Debug)]
pub(super) struct Scanning {
    pub rule: String,
    /// Probes must start within this long of each other to be one scan.
    pub window_ms: u64,
    /// Distinct ports probed on one address that make a port scan.
    pub ports_on_one_host: usize,
    /// Distinct addresses probed that make a host sweep.
    pub hosts: usize,
    pub words: Words,
}

/// The rule in `text`, or `None` when it does not parse.
pub(super) fn parse(text: &str) -> Option<Scanning> {
    let value: Value = serde_json::from_str(text).ok()?;
    let t = value.get("thresholds")?;
    let n = |f: &str| t.get(f).and_then(Value::as_u64);
    Some(Scanning {
        rule: value.get("rule")?.as_str()?.to_owned(),
        window_ms: n("window_ms")?,
        ports_on_one_host: usize::try_from(n("ports_on_one_host")?).ok()?,
        hosts: usize::try_from(n("hosts")?).ok()?,
        words: Words::parse(value.get("card")?)?,
    })
}

/// The shipped rule. Checked by a test; if it did not parse, the bars are set
/// out of reach so nothing fires rather than everything.
pub(super) fn scanning() -> &'static Scanning {
    static PARSED: OnceLock<Scanning> = OnceLock::new();
    PARSED.get_or_init(|| {
        parse(DATA).unwrap_or_else(|| Scanning {
            rule: "NETWORK_SCANNING".into(),
            window_ms: BURST_WINDOW_MS,
            ports_on_one_host: usize::MAX,
            hosts: usize::MAX,
            words: Words::bare("network_scanning", "Network Scanning", "high"),
        })
    })
}

/// The run's probes: real destinations it wrote nothing to.
fn probes(merged: &Merged) -> Vec<&DestTotals> {
    let mut probes: Vec<&DestTotals> = merged
        .destinations
        .values()
        .filter(|d| d.port != 0 && d.port != 53 && !d.host.is_empty())
        .filter(|d| d.attempts > 0 && d.bytes == 0)
        .collect();
    probes.sort_by_key(|d| d.first_at);
    probes
}

/// The largest set of `probes` (sorted by start) starting within `window_ms`
/// of each other, counted by `key`, as `(distinct keys, the probes in that
/// window)`. One pass: keys are counted in and out as the window slides.
fn densest<'a, K: Ord>(
    probes: &[&'a DestTotals],
    window_ms: u64,
    key: impl Fn(&DestTotals) -> K,
) -> (usize, Vec<&'a DestTotals>) {
    let mut inside: BTreeMap<K, usize> = BTreeMap::new();
    let mut best = (0, 0..0);
    let mut from = 0;
    for (to, probe) in probes.iter().enumerate() {
        *inside.entry(key(probe)).or_default() += 1;
        while let Some(old) = probes.get(from)
            && probe.first_at.saturating_sub(old.first_at) > window_ms
        {
            let k = key(old);
            if let Some(n) = inside.get_mut(&k) {
                *n -= 1;
                if *n == 0 {
                    inside.remove(&k);
                }
            }
            from += 1;
        }
        if inside.len() > best.0 {
            best = (inside.len(), from..to + 1);
        }
    }
    (
        best.0,
        probes.get(best.1).map(<[_]>::to_vec).unwrap_or_default(),
    )
}

/// How a set of probes ended, in words: `78 refused, 22 got no answer`.
fn outcomes(probes: &[&DestTotals]) -> String {
    let refused: u64 = probes.iter().map(|d| u64::from(d.failed)).sum();
    let pending: u64 = probes.iter().map(|d| u64::from(d.in_progress)).sum();
    let answered: u64 = probes.iter().map(|d| u64::from(d.connected)).sum();
    let mut parts = Vec::new();
    if refused > 0 {
        parts.push(format!("{} refused or failed", count(refused)));
    }
    if pending > 0 {
        parts.push(format!("{} did not connect at once", count(pending)));
    }
    if answered > 0 {
        parts.push(format!("{} connected", count(answered)));
    }
    parts.join(", ")
}

/// What a run's probes add up to.
struct Found<'a> {
    /// The host with the most distinct ports in one window, when over the bar.
    port_scan: Option<(&'a str, usize, Vec<&'a DestTotals>)>,
    /// The most distinct hosts in one window, when over the bar.
    sweep: Option<(usize, Vec<&'a DestTotals>)>,
    /// Every probe the run made.
    probes: usize,
}

/// The verdict: whether `merged`'s probes are a port scan, a host sweep, or
/// both, by `rule`'s numbers. `None` when neither.
fn detect<'a>(merged: &'a Merged, rule: &Scanning) -> Option<Found<'a>> {
    let probes = probes(merged);
    let mut by_host: BTreeMap<&str, Vec<&DestTotals>> = BTreeMap::new();
    for d in &probes {
        by_host.entry(d.host.as_str()).or_default().push(d);
    }
    let port_scan = by_host
        .iter()
        .map(|(host, ds)| {
            let (n, window) = densest(ds, rule.window_ms, |d| d.port);
            (*host, n, window)
        })
        .max_by_key(|(_, n, _)| *n)
        .filter(|(_, n, _)| *n >= rule.ports_on_one_host);
    let sweep = Some(densest(&probes, rule.window_ms, |d| d.host.clone()))
        .filter(|(n, _)| *n >= rule.hosts);
    (port_scan.is_some() || sweep.is_some()).then_some(Found {
        port_scan,
        sweep,
        probes: probes.len(),
    })
}

/// The card for `run`, or `None` when it did not scan.
pub(super) fn card(run: &Run, merged: &Merged, rule: &Scanning) -> Option<Value> {
    let Found {
        port_scan,
        sweep,
        probes,
    } = detect(merged, rule)?;
    let minutes = rule.window_ms / 60_000;
    let mut found = Vec::new();
    if let Some((host, ports, ds)) = &port_scan {
        found.push(format!(
            "tried {} on {host} within {minutes} minutes ({})",
            plural(*ports as u64, "port", "ports"),
            outcomes(ds)
        ));
    }
    if let Some((hosts, ds)) = &sweep {
        found.push(format!(
            "tried {} within {minutes} minutes ({})",
            plural(*hosts as u64, "address", "addresses"),
            outcomes(ds)
        ));
    }
    let headline = format!(
        "{} {}, and sent no data to any of them.",
        run.name,
        found.join(", and ")
    );
    let scanned: Vec<&DestTotals> = port_scan
        .iter()
        .flat_map(|(_, _, ds)| ds.iter().copied())
        .chain(sweep.iter().flat_map(|(_, ds)| ds.iter().copied()))
        .collect();
    let first_at = scanned.iter().map(|d| d.first_at).min().unwrap_or(0);
    let last_at = scanned.iter().map(|d| d.last_at).max().unwrap_or(first_at);
    let rows = |ds: &[&DestTotals]| -> Vec<Value> {
        ds.iter()
            .take(50)
            .map(|d| {
                json!({
                    "address": d.host, "port": d.port, "attempts": d.attempts,
                    "connected": d.connected, "in_progress": d.in_progress, "failed": d.failed,
                    "first_at": d.first_at,
                })
            })
            .collect()
    };
    Some(json!({
        "id": format!("scan:{}:{}", run.key.pid, run.key.started_at.0),
        "rule": rule.rule,
        "kind": rule.words.kind,
        "name": rule.words.name,
        "severity": rule.words.severity,
        "headline": headline,
        "why": rule.words.why(run),
        "actions": rule.words.actions(run),
        "agent": card::agent(run),
        "numbers": {
            "ports_on_one_host": port_scan.as_ref().map(|(_, n, _)| *n),
            "hosts": sweep.as_ref().map(|(n, _)| *n),
            "probes": probes,
        },
        "evidence": {
            "port_scan": port_scan.as_ref().map(|(host, n, ds)| json!({
                "address": host, "ports": n, "probes": rows(ds),
            })),
            "host_sweep": sweep.as_ref().map(|(n, ds)| json!({
                "addresses": n, "probes": rows(ds),
            })),
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

    /// One destination: `failed` and `pending` attempts, `bytes` written.
    fn probe(host: &str, port: u16, at: u64, bytes: u64, failed: u32, pending: u32) -> DestTotals {
        DestTotals {
            host: host.into(),
            port,
            attempts: failed + pending,
            failed,
            in_progress: pending,
            bytes,
            first_at: at,
            last_at: at + 1_000,
            ..DestTotals::default()
        }
    }

    fn merged(dests: Vec<DestTotals>) -> Merged {
        let mut m = Merged::default();
        for d in dests {
            m.destinations.insert((d.host.clone(), d.port), d);
        }
        m
    }

    fn card_of(dests: Vec<DestTotals>) -> Option<Value> {
        card(&run(), &merged(dests), scanning())
    }

    #[test]
    fn the_shipped_rule_parses() {
        let rule = parse(DATA).unwrap();
        assert_eq!(rule.ports_on_one_host, 20);
        assert_eq!(rule.hosts, 20);
        assert_eq!(rule.window_ms, 300_000);
    }

    #[test]
    fn a_port_scan_of_one_host_is_one_card() {
        // Ports 1000-1099, clear of 53, which is never a probe.
        let ports = (1_000..1_100).map(|p| probe("192.0.2.5", p, u64::from(p) * 500, 0, 1, 0));
        let card = card_of(ports.collect()).unwrap();
        assert_eq!(card["kind"], "network_scanning");
        assert_eq!(card["severity"], "high");
        assert_eq!(
            card["headline"],
            "python3 tried 100 ports on 192.0.2.5 within 5 minutes (100 refused or failed), and sent no data to any of them."
        );
        assert_eq!(card["numbers"]["ports_on_one_host"], 100);
        assert!(card["numbers"]["hosts"].is_null());
    }

    #[test]
    fn a_host_sweep_with_no_answers_is_caught_though_nothing_failed() {
        // Non-blocking connects: every attempt "in progress", none refused.
        let hosts =
            (1..=30).map(|n| probe(&format!("198.51.100.{n}"), 22, 1_000 + n * 2_000, 0, 0, 1));
        let card = card_of(hosts.collect()).unwrap();
        let headline = card["headline"].as_str().unwrap();
        assert!(
            headline.contains("tried 30 addresses within 5 minutes (30 did not connect at once)"),
            "{headline}"
        );
        assert_eq!(card["evidence"]["host_sweep"]["addresses"], 30);
    }

    #[test]
    fn ordinary_traffic_and_edges_stay_silent() {
        // A package install: 40 hosts, each sent a request.
        let install = (1..=40).map(|n| {
            probe(
                &format!("203.0.113.{n}"),
                443,
                1_000 + n * 1_000,
                2_000,
                0,
                1,
            )
        });
        assert!(card_of(install.collect()).is_none());
        // 19 ports, one under the bar.
        let few = (1..=19).map(|p| probe("192.0.2.5", p, 1_000, 0, 1, 0));
        assert!(card_of(few.collect()).is_none());
        // 30 ports, one every 20 minutes: never 20 within 5 minutes.
        let slow = (1..=30).map(|p| probe("192.0.2.5", p, u64::from(p) * 1_200_000, 0, 1, 0));
        assert!(card_of(slow.collect()).is_none());
        // Resolver traffic: port 53 and port-0 ranking connects.
        let dns = (1..=40).flat_map(|n| {
            let host = format!("192.0.2.{n}");
            [
                probe(&host, 53, 1_000, 0, 1, 0),
                probe(&host, 0, 1_000, 0, 1, 0),
            ]
        });
        assert!(card_of(dns.collect()).is_none());
    }

    #[test]
    fn the_window_finds_the_dense_stretch_inside_a_long_run() {
        // Ten quiet probes over an hour, then 25 hosts in one minute.
        let quiet = (1..=10).map(|n| probe(&format!("10.0.0.{n}"), 80, n * 360_000, 0, 1, 0));
        let burst =
            (1..=25).map(|n| probe(&format!("10.0.1.{n}"), 80, 4_000_000 + n * 2_000, 0, 1, 0));
        let card = card_of(quiet.chain(burst).collect()).unwrap();
        assert_eq!(card["numbers"]["hosts"], 25);
    }
}
