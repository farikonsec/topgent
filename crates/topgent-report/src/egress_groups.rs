//! Destinations grouped by who owns them, for the egress tests.
//!
//! One vendor answers from many addresses, and one cloud hands an uploader as
//! many as it likes. Judged per address, an upload split across them stays
//! under every bar. The workspace-exfiltration rule ([`crate::incidents`])
//! judges owners instead: by the owner of an address's name when it is known,
//! else the name's domain, else the network it sits in.
//!
//! This only groups and sums. It decides nothing: the thresholds and the
//! verdict stay with the rule.

use std::collections::BTreeMap;
use std::net::IpAddr;

use topgent_collect::observed::tally::DestTotals;

/// Destinations that belong to one owner, judged as one place.
///
/// One vendor answers from many addresses: GLM sent 2.2 MB to Z.ai over two,
/// each under the bar alone. Judged per address, a real upload split across a
/// cloud's addresses would hide the same way, so the tests run on owners.
#[derive(Debug, Clone)]
pub(crate) struct Group {
    /// What to call it: an owner, a domain, or a network.
    pub label: String,
    /// Whether these are the agent's own services.
    pub own: bool,
    /// Its addresses, most bytes first, with their names when looked up.
    pub members: Vec<(DestTotals, Option<String>)>,
    /// Bytes sent to all of them.
    pub bytes: u64,
    /// The most sent to all of them within one burst window.
    pub burst_bytes: u64,
    /// When that burst ended, in the start-time base.
    pub burst_at: u64,
    /// First and last activity across them.
    pub first_at: u64,
    /// As above.
    pub last_at: u64,
}

/// Which owner an address belongs to, as `(key, label)`: the owner of its
/// name, else the name's last two labels, else its network (/24 for IPv4,
/// /48 for IPv6). A network is a stand-in for the operator's address block
/// when no name says who it is.
fn owner_key(host: &str, name: Option<&str>) -> (String, String) {
    if let Some(name) = name {
        if let Some(owner) = topgent_collect::resolve::owner_of(name) {
            return (format!("owner:{owner}"), owner.to_owned());
        }
        let mut labels = name.trim_end_matches('.').rsplit('.');
        if let (Some(top), Some(second)) = (labels.next(), labels.next()) {
            let domain = format!("{second}.{top}").to_ascii_lowercase();
            return (format!("domain:{domain}"), domain);
        }
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            let [a, b, c, _] = ip.octets();
            let net = format!("{a}.{b}.{c}.0/24");
            (format!("net:{net}"), format!("network {net}"))
        }
        Ok(IpAddr::V6(ip)) => {
            let s = ip.segments();
            let net = format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2]);
            (format!("net:{net}"), format!("network {net}"))
        }
        Err(_) => (format!("host:{host}"), host.to_owned()),
    }
}

/// The most bytes sent to `members` together within one burst window, and
/// when it ended. One address keeps the collector's own burst. Several add
/// their per-minute bytes; their own bursts still count, because per-minute
/// history is kept only for the most recent minutes.
fn group_burst(members: &[(DestTotals, Option<String>)]) -> (u64, u64) {
    let single = members
        .iter()
        .map(|(d, _)| (d.burst_bytes, d.burst_at))
        .max_by_key(|(b, _)| *b)
        .unwrap_or((0, 0));
    if members.len() < 2 {
        return single;
    }
    let mut per_minute: BTreeMap<u64, u64> = BTreeMap::new();
    for (d, _) in members {
        for (minute, b) in &d.minutes {
            let slot = per_minute.entry(*minute).or_default();
            *slot = slot.saturating_add(*b);
        }
    }
    let span = topgent_collect::observed::tally::BURST_WINDOW_MS / 60_000;
    let summed = per_minute
        .keys()
        .map(|end| {
            let total = per_minute
                .range(end.saturating_sub(span - 1)..=*end)
                .map(|(_, b)| *b)
                .fold(0_u64, u64::saturating_add);
            (total, (end + 1) * 60_000)
        })
        .max_by_key(|(b, _)| *b)
        .unwrap_or((0, 0));
    if summed.0 > single.0 { summed } else { single }
}

/// Members of one owner, keyed by owner, with the owner's label.
type ByOwner = BTreeMap<String, (String, Vec<(DestTotals, Option<String>)>)>;

/// Groups `dests` by owner. `own` puts them all in one group: an agent's own
/// services are one place whoever runs them.
pub(crate) fn group(dests: &[(DestTotals, Option<String>)], own: bool) -> Vec<Group> {
    let mut by_key: ByOwner = BTreeMap::new();
    for (d, name) in dests {
        let (key, label) = if own {
            ("own".to_owned(), "its own service".to_owned())
        } else if d.host.is_empty() {
            (
                "unseen".to_owned(),
                "a connection Topgent saw used but not opened".to_owned(),
            )
        } else {
            owner_key(&d.host, name.as_deref())
        };
        by_key
            .entry(key)
            .or_insert_with(|| (label, Vec::new()))
            .1
            .push((d.clone(), name.clone()));
    }
    by_key
        .into_values()
        .map(|(label, mut members)| {
            members.sort_by_key(|(d, _)| std::cmp::Reverse(d.bytes));
            let (burst_bytes, burst_at) = group_burst(&members);
            Group {
                label,
                own,
                bytes: members
                    .iter()
                    .map(|(d, _)| d.bytes)
                    .fold(0, u64::saturating_add),
                burst_bytes,
                burst_at,
                first_at: members.iter().map(|(d, _)| d.first_at).min().unwrap_or(0),
                last_at: members.iter().map(|(d, _)| d.last_at).max().unwrap_or(0),
                members,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn owners_come_from_names_then_networks() {
        assert_eq!(owner_key("203.0.113.9", None).0, "net:203.0.113.0/24");
        assert_eq!(owner_key("2001:db8:1:2::9", None).0, "net:2001:db8:1::/48");
        assert_eq!(
            owner_key("203.0.113.9", Some("bucket.oss-cn-hongkong.aliyuncs.com")).1,
            topgent_collect::resolve::owner_of("aliyuncs.com").unwrap_or("aliyuncs.com")
        );
        assert_eq!(
            owner_key("1.2.3.4", Some("x.example.org.")).0,
            "domain:example.org"
        );
    }
}
