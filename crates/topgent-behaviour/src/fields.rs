//! The fields Topgent supplies to the rules, and where each comes from.
//!
//! One list, in `data/topgent-fields.json`, read by this crate and by the
//! fixture generator. A field not on it is unknown to every rule, which is
//! what decides whether a rule can fire on Topgent's own events.

use std::collections::BTreeMap;
use std::sync::OnceLock;

const FIELDS: &str = include_str!("../data/topgent-fields.json");

/// Every field Topgent supplies, with the source of its value.
#[must_use]
pub fn provided() -> &'static BTreeMap<String, String> {
    static PROVIDED: OnceLock<BTreeMap<String, String>> = OnceLock::new();
    PROVIDED.get_or_init(|| {
        serde_json::from_str::<serde_json::Value>(FIELDS)
            .ok()
            .and_then(|value| serde_json::from_value(value.get("fields")?.clone()).ok())
            .unwrap_or_default()
    })
}

/// Fields Topgent answers only for a process in the host's pid namespace:
/// `container.id` is `host`, and the rest are absent.
#[must_use]
pub fn host_only_absent(field: &str) -> bool {
    static ABSENT: OnceLock<Vec<String>> = OnceLock::new();
    ABSENT
        .get_or_init(|| {
            serde_json::from_str::<serde_json::Value>(FIELDS)
                .ok()
                .and_then(|v| {
                    serde_json::from_value(v.get("host_only")?.get("absent")?.clone()).ok()
                })
                .unwrap_or_default()
        })
        .iter()
        .any(|known| known == field)
}

/// Whether Topgent supplies `field`.
#[must_use]
pub fn is_provided(field: &str) -> bool {
    provided().contains_key(field)
}

/// Whether one rule can fire on Topgent's fields, and if not, what it needs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct RuleCoverage {
    /// The rule.
    pub name: String,
    /// Whether an event built only from Topgent's fields can fire it.
    pub live: bool,
    /// The fields it is waiting for, when it cannot.
    pub needs: Vec<String>,
    /// Whether it only fires for a process in a container, whose image,
    /// pod and mounts Topgent does not read.
    pub container_only: bool,
    /// Whether it can fire on each syscall source's fields: `audit` and
    /// `ebpf`. The eBPF source names containers, so it can fire some
    /// container-only rules; each source lacks fields the other has.
    #[serde(default)]
    pub live_by_source: std::collections::BTreeMap<String, bool>,
}

impl RuleCoverage {
    /// Whether the rule can fire when `source` delivers the syscalls. A
    /// source this table does not know falls back to [`RuleCoverage::live`].
    #[must_use]
    pub fn live_on(&self, source: &str) -> bool {
        self.live_by_source
            .get(source)
            .copied()
            .unwrap_or(self.live)
    }
}

const COVERAGE: &str = include_str!("../data/f/coverage.json");

/// Coverage of every rule, generated with the fixtures and checked against
/// them by the coverage tests.
#[must_use]
pub fn coverage() -> &'static [RuleCoverage] {
    static TABLE: OnceLock<Vec<RuleCoverage>> = OnceLock::new();
    TABLE.get_or_init(|| {
        serde_json::from_str::<serde_json::Value>(COVERAGE)
            .ok()
            .and_then(|value| serde_json::from_value(value.get("rules")?.clone()).ok())
            .unwrap_or_default()
    })
}
