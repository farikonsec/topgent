//! One-line, plain-English summaries of what each rule means to a reader.
//!
//! The rule's own name and description stay the technical reference; this adds a
//! short, non-technical line the interface shows beside it. Kept as data so the
//! wording is edited without touching code, and looked up by rule name.

use std::collections::BTreeMap;
use std::sync::OnceLock;

const RAW: &str = include_str!("../data/f/summaries.json");

fn map() -> &'static BTreeMap<String, String> {
    static MAP: OnceLock<BTreeMap<String, String>> = OnceLock::new();
    MAP.get_or_init(|| serde_json::from_str(RAW).unwrap_or_default())
}

/// The plain-English summary for a rule, if one is written.
#[must_use]
pub fn summary(rule: &str) -> Option<&'static str> {
    map().get(rule).map(String::as_str)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]
    use super::summary;
    use crate::catalogue::Catalogue;

    #[test]
    fn every_rule_has_a_short_plain_summary() {
        let catalogue = Catalogue::pinned().expect("catalogue");
        for rule in &catalogue.compile().expect("compile") {
            let s = summary(&rule.name).unwrap_or_else(|| panic!("no summary for {}", rule.name));
            assert!(
                !s.is_empty() && s.split_whitespace().count() <= 12,
                "{}: {s:?}",
                rule.name
            );
        }
        assert!(summary("Credential access followed by non-loopback connection").is_some());
    }
}
