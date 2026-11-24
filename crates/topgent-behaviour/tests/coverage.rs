//! Which rules can fire on the fields Topgent supplies.
//!
//! For every rule the fixtures hold either an event built only from Topgent's
//! fields that fires it, or the fields it is waiting for. Both are checked
//! here, so the coverage table cannot claim a rule is live when it is not.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use serde_json::Value;
use topgent_behaviour::catalogue::Catalogue;
use topgent_behaviour::eval::{Truth, evaluate};
use topgent_behaviour::event::MapEvent;
use topgent_behaviour::fields::{coverage, is_provided, provided};

const FIXTURES: &str = include_str!("../data/f/fixtures.json");

/// Rules that can fire on Topgent's fields today. A change here is a change to
/// what Topgent detects, and must be deliberate. 52 since E4 added
/// `fd.l4proto` (eBPF source only): Unexpected UDP Traffic and Disallowed SSH
/// Connection Non Standard Port.
const LIVE: usize = 55;
/// The same, counted per syscall source (E5): Audit lacks `fd.l4proto`; the
/// eBPF names the container each event ran in and the runtime supplies its
/// image, privilege, pod, accounts and mounts. TTY presence and namespace pid
/// complete the remaining process context used by the live rules.
const LIVE_AUDIT: usize = 53;
const LIVE_EBPF: usize = 88;

fn event(fields: &Value) -> MapEvent {
    let mut event = MapEvent::default();
    for (key, value) in fields.as_object().expect("an object") {
        let (name, arg) = match key.split_once('[') {
            Some((name, rest)) => (name, rest.strip_suffix(']')),
            None => (key.as_str(), None),
        };
        match (value, arg) {
            (Value::Null, None) => event.set_absent(name),
            (Value::Null, Some(arg)) => event.set_absent_arg(name, arg),
            (Value::String(text), None) => event.set(name, text),
            (Value::String(text), Some(arg)) => event.set_arg(name, arg, text),
            _ => {}
        }
    }
    event
}

#[test]
fn the_field_list_loads_and_every_field_is_one_a_rule_reads() {
    assert!(provided().len() > 50);
    let rules = Catalogue::pinned()
        .expect("loads")
        .compile()
        .expect("compiles");
    for field in provided().keys() {
        assert!(
            rules.iter().any(|rule| rule.fields.contains(field)),
            "{field} is supplied but no rule reads it"
        );
    }
}

#[test]
fn a_live_rule_fires_on_topgent_fields_alone_and_a_blocked_one_names_its_gap() {
    let fixtures: Value = serde_json::from_str(FIXTURES).expect("fixtures parse");
    let catalogue = Catalogue::pinned().expect("loads");
    let (mut live, mut blocked) = (0, 0);
    for fixture in fixtures["rules"].as_array().expect("rules") {
        let name = fixture["name"].as_str().expect("name");
        let coverage = &fixture["topgent"];
        if coverage["fires"].is_null() {
            blocked += 1;
            let needs = coverage["needs"].as_array().expect("needs");
            assert!(
                !needs.is_empty() || coverage["container_only"] == true,
                "{name} is blocked by nothing"
            );
            for field in needs {
                assert!(
                    !is_provided(field.as_str().expect("text")),
                    "{name}: {field} is supplied"
                );
            }
            continue;
        }
        live += 1;
        for key in coverage["fires"].as_object().expect("event").keys() {
            let base = key.split('[').next().expect("name");
            assert!(
                is_provided(base),
                "{name} fires on {key}, which Topgent does not supply"
            );
        }
        // Customised rules are covered by their own tests; the shipped rule
        // decides live coverage.
        if fixture.get("customise").is_some() {
            continue;
        }
        let rule = catalogue.compile_rule(name).expect("compiles");
        assert_eq!(
            evaluate(&rule.condition, &event(&coverage["fires"])),
            Truth::True,
            "{name} does not fire on its Topgent-only event"
        );
    }
    assert_eq!(live + blocked, 95);
    assert_eq!(
        live, LIVE,
        "live coverage changed: update the S7 coverage table"
    );
}

/// The embedded table the UI shows agrees with the fixtures it was made from.
#[test]
fn the_embedded_coverage_table_matches_the_fixtures() {
    let fixtures: Value = serde_json::from_str(FIXTURES).expect("fixtures parse");
    let table = coverage();
    assert_eq!(table.len(), 95);
    for (fixture, row) in fixtures["rules"]
        .as_array()
        .expect("rules")
        .iter()
        .zip(table)
    {
        assert_eq!(fixture["name"].as_str(), Some(row.name.as_str()));
        assert_eq!(
            !fixture["topgent"]["fires"].is_null(),
            row.live,
            "{}",
            row.name
        );
    }
    assert_eq!(table.iter().filter(|r| r.live).count(), LIVE);
    assert_eq!(
        table.iter().filter(|r| r.live_on("audit")).count(),
        LIVE_AUDIT
    );
    assert_eq!(
        table.iter().filter(|r| r.live_on("ebpf")).count(),
        LIVE_EBPF
    );
}
