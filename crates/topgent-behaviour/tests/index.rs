//! The event-type index never skips a rule on an event it fires on.
//!
//! Every firing fixture, and every corpus event the reference evaluator
//! found true, is checked against its rule's type set: a rule skipped for an
//! event type it could fire on would be a detection silently lost.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use serde_json::Value;
use topgent_behaviour::catalogue::Catalogue;
use topgent_behaviour::index::event_types;

const FIXTURES: &str = include_str!("../data/f/fixtures.json");

#[test]
fn no_rule_is_skipped_for_an_event_it_fires_on() {
    let fixtures: Value = serde_json::from_str(FIXTURES).expect("fixtures parse");
    let catalogue = Catalogue::pinned().expect("the pinned catalogue");
    let (mut narrowed, mut checked) = (0, 0);
    for fixture in fixtures["rules"].as_array().expect("rules") {
        // A customised rule is evaluated from its customised condition, which
        // its own tests cover; the shipped one is what the index sees here.
        if fixture.get("customise").is_some() {
            continue;
        }
        let name = fixture["name"].as_str().expect("a name");
        let rule = catalogue.compile_rule(name).expect("compiles");
        let Some(types) = event_types(&rule.condition) else {
            continue;
        };
        narrowed += 1;
        let firing = std::iter::once(&fixture["fires"]).chain(
            fixture["corpus"]
                .as_array()
                .expect("a corpus")
                .iter()
                .filter(|case| case["expect"] == "true")
                .map(|case| &case["event"]),
        );
        for event in firing {
            checked += 1;
            let kind = event["evt.type"].as_str();
            assert!(
                kind.is_some_and(|kind| types.contains(kind)),
                "{name} would be skipped for {kind:?}, on which it fires; its types {types:?}"
            );
        }
    }
    // The index is only worth having if it narrows most rules.
    assert!(narrowed >= 60, "only {narrowed} rules narrowed");
    assert!(checked > narrowed, "{checked} firing events checked");
    eprintln!("{narrowed} rules narrowed, {checked} firing events checked");
}
