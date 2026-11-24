//! Every one of the 95 rules, tested.
//!
//! The fixtures were generated and checked by an independent reference
//! evaluator (`scripts/f_reference.py`). For each rule this engine must agree
//! with it: the firing event fires, the near miss (one field changed) does
//! not, and every corpus event gets the same verdict, unknown included. Two
//! implementations agreeing on 4,000-odd events, many of them at the edge of
//! a condition, is the check that neither misreads the language.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use serde_json::Value;
use topgent_behaviour::catalogue::Catalogue;
use topgent_behaviour::eval::{Truth, evaluate};
use topgent_behaviour::event::MapEvent;

const FIXTURES: &str = include_str!("../data/f/fixtures.json");

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
            (Value::Object(hex), None) => {
                let hex = hex["hex"].as_str().expect("hex");
                let bytes: Vec<u8> = (0..hex.len())
                    .step_by(2)
                    .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).expect("hex digit"))
                    .collect();
                event.set_bytes(name, &bytes);
            }
            other => panic!("unexpected fixture value {other:?}"),
        }
    }
    event
}

fn truth(text: &str) -> Truth {
    match text {
        "true" => Truth::True,
        "false" => Truth::False,
        _ => Truth::Unknown,
    }
}

fn catalogue_for(fixture: &Value) -> Catalogue {
    let mut catalogue = Catalogue::pinned().expect("loads");
    if let Some(custom) = fixture.get("customise") {
        for (name, items) in custom["lists"].as_object().into_iter().flatten() {
            let items: Vec<&str> = items
                .as_array()
                .expect("items")
                .iter()
                .map(|i| i.as_str().expect("text"))
                .collect();
            catalogue = catalogue.with_list(name, &items);
        }
        for (name, condition) in custom["macros"].as_object().into_iter().flatten() {
            catalogue = catalogue.with_macro(name, condition.as_str().expect("text"));
        }
    }
    catalogue
}

#[test]
fn every_rule_fires_on_its_fixture_and_not_on_its_near_miss() {
    let fixtures: Value = serde_json::from_str(FIXTURES).expect("fixtures parse");
    let rules = fixtures["rules"].as_array().expect("rules");
    assert_eq!(rules.len(), 95, "a fixture for every rule, none skipped");
    let mut wrong = Vec::new();
    let mut corpus_checked = 0;
    for fixture in rules {
        let name = fixture["name"].as_str().expect("name");
        let rule = catalogue_for(fixture)
            .compile_rule(name)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let fires = evaluate(&rule.condition, &event(&fixture["fires"]));
        if fires != Truth::True {
            wrong.push(format!("{name}: firing event gave {fires:?}"));
        }
        let miss = evaluate(&rule.condition, &event(&fixture["near_miss"]));
        if miss != Truth::False {
            wrong.push(format!("{name}: near miss gave {miss:?}"));
        }
        for (i, case) in fixture["corpus"]
            .as_array()
            .expect("corpus")
            .iter()
            .enumerate()
        {
            let expected = truth(case["expect"].as_str().expect("verdict"));
            let got = evaluate(&rule.condition, &event(&case["event"]));
            corpus_checked += 1;
            if got != expected {
                wrong.push(format!(
                    "{name}: corpus {i} gave {got:?}, reference {expected:?}"
                ));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} disagreements:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    assert!(corpus_checked > 4_000, "{corpus_checked}");
}

/// The two rules that cannot fire as shipped are tested as an operator would
/// run them, and the fixtures record that they are silent until customised.
#[test]
fn rules_that_need_customising_are_silent_as_shipped() {
    let fixtures: Value = serde_json::from_str(FIXTURES).expect("fixtures parse");
    let shipped = Catalogue::pinned().expect("loads");
    let custom: Vec<&Value> = fixtures["rules"]
        .as_array()
        .expect("rules")
        .iter()
        .filter(|f| f.get("customise").is_some())
        .collect();
    assert_eq!(custom.len(), 2);
    for fixture in custom {
        let name = fixture["name"].as_str().expect("name");
        assert_eq!(fixture["as_shipped_fires"], false, "{name}");
        let rule = shipped.compile_rule(name).expect("compiles");
        assert_ne!(
            evaluate(&rule.condition, &event(&fixture["fires"])),
            Truth::True,
            "{name} fired as shipped"
        );
    }
}
