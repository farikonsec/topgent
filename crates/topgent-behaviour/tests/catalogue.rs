//! The pinned catalogue loads whole, and every rule resolves to one condition.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use topgent_behaviour::catalogue::{Catalogue, Maturity};
use topgent_behaviour::lang::{Expr, Operand};

fn has_macro(expr: &Expr) -> bool {
    match expr {
        Expr::Macro(_) => true,
        Expr::And(parts) | Expr::Or(parts) => parts.iter().any(has_macro),
        Expr::Not(inner) => has_macro(inner),
        Expr::Compare { .. } | Expr::Exists(_) => false,
    }
}

#[test]
fn the_pinned_catalogue_loads_whole() {
    let catalogue = Catalogue::pinned().expect("loads");
    assert_eq!(
        catalogue.commit(),
        "e822409d8a2a28c9719f56ace66e8cadebfd2bc3"
    );
    assert_eq!(catalogue.counts(), (95, 355, 165));
}

#[test]
fn every_rule_resolves_with_no_macro_left() {
    let rules = Catalogue::pinned()
        .expect("loads")
        .compile()
        .expect("compiles");
    assert_eq!(rules.len(), 95);
    for rule in &rules {
        assert!(!has_macro(&rule.condition), "{} kept a macro", rule.name);
        assert!(!rule.fields.is_empty(), "{} reads no field", rule.name);
    }
    let by_maturity = |m| rules.iter().filter(|r| r.maturity == m).count();
    assert_eq!(by_maturity(Maturity::Stable), 25);
    assert_eq!(by_maturity(Maturity::Incubating), 31);
    assert_eq!(by_maturity(Maturity::Sandbox), 39);
    assert_eq!(rules.iter().filter(|r| r.enabled).count(), 81);
}

const TINY: &str = r#"{
  "commit": "test", "files": [],
  "lists": [
    {"file": "stable", "name": "shells", "items": ["sh", "bash"]},
    {"file": "stable", "name": "all_shells", "items": ["shells", "zsh"]},
    {"file": "stable", "name": "tools", "items": ["curl"]},
    {"file": "sandbox", "name": "tools", "items": ["wget"]}
  ],
  "macros": [
    {"file": "stable", "name": "spawned", "condition": "evt.type = execve"},
    {"file": "stable", "name": "loop_a", "condition": "loop_b"},
    {"file": "stable", "name": "loop_b", "condition": "loop_a"}
  ],
  "rules": [
    {"file": "stable", "name": "Shell", "condition": "spawned and proc.name in (all_shells)",
     "priority": "WARNING", "tags": ["t"], "enabled": true, "desc": "d"},
    {"file": "sandbox", "name": "Tool", "condition": "proc.name in (tools)",
     "priority": "NOTICE", "tags": [], "enabled": false, "desc": "d"},
    {"file": "stable", "name": "Loop", "condition": "loop_a",
     "priority": "NOTICE", "tags": [], "enabled": true, "desc": "d"}
  ]
}"#;

fn set_of(expr: &Expr) -> Vec<String> {
    match expr {
        Expr::Compare {
            value: Operand::Set(items),
            ..
        } => items.iter().map(|i| i.text().to_owned()).collect(),
        Expr::And(parts) | Expr::Or(parts) => parts.iter().flat_map(set_of).collect(),
        Expr::Not(inner) => set_of(inner),
        _ => Vec::new(),
    }
}

#[test]
fn lists_inside_lists_expand_and_a_rule_sees_its_own_files_definitions() {
    let catalogue = Catalogue::from_json(TINY).expect("loads");
    let shell = catalogue.compile_rule("Shell").expect("compiles");
    assert_eq!(set_of(&shell.condition), ["sh", "bash", "zsh"]);
    let tool = catalogue.compile_rule("Tool").expect("compiles");
    assert_eq!(
        set_of(&tool.condition),
        ["wget"],
        "the sandbox rule uses the sandbox list"
    );
}

#[test]
fn a_macro_cycle_is_an_error_not_a_hang() {
    let catalogue = Catalogue::from_json(TINY).expect("loads");
    assert!(catalogue.compile_rule("Loop").is_err());
    assert!(
        catalogue.compile().is_err(),
        "one bad rule fails the catalogue"
    );
}

#[test]
fn malformed_catalogues_are_errors() {
    assert!(Catalogue::from_json("{").is_err());
    assert!(Catalogue::from_json(r#"{"commit":"x"}"#).is_err());
    let bad_rule = TINY.replace("spawned and proc.name", "spawned and and proc.name");
    assert!(
        Catalogue::from_json(&bad_rule)
            .expect("loads")
            .compile()
            .is_err()
    );
}

const QUOTED: &str = r#"{
  "commit": "test", "files": [],
  "lists": [
    {"file": "stable", "name": "login_binaries", "items": ["\"(systemd)\"", "login"]},
    {"file": "stable", "name": "scope", "items": []}
  ],
  "macros": [
    {"file": "stable", "name": "allowed", "condition": "container.id exists"}
  ],
  "rules": [
    {"file": "stable", "name": "Login", "condition": "proc.name in (login_binaries)",
     "priority": "NOTICE", "tags": [], "enabled": true, "desc": "d"},
    {"file": "stable", "name": "Scoped", "condition": "k8s.ns.name in (scope) and not allowed",
     "priority": "NOTICE", "tags": [], "enabled": true, "desc": "d"}
  ]
}"#;

/// A list item written with quotes is a quoted value, as it would be if the
/// item were written into the condition by hand.
#[test]
fn a_quoted_list_item_loses_its_quotes() {
    let rule = Catalogue::from_json(QUOTED)
        .expect("loads")
        .compile_rule("Login")
        .expect("compiles");
    assert_eq!(set_of(&rule.condition), ["(systemd)", "login"]);
}

/// Thirteen catalogue lists ship empty for the operator to fill, and some
/// macros are placeholders to be replaced. Both can be customised, in every
/// file at once.
#[test]
fn lists_and_macros_can_be_customised() {
    let custom = Catalogue::from_json(QUOTED)
        .expect("loads")
        .with_list("scope", &["prod"])
        .with_macro(
            "allowed",
            "container.image.repository = trusted.example/app",
        );
    let rule = custom.compile_rule("Scoped").expect("compiles");
    assert_eq!(set_of(&rule.condition), ["prod"]);
    assert!(rule.fields.contains("container.image.repository"));
    assert!(!rule.fields.contains("container.id"));
}
