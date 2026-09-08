//! What an item condition can and cannot say.
//!
//! The point of the split between flags and combinators is that a condition
//! expresses *which combination matters*, never *how an address is
//! classified*. These tests hold that line.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use topgent_policy::{Flag, Item, ItemCondition, ItemKind, Number, NumberList};

fn parse(json: &str) -> ItemCondition {
    serde_json::from_str(json).expect("a well-formed item condition")
}

fn endpoint(port: u32, flags: &[Flag]) -> Item {
    Item {
        kind: Some(ItemKind::Endpoints),
        text: "10.0.0.5".to_owned(),
        port,
        flags: flags.to_vec(),
        ..Item::default()
    }
}

fn ports(list: NumberList) -> Vec<u32> {
    match list {
        NumberList::SuspiciousPorts => vec![1337, 4444, 5555, 6666, 9001],
    }
}

#[test]
fn a_flag_is_read_from_the_item() {
    let condition = parse(r#"{"is": "listening"}"#);

    assert!(condition.holds(&endpoint(80, &[Flag::Listening]), &ports));
    assert!(!condition.holds(&endpoint(80, &[Flag::Outbound]), &ports));
}

#[test]
fn a_port_is_tested_against_a_named_list_rather_than_a_copied_number() {
    // The whole reason a list can be named: an operator who adds a port to the
    // signals file must not have to find every condition that mentioned it.
    let condition = parse(r#"{"in_list": ["port", "suspicious_ports"]}"#);

    assert!(condition.holds(&endpoint(4444, &[]), &ports));
    assert!(!condition.holds(&endpoint(443, &[]), &ports));
}

#[test]
fn the_four_combinators_behave_as_written() {
    let both = parse(r#"{"all": [{"is": "outbound"}, {"is": "private_peer"}]}"#);
    let either = parse(r#"{"any": [{"is": "outbound"}, {"is": "private_peer"}]}"#);
    let neither = parse(r#"{"not": {"is": "loopback"}}"#);

    let outbound_only = endpoint(80, &[Flag::Outbound]);
    assert!(!both.holds(&outbound_only, &ports));
    assert!(either.holds(&outbound_only, &ports));
    assert!(neither.holds(&outbound_only, &ports));
    assert!(both.holds(&endpoint(80, &[Flag::Outbound, Flag::PrivatePeer]), &ports));
    assert!(!neither.holds(&endpoint(80, &[Flag::Loopback]), &ports));
}

#[test]
fn an_empty_all_is_true_and_an_empty_any_is_false() {
    assert!(parse(r#"{"all": []}"#).holds(&endpoint(1, &[]), &ports));
    assert!(!parse(r#"{"any": []}"#).holds(&endpoint(1, &[]), &ports));
}

#[test]
fn a_flag_this_build_does_not_know_fails_to_parse() {
    let error = serde_json::from_str::<ItemCondition>(r#"{"is": "smells_wrong"}"#)
        .expect_err("an unknown flag is refused");
    assert!(error.to_string().contains("smells_wrong"), "{error}");
}

#[test]
fn a_list_this_build_does_not_know_fails_to_parse() {
    assert!(serde_json::from_str::<ItemCondition>(r#"{"in_list": ["port", "vibes"]}"#).is_err());
}

#[test]
fn asking_an_endpoint_a_question_only_a_resource_answers_is_caught() {
    // Otherwise the factor never fires, which looks exactly like a quiet host.
    let wrong = parse(r#"{"is": "sensitive"}"#);

    assert!(!wrong.fields_exist_on(ItemKind::Endpoints));
    assert!(wrong.fields_exist_on(ItemKind::Resources));
}

#[test]
fn asking_a_resource_for_a_port_is_caught() {
    let wrong = parse(r#"{"at_least": ["port", 1]}"#);

    assert!(!wrong.fields_exist_on(ItemKind::Resources));
    assert!(wrong.fields_exist_on(ItemKind::Endpoints));
}

#[test]
fn a_condition_names_every_field_it_reads() {
    let condition = parse(
        r#"{"all": [
             {"is": "outbound"},
             {"not": {"is": "loopback"}},
             {"in_list": ["port", "suspicious_ports"]}
           ]}"#,
    );

    assert_eq!(condition.flags(), vec![Flag::Loopback, Flag::Outbound]);
    assert_eq!(condition.numbers(), vec![Number::Port]);
}

#[test]
fn every_kind_declares_the_fields_its_items_carry() {
    // A kind with no declared fields would accept any condition, including
    // nonsense, and every factor over it would silently never fire.
    for kind in ItemKind::all() {
        assert!(
            !kind.flags().is_empty(),
            "{} declares no flags",
            kind.as_str()
        );
        for flag in kind.flags() {
            assert!(!flag.as_str().is_empty());
        }
        for number in kind.numbers() {
            assert!(!number.as_str().is_empty());
        }
    }
}

#[test]
fn no_flag_is_shared_between_two_kinds() {
    // Sharing one would make `fields_exist_on` unable to catch a condition
    // pointed at the wrong collection, which is the check it exists for.
    for left in ItemKind::all() {
        for right in ItemKind::all() {
            if left == right {
                continue;
            }
            for flag in left.flags() {
                assert!(
                    !right.flags().contains(flag),
                    "{} is on both {} and {}",
                    flag.as_str(),
                    left.as_str(),
                    right.as_str()
                );
            }
        }
    }
}

#[test]
fn a_template_fills_in_the_matched_item() {
    let template =
        topgent_policy::Template::new("Opened a listener on {host}:{port}", ItemKind::Endpoints)
            .expect("both placeholders belong to an endpoint");

    assert_eq!(
        template.render(&endpoint(8080, &[])),
        "Opened a listener on 10.0.0.5:8080"
    );
}

#[test]
fn a_placeholder_this_build_does_not_know_is_refused_at_load() {
    // Otherwise the literal text `{country}` reaches a finding and an operator
    // has to work out whether it is a bug or a hostname.
    let error = topgent_policy::Template::new("from {country}", ItemKind::Endpoints)
        .expect_err("an unknown placeholder is refused");
    assert_eq!(
        error,
        topgent_policy::TemplateError::Unknown {
            name: "country".to_owned()
        }
    );
}

#[test]
fn a_placeholder_the_kind_does_not_carry_is_refused() {
    let error = topgent_policy::Template::new("wrote {path}", ItemKind::Endpoints)
        .expect_err("an endpoint has no path");
    assert_eq!(
        error,
        topgent_policy::TemplateError::WrongKind {
            name: "path".to_owned(),
            kind: "endpoints"
        }
    );
    topgent_policy::Template::new("wrote {path}", ItemKind::Resources)
        .expect("a resource does have one");
}

#[test]
fn an_unclosed_brace_is_refused_rather_than_swallowing_the_rest() {
    assert_eq!(
        topgent_policy::Template::new("listener on {host", ItemKind::Endpoints),
        Err(topgent_policy::TemplateError::Unbalanced)
    );
}

#[test]
fn a_template_that_renders_nothing_is_refused() {
    assert_eq!(
        topgent_policy::Template::new("   ", ItemKind::Endpoints),
        Err(topgent_policy::TemplateError::Blank)
    );
}

#[test]
fn a_template_with_no_placeholders_is_fine() {
    let template =
        topgent_policy::Template::new("Modified Topgent or its policy", ItemKind::Resources)
            .expect("a constant sentence is a valid template");
    assert_eq!(
        template.render(&endpoint(1, &[])),
        "Modified Topgent or its policy"
    );
}

#[test]
fn no_placeholder_survives_into_a_rendered_finding() {
    // The construction check is what guarantees this, so the test is the proof
    // that the two halves agree.
    for kind in ItemKind::all() {
        for placeholder in kind.placeholders() {
            let text = format!("value is {{{}}}", placeholder.as_str());
            let template =
                topgent_policy::Template::new(&text, kind).expect("its own kind accepts it");
            let rendered = template.render(&endpoint(7, &[]));
            assert!(
                !rendered.contains('{') && !rendered.contains('}'),
                "{rendered} still holds a placeholder"
            );
        }
    }
}

#[test]
fn every_kind_offers_at_least_one_placeholder() {
    for kind in ItemKind::all() {
        assert!(
            !kind.placeholders().is_empty(),
            "{} can name nothing, so its findings cannot say what they matched",
            kind.as_str()
        );
    }
}
