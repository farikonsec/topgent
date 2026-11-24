//! The condition language, operator by operator.
//!
//! Each test states one rule of the language the F catalogue is written in.
//! The catalogue's 95 rules are only as right as these: a wrong `pmatch` or a
//! `not` that turns "unknown" into "true" would fire rules on evidence that
//! was never collected.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use topgent_behaviour::eval::{Truth, evaluate};
use topgent_behaviour::event::MapEvent;
use topgent_behaviour::lang::parse;

fn truth(condition: &str, event: &MapEvent) -> Truth {
    evaluate(&parse(condition).expect("parses"), event)
}

fn event(fields: &[(&str, &str)]) -> MapEvent {
    let mut event = MapEvent::default();
    for (name, value) in fields {
        event.set(name, value);
    }
    event
}

#[test]
fn equality_and_inequality_compare_text_exactly() {
    let e = event(&[("proc.name", "cat")]);
    assert_eq!(truth("proc.name = cat", &e), Truth::True);
    assert_eq!(truth("proc.name=cat", &e), Truth::True, "no spaces");
    assert_eq!(truth("proc.name = Cat", &e), Truth::False);
    assert_eq!(truth("proc.name != cat", &e), Truth::False);
    assert_eq!(truth("proc.name != sh", &e), Truth::True);
}

#[test]
fn quoted_values_keep_their_spaces_and_either_quote_works() {
    let e = event(&[("proc.cmdline", "perl /usr/bin/updmap -x")]);
    assert_eq!(
        truth(r#"proc.cmdline startswith "perl /usr/bin/updmap""#, &e),
        Truth::True
    );
    assert_eq!(truth("proc.cmdline contains ' -x'", &e), Truth::True);
}

#[test]
fn substring_operators() {
    let e = event(&[("fd.name", "/home/u/.ssh/id_rsa")]);
    assert_eq!(truth("fd.name contains id_rsa", &e), Truth::True);
    assert_eq!(truth("fd.name icontains ID_RSA", &e), Truth::True);
    assert_eq!(truth("fd.name contains ID_RSA", &e), Truth::False);
    assert_eq!(truth("fd.name startswith /home", &e), Truth::True);
    assert_eq!(truth("fd.name endswith id_rsa", &e), Truth::True);
    assert_eq!(truth("fd.name endswith /home", &e), Truth::False);
}

#[test]
fn bcontains_takes_hex_bytes() {
    let e = event(&[("evt.buffer", "GET /x HTTP")]);
    // "GET" is 474554.
    assert_eq!(truth("evt.buffer bcontains 474554", &e), Truth::True);
    assert_eq!(truth("evt.buffer bcontains 505554", &e), Truth::False);
}

#[test]
fn numbers_compare_as_numbers() {
    let e = event(&[("evt.rawres", "3"), ("fd.sport", "32768")]);
    assert_eq!(truth("evt.rawres >= 0", &e), Truth::True);
    assert_eq!(truth("evt.rawres>=0", &e), Truth::True);
    assert_eq!(truth("fd.sport <= 32767", &e), Truth::False);
    assert_eq!(truth("fd.sport >= 30000", &e), Truth::True);
    let failed = event(&[("evt.rawres", "-13")]);
    assert_eq!(truth("evt.rawres >= 0", &failed), Truth::False);
}

#[test]
fn in_matches_any_listed_value_including_bracketed_bare_words() {
    let e = event(&[("proc.pname", "runc:[0:PARENT]")]);
    assert_eq!(
        truth("proc.pname in (runc:[0:PARENT], runc:[1:CHILD], runc)", &e),
        Truth::True
    );
    assert_eq!(truth("proc.pname in (runc, crio)", &e), Truth::False);
}

#[test]
fn glob_star_crosses_slashes_and_question_matches_one() {
    let e = event(&[("fd.name", "/home/u/.ssh/authorized_keys")]);
    assert_eq!(truth("fd.name glob '/home/*/.ssh/*'", &e), Truth::True);
    assert_eq!(truth("fd.name glob '/home/?/.ssh/*'", &e), Truth::True);
    assert_eq!(truth("fd.name glob '/root/*'", &e), Truth::False);
    let traversal = event(&[("fd.nameraw", "/a/../../etc/shadow")]);
    assert_eq!(
        truth("fd.nameraw glob '*../*../*'", &traversal),
        Truth::True
    );
}

#[test]
fn pmatch_is_a_path_prefix_on_path_boundaries() {
    let e = event(&[("fd.name", "/etc/apt/sources.list.d/x.list")]);
    assert_eq!(
        truth("fd.name pmatch (/etc/apt, /usr/lib)", &e),
        Truth::True
    );
    assert_eq!(
        truth("fd.name pmatch (/etc/ap)", &e),
        Truth::False,
        "not a path boundary"
    );
    let exact = event(&[("fd.name", "/etc/apt")]);
    assert_eq!(truth("fd.name pmatch (/etc/apt)", &exact), Truth::True);
}

#[test]
fn intersects_is_true_when_any_element_is_shared() {
    let e = event(&[("proc.args", "-l -p 4444")]);
    assert_eq!(
        truth(r#"proc.args intersects ("-V", "-l", "-h")"#, &e),
        Truth::True
    );
    assert_eq!(
        truth(r#"proc.args intersects ("-V", "-h")"#, &e),
        Truth::False
    );
}

#[test]
fn exists_is_false_for_a_collected_field_with_no_value() {
    let mut e = event(&[("proc.name", "cat")]);
    e.set_absent("proc.pname");
    assert_eq!(truth("proc.pname exists", &e), Truth::False);
    assert_eq!(truth("proc.name exists", &e), Truth::True);
    // A comparison on a value that is not there is false, and `not` of it true.
    assert_eq!(truth("proc.pname = sh", &e), Truth::False);
    assert_eq!(truth("not proc.pname = sh", &e), Truth::True);
}

/// The rule the whole engine rests on: a field Topgent does not collect is
/// unknown, and unknown never becomes true or false by negation.
#[test]
fn a_field_not_collected_is_unknown_and_stays_unknown_under_not() {
    let e = event(&[("proc.name", "cat")]);
    assert_eq!(truth("proc.cmdline contains curl", &e), Truth::Unknown);
    assert_eq!(truth("not proc.cmdline contains curl", &e), Truth::Unknown);
    assert_eq!(truth("proc.cmdline exists", &e), Truth::Unknown);
    // Three-valued logic: false wins an `and`, true wins an `or`.
    assert_eq!(
        truth("proc.name = sh and proc.cmdline contains x", &e),
        Truth::False
    );
    assert_eq!(
        truth("proc.name = cat and proc.cmdline contains x", &e),
        Truth::Unknown
    );
    assert_eq!(
        truth("proc.name = cat or proc.cmdline contains x", &e),
        Truth::True
    );
    assert_eq!(
        truth("proc.name = sh or proc.cmdline contains x", &e),
        Truth::Unknown
    );
}

#[test]
fn and_binds_tighter_than_or_and_not_tighter_than_and() {
    let e = event(&[("a.x", "1"), ("a.y", "0"), ("a.z", "1")]);
    // a or (b and c)
    assert_eq!(truth("a.x = 1 or a.y = 1 and a.z = 0", &e), Truth::True);
    // (not a) and b
    assert_eq!(truth("not a.x = 1 and a.z = 1", &e), Truth::False);
    assert_eq!(truth("not (a.x = 1 and a.y = 1)", &e), Truth::True);
    assert_eq!(truth("((a.x = 1))", &e), Truth::True);
}

#[test]
fn field_arguments_are_passed_to_the_event() {
    let mut e = MapEvent::default();
    e.set_arg("proc.aname", "2", "codex");
    e.set_arg("proc.aname", "1", "sh");
    assert_eq!(truth("proc.aname[2] = codex", &e), Truth::True);
    assert_eq!(truth("proc.aname[1] = codex", &e), Truth::False);
    assert_eq!(
        truth("proc.aname[3] = codex", &e),
        Truth::Unknown,
        "not provided"
    );
}

#[test]
fn malformed_conditions_are_errors_not_panics() {
    for bad in [
        "",
        "(",
        "proc.name =",
        "proc.name in (a, b",
        "proc.name = 'unterminated",
        "and",
        "proc.name = a b",
        ")",
        "proc.name ~ a",
    ] {
        assert!(parse(bad).is_err(), "{bad:?} parsed");
    }
}

#[test]
fn deep_nesting_is_refused_rather_than_overflowing_the_stack() {
    let deep = format!("{}a.x = 1{}", "(".repeat(10_000), ")".repeat(10_000));
    assert!(parse(&deep).is_err());
    let nots = format!("{}a.x = 1", "not ".repeat(10_000));
    assert!(parse(&nots).is_err());
}

/// `fd.net`, `fd.snet`, `fd.cnet`, `fd.lnet` and `fd.rnet` hold an address and
/// compare against networks: `fd.net = 127.0.0.0/8` means "inside 127/8".
#[test]
fn network_fields_compare_by_containment() {
    let e = event(&[
        ("fd.net", "127.0.0.1"),
        ("fd.snet", "192.168.4.20"),
        ("fd.rnet", "2001:db8::7"),
    ]);
    assert_eq!(truth("fd.net = 127.0.0.0/8", &e), Truth::True);
    assert_eq!(truth("fd.net != 127.0.0.0/8", &e), Truth::False);
    assert_eq!(
        truth(
            r#"fd.snet in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")"#,
            &e
        ),
        Truth::True
    );
    assert_eq!(truth("fd.snet in (10.0.0.0/8)", &e), Truth::False);
    assert_eq!(truth("fd.rnet = 2001:db8::/32", &e), Truth::True);
    assert_eq!(truth("fd.rnet = 2001:db9::/32", &e), Truth::False);
    // A plain address is a network of one.
    assert_eq!(truth("fd.net = 127.0.0.1", &e), Truth::True);
    // Other fields keep plain text equality.
    let ip = event(&[("fd.ip", "127.0.0.1")]);
    assert_eq!(truth("fd.ip = 127.0.0.0/8", &ip), Truth::False);
}

/// A field that carries raw bytes, such as a read buffer, is matched on its
/// bytes: `CAFEBABE` is not valid text and must still be found.
#[test]
fn byte_operators_match_raw_bytes() {
    let mut e = MapEvent::default();
    e.set_bytes("evt.buffer", &[0x00, 0xca, 0xfe, 0xba, 0xbe, 0x01]);
    assert_eq!(truth("evt.buffer bcontains cafebabe", &e), Truth::True);
    assert_eq!(truth("evt.buffer bstartswith 00cafe", &e), Truth::True);
    assert_eq!(truth("evt.buffer bcontains cafe00", &e), Truth::False);
}

/// `proc.aname` with no index is every ancestor at once: a comparison holds
/// if any ancestor satisfies it. An empty chain holds nothing.
#[test]
fn an_unindexed_ancestor_field_matches_any_ancestor() {
    let mut e = MapEvent::default();
    e.set_many("proc.aname", &["sh", "sshd", "systemd"]);
    assert_eq!(truth("proc.aname = sshd", &e), Truth::True);
    assert_eq!(truth("proc.aname in (codex, systemd)", &e), Truth::True);
    assert_eq!(truth("proc.aname = codex", &e), Truth::False);
    assert_eq!(truth("proc.aname exists", &e), Truth::True);
    let mut orphan = MapEvent::default();
    orphan.set_many("proc.aname", &[]);
    assert_eq!(truth("proc.aname = sshd", &orphan), Truth::False);
    assert_eq!(truth("proc.aname exists", &orphan), Truth::False);
}

/// Process history can stop short of the root. The ancestors it holds are
/// some of the ancestors: a match among them is true, but no match is not
/// false, because an ancestor it never recorded might match.
#[test]
fn an_incomplete_ancestor_chain_is_true_on_a_match_and_unknown_otherwise() {
    let mut e = MapEvent::default();
    e.set_partial("proc.aname", &["sh", "codex"]);
    assert_eq!(truth("proc.aname = codex", &e), Truth::True);
    assert_eq!(truth("proc.aname = sshd", &e), Truth::Unknown);
    assert_eq!(
        truth("not proc.aname in (sshd, systemd)", &e),
        Truth::Unknown
    );
    assert_eq!(truth("proc.aname exists", &e), Truth::True);
}
