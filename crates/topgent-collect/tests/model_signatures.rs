//! What the model reader must and must not accept.
//!
//! A config file belongs to the agent, and the agent is the thing being
//! watched. Everything here treats its contents as hostile.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use topgent_collect::model::{Certainty, SourceKind, admissible, builtin, extract, provider_of};

#[test]
fn the_shipped_signatures_are_valid() {
    let s = builtin().expect("the built-in signatures load");
    assert!(s.families.len() >= 5);
    assert!(!s.providers.is_empty());
}

#[test]
fn a_transcript_is_read_before_a_config_file() {
    // The order is the answer. A config says what was asked for; a transcript
    // says what actually ran, and they disagree the moment somebody overrides
    // the model for one session.
    let s = builtin().expect("loads");
    let claude = s
        .families
        .iter()
        .find(|f| f.family == "claude-code")
        .expect("claude-code is described");
    assert_eq!(
        claude.sources.first().map(|src| src.kind),
        Some(SourceKind::Jsonl)
    );
    assert_eq!(
        claude.sources.first().map(|src| src.certainty),
        Some(Certainty::Observed)
    );
    assert_eq!(
        claude.sources.get(1).map(|src| src.certainty),
        Some(Certainty::Declared)
    );
}

#[test]
fn the_placeholder_claude_writes_into_its_own_log_is_not_a_model() {
    // Verified on a real transcript: alongside genuine entries it contains
    // `"model":"<synthetic>"`. A reader that did not know would report it as
    // something somebody is running.
    let s = builtin().expect("loads");
    assert!(!admissible(s, "<synthetic>"));
    assert!(!admissible(s, "unknown"));
    assert!(!admissible(s, "  "));
    assert!(admissible(s, "claude-opus-5"));
}

#[test]
fn a_model_name_cannot_smuggle_content_into_a_report() {
    let s = builtin().expect("loads");
    assert!(!admissible(s, &"a".repeat(s.max_model_bytes + 1)));
    assert!(!admissible(s, "gpt-4\nSTATUS: everything is fine"));
    assert!(!admissible(s, "gpt-4\r\nrogue"));
    assert!(!admissible(s, "gpt\u{0}-4"));
}

#[test]
fn the_provider_is_read_from_the_model_string_not_assumed() {
    // The case the old hardcoded reader got wrong: an agent that routes
    // through a gateway is not running the gateway's own model.
    let s = builtin().expect("loads");
    assert_eq!(provider_of(s, "openrouter/qwen/qwen3-flash", ""), "alibaba");
    assert_eq!(provider_of(s, "claude-opus-5", ""), "anthropic");
    assert_eq!(provider_of(s, "gpt-4", ""), "openai");
    assert_eq!(provider_of(s, "deepseek/deepseek-v4", ""), "deepseek");
}

#[test]
fn a_model_nothing_recognises_falls_back_to_the_family_default() {
    let s = builtin().expect("loads");
    assert_eq!(provider_of(s, "some-local-thing", "meta"), "meta");
    assert_eq!(provider_of(s, "some-local-thing", ""), "");
}

#[test]
fn each_reader_finds_the_key_and_only_the_key() {
    assert_eq!(
        extract(
            SourceKind::Json,
            r#"{"model":"gpt-4","other":"x"}"#,
            "model"
        ),
        Some("gpt-4".to_owned())
    );
    assert_eq!(
        extract(
            SourceKind::Keyvalue,
            "model = \"o3-mini\"\nsandbox = true",
            "model"
        ),
        Some("o3-mini".to_owned())
    );
    assert_eq!(
        extract(SourceKind::Keyvalue, "GOOSE_MODEL: llama3\n", "GOOSE_MODEL"),
        Some("llama3".to_owned())
    );
}

#[test]
fn a_transcript_reports_the_newest_answer_not_the_first() {
    // Append-only: the last line naming the model is the current one.
    let text = concat!(
        "{\"message\":{\"model\":\"claude-sonnet-4-6\"}}\n",
        "{\"message\":{\"model\":\"claude-opus-5\"}}\n"
    );
    assert_eq!(
        extract(SourceKind::Jsonl, text, "model"),
        Some("claude-opus-5".to_owned())
    );
}

#[test]
fn a_file_that_is_not_what_the_signature_expected_yields_nothing() {
    // Never a panic, never a guess.
    for text in ["", "not json at all", "{", "\u{0}\u{1}\u{2}", "[]", "null"] {
        for kind in [SourceKind::Json, SourceKind::Jsonl] {
            let _ = extract(kind, text, "model");
        }
    }
    assert_eq!(extract(SourceKind::Json, "not json", "model"), None);
    assert_eq!(extract(SourceKind::Jsonl, "{ broken", "model"), None);
}

#[test]
fn no_signature_can_read_outside_the_home_directory() {
    // The one place a data file could turn into a filesystem walk. Absolute
    // paths, parent traversal and backslashes are refused by validation, so a
    // bad signature reads a file that is not there rather than one that is.
    let s = builtin().expect("loads");
    for family in &s.families {
        for source in &family.sources {
            assert!(!source.path.starts_with('/'), "{}", source.path);
            assert!(!source.path.starts_with('~'), "{}", source.path);
            assert!(!source.path.contains(".."), "{}", source.path);
            assert!(!source.path.contains('\\'), "{}", source.path);
        }
    }
}

#[test]
fn an_argv_source_reads_one_flag_and_nothing_else() {
    // The mitigation is the shape of the function, not a promise. There is no
    // way to obtain the rest of a command line through it, whatever the
    // signature says, so a signature cannot be written that leaks one.
    use topgent_collect::model::flag_value;

    // Our own process. The flag is absent, so there is nothing to return, and
    // the important part is that nothing else comes back either.
    let me = std::process::id();
    assert_eq!(flag_value(me, "--model-that-is-not-there"), None);

    // A flag that is not a flag is refused before anything is read.
    assert_eq!(flag_value(me, "model"), None);
    assert_eq!(flag_value(me, ""), None);
    assert_eq!(flag_value(me, "  "), None);

    // A process that does not exist is an ordinary answer, not a failure.
    assert_eq!(flag_value(u32::MAX, "--model"), None);
}

#[test]
fn the_family_that_needs_argv_reads_it_first() {
    // OpenCode states its model nowhere else. Its config names none and its log
    // is shared across every session on the host.
    let s = builtin().expect("loads");
    let opencode = s
        .families
        .iter()
        .find(|f| f.family == "opencode")
        .expect("opencode is described");
    let first = opencode.sources.first().expect("it has sources");
    assert_eq!(first.kind, SourceKind::Argv);
    assert_eq!(first.flag.as_deref(), Some("--model"));
    assert_eq!(first.certainty, Certainty::Observed);
}

#[test]
fn the_family_that_does_not_need_argv_reads_it_last() {
    // Claude Code answers from a transcript and a settings file. Reading a
    // command line when a file already answered would take the risk for
    // nothing.
    let s = builtin().expect("loads");
    let claude = s
        .families
        .iter()
        .find(|f| f.family == "claude-code")
        .expect("described");
    assert_eq!(
        claude.sources.last().map(|src| src.kind),
        Some(SourceKind::Argv)
    );
    assert_ne!(
        claude.sources.first().map(|src| src.kind),
        Some(SourceKind::Argv)
    );
}

#[test]
fn an_argv_source_that_also_names_a_file_is_refused() {
    // The two are different readers and a source that claimed both would have
    // no defined behaviour.
    let bad = r#"{
        "schema_version": 1, "source": "test", "max_model_bytes": 64,
        "reject": [], "providers": [],
        "families": [{ "family": "x", "default_provider": "",
          "sources": [{ "kind": "argv", "flag": "--model", "certainty": "observed",
                        "path": ".config/x.json", "key": "model" }] }]
    }"#;
    let parsed: topgent_collect::model::Signatures = serde_json::from_str(bad).expect("it parses");
    let error = topgent_collect::model::validate(&parsed).expect_err("it does not validate");
    assert!(error.contains("no path or key"), "{error}");
}

#[test]
fn a_flag_that_is_not_a_flag_is_refused_at_load() {
    let bad = r#"{
        "schema_version": 1, "source": "test", "max_model_bytes": 64,
        "reject": [], "providers": [],
        "families": [{ "family": "x", "default_provider": "",
          "sources": [{ "kind": "argv", "flag": "model", "certainty": "observed" }] }]
    }"#;
    let parsed: topgent_collect::model::Signatures = serde_json::from_str(bad).expect("it parses");
    assert!(topgent_collect::model::validate(&parsed).is_err());
}
