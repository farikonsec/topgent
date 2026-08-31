//! `topgent context` — the semantic record an agent's own harness reported.

use crate::hooks::harness_hook;
use crate::hooks::hooks_command;
use crate::hooks::topgent_policy_enabled;
use crate::output::print_result;
use std::io::Read;
use topgent_journal::Journal;
use topgent_journal::SemanticRecord;

pub(crate) fn context_command(args: &[String]) -> i32 {
    match args.get(1).map(String::as_str) {
        Some("enable") => print_result(&topgent_report::set_semantic_enabled(true)),
        Some("disable") => print_result(&topgent_report::set_semantic_enabled(false)),
        Some("clear") => print_result(&topgent_report::clear_semantic_context()),
        Some("hook") => harness_hook(args),
        Some("hooks") => hooks_command(args),
        Some("ingest") if args.iter().any(|argument| argument == "--stdin") => {
            if !topgent_policy_enabled() {
                eprintln!("topgent context: disabled; run `topgent context enable` first");
                return 3;
            }
            let mut input = String::new();
            if let Err(error) = std::io::stdin().read_to_string(&mut input) {
                eprintln!("topgent context: {error}");
                return 1;
            }
            let value = match serde_json::from_str(&input) {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("topgent context: invalid JSON: {error}");
                    return 2;
                }
            };
            let Some(record) = SemanticRecord::from_untrusted(&value) else {
                eprintln!("topgent context: missing or invalid required fields");
                return 2;
            };
            match Journal::open_default().append_semantic(record) {
                Ok(()) => {
                    println!("{{\"ok\":true}}");
                    0
                }
                Err(error) => {
                    eprintln!("topgent context: {error}");
                    1
                }
            }
        }
        _ => {
            eprintln!("topgent context enable|disable|clear|ingest --stdin|hook <harness>");
            2
        }
    }
}
