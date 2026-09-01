//! `topgent events` — the journal, as a timeline.

use crate::output::stamp;
use topgent_journal::Journal;

/// Print the event log.
pub(crate) fn events_command(args: &[String]) -> i32 {
    let limit: usize = args
        .iter()
        .position(|a| a == "--limit")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(40);

    let journal = Journal::open_default();
    match journal.tail(limit) {
        Ok(entries) if entries.is_empty() => {
            println!("No events yet. The log is at {}", journal.path().display());
            0
        }
        Ok(entries) => {
            println!("\n  {:<14} {:<20} {:<9} DETAIL", "WHEN", "KIND", "PID");
            for e in entries {
                println!(
                    "  {:<14} {:<20} {:<9} {} — {}",
                    stamp(e.at),
                    e.kind.as_str(),
                    e.pid,
                    e.agent,
                    e.detail
                );
            }
            println!("\n  {}\n", journal.path().display());
            0
        }
        Err(e) => {
            eprintln!("topgent events: {e}");
            1
        }
    }
}
