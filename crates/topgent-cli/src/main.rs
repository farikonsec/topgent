//! Headless Topgent.
//!
//! Runs the collectors, folds the facts, scores every agent and prints. The
//! desktop app consumes exactly the same JSON this emits, so anything the app
//! shows can be reproduced from a terminal and pasted into a bug report.
//!
//! This file is dispatch and nothing else. Each subcommand lives in its own
//! module under `commands/`, takes the raw argument list and returns the exit
//! code, because CI reads those codes and they are part of the contract.

#![forbid(unsafe_code)]

mod commands;
mod hooks;
mod output;
mod render;
mod style;

pub(crate) const USAGE: &str = "\
topgent - AI agent security monitor

  topgent                  what is running now
  topgent --json           the same, machine-readable
  topgent --watch          keep looking
  topgent doctor           which sensors work on this host
  topgent events           what changed
  topgent stop <pid>       terminate a process, re-checking its identity first

  topgent export cyclonedx [--format json|html] [--output PATH]
  topgent policy check [--input REPORT] [--threshold LEVEL] [--require-coverage]
  topgent evidence explain <claim-id> --bundle PATH

  topgent --version        which build this is

Full command reference: https://github.com/farikonsec/topgent
";

fn main() {
    // Reading argv is what a command-line tool does; every value is matched against a
    // fixed set below.
    let args: Vec<String> = std::env::args().skip(1).collect(); // nosemgrep: rust.lang.security.args.args

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{USAGE}");
        return;
    }

    // The version a report carries is the one the binary was built from, and a
    // person holding an unmarked download needs a way to ask which that is.
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("topgent {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    // `stop` and `kill` are the same command, and `events` and `log` are the
    // same command. Both pairs exist because people reach for either word.
    if let Some(name) = args.first() {
        let code = match name.as_str() {
            "stop" | "kill" => Some(commands::stop::stop_command(&args)),
            "events" | "log" => Some(commands::events::events_command(&args)),
            "doctor" => Some(commands::doctor::doctor_command(&args)),
            "evidence" => Some(commands::evidence::evidence_command(&args)),
            "lab" => Some(commands::lab::lab_command(&args)),
            "export" => Some(commands::export::export_command(&args)),
            "policy" => Some(commands::policy::policy_command(&args)),
            "rule" => Some(commands::rule::rule_command(&args)),
            "asset" => Some(commands::asset::asset_command(&args)),
            "context" => Some(commands::context::context_command(&args)),
            "network" => Some(commands::network::network_command(&args)),
            "approval" => Some(commands::approval::approval_command(&args)),
            _ => None,
        };
        if let Some(code) = code {
            std::process::exit(code);
        }
    }

    // No subcommand: scan and print.
    let json_out = args.iter().any(|a| a == "--json");
    let show_facts = args.iter().any(|a| a == "--facts");
    let watch = args.iter().any(|a| a == "--watch");
    let every: u64 = args
        .iter()
        .position(|a| a == "--every")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_500);

    if watch {
        loop {
            // Clear and home, so the table refreshes in place like a task
            // manager rather than scrolling away.
            print!("\x1b[2J\x1b[H");
            render::render(show_facts);
            std::thread::sleep(std::time::Duration::from_millis(every.max(200)));
        }
    }

    if json_out {
        println!("{}", topgent_report::scan());
        return;
    }
    render::render(show_facts);
}
