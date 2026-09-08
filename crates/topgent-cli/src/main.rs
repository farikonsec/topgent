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

  topgent --evidence-out PATH   write a signed evidence bundle for this sweep
  topgent replay <bundle>       score a bundle without touching the host
  topgent capture status        what deeper network visibility would add, and its price

  topgent export cyclonedx [--format json|html] [--output PATH]
  topgent policy check [--input REPORT] [--threshold LEVEL] [--require-coverage]
  topgent evidence explain <claim-id> --bundle PATH

  topgent --version        which build this is

Full command reference: https://github.com/farikonsec/topgent
";

fn main() {
    // Reading argv is what a command-line tool does; every value is matched
    // against a fixed set below.
    let Some(args) = arguments() else {
        eprintln!("topgent: an argument is not valid text, and every option this tool takes is");
        std::process::exit(2);
    };

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{USAGE}");
        return;
    }

    // The version a report carries is the one the binary was built from, and a
    // person holding an unmarked download needs a way to ask which that is.
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("topgent {}", topgent_report::version());
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
            "replay" => Some(commands::replay::replay_command(&args)),
            "lab" => Some(commands::lab::lab_command(&args)),
            "export" => Some(commands::export::export_command(&args)),
            "policy" => Some(commands::policy::policy_command(&args)),
            "rule" => Some(commands::rule::rule_command(&args)),
            "asset" => Some(commands::asset::asset_command(&args)),
            "context" => Some(commands::context::context_command(&args)),
            "capture" => Some(commands::capture::capture_command(&args)),
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

    // A bundle is a second artefact of the same sweep, so asking for one takes
    // the path that keeps the sweep rather than running the collectors twice.
    if let Some(path) = args
        .iter()
        .position(|a| a == "--evidence-out")
        .and_then(|i| args.get(i + 1))
    {
        let state = topgent_report::default_state();
        let (report, bundle) = topgent_report::scan_with_evidence(&state);
        match bundle {
            Ok(bundle) => {
                if let Err(error) = std::fs::write(path, topgent_evidence::Canonical::of(&bundle)) {
                    eprintln!("topgent: {path}: {error}");
                    std::process::exit(2);
                }
                // The key is printed so the operator can verify the bundle
                // without asking the process that wrote it for permission.
                match topgent_report::sensor_key(&state) {
                    Ok(key) => eprintln!(
                        "wrote {path}: {} records, verify with --key {}",
                        bundle.ledger().record_count(),
                        key.public().to_hex()
                    ),
                    Err(error) => {
                        eprintln!("wrote {path}, but the key could not be printed: {error}");
                    }
                }
            }
            Err(error) => {
                eprintln!("topgent: no evidence bundle written: {error}");
                std::process::exit(2);
            }
        }
        // The table view runs its own sweep, and re-sweeping here would print a
        // different moment from the one just signed. So this path prints the
        // report it actually has, or nothing but the summary line above.
        if json_out {
            println!("{report}");
        }
        return;
    }

    if json_out {
        println!("{}", topgent_report::scan());
        return;
    }
    render::render(show_facts);
}

/// The command line as text, or nothing when one argument is not text.
///
/// `std::env::args` panics on an argument that is not valid Unicode, and on
/// any Unix a file path is a bag of bytes, so a real path can be handed in
/// that it will not accept. Panicking while reading your own command line is a
/// poor answer from a tool that reports on other software. Converting lossily
/// is worse: a mangled path names a different file, and the tool would then
/// read the wrong one and say nothing about it. So it refuses instead.
fn arguments() -> Option<Vec<String>> {
    // The rule fires on reading argv at all, which is the one thing a
    // command-line tool has to do. Every value is matched against a fixed set
    // below and none of them reaches a shell.
    // nosemgrep: rust.lang.security.args-os.args-os
    std::env::args_os()
        .skip(1)
        .map(|argument| argument.into_string().ok())
        .collect()
}
