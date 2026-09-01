//! `topgent network` — the retained endpoint history for one agent.

pub(crate) fn network_command(args: &[String]) -> i32 {
    if args.get(1).map(String::as_str) != Some("baseline")
        || args.get(2).map(String::as_str) != Some("reset")
    {
        eprintln!("topgent network baseline reset <pid> <started-at-ms> [--yes]");
        return 2;
    }
    let Some(pid) = args.get(3).and_then(|value| value.parse::<u32>().ok()) else {
        eprintln!("topgent network baseline reset: pid must be a number");
        return 2;
    };
    let Some(started_at) = args.get(4).and_then(|value| value.parse::<u64>().ok()) else {
        eprintln!("topgent network baseline reset: started-at-ms must be a number");
        return 2;
    };
    if !args.iter().any(|argument| argument == "--yes") {
        eprintln!(
            "topgent network baseline reset: this removes retained network history only for pid {pid}, start {started_at}."
        );
        eprintln!("Re-run with --yes to begin a fresh collecting baseline.");
        return 3;
    }
    let outcome = topgent_report::reset_network_baseline(pid, started_at);
    println!("{outcome}");
    i32::from(outcome.get("ok").and_then(serde_json::Value::as_bool) != Some(true))
}
