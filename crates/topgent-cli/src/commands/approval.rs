//! `topgent approval` — granting, listing and revoking the consent a stop needs.

pub(crate) fn approval_command(args: &[String]) -> i32 {
    if args.get(1).map(String::as_str) != Some("resolve") {
        eprintln!(
            "topgent approval resolve <request-id> <pid> <started-at-ms> <approve|deny> [--yes]"
        );
        return 2;
    }
    let Some(request_id) = args.get(2) else {
        eprintln!("topgent approval resolve: request-id is required");
        return 2;
    };
    let Some(pid) = args.get(3).and_then(|value| value.parse::<u32>().ok()) else {
        eprintln!("topgent approval resolve: pid must be a number");
        return 2;
    };
    let Some(started_at) = args.get(4).and_then(|value| value.parse::<u64>().ok()) else {
        eprintln!("topgent approval resolve: started-at-ms must be a number");
        return 2;
    };
    let approve = match args.get(5).map(String::as_str) {
        Some("approve") => true,
        Some("deny") => false,
        _ => {
            eprintln!("topgent approval resolve: decision must be approve or deny");
            return 2;
        }
    };
    if approve && !args.iter().any(|argument| argument == "--yes") {
        eprintln!("topgent approval resolve: approval will stop the exact agent process.");
        eprintln!("Re-run with --yes to approve and execute guarded termination.");
        return 3;
    }
    let outcome =
        topgent_report::resolve_termination_approval(request_id, pid, started_at, approve);
    println!("{outcome}");
    i32::from(outcome.get("ok").and_then(serde_json::Value::as_bool) != Some(true))
}
