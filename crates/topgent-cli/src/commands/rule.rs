//! `topgent rule` — reading and setting the policy an installation runs.

/// Add or remove a watchlist rule.
pub(crate) fn rule_command(args: &[String]) -> i32 {
    match args.get(1).map(String::as_str) {
        Some("response") => {
            let (Some(index), Some(response)) = (
                args.get(2).and_then(|value| value.parse::<usize>().ok()),
                args.get(3),
            ) else {
                eprintln!("topgent rule response <index> <observe|alert|approval|block|kill>");
                return 2;
            };
            let out = topgent_report::set_rule_response(index, response);
            println!("{out}");
            i32::from(out.get("ok") != Some(&serde_json::Value::Bool(true)))
        }
        Some("add") => {
            let (Some(path), Some(cond), Some(sev)) = (args.get(2), args.get(3), args.get(4))
            else {
                eprintln!("topgent rule add <path> <reachable|observed|write> <critical|N>");
                return 2;
            };
            let out = topgent_report::add_rule(path, cond, sev);
            println!("{out}");
            i32::from(out.get("ok") != Some(&serde_json::Value::Bool(true)))
        }
        Some("remove") => {
            let Some(i) = args.get(2).and_then(|s| s.parse::<usize>().ok()) else {
                eprintln!("topgent rule remove <index>");
                return 2;
            };
            println!("{}", topgent_report::remove_rule(i));
            0
        }
        _ => {
            eprintln!("topgent rule add|remove …");
            2
        }
    }
}
