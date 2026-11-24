//! `topgent honeytoken` — planting, listing and removing decoy secrets.

/// Plant, list or remove honeytokens.
pub(crate) fn honeytoken_command(args: &[String]) -> i32 {
    let out = match (args.get(1).map(String::as_str), args.get(2)) {
        (Some("plant"), Some(dir)) => topgent_report::plant_honeytokens(dir),
        (Some("list"), None) => topgent_report::list_honeytokens(),
        (Some("remove"), Some(target)) => topgent_report::remove_honeytokens(target),
        _ => {
            eprintln!("topgent honeytoken plant <dir> | list | remove <path|all>");
            return 2;
        }
    };
    println!("{out}");
    i32::from(out.get("ok") != Some(&serde_json::Value::Bool(true)))
}
