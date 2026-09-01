//! `topgent asset` — the inventory of what agents reach.

/// Set one inventory asset's global or agent-scoped disposition.
pub(crate) fn asset_command(args: &[String]) -> i32 {
    let (Some("set"), Some(asset_id), Some(disposition)) =
        (args.get(1).map(String::as_str), args.get(2), args.get(3))
    else {
        eprintln!(
            "topgent asset set <id> <unreviewed|approved|restricted|disallowed> [--agent FAMILY]"
        );
        return 2;
    };
    let family = args
        .iter()
        .position(|arg| arg == "--agent")
        .and_then(|index| args.get(index + 1));
    let out =
        topgent_report::set_asset_disposition(asset_id, family.map(String::as_str), disposition);
    println!("{out}");
    i32::from(out.get("ok") != Some(&serde_json::Value::Bool(true)))
}
