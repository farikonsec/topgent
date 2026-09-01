//! `topgent lab` — the reproducible scenarios the sensors are tested against.

pub(crate) fn lab_command(args: &[String]) -> i32 {
    match args.get(1).map(String::as_str) {
        Some("catalogue") => {
            let Ok(catalogue) = topgent_collect::signatures::builtin() else {
                eprintln!("topgent lab: built-in signature catalogue is invalid");
                return 2;
            };
            if args.iter().any(|argument| argument == "--json") {
                let families = catalogue
                    .families
                    .iter()
                    .map(|family| {
                        serde_json::json!({
                            "id": family.id,
                            "name": family.name,
                            "kind": family.kind.as_str(),
                            "verified_platforms": family.verified_platforms,
                            "last_verified_at": family.last_verified_at,
                            "provenance_required": !family.path_markers.is_empty(),
                        })
                    })
                    .collect::<Vec<_>>();
                println!(
                    "{}",
                    serde_json::json!({
                        "schema_version": catalogue.schema_version,
                        "source": catalogue.source,
                        "families": families,
                    })
                );
            } else {
                for family in &catalogue.families {
                    println!(
                        "{:<18} {:<16} {}",
                        family.id,
                        family.kind.as_str(),
                        family.name
                    );
                }
            }
            0
        }
        Some("assert") => {
            let (Some(family), Some(state)) = (args.get(2), args.get(3)) else {
                eprintln!(
                    "topgent lab assert <family> <absent|idle|clean|running> [--listener PORT] [--json]"
                );
                return 2;
            };
            let expected = match state.as_str() {
                "absent" | "idle" | "clean" => topgent_lab::ExpectedState::Absent,
                "running" => topgent_lab::ExpectedState::Running,
                _ => {
                    eprintln!("topgent lab: unknown expected state {state}");
                    return 2;
                }
            };
            let known = topgent_collect::signatures::builtin()
                .is_ok_and(|catalogue| catalogue.families.iter().any(|entry| entry.id == *family));
            if !known {
                eprintln!("topgent lab: unknown family {family}");
                return 2;
            }
            let listener = args
                .iter()
                .position(|argument| argument == "--listener")
                .and_then(|index| args.get(index + 1))
                .and_then(|value| value.parse::<u16>().ok());
            if args.iter().any(|argument| argument == "--listener") && listener.is_none() {
                eprintln!("topgent lab: --listener requires a TCP port from 1 to 65535");
                return 2;
            }
            let result = topgent_lab::evaluate(
                &topgent_report::scan(),
                &topgent_lab::CheckRequest {
                    family,
                    state: expected,
                    listener,
                },
            );
            if args.iter().any(|argument| argument == "--json") {
                println!("{}", serde_json::to_string(&result).unwrap_or_default());
            } else if result.passed {
                println!("PASS: {family} {state}");
            } else {
                println!("FAIL: {family} {state}: {}", result.failures.join("; "));
            }
            i32::from(!result.passed)
        }
        _ => {
            eprintln!("topgent lab catalogue|assert");
            2
        }
    }
}
