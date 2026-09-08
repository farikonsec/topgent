//! `topgent capture` — what deeper network visibility would add, and its price.
//!
//! The same words the desktop button shows, available without the desktop. A
//! capability described in one place and offered in two is a capability whose
//! description can drift; this and the window read the same data.
//!
//! Nothing here elevates anything. The command prints the step and the operator
//! runs it, which is the whole point: the operating system does the asking, and
//! Topgent goes on running as an ordinary user afterwards.

const USAGE: &str = "\
topgent capture status          what deeper visibility would add here, and what it needs
topgent capture status --json   the same, machine-readable

Exit codes: 0 available, 1 a grant is needed, 2 unsupported or unusable.
";

pub(crate) fn capture_command(args: &[String]) -> i32 {
    if args.get(1).map(String::as_str) != Some("status") {
        eprint!("{USAGE}");
        return 2;
    }
    let offer = topgent_collect::capture::offer();

    let exposure = topgent_collect::capture::exposure();

    if args.iter().any(|argument| argument == "--json") {
        println!("{}", as_json(&offer, exposure.as_deref()));
    } else {
        println!("{offer}");
        // After the offer, because it is a note about a working install rather
        // than a reason capture is unavailable. It does not change the exit
        // code for the same reason: nothing here stops capture.
        if let Some(detail) = &exposure {
            println!();
            println!("Wider than it needs to be: {detail}");
        }
    }

    match offer.state {
        // A grant that has landed and needs a restart is a success, and a
        // pipeline that treated it as a failure would keep asking for it.
        topgent_collect::capture::State::Available
        | topgent_collect::capture::State::NeedsRestart { .. } => 0,
        topgent_collect::capture::State::NeedsGrant { .. } => 1,
        topgent_collect::capture::State::Unsupported { .. }
        | topgent_collect::capture::State::Unknown { .. } => 2,
    }
}

/// The offer as data, for the interface and for a pipeline.
fn as_json(offer: &topgent_collect::capture::Offer, exposure: Option<&str>) -> serde_json::Value {
    use topgent_collect::capture::{Remedy, State};
    let mut row = serde_json::json!({
        "state": offer.state.as_str(),
        "grantable": offer.state.is_grantable(),
        "privilege": offer.privilege,
        "gains": offer.gains,
        "limits": offer.limits,
        "exposure": exposure,
    });
    // Built through the map rather than through indexing. `Value`'s index
    // operator panics on a shape it did not expect, and a status command that
    // can panic while reporting a status is worse than no status command.
    let Some(fields) = row.as_object_mut() else {
        return row;
    };
    let mut put = |key: &str, value: serde_json::Value| {
        fields.insert(key.to_owned(), value);
    };
    match &offer.state {
        State::NeedsGrant { missing, remedy } => {
            put("missing", missing.clone().into());
            put(
                "remedy",
                match remedy {
                    Remedy::Command {
                        command,
                        effect,
                        undo,
                    } => serde_json::json!({
                        "kind": "command",
                        "command": command,
                        "effect": effect,
                        "undo": undo,
                    }),
                    Remedy::Install { what, source } => serde_json::json!({
                        "kind": "install",
                        "what": what,
                        "source": source,
                    }),
                },
            );
        }
        State::NeedsRestart { detail } | State::Unknown { detail } => {
            put("detail", detail.clone().into());
        }
        State::Unsupported { reason } => put("reason", reason.clone().into()),
        State::Available => {}
    }
    row
}
