//! The offline verifier.
//!
//! Decision D4 of `docs/MAJOR_UPGRADE_RESEARCH_PLAN.md`: a signature scheme only
//! its own producer can check proves nothing to a third party. This binary
//! exists so a researcher, an auditor, a customer, or a CI job can check a
//! Topgent bundle without running Topgent.
//!
//! It depends on `topgent-evidence` and nothing else. No collectors, no policy,
//! no report renderer, no user interface. If verifying required any of those,
//! verification would be a statement about the producer rather than about the
//! bundle.
//!
//! # What a pass means
//!
//! That the records were not modified, inserted, reordered, or truncated after
//! the covering checkpoint was signed, by a holder of the key you supplied. It
//! does not mean the sensor observed correctly, and it does not mean nothing
//! was missed. The second is why `intact, with holes` is a separate outcome
//! with its own exit code.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use topgent_evidence::{Bundle, PublicKey, Reader, Verdict};

const USAGE: &str = "\
topgent-verify <bundle> --key HEX    check against a key you already hold
topgent-verify <bundle> --self       internal consistency only, establishes no origin

Exit codes
  0  intact
  1  intact, with holes in the record stream
  2  broken, or the bundle could not be read
  3  usage
";

fn main() {
    std::process::exit(run());
}

/// Parses the arguments and verifies, returning the exit code.
fn run() -> i32 {
    // Reading argv is what a command-line tool does; every value is matched
    // against a fixed set below.
    let args: Vec<String> = std::env::args().skip(1).collect(); // nosemgrep: rust.lang.security.args.args

    if args.is_empty() || args.iter().any(|value| value == "--help" || value == "-h") {
        print!("{USAGE}");
        return 3;
    }
    let Some(path) = args.first().filter(|value| !value.starts_with('-')) else {
        eprint!("{USAGE}");
        return 3;
    };

    let bundle = match read(path) {
        Ok(bundle) => bundle,
        Err(reason) => {
            eprintln!("{reason}");
            return 2;
        }
    };

    let self_only = args.iter().any(|value| value == "--self");
    let trusted = match key_argument(&args) {
        Ok(Some(key)) => vec![key],
        Ok(None) if self_only => bundle.keys().to_vec(),
        Ok(None) => {
            eprintln!("topgent-verify: --key HEX or --self is required");
            return 3;
        }
        Err(reason) => {
            eprintln!("topgent-verify: {reason}");
            return 3;
        }
    };
    if self_only {
        println!("internal consistency only: the bundle supplied its own key, so this");
        println!("says nothing about where it came from.");
    }

    report(&bundle.verify(&trusted))
}

/// Reads and decodes a bundle.
///
/// Decoding runs every construction rule again, so a bundle holding a duplicate
/// address, a dangling reference, or a record that could not have been
/// collected is refused here rather than reaching the verification stage.
fn read(path: &str) -> Result<Bundle, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{path}: {error}"))?;
    Reader::read::<Bundle>(&bytes).map_err(|error| format!("{path}: {error}"))
}

/// The key after `--key`, when there is one.
fn key_argument(args: &[String]) -> Result<Option<PublicKey>, String> {
    let Some(at) = args.iter().position(|value| value == "--key") else {
        return Ok(None);
    };
    let Some(hex) = args.get(at.saturating_add(1)) else {
        return Err("--key needs a 64-character hex public key".to_owned());
    };
    PublicKey::from_hex(hex)
        .map(Some)
        .map_err(|error| format!("--key: {error}"))
}

/// Prints the verdict and returns the exit code.
fn report(verdict: &Verdict) -> i32 {
    match verdict {
        Verdict::Intact(summary) => {
            println!(
                "intact through sequence {} under key {}",
                summary.through_sequence,
                summary.key_id.short()
            );
            println!(
                "  {} record(s), {} claim(s), from {} on {}",
                summary.records,
                summary.claims,
                summary.origin.sensor_instance,
                summary.origin.host_id
            );
            println!("nothing was altered after signing. Whether the sensor was right, and");
            println!("whether anything was missed, are separate questions this cannot answer.");
            0
        }
        Verdict::IntactWithGaps { summary, gaps } => {
            println!(
                "intact through sequence {} under key {}, with holes",
                summary.through_sequence,
                summary.key_id.short()
            );
            for gap in gaps {
                println!("  {gap}");
            }
            println!("nothing was altered. Records are missing, and a partial disclosure and a");
            println!("sensor that dropped records look identical from here.");
            1
        }
        Verdict::Broken(breaches) => {
            for breach in breaches {
                eprintln!("{breach}");
            }
            eprintln!("{} problem(s)", breaches.len());
            2
        }
    }
}
