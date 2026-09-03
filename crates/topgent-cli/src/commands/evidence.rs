//! `topgent evidence` — read a bundle without trusting the thing that wrote it.
//!
//! Milestone M1 of `docs/MAJOR_UPGRADE_RESEARCH_PLAN.md`. `explain` is its exit
//! test: any statement Topgent makes must resolve to the records it came from,
//! and a reader must be able to walk that path knowing only the bundle format.
//!
//! Nothing here consults the journal, the report, or a running sensor. That is
//! the point: decision D4 makes the verifier independent, and a verifier that
//! needs the producer to be running verifies nothing.

use topgent_evidence::{Bundle, Ledger, PublicKey, Reader, Verdict};

use crate::output::option_value;

const USAGE: &str = "\
topgent evidence explain <claim-id> --bundle PATH     the records behind one claim
topgent evidence list --bundle PATH                   every claim in the bundle
topgent evidence verify --bundle PATH --key HEX       check against a key you hold
topgent evidence verify --bundle PATH --self          internal consistency only

Exit codes: 0 intact, 1 intact with gaps or not found, 2 broken or unusable.
";

pub(crate) fn evidence_command(args: &[String]) -> i32 {
    let Some(action) = args.get(1).map(String::as_str) else {
        eprint!("{USAGE}");
        return 2;
    };
    let Some(path) = option_value(args, "--bundle") else {
        eprintln!("topgent evidence: --bundle PATH is required");
        return 2;
    };
    let bundle = match load(path) {
        Ok(bundle) => bundle,
        Err(error) => {
            eprintln!("topgent evidence: {error}");
            return 2;
        }
    };

    match action {
        "explain" => explain(bundle.ledger(), args),
        "list" => list(bundle.ledger()),
        "verify" => verify(&bundle, args),
        _ => {
            eprint!("{USAGE}");
            2
        }
    }
}

/// Reads a bundle from disk.
///
/// Every construction rule runs again on the way in, so a bundle holding a
/// duplicate address, a dangling reference, or a record that could not have
/// been collected is refused here rather than surfacing as a strange report.
fn load(path: &str) -> Result<Bundle, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{path}: {error}"))?;
    Reader::read::<Bundle>(&bytes).map_err(|error| format!("{path}: {error}"))
}

/// Prints the full derivation of one claim.
fn explain(ledger: &Ledger, args: &[String]) -> i32 {
    let Some(wanted) = args.get(2).filter(|value| !value.starts_with("--")) else {
        eprintln!("topgent evidence explain: a claim id is required");
        return 2;
    };
    let Some(claim) = ledger.resolve_claim(wanted) else {
        eprintln!("topgent evidence explain: no single claim matches {wanted}");
        return 1;
    };
    let Some(derivation) = ledger.explain(claim.id()) else {
        eprintln!("topgent evidence explain: {wanted} resolved but could not be explained");
        return 1;
    };
    print!("{}", derivation.render());
    0
}

/// Prints one line per claim.
fn list(ledger: &Ledger) -> i32 {
    for claim in ledger.claims() {
        println!(
            "{}  {:<9} {:<20} {}",
            claim.id().short(),
            claim.quality().as_str(),
            claim.coverage().as_str(),
            claim.statement()
        );
    }
    0
}

/// Checks the bundle against keys the caller supplies.
///
/// `--key` is the honest mode: the verifier holds the key and the bundle does
/// not get to nominate its own. `--self` checks internal consistency only and
/// says so on every line of output, because a bundle that vouches for itself
/// establishes nothing about where it came from.
fn verify(bundle: &Bundle, args: &[String]) -> i32 {
    let self_only = args.iter().any(|argument| argument == "--self");
    let trusted = match option_value(args, "--key") {
        Some(hex) => match PublicKey::from_hex(hex) {
            Ok(key) => vec![key],
            Err(error) => {
                eprintln!("topgent evidence verify: --key: {error}");
                return 2;
            }
        },
        None if self_only => bundle.keys().to_vec(),
        None => {
            eprintln!("topgent evidence verify: --key HEX or --self is required");
            return 2;
        }
    };
    if self_only {
        println!("checking internal consistency only; nothing here establishes origin");
    }

    match bundle.verify(&trusted) {
        Verdict::Intact(summary) => {
            println!(
                "intact through sequence {} under key {}: {} record(s), {} claim(s) from {}",
                summary.through_sequence,
                summary.key_id.short(),
                summary.records,
                summary.claims,
                summary.origin.sensor_instance
            );
            println!("this says nothing was altered; it does not say the sensor was right");
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
            println!("nothing was altered; records are missing and the bundle cannot say why");
            1
        }
        Verdict::Broken(breaches) => {
            for breach in &breaches {
                eprintln!("{breach}");
            }
            eprintln!("{} problem(s) found", breaches.len());
            2
        }
    }
}
