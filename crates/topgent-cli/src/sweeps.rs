//! `--json --sweeps N`: several sweeps in one process.
//!
//! Separate from the dispatch because it is the one path that keeps a
//! process, and so a running sensor, across sweeps. A single sweep sees only
//! what happens during its own second.

/// Prints the report of the last of `--sweeps N` sweeps, or of each; with
/// `--follow`, a report per sweep until stdout closes.
pub(crate) fn print(args: &[String], every: u64) {
    if args.iter().any(|a| a == "--follow") {
        follow(every);
        return;
    }
    // `--sweeps N` keeps one process, and so one running sensor, across N
    // sweeps `--every` apart, and prints the last. A single sweep sees only
    // what happens during its own second; a sensor that runs between
    // sweeps is what catches a process shorter than one.
    let sweeps: u32 = args
        .iter()
        .position(|a| a == "--sweeps")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(1)
        .clamp(1, 1_000);
    // `--each` prints every sweep, one report per line: loss and sensor
    // gaps are per interval, and the last sweep alone can hide them.
    let each = args.iter().any(|a| a == "--each");
    for _ in 1..sweeps {
        let report = topgent_report::scan();
        if each {
            println!("{report}");
        }
        std::thread::sleep(std::time::Duration::from_millis(every.max(200)));
    }
    println!("{}", topgent_report::scan());
}

/// `--json --follow`: one report per line, a sweep every `every` ms, until
/// whoever reads stops reading. One process, so one running sensor, for as
/// long as a front end runs: the development viewer reads this, and so sees
/// what the desktop application sees, sweep for sweep.
fn follow(every: u64) {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    loop {
        let report = topgent_report::scan();
        // A closed pipe is the reader gone: stop, rather than sweep for no one.
        if writeln!(out, "{report}")
            .and_then(|()| out.flush())
            .is_err()
        {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(every.max(200)));
    }
}
