//! `topgent lab benchmark` — score the collectors against a known run.
//!
//! Milestone M9 of `docs/MAJOR_UPGRADE_RESEARCH_PLAN.md`, against the snapshot
//! collectors that ship today rather than against collectors that do not exist
//! yet. The snapshot limits are the result: a periodic sweep cannot see a
//! process that lived and died between two sweeps, and a measured number for
//! how much it misses is worth more than a promise to fix it later.
//!
//! The fixture is a separate binary that records what it did from its own
//! return values, so the thing measured and the thing measuring cannot share a
//! bug. It binds loopback and writes to a temporary directory it created;
//! nothing here reaches the network.

use topgent_lab::bench::{Benchmark, CollectorTiming, GroundTruth, evaluate};

use crate::output::option_value;

const USAGE: &str = "\
topgent lab benchmark [--json] [--hold-ms 8000] [--fixture PATH]

Scores the collectors against a fixture run whose behaviour is known exactly.
Exit codes: 0 scored, 1 a fixture process was classified as an agent, 2 could
not run.
";

pub(crate) fn benchmark_command(args: &[String]) -> i32 {
    if args.iter().any(|value| value == "--help") {
        print!("{USAGE}");
        return 0;
    }
    let hold_ms: u64 = option_value(args, "--hold-ms")
        .and_then(|value| value.parse().ok())
        .unwrap_or(8_000);

    let fixture = match fixture_path(args) {
        Ok(path) => path,
        Err(reason) => {
            eprintln!("topgent lab benchmark: {reason}");
            return 2;
        }
    };
    // The fixture runs under a name the catalogue recognises. Three of
    // Topgent's collectors produce detail only for a process it has classified
    // as an agent, so a fixture that is deliberately unrecognised scores zero
    // on ancestry, sockets and reachability by construction, and the benchmark
    // measures nothing about them. Recognised, they become numbers.
    //
    // What that costs is the false-positive check: a fixture that is meant to
    // be recognised cannot also prove that an unrecognised one is left alone.
    // `--unrecognised` keeps the old shape for exactly that, and the report
    // says which run it was.
    let recognised = !args.iter().any(|value| value == "--unrecognised");
    let staged = match stage(&fixture, recognised) {
        Ok(path) => path,
        Err(reason) => {
            eprintln!("topgent lab benchmark: {reason}");
            return 2;
        }
    };
    let fixture = staged.clone();

    let truth_path = scratch(&format!("topgent-truth-{}.json", std::process::id()));

    let mut child = match spawn_fixture(&fixture, &truth_path, hold_ms) {
        Ok(child) => child,
        Err(error) => {
            eprintln!("topgent lab benchmark: {error}");
            return 2;
        }
    };

    let truth = match wait_for_truth(&truth_path) {
        Ok(truth) => truth,
        Err(reason) => {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!("topgent lab benchmark: {reason}");
            return 2;
        }
    };
    if !truth.is_known_schema() {
        let _ = child.kill();
        eprintln!(
            "topgent lab benchmark: the fixture wrote schema {}, this build reads {}",
            truth.schema,
            topgent_lab::bench::GROUND_TRUTH_SCHEMA
        );
        return 2;
    }

    // The interval the lifetime split is made against is measured, not assumed.
    // It is how long the fixture had been running when the sweep happened, so
    // anything shorter-lived than that was already gone before the collectors
    // had their one look.
    let sweep_at = now_ms();
    let resident_before = topgent_collect::overhead::resident_bytes();
    let started = std::time::Instant::now();
    let sweep = topgent_collect::sweep(&benchmark_collectors(), &topgent_collect::SystemClock);
    let sweep_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let resident_after = topgent_collect::overhead::resident_bytes();
    let interval = sweep_at.saturating_sub(truth.started_at_ms).max(1);

    let mut report = evaluate(&truth, &sweep.facts, interval);
    report.recognised = recognised;
    report.overhead = Some(topgent_lab::bench::Overhead {
        sweep_ms,
        resident_before,
        resident_after,
    });
    report.notes = topgent_lab::bench::notes_for_report(&report);
    report.collectors = sweep
        .runs
        .iter()
        .map(|run| CollectorTiming {
            collector: run.collector.to_owned(),
            state: run.state.as_str().to_owned(),
            facts: run.fact_count,
            duration_ms: run.duration_ms,
            dropped_events: run.dropped_events,
        })
        .collect();

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(&truth_path);
    if recognised && let Some(parent) = staged.parent() {
        let _ = std::fs::remove_dir_all(parent);
    }

    if args.iter().any(|value| value == "--json") {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(error) => {
                eprintln!("topgent lab benchmark: {error}");
                return 2;
            }
        }
    } else {
        print!("{}", render(&report));
    }

    // Unrecognised: any classified fixture process is a false positive.
    // Recognised: exactly the root should be, and no descendant.
    let expected = usize::from(recognised);
    i32::from(report.false_agents != expected)
}

/// The collectors, with the process sweep set to report every process.
///
/// The shipping default emits a process fact only for a recognised agent
/// family, which is right for a report about agents and wrong for a benchmark
/// about visibility. Measured on Kali: with the default, a host running no
/// agent produced zero facts from all eight collectors, and the benchmark
/// scored zero recall against a fixture the tool had simply not been asked to
/// look at.
///
/// It was worse than a zero on macOS. There the fixture scored 60% only
/// because the benchmark ran as a descendant of a real agent, so the fixture
/// appeared as that agent's child. The number measured the ancestry of the
/// harness rather than anything about the collector.
fn benchmark_collectors() -> Vec<Box<dyn topgent_collect::Collector>> {
    let mut collectors = topgent_collect::default_collectors();
    collectors.insert(
        0,
        Box::new(topgent_collect::process::ProcessCollector {
            include_unrecognised: true,
        }),
    );
    collectors.remove(1);
    collectors
}

/// A path under the system temporary directory, named by this process.
///
/// Both callers are lab scaffolding: a ground-truth file the benchmark writes
/// and reads back within one run, and a directory the fixture is staged into.
/// Neither is a trust boundary, and both are named by pid so two runs cannot
/// collide.
fn scratch(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(name) // nosemgrep: rust.lang.security.temp-dir.temp-dir - lab scaffolding named by pid, not a trust boundary
}

/// Puts the fixture where the sweep will or will not recognise it.
///
/// Recognised means copying it to a name the catalogue knows. That is the
/// whole mechanism: `claude-code` requires no path provenance, so the name is
/// what decides, and the copy makes the decision explicit rather than
/// depending on where the binary happened to be built.
fn stage(fixture: &std::path::Path, recognised: bool) -> Result<std::path::PathBuf, String> {
    if !recognised {
        return Ok(fixture.to_path_buf());
    }
    let directory = scratch(&format!("topgent-bench-agent-{}", std::process::id()));
    std::fs::create_dir_all(&directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?;
    let staged = directory.join("claude");
    std::fs::copy(fixture, &staged).map_err(|error| format!("{}: {error}", staged.display()))?;
    Ok(staged)
}

/// Unix milliseconds now.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| u64::try_from(since.as_millis()).unwrap_or(0))
}

/// Where the fixture binary is.
fn fixture_path(args: &[String]) -> Result<std::path::PathBuf, String> {
    if let Some(given) = option_value(args, "--fixture") {
        return Ok(std::path::PathBuf::from(given));
    }
    // nosemgrep: rust.lang.security.current-exe.current-exe - finding the fixture beside this binary, in a lab command that is not a trust boundary
    let here = std::env::current_exe().map_err(|error| error.to_string())?;
    let directory = here
        .parent()
        .ok_or_else(|| "this binary has no directory".to_owned())?;
    let candidate = directory.join(format!(
        "topgent-fixture-agent{}",
        std::env::consts::EXE_SUFFIX
    ));
    if candidate.exists() {
        Ok(candidate)
    } else {
        Err(format!(
            "no fixture at {}; pass --fixture PATH",
            candidate.display()
        ))
    }
}

/// Waits for the fixture to declare what it did.
///
/// Bounded, because a fixture that never writes is a failure to report rather
/// than something to wait out.
fn wait_for_truth(path: &std::path::Path) -> Result<GroundTruth, String> {
    for _ in 0..100 {
        if let Ok(text) = std::fs::read_to_string(path)
            && let Ok(truth) = serde_json::from_str::<GroundTruth>(&text)
        {
            return Ok(truth);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Err(format!(
        "the fixture wrote no ground truth to {} within five seconds",
        path.display()
    ))
}

/// One value as a percentage, or a dash when the question did not arise.
fn share(value: Option<f64>) -> String {
    value.map_or_else(
        || "  -  ".to_owned(),
        |ratio| format!("{:5.1}%", ratio * 100.0),
    )
}

/// Starts the fixture and hands back the child.
fn spawn_fixture(
    fixture: &std::path::Path,
    truth_path: &std::path::Path,
    hold_ms: u64,
) -> Result<std::process::Child, String> {
    std::process::Command::new(fixture)
        .arg("--out")
        .arg(truth_path)
        .arg("--hold-ms")
        .arg(hold_ms.to_string())
        .spawn()
        .map_err(|error| format!("{}: {error}", fixture.display()))
}

/// What the sweep cost, or nothing when it was not measured.
fn cost_line(report: &Benchmark) -> String {
    let Some(cost) = report.overhead else {
        return String::new();
    };
    let mb = |bytes: Option<u64>| {
        bytes.map_or_else(
            || "   -   ".to_owned(),
            |value| {
                #[allow(clippy::cast_precision_loss)] // A resident size in bytes is far below 2^53.
                let megabytes = value as f64 / 1_048_576.0;
                format!("{megabytes:.1}MB")
            },
        )
    };
    format!(
        "sweep cost              {}ms wall, resident {} before, {} after\n",
        cost.sweep_ms,
        mb(cost.resident_before),
        mb(cost.resident_after)
    )
}

/// The report as text.
fn render(report: &Benchmark) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "fixture root pid {}", report.root_pid);
    let _ = writeln!(
        out,
        "\n{:<22} {:>8} {:>8} {:>8} {:>8}",
        "", "expected", "seen", "recall", "missed"
    );
    for (label, score) in [
        ("processes", &report.processes),
        ("  resident", &report.lifetimes.resident),
        ("  short-lived", &report.lifetimes.short_lived),
        ("parent edges", &report.ancestry),
        ("sockets", &report.sockets),
    ] {
        let _ = writeln!(
            out,
            "{:<22} {:>8} {:>8} {:>8} {:>8}",
            label,
            score.expected,
            score.matched,
            share(score.recall()),
            score.missed()
        );
    }
    let _ = writeln!(
        out,
        "\nlifetime split made against {}ms, the age of the fixture when the sweep ran",
        report.lifetimes.sweep_interval_ms
    );
    let _ = writeln!(
        out,
        "reachability            {} of {} answered, {} agreed, {} disagreed",
        report.reachability.answered,
        report.reachability.expected,
        report.reachability.agreed,
        report.reachability.disagreed
    );
    let _ = writeln!(
        out,
        "fixture processes classified as an agent: {} (expected {})",
        report.false_agents,
        usize::from(report.recognised)
    );
    out.push_str(&cost_line(report));
    let _ = writeln!(
        out,
        "\n{:<22} {:>10} {:>8} {:>8}",
        "collector", "state", "facts", "ms"
    );
    for timing in &report.collectors {
        let _ = writeln!(
            out,
            "{:<22} {:>10} {:>8} {:>8}",
            timing.collector, timing.state, timing.facts, timing.duration_ms
        );
    }
    if !report.notes.is_empty() {
        let _ = writeln!(out, "\nwhy the zeros are zero");
        for note in &report.notes {
            let _ = writeln!(out, "  {:<14} {}", note.metric, note.text);
        }
    }
    let _ = writeln!(
        out,
        "\nThese are agreement between two observers of one controlled run, not\naccuracy against the world. A missed short-lived process is the method\nworking as designed; the number says how much the method cannot see."
    );
    out
}
