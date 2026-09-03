//! The ground-truth fixture.
//!
//! A deterministic program that does a known set of things and writes down what
//! it did, from its own return values. The benchmark scores a collector against
//! this file. It is a separate binary from the scoring code on purpose: the
//! thing being measured and the thing measuring must not be able to share a
//! bug.
//!
//! It is not an AI agent and must never be classified as one. Any run where the
//! collectors attach an agent family to a fixture process is a false positive,
//! and that count is one of the benchmark's headline numbers.
//!
//! # Safety
//!
//! Everything is loopback and a temporary directory. It binds `127.0.0.1:0`,
//! so the kernel picks a free port and no external address is contacted. It
//! writes only inside a directory it created. It holds for a bounded time and
//! exits. There is no configuration that makes it reach the network.
//!
//! ```text
//! topgent-fixture-agent --out PATH [--hold-ms 8000]
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::io::Write as _;
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};

use topgent_lab::bench::{
    GROUND_TRUTH_SCHEMA, GroundTruth, TruthProcess, TruthResource, TruthSocket,
};

/// How long a short-lived child stays alive, in milliseconds.
///
/// Chosen to be far below any sweep interval a person would configure. The
/// point of the fixture is to create activity a snapshot collector cannot see,
/// so that the report can say how much it cannot see.
const SHORT_LIFE_MS: u64 = 40;

/// Children the root spawns directly.
const DIRECT_CHILDREN: usize = 2;

/// Children spawned by the resident child.
const NESTED_CHILDREN: usize = 2;

fn main() {
    match run() {
        Ok(()) => {}
        Err(error) => {
            eprintln!("topgent-fixture-agent: {error}");
            std::process::exit(1);
        }
    }
}

/// Dispatches between the root role and the child role.
fn run() -> Result<(), String> {
    // Reading argv is what a command-line tool does; every value is matched
    // against a fixed set below.
    let args: Vec<String> = std::env::args().skip(1).collect(); // nosemgrep: rust.lang.security.args.args
    match option(&args, "--child-report") {
        Some(report) => child(&args, report),
        None => root(&args),
    }
}

/// The value after a named option.
fn option<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|value| value == name)
        .and_then(|at| args.get(at.saturating_add(1)))
        .map(String::as_str)
}

/// A number after a named option, or a default.
fn number(args: &[String], name: &str, fallback: u64) -> u64 {
    option(args, name)
        .and_then(|value| value.parse().ok())
        .unwrap_or(fallback)
}

/// Unix milliseconds now.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| u64::try_from(since.as_millis()).unwrap_or(0))
}

/// A child process: announces itself, lives for its allotted time, exits.
///
/// It announces before it sleeps, so a child that lives forty milliseconds is
/// still in the ground truth. A fixture that only recorded survivors would be
/// unable to measure what the collector misses.
fn child(args: &[String], report: &str) -> Result<(), String> {
    let depth = number(args, "--depth", 1);
    let lifetime = number(args, "--lifetime-ms", SHORT_LIFE_MS);
    let parent = number(args, "--parent-pid", 0);
    announce(
        report,
        std::process::id(),
        u32::try_from(parent).unwrap_or(0),
        depth,
        lifetime,
    )?;

    let mut nested = Vec::new();
    if depth == 1 && lifetime > SHORT_LIFE_MS {
        for index in 0..NESTED_CHILDREN {
            let short = index % 2 == 1;
            nested.push(spawn(
                report,
                2,
                if short { SHORT_LIFE_MS } else { lifetime },
                std::process::id(),
            )?);
        }
    }

    std::thread::sleep(std::time::Duration::from_millis(lifetime));
    for mut handle in nested {
        let _ = handle.wait();
    }
    Ok(())
}

/// Appends one line describing a process to the shared report.
///
/// Line-buffered and opened in append mode by each writer, because several
/// processes write to it at once and a partial line would be a fabricated
/// process id.
fn announce(
    report: &str,
    pid: u32,
    parent_pid: u32,
    depth: u64,
    lifetime_ms: u64,
) -> Result<(), String> {
    // nosemgrep: rust.lang.security.current-exe.current-exe - the fixture spawns copies of itself on purpose; its own path is the thing being tested, not a lookup that could be redirected
    let name = std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "topgent-fixture-agent".to_owned());
    let line = format!("{pid} {parent_pid} {depth} {lifetime_ms} {name}\n");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(report)
        .map_err(|error| format!("{report}: {error}"))?;
    file.write_all(line.as_bytes())
        .map_err(|error| format!("{report}: {error}"))
}

/// Starts one child of this executable.
fn spawn(
    report: &str,
    depth: u64,
    lifetime_ms: u64,
    parent_pid: u32,
) -> Result<std::process::Child, String> {
    // nosemgrep: rust.lang.security.current-exe.current-exe - the fixture spawns copies of itself on purpose; its own path is the thing being tested, not a lookup that could be redirected
    let exe = std::env::current_exe().map_err(|error| error.to_string())?;
    std::process::Command::new(exe)
        .arg("--child-report")
        .arg(report)
        .arg("--depth")
        .arg(depth.to_string())
        .arg("--lifetime-ms")
        .arg(lifetime_ms.to_string())
        .arg("--parent-pid")
        .arg(parent_pid.to_string())
        .spawn()
        .map_err(|error| format!("spawning a child: {error}"))
}

/// The root: prepares resources, spawns the tree, writes the ground truth, holds.
fn root(args: &[String]) -> Result<(), String> {
    let Some(out) = option(args, "--out") else {
        return Err("--out PATH is required".to_owned());
    };
    let hold_ms = number(args, "--hold-ms", 8_000);
    let started_at_ms = now_ms();
    let root_pid = std::process::id();

    let workspace = workspace(root_pid)?;
    let resources = prepare_resources(&workspace)?;
    let (listener, datagram, sockets) = open_sockets()?;
    let report = workspace.join("processes.txt");
    let report_path = report.to_string_lossy().into_owned();

    announce(&report_path, root_pid, parent_of_root(), 0, hold_ms)?;
    let mut children = Vec::new();
    for index in 0..DIRECT_CHILDREN {
        let short = index % 2 == 1;
        children.push(spawn(
            &report_path,
            1,
            if short { SHORT_LIFE_MS } else { hold_ms },
            root_pid,
        )?);
    }

    // Long enough for every child, including the ones that exit immediately, to
    // have appended its line. Reading earlier would drop the short-lived
    // processes from the ground truth, which are the ones the benchmark exists
    // to count.
    std::thread::sleep(std::time::Duration::from_millis(400));
    let processes = read_report(&report)?;

    let truth = GroundTruth {
        schema: GROUND_TRUTH_SCHEMA,
        root_pid,
        // nosemgrep: rust.lang.security.current-exe.current-exe - the fixture spawns copies of itself on purpose; its own path is the thing being tested, not a lookup that could be redirected
        root_exe: std::env::current_exe()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default(),
        started_at_ms,
        ended_at_ms: now_ms(),
        processes,
        resources,
        sockets,
    };
    let json = serde_json::to_string_pretty(&truth).map_err(|error| error.to_string())?;
    std::fs::write(out, json).map_err(|error| format!("{out}: {error}"))?;

    std::thread::sleep(std::time::Duration::from_millis(hold_ms));
    drop(listener);
    drop(datagram);
    for mut handle in children {
        let _ = handle.wait();
    }
    let _ = std::fs::remove_dir_all(&workspace);
    Ok(())
}

/// The parent of the root, where the platform makes it cheap to ask.
const fn parent_of_root() -> u32 {
    0
}

/// Creates the temporary directory this run works inside.
fn workspace(root_pid: u32) -> Result<PathBuf, String> {
    // nosemgrep: rust.lang.security.temp-dir.temp-dir - a fixture workspace, not a trust boundary
    let path = std::env::temp_dir().join(format!("topgent-fixture-{root_pid}"));
    std::fs::create_dir_all(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(path)
}

/// Writes one readable file and one the account should not be able to read.
///
/// What goes in the ground truth is what reading actually did, not what the
/// permission bits were set to. Running as root, or on a filesystem that does
/// not honour the mode, would otherwise put a false expectation in the file and
/// score a correct collector as wrong.
fn prepare_resources(workspace: &Path) -> Result<Vec<TruthResource>, String> {
    let mut resources = Vec::new();
    for (name, mode) in [("readable.txt", 0o644_u32), ("denied.txt", 0o000_u32)] {
        let path = workspace.join(name);
        std::fs::write(&path, b"fixture\n")
            .map_err(|error| format!("{}: {error}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode));
        }
        #[cfg(not(unix))]
        let _ = mode;
        resources.push(TruthResource {
            path: path.to_string_lossy().into_owned(),
            readable: std::fs::File::open(&path).is_ok(),
        });
    }
    Ok(resources)
}

/// Binds a TCP listener and a UDP socket on loopback.
fn open_sockets() -> Result<(TcpListener, UdpSocket, Vec<TruthSocket>), String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|error| format!("binding a loopback listener: {error}"))?;
    let datagram = UdpSocket::bind("127.0.0.1:0")
        .map_err(|error| format!("binding a loopback datagram socket: {error}"))?;
    let sockets = vec![
        TruthSocket {
            protocol: "tcp".to_owned(),
            local_port: listener
                .local_addr()
                .map_err(|error| error.to_string())?
                .port(),
            listening: true,
        },
        TruthSocket {
            protocol: "udp".to_owned(),
            local_port: datagram
                .local_addr()
                .map_err(|error| error.to_string())?
                .port(),
            listening: true,
        },
    ];
    Ok((listener, datagram, sockets))
}

/// Reads the lines every process appended.
///
/// A malformed line is dropped rather than guessed at. A fabricated process id
/// in the ground truth would score a collector against something that never ran.
fn read_report(report: &Path) -> Result<Vec<TruthProcess>, String> {
    let text = std::fs::read_to_string(report)
        .map_err(|error| format!("{}: {error}", report.display()))?;
    let mut processes = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(pid), Some(parent), Some(depth), Some(lifetime), Some(name)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        let (Ok(pid), Ok(parent_pid), Ok(depth), Ok(lifetime_ms)) = (
            pid.parse::<u32>(),
            parent.parse::<u32>(),
            depth.parse::<u16>(),
            lifetime.parse::<u64>(),
        ) else {
            continue;
        };
        processes.push(TruthProcess {
            pid,
            name: name.to_owned(),
            parent_pid,
            depth,
            lifetime_ms,
        });
    }
    processes.sort_by_key(|process| process.pid);
    processes.dedup_by_key(|process| process.pid);
    Ok(processes)
}
