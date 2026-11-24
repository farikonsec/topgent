//! Loads the probe, prints every process event for a few seconds, then
//! unloads it. While it runs, `bpftool prog show id <id>` shows the
//! programs.
//!
//! ```sh
//! cargo build -p topgent-ebpf --features probe --example probe-check
//! sudo target/debug/examples/probe-check
//! ```

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::{
    process::ExitCode,
    thread,
    time::{Duration, Instant},
};

use topgent_ebpf::{Kind, ProcessEvent, text};

/// How long the probe stays loaded.
const HOLD: Duration = Duration::from_secs(10);

fn main() -> ExitCode {
    let mut probe = match topgent_ebpf::load() {
        Ok(probe) => probe,
        Err(why) => {
            eprintln!("not loaded: {why}");
            return ExitCode::FAILURE;
        }
    };
    match probe.program_ids() {
        Ok(ids) => println!("loaded program ids: {ids:?}; watching {}s", HOLD.as_secs()),
        Err(why) => println!("loaded, but {why}"),
    }

    let until = Instant::now() + HOLD;
    let mut events = Vec::new();
    while Instant::now() < until {
        probe.drain(&mut events);
        for event in events.drain(..) {
            println!("{}", line(&event));
        }
        thread::sleep(Duration::from_millis(50));
    }

    match probe.lost() {
        Ok(lost) => println!("lost {lost} · malformed {}", probe.malformed()),
        Err(why) => println!("{why}"),
    }
    println!("probe check complete; unloading on exit");
    ExitCode::SUCCESS
}

fn line(event: &ProcessEvent) -> String {
    let comm = String::from_utf8_lossy(text(&event.comm));
    match event.kind() {
        Some(Kind::Spawn) => format!("spawn {:>7}  by {} ({comm})", event.pid, event.creator),
        Some(Kind::Exec) => format!(
            "exec  {:>7}  {}",
            event.pid,
            String::from_utf8_lossy(text(&event.filename))
        ),
        Some(Kind::Exit) => format!("exit  {:>7}  ({comm})", event.pid),
        None => format!("unknown kind {} for {}", event.kind, event.pid),
    }
}
