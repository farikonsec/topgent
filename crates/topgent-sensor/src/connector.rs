//! The fallback source: the kernel's process connector.
//!
//! Used when eBPF is not available. The connector says only which pid did
//! what, so names and programs are read from `/proc` as each event arrives,
//! and a process gone by then keeps what the kernel said about it.

use std::collections::HashMap;
use std::process::ExitCode;

use topgent_collect::procconn::{Connector, Kind, SequenceTracker, parse_datagram};
use topgent_collect::process::boot_seconds;

use crate::clock::{clock_ns, event_ms, now_ms};
use crate::line::{Happened, Known, comm, describe, forget, program};
use crate::output::Output;

/// `note` says why eBPF is not in use; every health line repeats it.
pub(crate) fn run(note: String) -> ExitCode {
    let connector = match Connector::open() {
        Ok(connector) => connector,
        Err(error) => {
            // Standard error is for the reason; standard output only ever
            // carries lines the reader can parse.
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                eprintln!(
                    "the process connector needs CAP_NET_ADMIN: sudo setcap cap_net_admin+ep \
                     on topgent-sensor ({error}); eBPF was not used either: {note}"
                );
            } else {
                eprintln!(
                    "the process connector could not be opened: {error}; eBPF was not used \
                     either: {note}"
                );
            }
            return ExitCode::from(3);
        }
    };
    let boot = boot_seconds();
    let mut out = Output::new("connector", Some(note));
    let mut known: HashMap<u32, Known> = HashMap::new();
    let mut sequence = SequenceTracker::default();
    let mut overflows = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let received = match connector.recv(&mut buffer) {
            Ok(received) => received,
            Err(error) if error.raw_os_error() == Some(105) => {
                // ENOBUFS: the socket overflowed and the kernel dropped
                // messages. The sequence gaps will say how many.
                overflows = overflows.saturating_add(1);
                0
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                0
            }
            Err(error) => {
                eprintln!("the process connector failed: {error}");
                return ExitCode::from(4);
            }
        };
        let wall = now_ms();
        let boot_minus_monotonic = clock_ns(rustix::time::ClockId::Boottime)
            .saturating_sub(clock_ns(rustix::time::ClockId::Monotonic));
        for event in parse_datagram(buffer.get(..received).unwrap_or_default()) {
            sequence.observe(event.cpu, event.seq);
            if !event.is_process_level() {
                continue;
            }
            let at = boot.map_or(wall, |boot| {
                event_ms(boot, event.timestamp_ns, boot_minus_monotonic)
            });
            let Some(happened) = happened(event.kind, event.name()) else {
                continue;
            };
            let ended = match happened {
                Happened::Exit { pid, .. } => Some(pid),
                _ => None,
            };
            if !out.event(&describe(happened, &mut known, boot, at)) {
                return ExitCode::SUCCESS;
            }
            if let Some(pid) = ended {
                forget(&mut known, pid);
            }
        }
        if !out.health(sequence.lost(), overflows) || !out.flush() {
            return ExitCode::SUCCESS;
        }
    }
}

/// What a connector message says, with names and programs read from
/// `/proc` while the process is still there.
fn happened(kind: Kind, event_name: Option<String>) -> Option<Happened> {
    Some(match kind {
        Kind::Fork {
            parent_tgid,
            child_tgid,
            ..
        } => Happened::Fork {
            parent: parent_tgid,
            child: child_tgid,
            name: comm(child_tgid),
            // The connector does not say; a sweep reads it while the process runs.
            pid_namespace: None,
        },
        Kind::Exec { tgid } => Happened::Exec {
            pid: tgid,
            name: comm(tgid),
            program: program(tgid),
            path: None,
            pid_namespace: None,
            // The connector carries no arguments; a sweep reads a running
            // process's from `/proc`.
            argv: None,
            loginuid: None,
            tty: None,
        },
        Kind::Exit { tgid, code, .. } => Happened::Exit {
            pid: tgid,
            code: Some(code),
        },
        Kind::Comm { tgid, .. } => Happened::Rename {
            pid: tgid,
            name: event_name?,
        },
        Kind::Other => return None,
    })
}
