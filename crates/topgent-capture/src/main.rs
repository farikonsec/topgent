//! The one part of Topgent that holds a privilege.
//!
//! # What it is
//!
//! A small program that reads packet headers and writes what it saw to its own
//! standard output, one JSON line per interval. It has no interface, no policy,
//! no files, and no network of its own. It is the only binary that needs the
//! capture capability, and it is deliberately the smallest one.
//!
//! This is Wireshark's arrangement. The capability goes on `dumpcap`, which
//! does nothing but read frames; the interface reads what it writes and holds
//! no privilege at all. The interface is the large, complicated, frequently
//! changed program, and it is exactly the one that must not hold a raw socket.
//!
//! # Granting it
//!
//! ```text
//! sudo setcap cap_net_raw,cap_net_admin+eip /path/to/topgent-capture
//! ```
//!
//! On macOS and Windows there is nothing to grant here: access comes from
//! group membership and from an installed driver respectively, and both apply
//! to every program the operator runs.
//!
//! # What it will not do
//!
//! It reads headers and never a payload: the buffer is short enough that the
//! rest of each frame is discarded by the kernel. It takes no arguments that
//! change what it captures, because a privileged program that can be pointed
//! at something is a privileged program somebody will point somewhere else.
//!
//! # Stopping
//!
//! It exits when its output closes, which is what happens the moment the
//! parent goes away. A privileged process outliving the thing that started it
//! is how a capture becomes something nobody knows is running.

use std::io::Write as _;

use topgent_collect::capture::{handoff, session::Session};

/// How often a batch is written.
///
/// Short enough that a sweep at any moment has recent traffic to report, long
/// enough that the parent is not woken constantly.
const INTERVAL: std::time::Duration = std::time::Duration::from_millis(1_000);

fn main() -> std::process::ExitCode {
    let session = match Session::start() {
        Ok(session) => session,
        Err(error) => {
            // The reason goes to standard error, where a parent can read it
            // and a person can see it. Standard output carries batches and
            // nothing else, so a failure never looks like a malformed batch.
            eprintln!("{error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let stdout = std::io::stdout();
    loop {
        std::thread::sleep(INTERVAL);
        if let Some(detail) = session.ended() {
            eprintln!("{detail}");
            return std::process::ExitCode::FAILURE;
        }
        let batch = handoff::to_wire(&session.drain());
        let Ok(line) = serde_json::to_string(&batch) else {
            continue;
        };
        let mut out = stdout.lock();
        // A write that fails means the parent has gone. There is nothing left
        // to capture for, and a privileged process with no reader is exactly
        // what should not keep running.
        if writeln!(out, "{line}").is_err() || out.flush().is_err() {
            return std::process::ExitCode::SUCCESS;
        }
    }
}
