//! The socket collector.
//!
//! Nothing is decrypted and no payload is read. A destination and a port is all
//! the egress question needs.
//!
//! Every platform answers this question with a different tool, and each tool
//! tells the truth about a slightly different set of things: macOS names the
//! connection, Linux adds the kernel's own byte counters, and Windows is the
//! only one that records when a connection was created. Rather than flattening
//! them to the smallest common answer, each parser lives in its own module and
//! reports exactly what its platform states. Everything absent stays absent —
//! the difference between two sweeps measures how long Topgent has been
//! watching, and presenting that as a connection's age would be invented.
//!
//! Every tool is resolved to a path the operating system owns and run with
//! fixed arguments. Nothing discovered anywhere in Topgent is interpolated into
//! a command line, and output is parsed as data rather than trusted as truth.
//!
//! # Layout
//!
//! | Module | What lives there |
//! |---|---|
//! | [`row`] | One parsed socket, in the terms every platform can agree on. |
//! | [`macos`] | `lsof -i -n -P`. |
//! | [`linux`] | `ss -H -t -a -n -p -i`, including the kernel's byte counters. |
//! | [`windows`] | `Get-NetTCPConnection` for connection age, `netstat` as the fallback. |
//! | [`collector`] | Running the right tool, and attributing each socket to an agent. |

mod collector;
mod linux;
mod macos;
mod row;
mod windows;

pub use collector::SocketCollector;
pub use linux::{parse_ss, tcp_info_bytes};
pub use macos::parse_lsof;
pub use row::SocketRow;
// `fuzzing` as well as `test`: a parser reachable only on the platform it
// parses for is a parser nobody fuzzes.
#[cfg(any(windows, test, fuzzing))]
pub use windows::{
    MAX_WINDOWS_CLOCK_SKEW_MS, MAX_WINDOWS_TCP_ROWS, parse_windows_netstat,
    parse_windows_tcp_connections,
};
