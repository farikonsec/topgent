//! The process sensor: the kernel's fork, exec and exit feed, one JSON line each.
//!
//! # What it is
//!
//! A small program that reads process lifecycle from the kernel and writes
//! what it hears to its own standard output. It holds nothing else: no
//! interface, no policy, no files, no network. The interface starts it and
//! reads it, the way it reads `topgent-capture`.
//!
//! # Where it listens
//!
//! Topgent's own eBPF probe (`topgent-ebpf`) when the kernel takes it: every
//! name, creator and exec path is then read in the kernel at the moment of
//! the event, so a process that lives for a millisecond is described in
//! full. Otherwise the kernel's process connector, as before, with names read
//! from `/proc` while the process is still there. Every health line says
//! which, and why eBPF was not used when it was not.
//!
//! # Granting it
//!
//! This is the only part of Topgent that holds kernel privileges. For eBPF
//! it needs to load and attach programs and read the kernel's tracepoint
//! descriptions; for the process connector, on kernels that restrict it,
//! `CAP_NET_ADMIN`:
//!
//! ```text
//! sudo setcap cap_bpf,cap_perfmon,cap_dac_read_search,cap_net_admin+ep /path/to/topgent-sensor
//! ```
//!
//! On Debian-family kernels (Kali included) `kernel.perf_event_paranoid`
//! is 3 by default, a Debian patch under which attaching a tracepoint needs
//! `CAP_SYS_ADMIN` as well; without it the sensor falls back to the
//! connector and its health note says so. The binary must also sit on a
//! filesystem not mounted `nosuid`, or its file capabilities are ignored.
//!
//! Measured on the Kali lab's 6.19 kernel, an unprivileged process was
//! allowed to subscribe to the process connector but not to load eBPF.
//! Whether either is refused is the kernel's decision, and a refusal is
//! reported rather than assumed.
//!
//! # What it writes
//!
//! `fork`, `exec` and `exit` for whole processes (threads are not processes),
//! with the pid, the parent on a fork (the process that created it), the
//! kernel start time and name where they can be read, the program's file
//! name on an exec, and its full path when eBPF read it. Through eBPF also:
//! an exec's arguments when all of them were read, the rule syscalls as
//! `sys` lines with their ancestry, and the container an event ran in. The
//! arguments are held in memory on the other side and never stored. No
//! environment, ever. Once a second, a `health` line: which run this is,
//! which source it uses and why, and how many events that source numbered or
//! queued and never delivered. A quiet sensor and a deaf one are told apart
//! by those numbers.
//!
//! # Stopping
//!
//! It exits when its output closes, which happens the moment the reader goes
//! away. A privileged process outliving whatever started it is how a sensor
//! becomes something nobody knows is running. Dropping the eBPF probe on exit
//! removes every program it put into the kernel.

#[cfg(target_os = "linux")]
mod cgroups;
#[cfg(target_os = "linux")]
mod clock;
#[cfg(target_os = "linux")]
mod connector;
#[cfg(target_os = "linux")]
mod ebpf;
#[cfg(target_os = "linux")]
mod line;
#[cfg(target_os = "linux")]
mod output;
#[cfg(target_os = "linux")]
mod run;

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    run::run()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("topgent-sensor reads Linux process lifecycle and does nothing elsewhere");
    std::process::ExitCode::from(2)
}
