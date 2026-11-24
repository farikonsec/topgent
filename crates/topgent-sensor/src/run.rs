//! Choosing the source: eBPF when the kernel takes Topgent's probe, the
//! process connector otherwise.
//!
//! The choice is made once, at start. The reason eBPF was not used travels in
//! every health line, so the report can say why rather than only which.

use std::process::ExitCode;

pub(crate) fn run() -> ExitCode {
    match topgent_ebpf::load() {
        Ok(probe) => crate::ebpf::run(probe),
        Err(why) => crate::connector::run(why.to_string()),
    }
}
