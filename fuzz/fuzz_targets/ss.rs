//! Linux `ss`, including the kernel counter continuation lines.
//
// The parser this exercises is compiled only on linux, so the target is a no-op
// elsewhere. Gated rather than deleted, because a target that vanishes from the
// suite on the maintainer's machine is one nobody notices has stopped running,
// and `cargo check --bins` in this directory used to fail on macOS for exactly
// this reason.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    #[cfg(target_os = "linux")]
    {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = topgent_collect::socket::parse_ss(text);
        for line in text.lines() {
            let _ = topgent_collect::socket::tcp_info_bytes(line);
        }
    }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = data;
    }
});
