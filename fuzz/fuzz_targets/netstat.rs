//! Windows `netstat -ano` and the structured connection table.
//
// The parser this exercises is compiled only on windows, so the target is a no-op
// elsewhere. Gated rather than deleted, because a target that vanishes from the
// suite on the maintainer's machine is one nobody notices has stopped running,
// and `cargo check --bins` in this directory used to fail on macOS for exactly
// this reason.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    #[cfg(target_os = "windows")]
    {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = topgent_collect::socket::parse_windows_netstat(text);
        let _ = topgent_collect::socket::parse_windows_tcp_connections(
            text,
            topgent_facts::UnixMillis(1_700_000_000_000),
        );
    }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = data;
    }
});
