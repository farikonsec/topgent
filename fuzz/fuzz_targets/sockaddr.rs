//! The hex `saddr` field of an audit record, decoded into an address and port.
//!
//! Length-prefixed binary decoded from text is the classic shape for an
//! out-of-bounds read, which is why it gets a target of its own.
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
        if let Some((host, _port)) = topgent_collect::network_event::parse_sockaddr(text) {
            // A decoded address must be one, or it should not have been
            // returned at all.
            assert!(
                host.parse::<std::net::IpAddr>().is_ok(),
                "parse_sockaddr returned {host:?}, which is not an address"
            );
        }
    }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = data;
    }
});
