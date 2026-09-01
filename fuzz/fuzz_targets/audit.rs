//! The Linux audit log, which is where connection and datagram evidence comes
//! from. Any process that can write to the log can shape this input.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = topgent_collect::network_event::parse_audit_connections(text);
    }
});
