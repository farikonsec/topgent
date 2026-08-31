//! Windows `netstat -ano` and the structured connection table.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = topgent_collect::socket::parse_windows_netstat(text);
        let _ = topgent_collect::socket::parse_windows_tcp_connections(
            text,
            topgent_facts::UnixMillis(1_700_000_000_000),
        );
    }
});
