//! `lsof -i -n -P`, which is what macOS socket evidence is parsed from.
//!
//! A process can name itself anything, and its name is the first column of
//! every row here. This target asserts the parser survives whatever it prints.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let rows = topgent_collect::socket::parse_lsof(text);
        for row in &rows {
            // A parsed row must never carry a host the parser invented.
            assert!(!row.host.is_empty(), "a row with an empty host was produced");
        }
    }
});
