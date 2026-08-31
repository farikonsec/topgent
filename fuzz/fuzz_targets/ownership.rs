//! Address ownership: the compiled table and the addresses looked up in it.
//!
//! The lookup does offset arithmetic over a 14 MB blob compiled into the
//! binary, which is the one place in this project that reads binary by index.
//! It is also the only code that decides what a network is called, and a wrong
//! answer there is a wrong answer about who an agent talked to.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let owner = topgent_ui::ownership::of(text);
    // Whatever comes back must be printable without panicking, and an unknown
    // owner must say so rather than drawing an empty flag.
    let (country, network) = (owner.country(), owner.network());
    assert!(!country.is_empty() && !network.is_empty());
    if !owner.known() {
        assert_eq!(country, "unknown");
        assert_eq!(network, "unknown");
    }
    // And every line the fuzzer produces is also tried as an address, so a
    // multi-line input exercises the parser rather than failing at the first
    // newline.
    for line in text.lines().take(16) {
        let _ = topgent_ui::ownership::of(line);
    }
});
