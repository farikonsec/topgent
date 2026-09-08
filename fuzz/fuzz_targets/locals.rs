//! This host's own addresses, as the kernel renders them.
//!
//! Direction hangs off this set, and both ways of getting it wrong are real:
//! an address wrongly admitted turns somebody else's traffic into an agent's,
//! and the fixed-width hex decoder is an easy place to index out of bounds.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // A routing table can name a great many networks. Nothing here may turn
    // that into unbounded memory.
    assert!(topgent_collect::capture::locals::parse_fib_trie(text).len() <= 512);
    assert!(topgent_collect::capture::locals::parse_if_inet6(text).len() <= 512);
});
