//! Shortening a value to fit a column, and the timestamps beside it.
//!
//! Every value in every table goes through this, including paths and process
//! names an attacker chooses. Cutting a string by bytes rather than characters
//! panics on the first non-ASCII path, and this machine has several.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let limit = usize::from(data.first().copied().unwrap_or(0));
    for path_column in [true, false] {
        let short = topgent_ui::table::shorten(text, limit, path_column);
        assert!(
            short.chars().count() <= text.chars().count().max(limit),
            "shortening made {text:?} longer"
        );
    }
    // A timestamp from anywhere in the range, including zero and the far
    // future, must format rather than wrap.
    let mut at = [0u8; 8];
    for (slot, byte) in at.iter_mut().zip(data) {
        *slot = *byte;
    }
    let _ = topgent_ui::clock::stamp(u64::from_le_bytes(at));
});
