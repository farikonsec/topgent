//! A saved session file, which a user may copy in from anywhere: the reader
//! must refuse what is not one and never panic on it.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(saved) = topgent_journal::parse_session(text) {
        // Accepted only with a report to show.
        assert!(saved.report.is_object(), "accepted without a report object");
    }
});
