//! The firing-condition decoder, which reads a file an operator may edit.
//!
//! A policy overlay is untrusted input in the same sense a socket listing is:
//! Topgent did not write it, and a malformed one must be refused rather than
//! panic the scorer. Evaluation is fuzzed alongside decoding, because a
//! condition that parses and then panics on some agent is the same defect
//! arriving one step later.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(condition) = serde_json::from_str::<topgent_policy::Firing>(text) {
        let thresholds = topgent_policy::Thresholds::default();
        let _ = condition.holds(&topgent_policy::Signals::default(), &thresholds);
        let _ = condition.is_satisfiable(&thresholds);
        let _ = condition.signals();
        let _ = condition.depth();
    }
});
