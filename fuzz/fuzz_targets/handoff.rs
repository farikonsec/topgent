//! What one process accepts from another about a capture.
//!
//! The helper is Topgent's own binary and its output is parsed anyway, because
//! a process that holds a privilege is exactly the wrong thing to extend blind
//! faith to. This is the one place a separate program's bytes reach the
//! accumulator, so it is fuzzed like any other reader.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(batch) = serde_json::from_str::<topgent_collect::capture::handoff::Batch>(text) else {
        return;
    };
    let Some(drained) = topgent_collect::capture::handoff::from_wire(&batch) else {
        return;
    };
    // Nothing admitted may exceed the accumulator's own bounds, and no row may
    // carry a host that is not an address: a report renders these directly.
    assert!(drained.flows.len() <= 8192);
    assert!(drained.scans.len() <= 8192);
    // Folding a batch in must not panic, whatever the numbers say.
    let mut flows = topgent_collect::capture::flows::Flows::new();
    flows.absorb(drained);
    let _ = flows.drain();
});
