//! The report the interface reads.
//!
//! This model has been wrong twice: once claiming a sequence where the report
//! sends a map, once refusing the whole document over a null in a `u64`. Both
//! shipped, and both made the window show nothing but an error.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else { return };
    // A report that cannot be read is an error the window shows. A report that
    // panics is a window that is gone.
    if let Ok(report) = serde_json::from_value::<topgent_ui::report::Report>(value) {
        for agent in &report.agents {
            let _ = agent.label();
            let _ = agent.recognition();
        }
        let _ = report.worst();
    }
});
