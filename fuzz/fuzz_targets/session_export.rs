//! The session export, which turns a report into a document someone opens in a
//! browser. Every value in it describes a process an attacker may have named.
//!
//! The property that matters is not that it survives: it is that nothing
//! reaching the page can act as markup.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let Ok(report) = serde_json::from_str::<serde_json::Value>(text) else { return };
    for detail in [topgent_export::Detail::Full, topgent_export::Detail::Redacted] {
        let html = topgent_export::session_html(&report, detail);
        for markup in ["<script", "<img", "<iframe", "<link", " src=", " href="] {
            assert!(!html.contains(markup), "{markup} reached the page from a report value");
        }
        if detail == topgent_export::Detail::Redacted {
            assert!(!html.contains("/Users/"), "a home directory survived redaction");
        }
    }
});
