//! A line from the privileged sensor helper, read as hostile: the collector
//! must never panic on one, and what it keeps must keep its promises.
//!
//! Covers the working-directory placement (E11): a relative path is placed
//! under the line's `cwd` only when that directory is absolute, and the raw
//! name is kept as sent.
#![no_main]
use libfuzzer_sys::fuzz_target;
use topgent_collect::process_events::{Line, parse_line};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    match parse_line(text) {
        Some(Line::Syscall(call)) => {
            let event = &call.event;
            if let Some(cwd) = &event.cwd {
                assert!(cwd.starts_with('/'), "a relative cwd was kept: {cwd:?}");
                assert!(!cwd.chars().any(char::is_control), "{cwd:?}");
            }
            for path in &event.paths {
                assert!(!path.raw.chars().any(char::is_control), "{:?}", path.raw);
                if path.name != path.raw {
                    // Placed: only ever under the line's own directory.
                    let cwd = event.cwd.as_deref().expect("placed without a cwd");
                    assert!(!path.raw.starts_with('/'), "an absolute path was moved");
                    assert!(
                        path.name.starts_with(cwd.trim_end_matches('/')),
                        "{:?} placed outside {cwd:?}",
                        path.name
                    );
                }
            }
        }
        Some(Line::Event(event)) => {
            if let Some(cwd) = &event.cwd {
                assert!(cwd.starts_with('/'), "a relative exec cwd: {cwd:?}");
            }
        }
        Some(Line::Health(_)) | None => {}
    }
});
