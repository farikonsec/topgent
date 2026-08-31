//! Linux `ss`, including the kernel counter continuation lines.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = topgent_collect::socket::parse_ss(text);
        for line in text.lines() {
            let _ = topgent_collect::socket::tcp_info_bytes(line);
        }
    }
});
