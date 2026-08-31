//! The Topgent desktop interface.
//!
//! A shim. Everything is in the library beside this, so that the parsers it
//! contains can be fuzzed: a fuzz target cannot link to a binary.

fn main() -> iced::Result {
    topgent_ui::run()
}
