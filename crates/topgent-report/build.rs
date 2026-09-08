//! Makes the build tag actually take effect when it changes.
//!
//! `option_env!` is read at compile time, and cargo does not know a crate
//! depends on an environment variable unless it is told. Without this line,
//! setting `TOPGENT_BUILD_TAG` on a tree that is otherwise unchanged produces a
//! binary that still claims to be untagged, which is the exact confusion the
//! tag exists to prevent.
fn main() {
    println!("cargo:rerun-if-env-changed=TOPGENT_BUILD_TAG");
}
