//! Shared scaffolding for the crate's tests.
//!
//! Journal tests write real files, so each one needs a directory of its own:
//! sharing would let a test see another's records and pass for the wrong
//! reason. The name is derived from the running thread and this process, which
//! keeps parallel tests apart without any coordination between them.

/// A directory this test alone will use.
pub(crate) fn test_dir(prefix: &str) -> std::path::PathBuf {
    let name = std::thread::current()
        .name()
        .unwrap_or("test")
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    // nosemgrep: rust.lang.security.temp-dir.temp-dir - test fixture, per-process name, not a trust boundary
    std::env::temp_dir().join(format!("topgent-{prefix}-{}-{name}", std::process::id()))
}
