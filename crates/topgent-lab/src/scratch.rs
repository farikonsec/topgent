//! Private working directories under the system temporary directory.
//!
//! # Why this is not `temp_dir().join(name)`
//!
//! A predictable name in a world-writable directory is a name somebody else
//! can get to first. `/tmp` carries the sticky bit, which stops one account
//! deleting another's files; it does nothing to stop an account *creating* a
//! name that does not exist yet, including a symlink pointing somewhere else.
//! `create_dir_all` then succeeds on what it finds, and everything written
//! afterwards goes wherever the symlink points, as the account that ran
//! Topgent.
//!
//! A name derived from the process id is predictable enough to lose that race:
//! process ids are small, visible to every account on the host, and reused.
//!
//! So the name is random and the create is exclusive. `create_dir` fails when
//! the name is taken, which turns the race into an error instead of a silent
//! write through somebody else's link.

use std::path::PathBuf;

/// How many names to try before giving up.
///
/// A collision means the random name was already taken, which is either
/// extraordinary luck or somebody guessing. Either way the answer is to pick
/// another name, and a bounded loop cannot spin.
const ATTEMPTS: u8 = 8;

/// A directory that did not exist until this call made it, readable only here.
///
/// # Errors
///
/// Returns the reason when no name could be created.
pub fn private_dir(prefix: &str) -> Result<PathBuf, String> {
    let mut last = String::new();
    for _ in 0..ATTEMPTS {
        // This module is the fix for that rule rather than an instance of it. The
        // name is unpredictable and the create below is exclusive, so a name
        // somebody else got to first is an error and never a write.
        // nosemgrep: rust.lang.security.temp-dir.temp-dir
        let path = std::env::temp_dir().join(format!("{prefix}-{:016x}", unpredictable()));
        // Exclusive on purpose. `create_dir_all` accepts a directory that is
        // already there, which is exactly the thing being defended against.
        match std::fs::create_dir(&path) {
            Ok(()) => {
                restrict(&path);
                return Ok(path);
            }
            Err(error) => last = format!("{}: {error}", path.display()),
        }
    }
    Err(last)
}

/// Owner-only, so the contents are not readable by other accounts either.
///
/// Best effort: a filesystem that does not carry Unix modes is not a reason to
/// fail, because the exclusive create above is what the security rests on.
#[cfg(unix)]
fn restrict(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;
    drop(std::fs::set_permissions(
        path,
        std::fs::Permissions::from_mode(0o700),
    ));
}

/// See the Unix note. Windows inherits the parent's access control here.
#[cfg(not(unix))]
const fn restrict(_path: &std::path::Path) {}

/// A number another account cannot predict.
///
/// `RandomState` is seeded by the operating system once per process and is
/// what the standard library's own hash maps use to resist collision attacks.
/// Hashing a fresh counter through it gives a value with no relationship to
/// the process id, the clock, or anything else visible from outside. This
/// costs no dependency, which matters in a tool whose supply chain is part of
/// what it is claiming.
fn unpredictable() -> u64 {
    use std::hash::{BuildHasher as _, Hasher as _};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_calls_never_return_the_same_directory() -> Result<(), String> {
        let first = private_dir("topgent-scratch-test")?;
        let second = private_dir("topgent-scratch-test")?;
        assert_ne!(
            first, second,
            "a reused name is a name somebody can predict"
        );
        drop(std::fs::remove_dir_all(&first));
        drop(std::fs::remove_dir_all(&second));
        Ok(())
    }

    #[test]
    fn the_directory_is_new_and_not_reachable_by_other_accounts() -> Result<(), String> {
        let path = private_dir("topgent-scratch-test")?;
        assert!(path.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path)
                .map_err(|error| error.to_string())?
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "group and other must have nothing");
        }
        drop(std::fs::remove_dir_all(&path));
        Ok(())
    }

    #[test]
    fn an_existing_name_is_refused_rather_than_adopted() -> Result<(), String> {
        // The property that matters: this module never writes into a directory
        // it did not create. Asked of the standard library directly, because
        // the random name cannot be made to collide on purpose.
        let taken = private_dir("topgent-scratch-taken")?;
        assert!(
            std::fs::create_dir(&taken).is_err(),
            "create_dir must refuse a name that already exists"
        );
        drop(std::fs::remove_dir_all(&taken));
        Ok(())
    }
}
