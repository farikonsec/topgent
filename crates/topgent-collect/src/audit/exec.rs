//! Exec records: the program a process became.
//!
//! The kernel's process connector says a process exec'd and names only the
//! pid. When the process is gone within a millisecond, its new program can no
//! longer be read from `/proc`. A successful `execve` in the Audit log carries
//! it: the `SYSCALL` record's `exe` field is the program the process is now
//! running.

use super::record::{audit_id, audit_time_ms, field};
use super::{Syscall, syscall};

/// One successful exec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExecRecord {
    /// The record id.
    pub record: String,
    /// The process.
    pub pid: u32,
    /// When, by the wall clock.
    pub at: u64,
    /// The program it now runs.
    pub program: String,
}

/// Executables carried by syscall records, keyed by their exact Audit id.
pub(crate) fn programs(text: &str) -> std::collections::BTreeMap<String, String> {
    text.lines()
        .filter(|line| line.starts_with("type=SYSCALL "))
        .filter_map(|line| Some((audit_id(line)?.to_owned(), program(field(line, "exe")?)?)))
        .collect()
}

/// Every successful exec in `text`.
pub(crate) fn parse(text: &str) -> Vec<ExecRecord> {
    text.lines()
        .filter(|line| line.starts_with("type=SYSCALL "))
        .filter(|line| field(line, "success") == Some("yes"))
        .filter(|line| matches!(syscall(line), Some(Syscall::Execve | Syscall::Execveat)))
        .filter_map(|line| {
            let record = audit_id(line)?;
            Some(ExecRecord {
                record: record.to_owned(),
                pid: field(line, "pid")?.parse().ok().filter(|pid| *pid > 0)?,
                at: audit_time_ms(record)?,
                program: program(field(line, "exe")?)?,
            })
        })
        .collect()
}

/// The `exe` field's path: quoted, or hex when it holds a space or anything
/// else Audit will not print bare. Only an absolute path with no control
/// character is kept.
fn program(raw: &str) -> Option<String> {
    let path = if let Some(quoted) = raw.strip_prefix('"') {
        quoted.strip_suffix('"')?.to_owned()
    } else {
        if !raw.len().is_multiple_of(2) || raw.len() > 8_192 {
            return None;
        }
        let bytes = (0..raw.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(raw.get(at..at + 2)?, 16).ok())
            .collect::<Option<Vec<u8>>>()?;
        String::from_utf8(bytes).ok()?
    };
    (path.starts_with('/') && path.len() <= 4_096 && !path.chars().any(char::is_control))
        .then_some(path)
}

#[cfg(test)]
mod tests {
    use super::{ExecRecord, parse};

    #[test]
    fn syscall_programs_remain_bound_to_their_record_ids() {
        let found = super::programs(
            "type=SYSCALL msg=audit(1.000:1): exe=\"/usr/bin/cat\"\ntype=SYSCALL msg=audit(1.000:2): exe=\"/usr/bin/sh\"\n",
        );
        assert_eq!(
            found.get("1.000:1").map(String::as_str),
            Some("/usr/bin/cat")
        );
        assert_eq!(
            found.get("1.000:2").map(String::as_str),
            Some("/usr/bin/sh")
        );
    }

    #[test]
    fn a_successful_exec_names_the_program_the_process_became() {
        let log = concat!(
            "type=SYSCALL msg=audit(1790000000.120:77): arch=c00000b7 syscall=221 success=yes exit=0 ppid=10 pid=11 comm=\"cat\" exe=\"/usr/bin/cat\" key=\"s6exec\"\n",
            "type=EXECVE msg=audit(1790000000.120:77): argc=2 a0=\"cat\"\n",
            "type=SYSCALL msg=audit(1790000000.130:78): arch=c000003e syscall=59 success=yes exit=0 pid=12 comm=\"sh\" exe=\"/usr/bin/dash\"\n",
        );
        assert_eq!(
            parse(log),
            vec![
                ExecRecord {
                    record: "1790000000.120:77".into(),
                    pid: 11,
                    at: 1_790_000_000_120,
                    program: "/usr/bin/cat".into()
                },
                ExecRecord {
                    record: "1790000000.130:78".into(),
                    pid: 12,
                    at: 1_790_000_000_130,
                    program: "/usr/bin/dash".into()
                },
            ]
        );
    }

    /// A path with a space is written as hex. It is decoded, and a path that
    /// is not absolute or holds a control character is refused.
    #[test]
    fn a_hex_program_is_decoded_and_a_hostile_one_refused() {
        let log = concat!(
            "type=SYSCALL msg=audit(1.000:1): arch=c00000b7 syscall=221 success=yes pid=5 exe=2F746D702F6120622063\n",
            "type=SYSCALL msg=audit(1.000:2): arch=c00000b7 syscall=221 success=yes pid=5 exe=2F746D700A78\n",
            "type=SYSCALL msg=audit(1.000:3): arch=c00000b7 syscall=221 success=yes pid=5 exe=\"relative\"\n",
        );
        let programs: Vec<String> = parse(log).into_iter().map(|r| r.program).collect();
        assert_eq!(programs, ["/tmp/a b c"]);
    }

    /// A failed exec leaves the process as it was, and an openat is not an
    /// exec whatever its path.
    #[test]
    fn a_failed_exec_or_another_syscall_is_not_an_exec() {
        let log = concat!(
            "type=SYSCALL msg=audit(1.000:1): arch=c00000b7 syscall=221 success=no exit=-2 pid=5 exe=\"/usr/bin/sh\"\n",
            "type=SYSCALL msg=audit(1.000:2): arch=c00000b7 syscall=56 success=yes pid=5 exe=\"/usr/bin/cat\"\n",
            "type=SYSCALL msg=audit(1.000:3): arch=c00000b7 syscall=221 success=yes exe=\"/usr/bin/cat\"\n",
        );
        assert!(parse(log).is_empty());
    }
}
