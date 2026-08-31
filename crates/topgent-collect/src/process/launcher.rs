//! Finding the real program when a runtime is running someone else's script.
//!
//! An npm-installed agent is a `node.exe` process with its entry script as the
//! first argument, so the executable name alone identifies the runtime and not
//! the agent. Only the first argument is read, and only for a runtime that runs
//! other people's programs: the rest of a command line can hold prompt text and
//! credentials, and Topgent has no business reading either.

use super::table::ProcInfo;
#[cfg(windows)]
use super::table::family_of;
#[cfg(target_os = "linux")]
use std::io::Read;

/// Language runtimes that run somebody else's program.
///
/// A process running one of these is not itself the thing to identify; the
/// script it was handed is. Anything else is taken at face value.
#[cfg(any(windows, test))]
pub const SCRIPT_RUNTIMES: [&str; 5] =
    ["node.exe", "python.exe", "pythonw.exe", "py.exe", "bun.exe"];

/// Whether this executable is a runtime that runs another program.
#[cfg(any(windows, test))]
#[must_use]
pub fn is_script_runtime(exe: &str) -> bool {
    let lowered = exe.to_ascii_lowercase().replace('\\', "/");
    let basename = lowered.rsplit('/').next().unwrap_or(&lowered);
    SCRIPT_RUNTIMES.contains(&basename)
}

#[cfg(target_os = "linux")]
pub(super) fn launcher_path(pid: u32) -> Option<String> {
    let file = std::fs::File::open(format!("/proc/{pid}/cmdline")).ok()?;
    let fields = first_nul_fields(file, 2);
    let launcher = fields.get(1)?;
    let path = std::path::Path::new(launcher);
    std::fs::canonicalize(path)
        .ok()
        .map(|resolved| resolved.to_string_lossy().to_string())
}

/// The script a language runtime was started with, on Windows.
///
/// An npm-installed agent does not run as itself. It runs as `node.exe` with
/// its own entry script as the first argument, so a collector that reads only
/// the executable sees Node and no agent at all. Linux recovers the script from
/// `/proc/PID/cmdline`; Windows keeps the same thing in the process's command
/// line, readable for the current user's processes without elevation.
///
/// Only the first argument is taken, and only when it names a file that exists.
/// Nothing else from the command line is read or retained: the rest routinely
/// contains prompts, paths and credentials, and none of it is Topgent's
/// business.
/// Windows resolves launchers for the whole sweep at once, afterwards.
#[cfg(windows)]
pub(super) fn launcher_path(_pid: u32) -> Option<String> {
    None
}

#[cfg(not(any(target_os = "linux", windows)))]
pub(super) fn launcher_path(_pid: u32) -> Option<String> {
    None
}

/// Give Windows script runtimes the identity of the program they are running.
#[cfg(windows)]
pub(super) fn resolve_windows_launchers(processes: &mut [ProcInfo]) {
    let candidates: Vec<u32> = processes
        .iter()
        .filter(|process| process.family.is_none() && is_script_runtime(&process.exe))
        .map(|process| process.pid)
        .take(128)
        .collect();
    if candidates.is_empty() {
        return;
    }
    let launchers = windows_launchers(&candidates);
    for process in processes.iter_mut() {
        let Some(launcher) = launchers.get(&process.pid) else {
            continue;
        };
        // Only a launcher Topgent recognises replaces the identity. An
        // unrecognised script leaves the process as the runtime it is, rather
        // than being renamed after whatever file it happened to open.
        if let Some(family) = family_of(launcher) {
            process.family = Some(family);
            process.exe.clone_from(launcher);
        }
    }
}

#[cfg(not(windows))]
pub(super) fn resolve_windows_launchers(_processes: &mut [ProcInfo]) {}

/// Ask Windows for the command lines of exactly these processes.
///
/// One query for the whole batch: a call per process would put a shell spawn in
/// the sweep's hot path for every language runtime on the machine.
#[cfg(windows)]
pub(super) fn windows_launchers(pids: &[u32]) -> std::collections::BTreeMap<u32, String> {
    use std::collections::BTreeMap;
    if pids.is_empty() || pids.len() > 128 {
        return BTreeMap::new();
    }
    // The filter is built from numbers this process already holds, so nothing
    // discovered anywhere crosses into the query text.
    let filter = pids
        .iter()
        .map(|pid| format!("ProcessId={pid}"))
        .collect::<Vec<_>>()
        .join(" OR ");
    let script = format!(
        "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); Get-CimInstance Win32_Process -Filter \"{filter}\" -ErrorAction Stop | ForEach-Object {{[pscustomobject]@{{pid=$_.ProcessId; cmd=$_.CommandLine}} | ConvertTo-Json -Compress}}"
    );
    let Ok(mut command) = crate::tool::POWERSHELL.command() else {
        return BTreeMap::new();
    };
    let Ok(output) = command
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
    else {
        return BTreeMap::new();
    };
    if !output.status.success() {
        return BTreeMap::new();
    }
    parse_windows_launchers(&String::from_utf8_lossy(&output.stdout))
        .into_iter()
        .filter(|(_, path)| std::path::Path::new(path).is_file())
        .collect()
}

/// Pull the first argument out of each command line.
#[cfg(any(windows, test))]
#[must_use]
pub fn parse_windows_launchers(out: &str) -> std::collections::BTreeMap<u32, String> {
    let mut launchers = std::collections::BTreeMap::new();
    for line in out.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
            continue;
        };
        let Some(pid) = value
            .get("pid")
            .and_then(serde_json::Value::as_u64)
            .and_then(|pid| u32::try_from(pid).ok())
        else {
            continue;
        };
        if pid == 0 {
            continue;
        }
        let Some(command) = value.get("cmd").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if let Some(launcher) = first_windows_argument(command) {
            launchers.insert(pid, launcher);
        }
    }
    launchers
}

/// The first argument of a Windows command line, quotes respected.
///
/// Bounded so a hostile command line cannot be walked forever, and stops at the
/// first argument so nothing beyond it is ever read.
#[cfg(any(windows, test))]
pub(super) fn first_windows_argument(command: &str) -> Option<String> {
    if command.len() > 8_192 {
        return None;
    }
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for character in command.chars() {
        match character {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !current.is_empty() {
                    fields.push(std::mem::take(&mut current));
                    if fields.len() == 2 {
                        break;
                    }
                }
            }
            c => current.push(c),
        }
    }
    if fields.len() < 2 && !current.is_empty() {
        fields.push(current);
    }
    let argument = fields.get(1)?.trim();
    (!argument.is_empty() && !argument.starts_with('-') && argument.len() <= 4_096)
        .then(|| argument.to_owned())
}

#[cfg(target_os = "linux")]
fn first_nul_fields(mut reader: impl Read, limit: usize) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = Vec::new();
    let mut byte = [0_u8; 1];
    while fields.len() < limit && field.len() < 4_096 {
        match reader.read(&mut byte) {
            Ok(0) | Err(_) => break,
            Ok(_) if byte[0] == 0 => {
                fields.push(String::from_utf8_lossy(&field).to_string());
                field.clear();
            }
            Ok(_) => field.push(byte[0]),
        }
    }
    fields
}

#[cfg(test)]
mod tests {

    #[test]
    fn an_npm_agent_is_identified_by_the_script_it_runs_not_by_node() {
        // An npm-installed agent does not run as itself. It runs as node.exe
        // with its entry script as the first argument, so a collector reading
        // only the executable sees Node and no agent at all. Quoted paths with
        // spaces are the normal case on Windows, not the exception.
        let quoted = concat!(
            r#"{"pid":1234,"cmd":"\"C:/Program Files/nodejs/node.exe\" "#,
            r#"\"C:/Users/a/AppData/Roaming/npm/node_modules/@google/gemini-cli/dist/index.js\" --yolo"}"#,
        );
        let launchers = super::parse_windows_launchers(quoted);
        assert_eq!(
            launchers.get(&1234).map(String::as_str),
            Some("C:/Users/a/AppData/Roaming/npm/node_modules/@google/gemini-cli/dist/index.js")
        );

        // Unquoted, and a Windows path separator, are the same fact.
        let plain = r#"{"pid":5678,"cmd":"py.exe C:\\Tools\\aider-chat\\bin\\aider --model x"}"#;
        assert_eq!(
            super::parse_windows_launchers(plain)
                .get(&5678)
                .map(String::as_str),
            Some(r"C:\Tools\aider-chat\bin\aider")
        );
    }

    #[test]
    fn nothing_beyond_the_first_argument_is_read_from_a_command_line() {
        // The rest of a command line routinely carries prompts, paths and
        // credentials. None of it is Topgent's business, and none is retained.
        let secret = r#"{"pid":1,"cmd":"node.exe app.js --api-key sk-do-not-keep-this"}"#;
        let launchers = super::parse_windows_launchers(secret);
        assert_eq!(launchers.get(&1).map(String::as_str), Some("app.js"));
        assert!(!format!("{launchers:?}").contains("sk-do-not-keep-this"));

        for unusable in [
            r#"{"pid":1,"cmd":"node.exe"}"#,
            r#"{"pid":1,"cmd":""}"#,
            r#"{"pid":1,"cmd":"node.exe --inspect"}"#,
            r#"{"pid":0,"cmd":"node.exe app.js"}"#,
            r#"{"cmd":"node.exe app.js"}"#,
            r#"{"pid":1}"#,
            "not json",
            "",
        ] {
            assert!(
                super::parse_windows_launchers(unusable).is_empty(),
                "took something unusable from: {unusable}"
            );
        }

        // A command line long enough to be an attack is not walked.
        let flood = format!(r#"{{"pid":1,"cmd":"node.exe {}"}}"#, "a".repeat(9_000));
        assert!(super::parse_windows_launchers(&flood).is_empty());
    }

    #[test]
    fn only_a_runtime_that_runs_someone_elses_program_is_looked_through() {
        for runtime in super::SCRIPT_RUNTIMES {
            assert!(super::is_script_runtime(runtime), "{runtime}");
            assert!(super::is_script_runtime(&format!(
                r"C:\Program Files\nodejs\{runtime}"
            )));
            assert!(super::is_script_runtime(&runtime.to_ascii_uppercase()));
        }
        // An agent is itself, and is never looked through to whatever file it
        // happens to have opened.
        for direct in [
            "opencode.exe",
            "codex.exe",
            "claude",
            "notepad.exe",
            "nodemon.exe",
        ] {
            assert!(!super::is_script_runtime(direct), "{direct}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn launcher_reader_stops_before_prompt_and_argument_content() {
        use std::io::{Cursor, Seek};

        let input = b"/python\0/tools/aider-chat/bin/aider\0secret prompt\0".to_vec();
        let mut reader = Cursor::new(input);
        let fields = super::first_nul_fields(&mut reader, 2);
        assert_eq!(fields, ["/python", "/tools/aider-chat/bin/aider"]);
        assert_eq!(reader.stream_position().unwrap_or_default(), 36);
    }
}
