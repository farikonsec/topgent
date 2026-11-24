//! A run of several sweeps can print every one of them.
//!
//! Loss and sensor gaps are reported per interval. A run that prints only its
//! last sweep hides an interval that lost events or had no sensor, once the
//! next interval is clean. `--each` prints every sweep's report, one per line.

#![allow(clippy::expect_used)]

use std::process::Command;

#[test]
fn each_prints_one_report_per_sweep() {
    let dir = std::env::temp_dir().join(format!("topgent-each-{}", std::process::id()));
    let output = Command::new(env!("CARGO_BIN_EXE_topgent"))
        .args(["--json", "--sweeps", "2", "--every", "200", "--each"])
        .env("XDG_STATE_HOME", &dir)
        .output()
        .expect("the binary runs");
    let _ = std::fs::remove_dir_all(&dir);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let reports: Vec<serde_json::Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).expect("each line is one report"))
        .collect();
    assert_eq!(reports.len(), 2, "one report per sweep");
    assert!(reports.iter().all(|report| report.get("sensors").is_some()));
}
