//! End-to-end against real processes.
//!
//! This test stands up an estate: real executables with agent names, real
//! configuration files granting different things, real credential files sitting
//! in reach. It runs the actual collectors over them, folds, scores, and checks
//! that Topgent graded each one the way a security engineer would.
//!
//! Then it kills every process it started, through the real enforcement path,
//! and checks the guards refuse the ones they should.
//!
//! Nothing here is simulated except the estate itself, and the estate is
//! deleted on the way out.

#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use topgent_collect::{Clock, Collector, FixedClock, config, process, reach};
use topgent_core::{Grade, IdentityKind, analyse};
use topgent_enforce::{Action, Executed, Guard, Outcome, Refusal, SystemSignaller, execute};

/// A disposable estate on disk, removed when it drops.
struct Estate {
    root: PathBuf,
    children: Vec<Child>,
}

impl Drop for Estate {
    fn drop(&mut self) {
        for c in &mut self.children {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl Estate {
    fn new(tag: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("topgent-estate-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("bin")).unwrap();
        Self {
            root,
            children: Vec::new(),
        }
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn write(&self, rel: &str, body: &str) {
        let p = self.home().join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    /// Start a process whose executable name is one Topgent recognises.
    ///
    /// A copy of `sleep`, renamed. The point is that discovery works on what the
    /// process IS, not on anything the process cooperates with.
    ///
    /// On macOS a copied Apple-signed binary is `SIGKILL`ed the instant it runs,
    /// because the signature no longer matches where it now lives. Re-signing
    /// ad-hoc is the standard remedy and costs nothing elsewhere: on Linux the
    /// command is absent and the copy runs as it is.
    fn spawn_agent(&mut self, exe_name: &str) -> u32 {
        self.spawn_agent_in("bin", exe_name)
    }

    /// Start a recognised agent from a realistic install location.
    ///
    /// Families whose signature requires a package path marker are only
    /// recognised where they are actually installed, so a canary for one has
    /// to be laid out the way the real product is. A binary of the right name
    /// in an arbitrary directory is a same-name decoy, and is meant to be
    /// refused.
    fn spawn_agent_in(&mut self, rel_dir: &str, exe_name: &str) -> u32 {
        let dir = self.root.join(rel_dir);
        fs::create_dir_all(&dir).unwrap();
        let bin = dir.join(exe_name);
        fs::copy("/bin/sleep", &bin).unwrap();
        let _ = Command::new("codesign")
            .args(["-f", "-s", "-"])
            .arg(&bin)
            .output();
        let child = spawn_freshly_written(&bin);
        let pid = child.id();
        self.children.push(child);
        pid
    }
}

fn sweep_estate(home: &Path, clock: &dyn Clock) -> Vec<topgent_facts::Fact> {
    let collectors: Vec<Box<dyn Collector>> = vec![
        Box::new(process::ProcessCollector::default()),
        Box::new(config::ConfigCollector {
            home: Some(home.to_path_buf()),
        }),
        Box::new(reach::ReachCollector {
            home: Some(home.to_path_buf()),
            sensitive: None,
            watchlist: None,
        }),
    ];
    topgent_collect::sweep(&collectors, clock).facts
}

/// Wait for a spawned process to appear in the process table.
///
/// `sysinfo` reads a snapshot, and a process started microseconds ago is not
/// always in it yet.
/// Run a binary that was written moments ago, retrying while the kernel says it
/// is still being written to.
///
/// These tests run in parallel threads of one process. When one thread has a
/// newly copied binary open for writing and another forks, the child inherits
/// that writable descriptor until it execs, and any exec of that file in the
/// window fails with `ETXTBSY`. It is a property of fork/exec on Linux rather
/// than anything about Topgent, and it made whichever test lost the race look
/// like a discovery failure. Retrying is the remedy; the window is microseconds
/// and every other error is still fatal.
fn spawn_freshly_written(bin: &Path) -> std::process::Child {
    for _ in 0..50 {
        match Command::new(bin).arg("300").spawn() {
            Ok(child) => return child,
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(e) => panic!("{} did not start: {e}", bin.display()),
        }
    }
    panic!("{} stayed busy for a second", bin.display());
}

fn wait_for(pid: u32) {
    for _ in 0..50 {
        if process::snapshot().iter().any(|p| p.pid == pid) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(40));
    }
    panic!("pid {pid} never appeared in the process table");
}

const FULL_PERMISSIONS: &str = r#"{
  "permissions": {
    "allow": ["Bash(*)", "Write(/Users/**)", "Read(/**)"],
    "deny": []
  },
  "hooks": { "PreToolUse": [] }
}"#;

const NARROW_PERMISSIONS: &str = r#"{
  "permissions": {
    "allow": ["Read(~/work)"],
    "deny": ["Bash(*)"]
  }
}"#;

fn secrets(e: &Estate) {
    e.write(".ssh/id_rsa", "not a real key\n");
    e.write(".aws/credentials", "[default]\nnot_real = true\n");
}

#[test]
fn an_agent_with_shell_broad_write_and_credentials_in_reach_is_critical() {
    let mut e = Estate::new("critical");
    e.write(".claude/settings.json", FULL_PERMISSIONS);
    secrets(&e);
    let pid = e.spawn_agent("claude");
    wait_for(pid);

    let facts = sweep_estate(&e.home(), &FixedClock(1_000));
    let scored = analyse(&facts);
    let (agent, risk) = scored
        .iter()
        .find(|(a, _)| a.id.pid == pid)
        .expect("the spawned agent was not discovered");

    assert_eq!(agent.family.as_deref(), Some("claude-code"));
    assert_eq!(agent.identity, IdentityKind::DelegatedHuman);
    assert_eq!(risk.grade, Grade::Critical, "factors: {:#?}", risk.factors);

    let codes: Vec<&str> = risk.factors.iter().map(|f| f.code.as_str()).collect();
    assert!(codes.contains(&"ARBITRARY_EXECUTION"), "{codes:?}");
    assert!(codes.contains(&"BROAD_WRITE"), "{codes:?}");
    assert_eq!(
        codes.iter().filter(|c| **c == "SECRET_REACHABLE").count(),
        2,
        "both planted credentials should be in reach: {codes:?}"
    );

    // The three columns, on a real process.
    let key = agent
        .resources
        .iter()
        .find(|r| r.path == "~/.ssh/id_rsa")
        .expect("the ssh key should be listed");
    assert!(key.is_latent_secret());
    assert_eq!(key.observed.label(), "no", "nothing touched it");
    assert_eq!(key.reachable.label(), "yes");
}

#[test]
fn the_same_agent_with_narrow_permissions_and_nothing_to_steal_is_low() {
    let mut e = Estate::new("quiet");
    e.write(".claude/settings.json", NARROW_PERMISSIONS);
    let pid = e.spawn_agent("claude");
    wait_for(pid);

    let facts = sweep_estate(&e.home(), &FixedClock(1_000));
    let scored = analyse(&facts);
    let (agent, risk) = scored.iter().find(|(a, _)| a.id.pid == pid).unwrap();

    assert_eq!(agent.identity, IdentityKind::DelegatedHuman);
    assert_eq!(risk.score, 0, "factors: {:#?}", risk.factors);
    assert_eq!(risk.grade, Grade::Low);
    assert!(agent.latent_secrets().is_empty());
    assert!(!agent.can_execute(), "Bash is denied, not granted");
}

#[test]
fn a_local_model_server_holds_its_own_identity_and_scores_lower_for_it() {
    let mut e = Estate::new("service");
    secrets(&e);
    let pid = e.spawn_agent("ollama");
    wait_for(pid);

    let facts = sweep_estate(&e.home(), &FixedClock(1_000));
    let scored = analyse(&facts);
    let (agent, risk) = scored.iter().find(|(a, _)| a.id.pid == pid).unwrap();

    assert_eq!(agent.family.as_deref(), Some("ollama"));
    assert_eq!(
        agent.identity,
        IdentityKind::ServiceAccount,
        "no human's config stands behind it"
    );
    // The same two credentials are in reach, but a service identity is worth
    // less to an attacker, so the same evidence scores lower.
    assert_eq!(risk.identity_multiplier, 75);
    assert_eq!(risk.score, 20, "15 + 12, each at 75%: {:#?}", risk.factors);
}

#[test]
fn a_same_name_binary_outside_a_real_install_is_not_promoted_to_an_agent() {
    // A real process, correctly named, in a directory no product installs to.
    // Recognition requires package evidence as well as the name, so this is
    // refused: a wrong family name is worse than no family name.
    let mut e = Estate::new("decoy");
    secrets(&e);
    let pid = e.spawn_agent("codex");
    wait_for(pid);

    let scored = analyse(&sweep_estate(&e.home(), &FixedClock(1_000)));
    assert!(
        !scored.iter().any(|(a, _)| a.id.pid == pid),
        "a same-name binary in an arbitrary directory is not a Codex install"
    );
}

#[test]
fn a_sandboxed_coding_agent_is_not_charged_for_shell_it_cannot_use() {
    let mut sandboxed = Estate::new("codex-safe");
    sandboxed.write(".codex/config.toml", "sandbox_mode = \"workspace-write\"\n");
    let safe_pid = sandboxed.spawn_agent_in(".codex/bin", "codex");
    wait_for(safe_pid);
    let safe = analyse(&sweep_estate(&sandboxed.home(), &FixedClock(1_000)));
    let (_, safe_risk) = safe.iter().find(|(a, _)| a.id.pid == safe_pid).unwrap();

    let mut open = Estate::new("codex-open");
    open.write(
        ".codex/config.toml",
        "sandbox_mode = \"danger-full-access\"\n",
    );
    let open_pid = open.spawn_agent_in(".codex/bin", "codex");
    wait_for(open_pid);
    let loose = analyse(&sweep_estate(&open.home(), &FixedClock(1_000)));
    let (_, open_risk) = loose.iter().find(|(a, _)| a.id.pid == open_pid).unwrap();

    assert_eq!(safe_risk.score, 0, "{:#?}", safe_risk.factors);
    assert!(
        open_risk.score > safe_risk.score,
        "turning the sandbox off must cost something: {} vs {}",
        open_risk.score,
        safe_risk.score
    );
    assert_eq!(
        open_risk.factors.first().map(|f| f.code.as_str()),
        Some("ARBITRARY_EXECUTION")
    );
}

#[test]
fn topgent_stops_an_agent_it_started_and_records_that_it_did() {
    let mut e = Estate::new("kill");
    let pid = e.spawn_agent("claude");
    wait_for(pid);

    let started_at = process::snapshot()
        .into_iter()
        .find(|p| p.pid == pid)
        .unwrap()
        .started_at;

    let Executed { result, fact } = execute(
        &Action::Kill { pid, started_at },
        &Guard::current(),
        &SystemSignaller,
        &FixedClock(9_000),
    );

    assert_eq!(
        result,
        Ok(Outcome::StoppedGracefully),
        "sleep handles SIGTERM"
    );
    assert!(
        !process::snapshot().iter().any(|p| p.pid == pid),
        "the process should be gone"
    );

    // An action taken is the same shape in the log as an action observed.
    let fact = fact.expect("an action always writes a fact");
    assert_eq!(fact.claim().kind(), "action_taken");
    assert_eq!(fact.provenance().collector, "enforce");
    assert!(fact.provenance().probe.contains(&pid.to_string()));
}

#[test]
fn topgent_stops_a_disposable_process_tree_without_leaving_helpers() {
    let mut estate = Estate::new("kill-tree");
    let child = Command::new("/bin/sh")
        .args(["-c", "sleep 300 & wait"])
        .spawn()
        .unwrap();
    let root_pid = child.id();
    estate.children.push(child);
    wait_for(root_pid);
    let mut snapshot = Vec::new();
    for _ in 0..50 {
        snapshot = process::snapshot();
        if snapshot
            .iter()
            .any(|process| process.parent == Some(root_pid))
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(40));
    }
    let root = snapshot
        .iter()
        .find(|process| process.pid == root_pid)
        .unwrap();
    let helper_pids = snapshot
        .iter()
        .filter(|process| process.parent == Some(root_pid))
        .map(|process| process.pid)
        .collect::<Vec<_>>();
    assert!(
        !helper_pids.is_empty(),
        "fixture must create a child process"
    );

    let result = execute(
        &Action::KillTree {
            pid: root_pid,
            started_at: root.started_at,
        },
        &Guard::current(),
        &SystemSignaller,
        &FixedClock(9_000),
    )
    .result;
    assert_eq!(result, Ok(Outcome::TreeStoppedGracefully));
    let after = process::snapshot();
    assert!(!after.iter().any(|process| process.pid == root_pid));
    assert!(
        helper_pids
            .iter()
            .all(|pid| !after.iter().any(|process| process.pid == *pid)),
        "no approved helper may survive the tree response"
    );
}

#[test]
fn killing_a_pid_that_has_been_reused_is_refused() {
    let mut e = Estate::new("reuse");
    let pid = e.spawn_agent("claude");
    wait_for(pid);

    // Authorised against a start time that is not this process's. That is what a
    // stale UI row looks like after the kernel recycles a pid.
    let result = execute(
        &Action::Kill {
            pid,
            started_at: topgent_facts::UnixMillis(1),
        },
        &Guard::current(),
        &SystemSignaller,
        &FixedClock(9_000),
    )
    .result;

    assert!(
        matches!(result, Err(Refusal::IdentityChanged { .. })),
        "{result:?}"
    );
    assert!(
        process::snapshot().iter().any(|p| p.pid == pid),
        "the process must be untouched"
    );
}

#[test]
fn topgent_refuses_to_kill_itself_or_the_session_it_runs_in() {
    let guard = Guard::current();
    let me = process::snapshot()
        .into_iter()
        .find(|p| p.pid == guard.own_pid)
        .unwrap();

    assert!(matches!(
        guard.check(&me),
        Err(Refusal::Protected {
            why: "that is Topgent itself"
        })
    ));

    if let Some(parent) = guard.parent_pid
        && let Some(p) = process::snapshot().into_iter().find(|p| p.pid == parent)
    {
        assert!(matches!(guard.check(&p), Err(Refusal::Protected { .. })));
    }

    // pid 1 and other users' processes are refused by the same gate.
    let init = process::ProcInfo {
        owner: process::Owner::Uid(0),
        exe_path_known: true,
        pid: 1,
        started_at: topgent_facts::UnixMillis(0),
        exe: "/sbin/launchd".to_owned(),
        name: "launchd".to_owned(),
        uid: 0,
        user: "root".to_owned(),
        parent: None,
        family: None,
    };
    assert!(matches!(guard.check(&init), Err(Refusal::Protected { .. })));

    let other_user = process::ProcInfo {
        uid: 1,
        pid: 424_242,
        ..init
    };
    assert!(matches!(
        guard.check(&other_user),
        Err(Refusal::Protected { .. })
    ));
}

#[test]
fn killing_something_that_is_already_gone_is_not_an_error_worth_alarming_about() {
    let result = execute(
        &Action::Kill {
            pid: 999_999,
            started_at: topgent_facts::UnixMillis(1),
        },
        &Guard::current(),
        &SystemSignaller,
        &FixedClock(9_000),
    )
    .result;
    assert_eq!(result, Err(Refusal::NotRunning));
}
