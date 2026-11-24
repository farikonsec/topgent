#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::expect_used)]

use super::config::{CONFIG_JSON, object_storage, parse};
use super::format::count;
use super::*;
use topgent_core::lineage::Observation;

struct Fake {
    model: Vec<&'static str>,
    names: Vec<(&'static str, &'static str)>,
    workspace_bytes: u64,
}

impl Destinations for Fake {
    fn model_service(&mut self, host: &str) -> bool {
        self.model.contains(&host)
    }
    fn name(&mut self, host: &str) -> Option<String> {
        self.names
            .iter()
            .find(|(h, _)| *h == host)
            .map(|(_, n)| (*n).to_owned())
    }
    fn workspace(&mut self, _root: &str) -> Option<(u64, u64)> {
        Some((42_500, self.workspace_bytes))
    }
}

fn fake() -> Fake {
    Fake {
        model: vec!["198.51.100.7", "198.51.100.8"],
        names: vec![("203.0.113.9", "zcode-release.oss-cn-hongkong.aliyuncs.com")],
        // A large repository, so the older tests' totals decide alone.
        workspace_bytes: 900_000_000,
    }
}

fn root(files: u32, history: u32, at: u64) -> RootTotals {
    RootTotals {
        root: "/home/testuser/work/acme".into(),
        files,
        history_files: history,
        uncounted: 0,
        read_bytes: 0,
        unsized_files: 0,
        top: vec![("src".into(), files.saturating_sub(history))],
        first_at: at,
        last_at: at + 5_000,
        ..RootTotals::default()
    }
}

fn dest(host: &str, attempts: u32, failed: u32, bytes: u64, at: u64) -> DestTotals {
    DestTotals {
        host: host.into(),
        port: 443,
        attempts,
        connected: attempts - failed,
        in_progress: 0,
        failed,
        bytes,
        burst_bytes: 0,
        burst_at: 0,
        minutes: vec![(at / 60_000, bytes)],
        first_at: at,
        last_at: at + 60_000,
    }
}

fn process(pid: u32, roots: Vec<RootTotals>, destinations: Vec<DestTotals>) -> ProcessTotals {
    ProcessTotals {
        pid,
        name: Some("zcode".into()),
        first_at: 1_000,
        last_at: 100_000,
        ended: false,
        roots,
        destinations,
        recent_reads: Vec::new(),
        sensitive_reads: Vec::new(),
    }
}

fn lineage() -> Lineage {
    let mut lineage = Lineage::new(64);
    for (pid, parent, name) in [
        (1, None, "systemd"),
        (100, Some(1), "zcode"),
        (101, Some(100), "zcode"),
        (102, Some(101), "zcode"),
    ] {
        lineage.observe(observation(pid, parent, name, 500));
    }
    lineage
}

fn observation(pid: u32, parent: Option<u32>, name: &str, at: u64) -> Observation {
    Observation {
        key: ProcessKey {
            pid,
            started_at: UnixMillis(at),
        },
        parent_pid: parent,
        name: name.into(),
        exe: None,
        pid_namespace: None,
        at: UnixMillis(at),
        from_event: true,
    }
}

fn agents() -> BTreeMap<ProcessKey, (String, Option<String>)> {
    BTreeMap::from([(
        ProcessKey {
            pid: 100,
            started_at: UnixMillis(500),
        },
        ("ZCode".to_owned(), Some("zcode".to_owned())),
    )])
}

fn run(
    totals: Vec<ProcessTotals>,
    agents: &BTreeMap<ProcessKey, (String, Option<String>)>,
) -> Value {
    project(
        &json!({}),
        &Totals {
            processes: totals,
            forgotten: 0,
            saturated: false,
        },
        &lineage(),
        agents,
        &mut fake(),
        &|_| Vec::new(),
        &crate::honeytoken::Manifest::default(),
        "boot",
    )
}

#[test]
fn the_reported_zcode_pattern_is_one_critical_incident_in_plain_words() {
    // One helper reads, another uploads: one run, one incident.
    let out = run(
        vec![
            process(101, vec![root(42_411, 3_102, 2_000)], vec![]),
            process(
                102,
                vec![],
                vec![dest("203.0.113.9", 564, 560, 313_000_000, 8_000)],
            ),
        ],
        &agents(),
    );
    let rows = out["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    let incident = &rows[0];
    assert_eq!(incident["severity"], "critical");
    assert_eq!(incident["agent"]["name"], "ZCode");
    let headline = incident["headline"].as_str().unwrap();
    assert!(headline.starts_with("ZCode read 42,411 files from /home/testuser/work/acme (99% of the 42,500 files there), including 3,102 from its git history"), "{headline}");
    assert!(headline.contains("then sent 313 MB to zcode-release.oss-cn-hongkong.aliyuncs.com (203.0.113.9:443) over 564 connection attempts (560 failed)."), "{headline}");
    let why = incident["why"].to_string();
    assert!(why.contains("object storage"), "{why}");
    assert!(why.contains("Retried"), "{why}");
    assert!(
        incident["limits"][0]
            .as_str()
            .unwrap()
            .contains("cannot show")
    );
    assert_eq!(incident["evidence"]["processes"], json!([101, 102]));
}

#[test]
fn an_unrecognised_program_is_reported_by_its_own_name() {
    let out = run(
        vec![
            process(101, vec![root(900, 0, 2_000)], vec![]),
            process(
                102,
                vec![],
                vec![dest("203.0.113.9", 3, 0, 50_000_000, 8_000)],
            ),
        ],
        &BTreeMap::new(),
    );
    let incident = &out["rows"][0];
    assert_eq!(incident["agent"]["recognised"], false);
    assert_eq!(
        incident["agent"]["pid"], 100,
        "the topmost process of the program"
    );
    assert!(
        incident["headline"]
            .as_str()
            .unwrap()
            .starts_with("zcode read 900 files")
    );
    assert!(incident["why"].to_string().contains("does not recognise"));
}

#[test]
fn an_encryption_tool_in_the_run_is_named_without_claiming_the_bytes_were_read() {
    let totals = Totals {
        processes: vec![
            process(101, vec![root(42_411, 3_102, 2_000)], vec![]),
            process(
                102,
                vec![],
                vec![dest("203.0.113.9", 564, 560, 313_000_000, 8_000)],
            ),
        ],
        forgotten: 0,
        saturated: false,
    };
    // The run (actor pid 101) ran openssl.
    let tools = |a: &BTreeSet<u32>| {
        if a.contains(&101) {
            vec!["openssl".to_owned()]
        } else {
            Vec::new()
        }
    };
    let out = project(
        &json!({}),
        &totals,
        &lineage(),
        &agents(),
        &mut fake(),
        &tools,
        &crate::honeytoken::Manifest::default(),
        "boot",
    );
    let incident = &out["rows"][0];
    let headline = incident["headline"].as_str().unwrap();
    assert!(
        headline.contains("after packing it with an encryption tool"),
        "{headline}"
    );
    assert!(incident["numbers"]["encrypted"].as_bool().unwrap());
    assert_eq!(incident["evidence"]["encryption_tools"], json!(["openssl"]));
    assert!(
        incident["why"]
            .to_string()
            .contains("Encryption tool ran during the upload: openssl")
    );
    assert!(
        incident["limits"]
            .to_string()
            .contains("inside its own process"),
        "states the in-process boundary"
    );
}

// The first night with real ZCode 3.15.1 on Kali: it indexed the whole
// project on open, then talked to its own backend, Alibaba and Volcano
// Engine telemetry, and the local resolver. 708 KB in 20 minutes. That is
// not an exfiltration, and the first version of the rule said it was.
#[test]
fn real_zcode_indexing_and_telemetry_is_not_an_incident() {
    let d = |host: &str, port: u16, attempts: u32, bytes: u64| DestTotals {
        port,
        ..dest(host, attempts, 0, bytes, 3_000)
    };
    let out = run(
        vec![process(
            101,
            vec![root(3_210, 7, 2_000)],
            vec![
                d("163.181.242.222", 443, 18, 344_524),
                d("115.191.57.140", 443, 15, 157_545),
                d("8.130.222.161", 443, 3, 40_041),
                d("192.0.2.53", 53, 340, 11_491),
                d("123.56.37.46", 0, 18, 0),
                d("8.130.222.211", 0, 18, 0),
                d("59.110.96.118", 443, 25, 13_518),
            ],
        )],
        &agents(),
    );
    assert!(out["rows"].as_array().unwrap().is_empty(), "{out}");
    // Edges: 19 retries with data, or 20 retries with no data, stay silent.
    for (attempts, bytes) in [(19, 5_000_000), (20, 1_048_575)] {
        let out = run(
            vec![process(
                101,
                vec![root(800, 0, 2_000)],
                vec![dest("203.0.113.9", attempts, 0, bytes, 3_000)],
            )],
            &agents(),
        );
        assert!(
            out["rows"].as_array().unwrap().is_empty(),
            "{attempts} {bytes}: {out}"
        );
    }
}

fn burst(host: &str, total: u64, burst_bytes: u64) -> DestTotals {
    DestTotals {
        burst_bytes,
        burst_at: 4_000,
        ..dest(host, 3, 0, total, 3_000)
    }
}

fn flow_of(pid: u32, root: RootTotals, mut extra: ProcessTotals) -> Value {
    let mut f = fake();
    f.workspace_bytes = 2_700_000;
    extra.pid = pid;
    extra.roots = vec![root];
    project(
        &json!({}),
        &Totals {
            processes: vec![extra],
            forgotten: 0,
            saturated: false,
        },
        &lineage(),
        &agents(),
        &mut f,
        &|_| Vec::new(),
        &crate::honeytoken::Manifest::default(),
        "boot",
    )["flows"][0]
        .clone()
}

/// The incident rows from one process's totals.
fn incidents_of(extra: ProcessTotals) -> Vec<Value> {
    let mut f = fake();
    project(
        &json!({}),
        &Totals {
            processes: vec![extra],
            forgotten: 0,
            saturated: false,
        },
        &lineage(),
        &agents(),
        &mut f,
        &|_| Vec::new(),
        &crate::honeytoken::Manifest::default(),
        "boot",
    )["rows"]
        .as_array()
        .unwrap()
        .clone()
}

fn kind_of<'a>(rows: &'a [Value], kind: &str) -> Option<&'a Value> {
    rows.iter().find(|r| r["kind"] == kind)
}

#[test]
fn a_secret_read_then_data_to_a_stranger_is_a_secret_exfiltration() {
    let mut p = process(
        101,
        vec![root(20, 0, 2_000)],
        vec![dest("203.0.113.9", 3, 0, 50_000, 120_000)],
    );
    p.sensitive_reads = vec![(
        "/home/user/.ssh/id_ed25519".into(),
        120_000,
        411,
        "private_key".into(),
    )];
    let rows = incidents_of(p);
    let inc = kind_of(&rows, "secret_exfiltration").expect("no secret_exfiltration in {rows:#?}");
    assert_eq!(inc["severity"], "critical", "{inc}");
    assert_eq!(inc["evidence"]["secrets"][0]["class_name"], "private key");
    assert_eq!(inc["evidence"]["sent_to"][0]["address"], "203.0.113.9");
    assert!(
        inc["headline"]
            .as_str()
            .unwrap()
            .contains("then sent data to one place within 10 min"),
        "{inc}"
    );
}

#[test]
fn a_secret_read_then_data_to_the_model_is_lower_severity() {
    // 198.51.100.7 is the agent's own model service in the fixture.
    let mut p = process(
        101,
        vec![root(20, 0, 2_000)],
        vec![dest("198.51.100.7", 3, 0, 40_000, 120_000)],
    );
    p.sensitive_reads = vec![(
        "/home/user/app/.env".into(),
        120_000,
        120,
        "app_secret".into(),
    )];
    let rows = incidents_of(p);
    assert!(kind_of(&rows, "secret_exfiltration").is_none(), "{rows:#?}");
    let inc = kind_of(&rows, "secret_to_model").expect("no secret_to_model");
    assert_eq!(inc["severity"], "high", "{inc}");
}

#[test]
fn opening_a_password_vault_is_an_incident_even_with_no_egress() {
    let mut p = process(101, vec![root(20, 0, 2_000)], vec![]);
    p.sensitive_reads = vec![(
        "/home/user/Passwords.kdbx".into(),
        60_000,
        8_000_000,
        "password_manager".into(),
    )];
    let rows = incidents_of(p);
    let inc = kind_of(&rows, "credential_store_opened").expect("no store incident");
    assert_eq!(inc["severity"], "high", "{inc}");
    assert!(
        inc["headline"]
            .as_str()
            .unwrap()
            .contains("accessed a password manager vault"),
        "{inc}"
    );
    // Opening a vault and then sending out makes it critical.
    let mut p = process(
        101,
        vec![root(20, 0, 2_000)],
        vec![dest("203.0.113.9", 3, 0, 9_000_000, 120_000)],
    );
    p.sensitive_reads = vec![(
        "/home/user/Passwords.kdbx".into(),
        60_000,
        8_000_000,
        "password_manager".into(),
    )];
    let rows = incidents_of(p);
    assert_eq!(
        kind_of(&rows, "credential_store_opened").unwrap()["severity"],
        "critical"
    );
}

#[test]
fn ordinary_reads_raise_no_secret_incident() {
    let p = process(
        101,
        vec![root(20, 0, 2_000)],
        vec![dest("203.0.113.9", 3, 0, 50_000, 120_000)],
    );
    let rows = incidents_of(p);
    for kind in [
        "secret_exfiltration",
        "secret_to_model",
        "credential_store_opened",
    ] {
        assert!(kind_of(&rows, kind).is_none(), "{kind} fired: {rows:#?}");
    }
}

#[test]
fn a_small_read_gets_totals_but_no_alarming_share() {
    // Forty files read, then one ordinary 900 KB turn to the model.
    let flow = flow_of(
        101,
        RootTotals {
            read_bytes: 40_000,
            ..root(40, 0, 2_000)
        },
        process(101, vec![], vec![burst("198.51.100.7", 900_000, 900_000)]),
    );
    assert_eq!(flow["large_read"], false, "{flow}");
    assert!(flow["destinations"][0]["burst_percent_of_workspace"].is_null());
    assert_eq!(flow["destinations"][0]["over_threshold"], false);
    assert_eq!(flow["destinations"][0]["bytes"], 900_000);
}

#[test]
fn a_large_read_names_its_secrets_and_what_was_open_before_the_burst() {
    let mut extra = process(
        101,
        vec![],
        vec![burst("203.0.113.9", 3_000_000, 3_000_000)],
    );
    extra.recent_reads = vec![
        ("/home/testuser/work/acme/old.ts".into(), 1),
        ("/home/testuser/work/acme/src/a.ts".into(), 3_000),
        ("/home/testuser/work/acme/.env".into(), 3_500),
        ("/home/testuser/work/acme/after.ts".into(), 9_000),
    ];
    extra.sensitive_reads = vec![
        (
            "/home/testuser/.ssh/id_ed25519".into(),
            3_600,
            411,
            "private_key".into(),
        ),
        (
            "/home/testuser/work/acme/.env".into(),
            3_500,
            120,
            "app_secret".into(),
        ),
    ];
    let flow = flow_of(
        101,
        RootTotals {
            read_bytes: 2_500_000,
            ..root(3_210, 60, 2_000)
        },
        extra,
    );
    assert_eq!(flow["large_read"], true, "{flow}");
    assert_eq!(flow["compared_with"], "bytes read");
    let d = &flow["destinations"][0];
    assert_eq!(d["burst_percent_of_workspace"], 120);
    assert_eq!(d["over_threshold"], true);
    // Newest first, inside the window that ended with the burst at 4,000.
    let before: Vec<&str> = d["files_before_burst"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        before,
        [
            "/home/testuser/work/acme/.env",
            "/home/testuser/work/acme/src/a.ts",
            "/home/testuser/work/acme/old.ts"
        ]
    );
    // Oldest first, a key outside the workspace included.
    assert_eq!(flow["sensitive"][0], "/home/testuser/work/acme/.env");
    assert_eq!(flow["sensitive"][1], "/home/testuser/.ssh/id_ed25519");
}

#[test]
fn a_read_that_could_not_be_sized_is_not_used_as_a_tiny_basis() {
    // A container's paths do not resolve on the host: 3,000 of 3,210
    // files unsized, so the 50 KB sized is a floor, not the read.
    let flow = flow_of(
        101,
        RootTotals {
            read_bytes: 50_000,
            unsized_files: 3_000,
            ..root(3_210, 60, 2_000)
        },
        process(101, vec![], vec![burst("198.51.100.7", 900_000, 900_000)]),
    );
    assert_eq!(flow["compared_with"], "workspace size", "{flow}");
    assert_eq!(flow["destinations"][0]["burst_percent_of_workspace"], 33);
    assert_eq!(flow["destinations"][0]["over_threshold"], false);
}

fn small_repo(destinations: Vec<DestTotals>) -> Value {
    // The decoy on Kali: 3,203 files, 2.7 MB with its history.
    let mut f = fake();
    f.workspace_bytes = 2_700_000;
    project(
        &json!({}),
        &Totals {
            processes: vec![process(101, vec![root(3_210, 60, 2_000)], destinations)],
            forgotten: 0,
            saturated: false,
        },
        &lineage(),
        &agents(),
        &mut f,
        &|_| Vec::new(),
        &crate::honeytoken::Manifest::default(),
        "boot",
    )
}

#[test]
fn a_small_workspace_uploaded_in_a_burst_is_caught_wherever_it_goes() {
    // Elsewhere: a compressed archive, 25% of the workspace, in a burst.
    let out = small_repo(vec![burst("203.0.113.9", 700_000, 680_000)]);
    let headline = out["rows"][0]["headline"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(
        headline.contains("within 5 minutes, about 25% of the 2.7 MB workspace"),
        "{out}"
    );
    // To its own service, the whole of a small workspace stays under the
    // 32 MB floor: a long session re-sends that much as context.
    let out = small_repo(vec![burst("198.51.100.7", 3_300_000, 3_000_000)]);
    assert!(out["rows"].as_array().unwrap().is_empty(), "{out}");
    // A 40 MB workspace sent whole to its own service, at once, fires.
    let mut f = fake();
    f.workspace_bytes = 40_000_000;
    let out = project(
        &json!({}),
        &Totals {
            processes: vec![process(
                101,
                vec![root(3_210, 60, 2_000)],
                vec![burst("198.51.100.7", 44_500_000, 44_400_000)],
            )],
            forgotten: 0,
            saturated: false,
        },
        &lineage(),
        &agents(),
        &mut f,
        &|_| Vec::new(),
        &crate::honeytoken::Manifest::default(),
        "boot",
    );
    let row = &out["rows"][0];
    assert!(
        row["headline"]
            .as_str()
            .unwrap()
            .contains(", its own service,"),
        "{out}"
    );
    assert!(
        row["why"]
            .to_string()
            .contains("Volume matches the full workspace")
    );
    assert_eq!(row["evidence"]["burst"]["own_service"], true);
    assert_eq!(row["evidence"]["burst"]["percent_of_workspace"], 111);
    assert!(
        row["limits"].to_string().contains("only from 32.0 MB"),
        "{row}"
    );
}

#[test]
fn ordinary_model_traffic_to_its_own_service_is_not_a_burst() {
    // Over a whole session ZCode sent 4 MB to its own model, but never
    // more than 30% of the workspace within five minutes.
    let out = small_repo(vec![burst("198.51.100.7", 4_000_000, 800_000)]);
    assert!(out["rows"].as_array().unwrap().is_empty(), "{out}");
    // Silent, but still visible: where the data went and how much.
    let flow = &out["flows"][0];
    assert_eq!(flow["workspace_bytes"], 2_700_000);
    assert_eq!(flow["destinations"][0]["own_service"], true);
    assert_eq!(flow["destinations"][0]["bytes"], 4_000_000);
    assert_eq!(flow["destinations"][0]["burst_percent_of_workspace"], 29);
    // And a burst under the floor never fires, however small the repo.
    let mut f = fake();
    f.workspace_bytes = 100_000;
    let tiny = project(
        &json!({}),
        &Totals {
            processes: vec![process(
                101,
                vec![root(600, 0, 2_000)],
                vec![burst("203.0.113.9", 200_000, 200_000)],
            )],
            forgotten: 0,
            saturated: false,
        },
        &lineage(),
        &agents(),
        &mut f,
        &|_| Vec::new(),
        &crate::honeytoken::Manifest::default(),
        "boot",
    );
    assert!(tiny["rows"].as_array().unwrap().is_empty(), "{tiny}");
}

#[test]
fn a_model_service_reading_agent_and_benign_shapes_are_silent() {
    // Reads a whole repository and talks a lot to its model service.
    let busy = vec![process(
        101,
        vec![root(20_000, 400, 2_000)],
        vec![dest("198.51.100.7", 300, 0, 400_000_000, 3_000)],
    )];
    // Indexes everything, sends nothing.
    let indexer = vec![process(101, vec![root(40_000, 900, 2_000)], vec![])];
    // Uploads a lot without having read a workspace.
    let uploader = vec![process(
        101,
        vec![root(30, 0, 2_000)],
        vec![dest("203.0.113.9", 2, 0, 900_000_000, 3_000)],
    )];
    // Below both egress thresholds.
    let small = vec![process(
        101,
        vec![root(5_000, 0, 2_000)],
        vec![dest("203.0.113.9", 19, 0, 10_485_759, 3_000)],
    )];
    for (name, totals) in [
        ("busy", busy),
        ("indexer", indexer),
        ("uploader", uploader),
        ("small", small),
    ] {
        let out = run(totals, &agents());
        assert!(out["rows"].as_array().unwrap().is_empty(), "{name}: {out}");
    }
}

#[test]
fn thresholds_hold_at_their_edges_and_egress_long_before_the_harvest_does_not_count() {
    let at_edge = run(
        vec![process(
            101,
            vec![root(500, 0, 2_000)],
            vec![dest("203.0.113.9", 20, 0, 1_048_576, 3_000)],
        )],
        &agents(),
    );
    assert_eq!(at_edge["rows"].as_array().unwrap().len(), 1);
    assert_eq!(at_edge["rows"][0]["severity"], "high");
    let headline = at_edge["rows"][0]["headline"].as_str().unwrap();
    assert!(headline.contains("tried to reach zcode-release.oss-cn-hongkong.aliyuncs.com (203.0.113.9:443) 20 times and sent 1.0 MB."), "{headline}");
    let history_only = run(
        vec![process(
            101,
            vec![root(60, 50, 2_000)],
            vec![dest("203.0.113.9", 1, 0, 10_485_760, 3_000)],
        )],
        &agents(),
    );
    assert_eq!(history_only["rows"].as_array().unwrap().len(), 1);
    let before = run(
        vec![process(
            101,
            vec![root(5_000, 0, 10_000_000)],
            vec![DestTotals {
                last_at: 5_000,
                ..dest("203.0.113.9", 50, 0, 90_000_000, 1_000)
            }],
        )],
        &agents(),
    );
    assert!(before["rows"].as_array().unwrap().is_empty(), "{before}");
}

#[test]
fn two_hundred_runs_are_two_hundred_incidents_and_none_shrinks() {
    let mut lineage = Lineage::new(1_024);
    let mut agents = BTreeMap::new();
    let mut processes = Vec::new();
    for n in 0..200_u32 {
        let key = ProcessKey {
            pid: 1_000 + n,
            started_at: UnixMillis(500 + u64::from(n)),
        };
        lineage.observe(observation(key.pid, None, "zcode", key.started_at.0));
        agents.insert(key, ("ZCode".to_owned(), Some("zcode".to_owned())));
        let mut p = process(
            1_000 + n,
            vec![root(1_000, 60, 2_000)],
            vec![dest("203.0.113.9", 30, 30, 2_000_000, 3_000)],
        );
        p.first_at = 600 + u64::from(n);
        processes.push(p);
    }
    let totals = Totals {
        processes,
        forgotten: 0,
        saturated: false,
    };
    let no_tools = |_: &BTreeSet<u32>| Vec::new();
    let first = project(
        &json!({}),
        &totals,
        &lineage,
        &agents,
        &mut fake(),
        &no_tools,
        &crate::honeytoken::Manifest::default(),
        "boot",
    );
    assert_eq!(first["rows"].as_array().unwrap().len(), 200);
    // The collector restarts: no live totals. Nothing is lost.
    let empty = Totals::default();
    let second = project(
        &first,
        &empty,
        &Lineage::new(8),
        &BTreeMap::new(),
        &mut fake(),
        &no_tools,
        &crate::honeytoken::Manifest::default(),
        "boot",
    );
    assert_eq!(second["rows"].as_array().unwrap().len(), 200);
    let ids: BTreeSet<_> = second["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids.len(), 200);
}

/// The 2026-10-13 GLM run: 2.0 MB read, measured, from a 3,210-file
/// workspace.
fn glm(destinations: Vec<DestTotals>) -> Value {
    let mut f = fake();
    f.workspace_bytes = 2_000_000;
    f.names
        .push(("203.0.113.10", "bucket-a.oss-cn-hongkong.aliyuncs.com"));
    f.names
        .push(("203.0.113.11", "bucket-b.oss-cn-hongkong.aliyuncs.com"));
    let mut read = root(3_210, 60, 2_000);
    read.read_bytes = 2_000_000;
    project(
        &json!({}),
        &Totals {
            processes: vec![process(101, vec![read], destinations)],
            forgotten: 0,
            saturated: false,
        },
        &lineage(),
        &agents(),
        &mut f,
        &|_| Vec::new(),
        &crate::honeytoken::Manifest::default(),
        "boot",
    )
}

/// `bytes` sent to `host` in one minute starting at `at`.
fn chunk(host: &str, bytes: u64, at: u64) -> DestTotals {
    DestTotals {
        burst_bytes: bytes,
        burst_at: at + 60_000,
        ..dest(host, 1, 0, bytes, at)
    }
}

#[test]
fn glm_talking_to_its_own_vendor_over_two_addresses_stays_silent() {
    // 1.2 MB and 1.0 MB to two Z.ai addresses in the same minutes. Each
    // address alone was under the bar; grouped they are 110% of the read,
    // but the agent's own service needs 32 MB in one burst.
    let out = glm(vec![
        chunk("198.51.100.7", 1_200_000, 3_000),
        chunk("198.51.100.8", 1_000_000, 3_000),
    ]);
    assert!(out["rows"].as_array().unwrap().is_empty(), "{out}");
}

#[test]
fn the_same_total_in_three_late_object_storage_chunks_fires() {
    // 2.2 MB in three pieces, 45, 90 and 135 minutes after the read: each
    // after the 30-minute window, so only the whole-run ledger sees them.
    let minute = 60_000;
    let out = glm(vec![
        chunk("203.0.113.9", 733_334, 45 * minute),
        chunk("203.0.113.10", 733_333, 90 * minute),
        chunk("203.0.113.11", 733_333, 135 * minute),
    ]);
    let rows = out["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "{out}");
    let row = &rows[0];
    let headline = row["headline"].as_str().unwrap();
    assert!(headline.contains("then sent 2.2 MB to"), "{headline}");
    assert!(
        headline.contains("(3 addresses, most to 203.0.113.9:443) across the run"),
        "{headline}"
    );
    assert!(
        headline.contains("about 110% of the 2.0 MB it read"),
        "{headline}"
    );
    assert!(
        row["why"].to_string().contains("Totals cover the full run"),
        "{row}"
    );
    assert_eq!(row["evidence"]["whole_run"]["addresses"], 3);
    assert_eq!(row["evidence"]["whole_run"]["bytes"], 2_200_000);
    assert_eq!(row["numbers"]["bytes_sent"], 2_200_000);
    // Object storage with git history read: as critical as a burst.
    assert_eq!(row["severity"], "critical");
}

#[test]
fn an_upload_split_across_one_networks_addresses_is_one_burst() {
    // 2.2 MB over ten unnamed addresses in one /24 within five minutes:
    // each 220 KB, under the 256 KB floor alone.
    let pieces: Vec<DestTotals> = (20..30)
        .map(|n| chunk(&format!("192.0.2.{n}"), 220_000, 3_000))
        .collect();
    let out = glm(pieces);
    let rows = out["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "{out}");
    let headline = rows[0]["headline"].as_str().unwrap();
    assert!(
        headline.contains("then sent 2.2 MB to network 192.0.2.0/24 (10 addresses"),
        "{headline}"
    );
    assert!(headline.contains("within 5 minutes"), "{headline}");
    assert_eq!(rows[0]["evidence"]["burst"]["addresses"], 10);
    assert!(rows[0]["why"].to_string().contains("one owner"));
    // The same ten pieces spread an hour apart each are not a burst, and
    // sent to ten different networks they are ten small owners: silent.
    let spread: Vec<DestTotals> = (20..30_u64)
        .map(|n| chunk(&format!("192.0.{n}.1"), 220_000, 3_000 + n * 3_600_000))
        .collect();
    let out = glm(spread);
    assert!(out["rows"].as_array().unwrap().is_empty(), "{out}");
}

#[test]
fn a_planted_decoy_read_is_one_honeytoken_card_and_not_a_secret_card() {
    let planted = "/home/testuser/work/acme/.env";
    let mut honeytokens = crate::honeytoken::Manifest::default();
    honeytokens.tokens.insert(
        planted.into(),
        crate::honeytoken::manifest::Token {
            class: "app_secret".into(),
            bytes: 300,
            planted_at: 1,
        },
    );
    let mut p = process(101, vec![], vec![dest("203.0.113.9", 1, 0, 2_000, 3_000)]);
    p.sensitive_reads = vec![
        (planted.into(), 2_000, 300, "app_secret".into()),
        (
            "/home/testuser/.aws/credentials".into(),
            2_500,
            120,
            "cloud_credential".into(),
        ),
    ];
    let out = project(
        &json!({}),
        &Totals {
            processes: vec![p],
            forgotten: 0,
            saturated: false,
        },
        &lineage(),
        &agents(),
        &mut fake(),
        &|_| Vec::new(),
        &honeytokens,
        "boot",
    );
    let rows = out["rows"].as_array().unwrap();
    let card = kind_of(rows, "honeytoken_accessed").expect("a honeytoken card");
    assert_eq!(card["severity"], "critical");
    assert_eq!(card["headline"], "ZCode opened 1 honeytoken: .env.");
    assert_eq!(card["evidence"]["honeytokens"][0]["planted_at"], 1);
    // The real-looking credential still raises its secret card; the decoy
    // is not listed on it.
    let secret = rows
        .iter()
        .find(|r| r["kind"] != "honeytoken_accessed")
        .expect("a secret card for the real credential");
    assert!(
        !secret["evidence"].to_string().contains("acme/.env"),
        "{secret}"
    );
    // Without the manifest the same read is an ordinary secret read.
    let plain = incidents_of({
        let mut p = process(101, vec![], vec![dest("203.0.113.9", 1, 0, 2_000, 3_000)]);
        p.sensitive_reads = vec![(planted.into(), 2_000, 300, "app_secret".into())];
        p
    });
    assert!(kind_of(&plain, "honeytoken_accessed").is_none());
}

#[test]
fn object_storage_patterns_match_labels_not_substrings() {
    let p = &config().object_storage;
    assert!(object_storage(
        "zcode-release.oss-cn-hongkong.aliyuncs.com",
        p
    ));
    assert!(object_storage("s3-us-west-2-r-w.amazonaws.com", p));
    assert!(object_storage("acct.blob.core.windows.net", p));
    assert!(!object_storage("dashscope.aliyuncs.com", p));
    assert!(!object_storage("ec2-1-2-3-4.compute-1.amazonaws.com", p));
    assert!(!object_storage("oss.aliyuncs.com.evil.example", p));
}

#[test]
fn the_shipped_configuration_parses_and_numbers_read_like_numbers() {
    let cfg = parse(CONFIG_JSON).expect("parses");
    assert_eq!(cfg.thresholds.harvest_files, 500);
    assert_eq!(cfg.thresholds.own_service_floor_bytes, 32_000_000);
    assert_eq!(cfg.thresholds.run_percent_other, 50);
    assert_eq!(cfg.thresholds.run_floor_bytes, 1024 * 1024);
    // Every threshold is explained in words in the shipped file.
    let raw: Value = serde_json::from_str(CONFIG_JSON).unwrap();
    for key in raw["thresholds"].as_object().unwrap().keys() {
        assert!(
            raw["thresholds_explained"][key].is_string(),
            "{key} unexplained"
        );
    }
    assert!(cfg.model_services.iter().any(|s| s == "api.z.ai"));
    assert_eq!(bytes(313_000_000), "313 MB");
    assert_eq!(bytes(999), "999 bytes");
    assert_eq!(bytes(4_200), "4.2 KB");
    assert_eq!(count(42_411), "42,411");
    assert_eq!(count(7), "7");
}
