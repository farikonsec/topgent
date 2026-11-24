//! What one sweep costs, with the process table walked per collector or once.
//!
//! Ignored by default: it measures the machine it runs on rather than asserting
//! something about the code. Run it on the lab host with
//! `cargo test -p topgent-collect --test sweep_cost -- --ignored --nocapture`.
//! It prints one JSON line. The only assertion is the walk count, which does
//! not depend on the machine.

use std::time::Instant;

use topgent_collect::{FixedClock, default_collectors, process, sweep};

fn median(mut samples: Vec<u128>) -> u128 {
    samples.sort_unstable();
    samples.get(samples.len() / 2).copied().unwrap_or_default()
}

#[test]
#[ignore = "a measurement of the host, run by hand on the lab machine"]
fn shared_sweep_walks_once_and_costs_less() {
    let collectors = default_collectors();
    let clock = FixedClock(1);
    let rounds = 7;

    let (mut separate_ms, mut separate_walks) = (Vec::new(), 0);
    for _ in 0..rounds {
        let before = process::walks();
        let started = Instant::now();
        // What a sweep was before S3: every collector on its own.
        for collector in &collectors {
            let _ = collector.collect(&clock);
        }
        separate_ms.push(started.elapsed().as_millis());
        separate_walks = process::walks() - before;
    }

    let (mut shared_ms, mut shared_walks) = (Vec::new(), 0);
    for _ in 0..rounds {
        let before = process::walks();
        let started = Instant::now();
        let _ = sweep(&collectors, &clock);
        shared_ms.push(started.elapsed().as_millis());
        shared_walks = process::walks() - before;
    }

    let processes = process::snapshot().len();
    println!(
        "{{\"processes\":{processes},\"rounds\":{rounds},\"separate\":{{\"walks\":{separate_walks},\"median_ms\":{}}},\"shared\":{{\"walks\":{shared_walks},\"median_ms\":{}}}}}",
        median(separate_ms),
        median(shared_ms)
    );
    assert_eq!(shared_walks, 1);
    assert!(separate_walks > shared_walks);
}
