//! Fixed S8 identity accuracy gate over training and untouched partitions.

#![allow(clippy::expect_used)]

use serde::Deserialize;
use std::collections::BTreeSet;
use topgent_collect::signatures::classify;

#[derive(Deserialize)]
struct Corpus {
    schema_version: u16,
    #[serde(rename = "corpus_id")]
    id: String,
    frozen_at: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    partition: String,
    environment: String,
    executable: String,
    expected_class: String,
    expected_family: Option<String>,
}

#[test]
fn frozen_s8_identity_corpus_meets_the_accuracy_contract() {
    let corpus: Corpus = serde_json::from_str(include_str!("data/s8-identity-corpus.json"))
        .expect("S8 corpus must be valid JSON");
    assert_eq!(corpus.schema_version, 1);
    assert_eq!(corpus.id, "s8-identity-v1");
    assert_eq!(corpus.frozen_at, "2026-09-24");
    assert_eq!(corpus.cases.len(), 30, "case removal changes the score");

    let held_out_environments = corpus
        .cases
        .iter()
        .filter(|case| case.partition == "held_out")
        .map(|case| case.environment.as_str())
        .collect::<BTreeSet<_>>();
    assert!(held_out_environments.contains("held-out-qwen-family"));
    assert!(held_out_environments.contains("held-out-kimi-family"));
    assert!(held_out_environments.contains("held-out-rust-workspace"));

    let mut true_positives = 0_u64;
    let mut false_positives = 0_u64;
    let mut false_negatives = 0_u64;
    let mut held_out_positives = 0_u64;
    let mut held_out_true_positives = 0_u64;
    let mut failures = Vec::new();

    for case in &corpus.cases {
        let (class, family) = classify(&case.executable);
        let actual_class = class.as_str();
        let actual_family = family.map(|family| family.id.as_str());
        let expected_positive = case.expected_family.is_some();
        let exact =
            actual_class == case.expected_class && actual_family == case.expected_family.as_deref();

        if expected_positive {
            if case.partition == "held_out" {
                held_out_positives += 1;
            }
            if exact {
                true_positives += 1;
                if case.partition == "held_out" {
                    held_out_true_positives += 1;
                }
            } else {
                false_negatives += 1;
            }
        } else if actual_family.is_some() {
            false_positives += 1;
        }
        if !exact {
            failures.push(format!(
                "{}: expected {}/{:?}, got {}/{:?}",
                case.id, case.expected_class, case.expected_family, actual_class, actual_family
            ));
        }
    }

    let precision_milli = true_positives * 1_000 / (true_positives + false_positives);
    let recall_milli = true_positives * 1_000 / (true_positives + false_negatives);
    let held_out_recall_milli = held_out_true_positives * 1_000 / held_out_positives;
    println!(
        "S8 identity: cases={} precision={}.{:03} recall={}.{:03} held_out_recall={}.{:03} benign_false_positives={false_positives}",
        corpus.cases.len(),
        precision_milli / 1_000,
        precision_milli % 1_000,
        recall_milli / 1_000,
        recall_milli % 1_000,
        held_out_recall_milli / 1_000,
        held_out_recall_milli % 1_000,
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert_eq!(precision_milli, 1_000);
    assert_eq!(recall_milli, 1_000);
    assert_eq!(held_out_recall_milli, 1_000);
    assert_eq!(false_positives, 0);
}
