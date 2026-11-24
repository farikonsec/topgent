//! An agent's risk in plain words, for people who are not security engineers.
//!
//! The factors behind a score are precise and technical: `SECRET_REACHABLE`
//! three times, once per file, each with an ATLAS id. A person deciding whether
//! to let an agent keep running needs one sentence per kind of risk, why it
//! matters, and what to do. This folds the factors into those sentences using
//! `data/plain-risks.json`, so every front end says the same thing in the same
//! words and none of them invents its own translation.
//!
//! Each group appears once however many factors fed it; the factor titles are
//! kept as its `details` so nothing is lost, only folded. Groups are ordered
//! most urgent first, then in the data file's order, so the first one is the
//! headline.

use std::sync::OnceLock;

use serde_json::{Value, json};

const DATA: &str = include_str!("../data/plain-risks.json");

#[derive(Debug)]
struct Group {
    id: String,
    kind: String,
    level: String,
    headline: String,
    why: String,
    decision: String,
    codes: Vec<String>,
}

#[derive(Debug)]
struct Catalogue {
    groups: Vec<Group>,
    labels: Value,
}

fn catalogue() -> &'static Catalogue {
    static CATALOGUE: OnceLock<Catalogue> = OnceLock::new();
    CATALOGUE.get_or_init(|| {
        // Shipped with the binary and checked by a test; a parse failure is a
        // build defect, so it yields no groups rather than a panic.
        let data: Value = serde_json::from_str(DATA).unwrap_or(Value::Null);
        let text = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
        let groups = data
            .get("groups")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|g| Group {
                id: text(g, "id"),
                kind: text(g, "kind"),
                level: text(g, "level"),
                headline: text(g, "headline"),
                why: text(g, "why"),
                decision: text(g, "decision"),
                codes: g
                    .get("codes")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect(),
            })
            .collect();
        Catalogue {
            groups,
            labels: data.get("levels").cloned().unwrap_or(Value::Null),
        }
    })
}

/// How urgent a level is; lower sorts first.
fn rank(level: &str) -> u8 {
    match level {
        "act" => 0,
        "watch" => 1,
        "info" => 2,
        _ => 3,
    }
}

fn label(level: &str) -> String {
    catalogue()
        .labels
        .get(level)
        .and_then(Value::as_str)
        .unwrap_or(level)
        .to_owned()
}

/// One risk as a person reads it.
struct Risk {
    order: usize,
    id: String,
    kind: String,
    level: String,
    headline: String,
    why: String,
    decision: String,
    details: Vec<String>,
}

/// The plain summary of one agent's factors, given as `(code, title)` pairs.
///
/// A code the data file does not know still shows, under its own title and as
/// worth a look, so a new factor is never silently dropped from this view.
pub(crate) fn summary<'a>(factors: impl IntoIterator<Item = (&'a str, &'a str)>) -> Value {
    let groups = &catalogue().groups;
    let mut risks: Vec<Risk> = Vec::new();
    for (code, title) in factors {
        let found = groups
            .iter()
            .enumerate()
            .find(|(_, g)| g.codes.iter().any(|c| c == code));
        let (order, id) = match found {
            Some((i, g)) => (i, g.id.clone()),
            None => (groups.len(), format!("other:{code}")),
        };
        if let Some(existing) = risks.iter_mut().find(|r| r.id == id) {
            if !existing.details.iter().any(|d| d == title) {
                existing.details.push(title.to_owned());
            }
            continue;
        }
        let risk = match found {
            Some((_, g)) => Risk {
                order,
                id,
                kind: g.kind.clone(),
                level: g.level.clone(),
                headline: g.headline.clone(),
                why: g.why.clone(),
                decision: g.decision.clone(),
                details: vec![title.to_owned()],
            },
            None => Risk {
                order,
                id,
                kind: "access".to_owned(),
                level: "watch".to_owned(),
                headline: title.to_owned(),
                why: String::new(),
                decision: String::new(),
                details: Vec::new(),
            },
        };
        risks.push(risk);
    }
    risks.sort_by(|a, b| {
        rank(&a.level)
            .cmp(&rank(&b.level))
            .then(a.order.cmp(&b.order))
    });
    let level = risks
        .first()
        .map_or_else(|| "none".to_owned(), |r| r.level.clone());
    let headline = risks
        .iter()
        .find(|r| r.level != "info")
        .map_or_else(|| label(&level), |r| r.headline.clone());
    json!({
        "level": level,
        "label": label(&level),
        "headline": headline,
        "did_something": risks.iter().any(|r| r.kind == "activity"),
        "risks": risks.iter().map(|r| json!({
            "id": r.id,
            "kind": r.kind,
            "level": r.level,
            "label": label(&r.level),
            "headline": r.headline,
            "why": r.why,
            "decision": r.decision,
            "details": r.details,
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::expect_used)]

    use super::{catalogue, summary};
    use serde_json::Value;

    const FACTORS: &str = include_str!("../../topgent-policy/data/risk-factors.json");

    #[test]
    fn every_risk_factor_has_exactly_one_plain_group() {
        let factors: Value = serde_json::from_str(FACTORS).expect("risk factors parse");
        let codes: Vec<&str> = factors["factors"]
            .as_array()
            .expect("a list")
            .iter()
            .filter_map(|f| f["code"].as_str())
            .collect();
        assert_eq!(codes.len(), 20);
        for code in codes {
            let homes = catalogue()
                .groups
                .iter()
                .filter(|g| g.codes.iter().any(|c| c == code))
                .count();
            assert_eq!(homes, 1, "{code} belongs to {homes} plain groups");
        }
    }

    #[test]
    fn every_group_says_why_and_what_to_do() {
        for group in &catalogue().groups {
            assert!(
                !group.headline.is_empty() && !group.why.is_empty() && !group.decision.is_empty(),
                "{}",
                group.id
            );
            assert!(
                ["act", "watch", "info"].contains(&group.level.as_str()),
                "{}",
                group.id
            );
            assert!(
                ["access", "activity"].contains(&group.kind.as_str()),
                "{}",
                group.id
            );
        }
    }

    #[test]
    fn three_reachable_files_read_as_one_risk_with_three_details() {
        let out = summary([
            ("ARBITRARY_EXECUTION", "Can execute arbitrary processes"),
            ("SECRET_REACHABLE", "~/.aws/credentials is within reach"),
            ("SECRET_REACHABLE", "~/.ssh/id_rsa is within reach"),
            ("SECRET_REACHABLE", "~/.config/gh/hosts.yml is within reach"),
            ("EXFILTRATION_PATH", "Can reach a credential and act on it"),
        ]);
        let risks = out["risks"].as_array().expect("risks");
        assert_eq!(risks.len(), 2);
        assert_eq!(risks[0]["id"], "can_leak");
        assert_eq!(risks[0]["details"].as_array().expect("details").len(), 4);
        assert_eq!(out["level"], "watch");
        assert_eq!(out["headline"], "Credential exposure");
        assert_eq!(out["did_something"], false);
    }

    #[test]
    fn something_it_did_outranks_what_it_could_do() {
        let out = summary([
            ("ARBITRARY_EXECUTION", "Can execute arbitrary processes"),
            ("CREDENTIAL_ACCESS", "Read ~/.ssh/id_rsa"),
        ]);
        assert_eq!(out["level"], "act");
        assert_eq!(out["risks"][0]["id"], "secrets_read");
        assert_eq!(out["did_something"], true);
    }

    #[test]
    fn only_normal_capabilities_read_as_normal() {
        let out = summary([("ARBITRARY_EXECUTION", "Can execute arbitrary processes")]);
        assert_eq!(out["level"], "info");
        assert_eq!(out["headline"], "Info");
        let none = summary(std::iter::empty());
        assert_eq!(none["level"], "none");
        assert_eq!(none["headline"], "OK");
    }

    #[test]
    fn an_unknown_code_still_shows_under_its_own_title() {
        let out = summary([("SOMETHING_NEW", "Did something new")]);
        assert_eq!(out["risks"][0]["headline"], "Did something new");
        assert_eq!(out["level"], "watch");
    }
}
