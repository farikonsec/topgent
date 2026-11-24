//! The parts every incident card shares: its words from a data file, the
//! agent it is about, the reasons and the actions. Each rule supplies its
//! own headline, numbers and evidence.

use serde_json::{Value, json};

use super::Run;

/// A card's fixed words, as a rule's data file gives them under `card`.
#[derive(Debug, Clone)]
pub(crate) struct Words {
    pub kind: String,
    pub name: String,
    pub severity: String,
    pub why: Vec<String>,
    pub actions: Vec<String>,
    pub limits: Vec<String>,
}

impl Words {
    /// The words in a data file's `card` object, or `None` when one is missing.
    pub(crate) fn parse(card: &Value) -> Option<Self> {
        let text = |f: &str| card.get(f)?.as_str().map(str::to_owned);
        let list = |f: &str| -> Option<Vec<String>> {
            card.get(f)?
                .as_array()?
                .iter()
                .map(|v| v.as_str().map(str::to_owned))
                .collect()
        };
        Some(Self {
            kind: text("kind")?,
            name: text("name")?,
            severity: text("severity")?,
            why: list("why")?,
            actions: list("actions")?,
            limits: list("limits")?,
        })
    }

    /// Bare words for a data file that did not parse: the card still names
    /// what happened.
    pub(crate) fn bare(kind: &str, name: &str, severity: &str) -> Self {
        Self {
            kind: kind.into(),
            name: name.into(),
            severity: severity.into(),
            why: Vec::new(),
            actions: Vec::new(),
            limits: Vec::new(),
        }
    }

    /// The reasons, plus a line when the program is not a recognised agent.
    pub(crate) fn why(&self, run: &Run) -> Vec<String> {
        let mut why = self.why.clone();
        if run.family.is_none() {
            why.push(format!(
                "Topgent does not recognise {} as an AI agent. It is reported because of what it did.",
                run.name
            ));
        }
        why
    }

    /// Stopping the run first, then the data file's advice.
    pub(crate) fn actions(&self, run: &Run) -> Vec<Value> {
        std::iter::once(json!({
            "label": format!("Stop {}", run.name),
            "command": format!("topgent stop {}", run.key.pid),
        }))
        .chain(
            self.actions
                .iter()
                .map(|label| json!({"label": label, "command": ""})),
        )
        .collect()
    }
}

/// Who a card is about.
pub(crate) fn agent(run: &Run) -> Value {
    json!({
        "pid": run.key.pid,
        "started_at": run.key.started_at.0,
        "name": run.name,
        "family": run.family,
        "recognised": run.family.is_some(),
    })
}
