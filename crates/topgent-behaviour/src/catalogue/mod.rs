//! The pinned catalogue: rules, macros and lists, and resolving them.

mod resolve;

use std::collections::BTreeSet;

use serde::Deserialize;

use crate::lang::Expr;

/// The catalogue as vendored, in its JSON form.
const PINNED: &str = include_str!("../../data/f/catalogue.json");

/// Which of the three catalogue files a definition comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Maturity {
    /// Loaded by default upstream.
    Stable,
    /// Useful, less proven.
    Incubating,
    /// Experimental.
    Sandbox,
}

/// Why the catalogue could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogueError {
    /// What was wrong, naming the rule or macro where there is one.
    pub message: String,
}

impl std::fmt::Display for CatalogueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CatalogueError {}

#[derive(Debug, Clone, Deserialize)]
struct List {
    file: Maturity,
    name: String,
    items: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Macro {
    file: Maturity,
    name: String,
    condition: String,
}

#[derive(Debug, Clone, Deserialize)]
struct RawRule {
    file: Maturity,
    name: String,
    condition: String,
    priority: String,
    tags: Vec<String>,
    enabled: bool,
    desc: String,
}

/// The catalogue, loaded but not yet resolved.
#[derive(Debug, Clone, Deserialize)]
pub struct Catalogue {
    commit: String,
    lists: Vec<List>,
    macros: Vec<Macro>,
    rules: Vec<RawRule>,
}

/// One rule, resolved into a single condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// The rule's name in the catalogue.
    pub name: String,
    /// Which file it comes from.
    pub maturity: Maturity,
    /// Its priority as written: `CRITICAL`, `WARNING`, `NOTICE` and so on.
    pub priority: String,
    /// Its tags, including MITRE technique ids.
    pub tags: Vec<String>,
    /// Whether the catalogue enables it by default.
    pub enabled: bool,
    /// What it looks for, in the catalogue's words.
    pub desc: String,
    /// The condition with every macro and list resolved.
    pub condition: Expr,
    /// Every field the condition reads.
    pub fields: BTreeSet<String>,
}

impl Catalogue {
    /// The catalogue vendored with this build.
    ///
    /// # Errors
    ///
    /// Returns an error only if the embedded JSON is malformed, which a test
    /// guards against.
    pub fn pinned() -> Result<Self, CatalogueError> {
        Self::from_json(PINNED)
    }

    /// A catalogue from its JSON form.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed JSON or missing sections.
    pub fn from_json(text: &str) -> Result<Self, CatalogueError> {
        serde_json::from_str(text).map_err(|error| CatalogueError {
            message: format!("catalogue is malformed: {error}"),
        })
    }

    /// The catalogue with list `name` holding `items`, in every file.
    ///
    /// Thirteen lists ship empty for the operator to fill (the namespaces a
    /// rule applies to, known-good images); this is how they are filled.
    #[must_use]
    pub fn with_list(mut self, name: &str, items: &[&str]) -> Self {
        for list in self.lists.iter_mut().filter(|list| list.name == name) {
            list.items = items.iter().map(|item| (*item).to_owned()).collect();
        }
        self
    }

    /// The catalogue with macro `name` replaced by `condition`, in every file.
    ///
    /// Some macros are placeholders meant to be replaced, such as the one
    /// naming allowed containers.
    #[must_use]
    pub fn with_macro(mut self, name: &str, condition: &str) -> Self {
        for found in self.macros.iter_mut().filter(|m| m.name == name) {
            condition.clone_into(&mut found.condition);
        }
        self
    }

    /// The upstream commit the catalogue is pinned to.
    #[must_use]
    pub fn commit(&self) -> &str {
        &self.commit
    }

    /// How many rules, macros and lists it holds.
    #[must_use]
    pub fn counts(&self) -> (usize, usize, usize) {
        (self.rules.len(), self.macros.len(), self.lists.len())
    }

    /// Every rule, resolved.
    ///
    /// # Errors
    ///
    /// Returns the first rule that does not parse or resolve: a catalogue
    /// with one broken rule is not loaded partly.
    pub fn compile(&self) -> Result<Vec<Rule>, CatalogueError> {
        self.rules.iter().map(|rule| self.resolve(rule)).collect()
    }

    /// One rule by name, resolved.
    ///
    /// # Errors
    ///
    /// Returns an error if there is no such rule, or it does not resolve.
    pub fn compile_rule(&self, name: &str) -> Result<Rule, CatalogueError> {
        let rule = self
            .rules
            .iter()
            .find(|rule| rule.name == name)
            .ok_or_else(|| CatalogueError {
                message: format!("no rule named `{name}`"),
            })?;
        self.resolve(rule)
    }
}
