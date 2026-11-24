//! Turning a rule's condition into one tree: macros inlined, lists expanded.
//!
//! A rule is resolved in its own file's scope first, then in the other files
//! in load order (stable, incubating, sandbox). Three names are defined
//! differently in different files, and a rule must see its own file's
//! definition. Inlining is bounded and cycle-checked.

use std::collections::BTreeSet;

use super::{Catalogue, CatalogueError, Maturity, RawRule, Rule};
use crate::lang::{Expr, Item, Operand, parse};

/// Deepest chain of macros inside macros, and of lists inside lists.
const MAX_NESTING: usize = 64;

const LOAD_ORDER: [Maturity; 3] = [Maturity::Stable, Maturity::Incubating, Maturity::Sandbox];

impl Catalogue {
    pub(super) fn resolve(&self, raw: &RawRule) -> Result<Rule, CatalogueError> {
        let context = |message: String| CatalogueError {
            message: format!("rule `{}`: {message}", raw.name),
        };
        let parsed = parse(&raw.condition).map_err(|error| context(error.message))?;
        let condition = self
            .inline(parsed, raw.file, &mut Vec::new())
            .map_err(context)?;
        let mut fields = BTreeSet::new();
        collect_fields(&condition, &mut fields);
        Ok(Rule {
            name: raw.name.clone(),
            maturity: raw.file,
            priority: raw.priority.clone(),
            tags: raw.tags.clone(),
            enabled: raw.enabled,
            desc: raw.desc.clone(),
            condition,
            fields,
        })
    }

    /// Files to search for a name, the rule's own first.
    fn scope(file: Maturity) -> impl Iterator<Item = Maturity> {
        std::iter::once(file).chain(LOAD_ORDER.into_iter().filter(move |f| *f != file))
    }

    fn find_macro(&self, name: &str, file: Maturity) -> Option<&str> {
        Self::scope(file).find_map(|f| {
            self.macros
                .iter()
                .find(|m| m.file == f && m.name == name)
                .map(|m| m.condition.as_str())
        })
    }

    fn find_list(&self, name: &str, file: Maturity) -> Option<&[String]> {
        Self::scope(file).find_map(|f| {
            self.lists
                .iter()
                .find(|l| l.file == f && l.name == name)
                .map(|l| l.items.as_slice())
        })
    }

    fn inline(&self, expr: Expr, file: Maturity, chain: &mut Vec<String>) -> Result<Expr, String> {
        Ok(match expr {
            Expr::And(parts) => Expr::And(self.inline_all(parts, file, chain)?),
            Expr::Or(parts) => Expr::Or(self.inline_all(parts, file, chain)?),
            Expr::Not(inner) => Expr::Not(Box::new(self.inline(*inner, file, chain)?)),
            Expr::Macro(name) => {
                if chain.contains(&name) {
                    return Err(format!("macro cycle through `{name}`"));
                }
                if chain.len() >= MAX_NESTING {
                    return Err("macros nested too deeply".to_owned());
                }
                let condition = self
                    .find_macro(&name, file)
                    .ok_or_else(|| format!("unknown macro `{name}`"))?;
                let parsed =
                    parse(condition).map_err(|e| format!("macro `{name}`: {}", e.message))?;
                chain.push(name);
                let inlined = self.inline(parsed, file, chain);
                chain.pop();
                inlined?
            }
            Expr::Compare {
                field,
                op,
                value: Operand::Set(items),
            } => {
                let mut expanded = Vec::new();
                for item in items {
                    self.expand(item, file, &mut Vec::new(), &mut expanded)?;
                }
                Expr::Compare {
                    field,
                    op,
                    value: Operand::Set(expanded),
                }
            }
            other @ (Expr::Compare { .. } | Expr::Exists(_)) => other,
        })
    }

    fn inline_all(
        &self,
        parts: Vec<Expr>,
        file: Maturity,
        chain: &mut Vec<String>,
    ) -> Result<Vec<Expr>, String> {
        parts
            .into_iter()
            .map(|part| self.inline(part, file, chain))
            .collect()
    }

    /// A set item: a list name becomes the list's items, recursively.
    fn expand(
        &self,
        item: Item,
        file: Maturity,
        chain: &mut Vec<String>,
        out: &mut Vec<Item>,
    ) -> Result<(), String> {
        let Item::Bare(name) = &item else {
            out.push(item);
            return Ok(());
        };
        let Some(items) = self.find_list(name, file) else {
            out.push(item);
            return Ok(());
        };
        if chain.contains(name) || chain.len() >= MAX_NESTING {
            return Err(format!("list cycle through `{name}`"));
        }
        chain.push(name.clone());
        for inner in items {
            self.expand(list_item(inner), file, chain, out)?;
        }
        chain.pop();
        Ok(())
    }
}

/// A list item as the condition would read it if written in by hand: a
/// quoted item is a quoted value, a bare one may name another list.
fn list_item(text: &str) -> Item {
    match crate::lang::single_token(text) {
        Some(item) => item,
        None => Item::Quoted(text.to_owned()),
    }
}

fn collect_fields(expr: &Expr, out: &mut BTreeSet<String>) {
    match expr {
        Expr::And(parts) | Expr::Or(parts) => {
            for part in parts {
                collect_fields(part, out);
            }
        }
        Expr::Not(inner) => collect_fields(inner, out),
        Expr::Macro(_) => {}
        Expr::Compare { field, .. } | Expr::Exists(field) => {
            out.insert(field.name.clone());
        }
    }
}
