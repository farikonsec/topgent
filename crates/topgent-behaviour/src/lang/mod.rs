//! The condition language the catalogue is written in.
//!
//! Tokens, syntax tree and parser are separate files because each is read
//! and changed on its own: the lexer decides what a bare value is, the parser
//! decides precedence, and the tree is what the evaluator and the catalogue
//! share.

mod ast;
mod lex;
mod parse;

pub use ast::{Expr, FieldRef, Item, Op, Operand};

/// Why a condition could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// What was wrong.
    pub message: String,
}

impl ParseError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ParseError {}

/// A list item read as one value: `"a b"` is quoted, `sh` is bare. `None`
/// if the text is not exactly one value.
#[must_use]
pub fn single_token(text: &str) -> Option<Item> {
    match lex::tokens(text).ok()?.as_slice() {
        [lex::Token::Quoted(value)] => Some(Item::Quoted(value.clone())),
        [lex::Token::Word(value)] => Some(Item::Bare(value.clone())),
        _ => None,
    }
}

/// Parses one condition.
///
/// # Errors
///
/// Returns a [`ParseError`] for anything that is not a well-formed condition,
/// including one nested too deeply to evaluate safely.
pub fn parse(condition: &str) -> Result<Expr, ParseError> {
    parse::Parser::new(lex::tokens(condition)?).condition()
}
