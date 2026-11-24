//! Reading tokens into a condition.
//!
//! Precedence, loosest first: `or`, `and`, `not`. A bare name with no
//! operator after it is a macro. Nesting is capped, so a hostile condition is
//! an error rather than a stack overflow.

use super::ParseError;
use super::ast::{Expr, FieldRef, Item, Op, Operand};
use super::lex::Token;

/// Deepest nesting of parentheses and `not` accepted in one condition.
const MAX_DEPTH: usize = 200;

pub(crate) struct Parser {
    tokens: Vec<Token>,
    at: usize,
    depth: usize,
}

impl Parser {
    pub(crate) const fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            at: 0,
            depth: 0,
        }
    }

    /// The whole condition: one expression and nothing after it.
    pub(crate) fn condition(mut self) -> Result<Expr, ParseError> {
        let expr = self.or()?;
        match self.peek() {
            None => Ok(expr),
            Some(token) => Err(ParseError::new(format!(
                "unexpected {token:?} after the condition"
            ))),
        }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.at).cloned();
        self.at += 1;
        token
    }

    fn is_word(&self, word: &str) -> bool {
        matches!(self.peek(), Some(Token::Word(w)) if w == word)
    }

    fn enter(&mut self) -> Result<(), ParseError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(ParseError::new("condition is nested too deeply"));
        }
        Ok(())
    }

    fn or(&mut self) -> Result<Expr, ParseError> {
        let mut parts = vec![self.and()?];
        while self.is_word("or") {
            self.next();
            parts.push(self.and()?);
        }
        Ok(if parts.len() == 1 {
            parts.remove(0)
        } else {
            Expr::Or(parts)
        })
    }

    fn and(&mut self) -> Result<Expr, ParseError> {
        let mut parts = vec![self.unary()?];
        while self.is_word("and") {
            self.next();
            parts.push(self.unary()?);
        }
        Ok(if parts.len() == 1 {
            parts.remove(0)
        } else {
            Expr::And(parts)
        })
    }

    fn unary(&mut self) -> Result<Expr, ParseError> {
        if self.is_word("not") {
            self.next();
            self.enter()?;
            let inner = self.unary()?;
            self.depth -= 1;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, ParseError> {
        match self.next() {
            Some(Token::Open) => {
                self.enter()?;
                let inner = self.or()?;
                self.depth -= 1;
                match self.next() {
                    Some(Token::Close) => Ok(inner),
                    _ => Err(ParseError::new("missing `)`")),
                }
            }
            Some(Token::Word(word)) if !is_keyword(&word) => self.predicate(word),
            Some(token) => Err(ParseError::new(format!(
                "expected a condition, found {token:?}"
            ))),
            None => Err(ParseError::new("the condition ends too early")),
        }
    }

    /// A field comparison, an `exists` test, or a macro name.
    fn predicate(&mut self, name: String) -> Result<Expr, ParseError> {
        let op = match self.peek() {
            Some(Token::Symbol(symbol)) => Op::from_symbol(symbol),
            Some(Token::Word(word)) if word == "exists" => {
                self.next();
                return Ok(Expr::Exists(field(&name)?));
            }
            Some(Token::Word(word)) => Op::from_word(word),
            _ => None,
        };
        let Some(op) = op else {
            if name.contains('.') {
                return Err(ParseError::new(format!("`{name}` has no operator")));
            }
            return Ok(Expr::Macro(name));
        };
        self.next();
        let value = if op.takes_set() {
            Operand::Set(self.set()?)
        } else {
            Operand::One(self.item()?)
        };
        Ok(Expr::Compare {
            field: field(&name)?,
            op,
            value,
        })
    }

    fn item(&mut self) -> Result<Item, ParseError> {
        match self.next() {
            Some(Token::Quoted(text)) => Ok(Item::Quoted(text)),
            Some(Token::Word(text)) if !is_keyword(&text) => Ok(Item::Bare(text)),
            other => Err(ParseError::new(format!(
                "expected a value, found {other:?}"
            ))),
        }
    }

    /// `(a, b, c)`. A trailing comma is accepted; an empty set is not.
    fn set(&mut self) -> Result<Vec<Item>, ParseError> {
        if self.next() != Some(Token::Open) {
            return Err(ParseError::new("expected `(` before a set of values"));
        }
        let mut items = Vec::new();
        loop {
            if self.peek() == Some(&Token::Close) && !items.is_empty() {
                self.next();
                return Ok(items);
            }
            items.push(self.item()?);
            match self.next() {
                Some(Token::Comma) => {}
                Some(Token::Close) => return Ok(items),
                other => {
                    return Err(ParseError::new(format!(
                        "expected `,` or `)`, found {other:?}"
                    )));
                }
            }
        }
    }
}

fn is_keyword(word: &str) -> bool {
    matches!(word, "and" | "or" | "not")
}

/// `proc.aname[2]` into its name and argument.
fn field(name: &str) -> Result<FieldRef, ParseError> {
    if !name.contains('.') {
        return Err(ParseError::new(format!("`{name}` is not a field")));
    }
    match name.split_once('[') {
        Some((base, rest)) => match rest.strip_suffix(']') {
            Some(arg) if !base.is_empty() => Ok(FieldRef {
                name: base.to_owned(),
                arg: Some(arg.to_owned()),
            }),
            _ => Err(ParseError::new(format!(
                "malformed field argument in `{name}`"
            ))),
        },
        None => Ok(FieldRef {
            name: name.to_owned(),
            arg: None,
        }),
    }
}
