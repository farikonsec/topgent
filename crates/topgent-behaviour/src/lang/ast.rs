//! The syntax tree of one condition.

/// A condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// Every part holds.
    And(Vec<Expr>),
    /// Some part holds.
    Or(Vec<Expr>),
    /// The part does not hold.
    Not(Box<Expr>),
    /// A named macro, replaced by its condition when the catalogue resolves.
    Macro(String),
    /// A field compared with a value or a set of values.
    Compare {
        /// The field.
        field: FieldRef,
        /// How.
        op: Op,
        /// Against what.
        value: Operand,
    },
    /// The field has a value.
    Exists(FieldRef),
}

/// A field, with its bracketed argument if any: `proc.aname[2]`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FieldRef {
    /// `proc.aname`
    pub name: String,
    /// `2`
    pub arg: Option<String>,
}

/// A comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// `=`
    Eq,
    /// `!=`
    Ne,
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `>`
    Gt,
    /// `>=`
    Ge,
    /// `contains`
    Contains,
    /// `icontains`: case-insensitive.
    IContains,
    /// `bcontains`: the value holds these bytes, given as hex.
    BContains,
    /// `startswith`
    StartsWith,
    /// `bstartswith`: the value starts with these bytes, given as hex.
    BStartsWith,
    /// `endswith`
    EndsWith,
    /// `glob`
    Glob,
    /// `in`: equals one of the values.
    In,
    /// `intersects`: shares an element with the values.
    Intersects,
    /// `pmatch`: is one of the paths, or under one.
    PMatch,
}

impl Op {
    /// The operator a word names, if it names one.
    #[must_use]
    pub fn from_word(word: &str) -> Option<Self> {
        Some(match word {
            "contains" => Self::Contains,
            "icontains" => Self::IContains,
            "bcontains" => Self::BContains,
            "startswith" => Self::StartsWith,
            "bstartswith" => Self::BStartsWith,
            "endswith" => Self::EndsWith,
            "glob" => Self::Glob,
            "in" => Self::In,
            "intersects" => Self::Intersects,
            "pmatch" => Self::PMatch,
            _ => return None,
        })
    }

    /// The operator a symbol names, if it names one.
    #[must_use]
    pub fn from_symbol(symbol: &str) -> Option<Self> {
        Some(match symbol {
            "=" | "==" => Self::Eq,
            "!=" => Self::Ne,
            "<" => Self::Lt,
            "<=" => Self::Le,
            ">" => Self::Gt,
            ">=" => Self::Ge,
            _ => return None,
        })
    }

    /// Whether the operator takes a parenthesised set of values.
    #[must_use]
    pub const fn takes_set(self) -> bool {
        matches!(self, Self::In | Self::Intersects | Self::PMatch)
    }
}

/// What a field is compared against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    /// One value.
    One(Item),
    /// A set of values.
    Set(Vec<Item>),
}

/// One value as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// A quoted value: always itself.
    Quoted(String),
    /// A bare word: itself, or the name of a list the catalogue expands.
    Bare(String),
}

impl Item {
    /// The value as text.
    #[must_use]
    pub fn text(&self) -> &str {
        match self {
            Self::Quoted(text) | Self::Bare(text) => text,
        }
    }
}
