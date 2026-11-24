//! Splitting a condition into tokens.
//!
//! Values in the catalogue are often bare: paths, `runc:[0:PARENT]`, flag
//! names. A bare word runs until whitespace, a parenthesis, a comma, a quote
//! or a comparison symbol, so `evt.type=ptrace` and `evt.rawres>=0` split the
//! same way as their spaced forms.

use super::ParseError;

/// One token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Token {
    /// `(`
    Open,
    /// `)`
    Close,
    /// `,`
    Comma,
    /// `=`, `==`, `!=`, `<`, `<=`, `>`, `>=`
    Symbol(String),
    /// A bare word: a keyword, field, macro, list name or value.
    Word(String),
    /// A quoted value, quotes removed.
    Quoted(String),
}

/// Longest condition accepted. The catalogue's longest is under 3 KB.
const MAX_LEN: usize = 64 * 1024;

fn ends_word(c: char) -> bool {
    c.is_whitespace() || matches!(c, '(' | ')' | ',' | '"' | '\'' | '=' | '!' | '<' | '>')
}

/// Splits `condition` into tokens.
pub(crate) fn tokens(condition: &str) -> Result<Vec<Token>, ParseError> {
    if condition.len() > MAX_LEN {
        return Err(ParseError::new("condition is too long"));
    }
    let mut out = Vec::new();
    let mut chars = condition.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            c if c.is_whitespace() => {
                chars.next();
            }
            '(' => {
                chars.next();
                out.push(Token::Open);
            }
            ')' => {
                chars.next();
                out.push(Token::Close);
            }
            ',' => {
                chars.next();
                out.push(Token::Comma);
            }
            '"' | '\'' => {
                chars.next();
                out.push(Token::Quoted(quoted(&mut chars, c)?));
            }
            '=' | '!' | '<' | '>' => {
                chars.next();
                let mut symbol = c.to_string();
                if chars.peek() == Some(&'=') {
                    chars.next();
                    symbol.push('=');
                }
                match symbol.as_str() {
                    "=" | "==" | "!=" | "<" | "<=" | ">" | ">=" => out.push(Token::Symbol(symbol)),
                    _ => return Err(ParseError::new(format!("unknown operator `{symbol}`"))),
                }
            }
            _ => {
                let mut word = String::new();
                while let Some(&c) = chars.peek() {
                    if ends_word(c) {
                        break;
                    }
                    word.push(c);
                    chars.next();
                }
                out.push(Token::Word(word));
            }
        }
    }
    Ok(out)
}

/// A quoted value. A backslash escapes the next character.
fn quoted(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    quote: char,
) -> Result<String, ParseError> {
    let mut value = String::new();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some(escaped) => value.push(escaped),
                None => break,
            },
            c if c == quote => return Ok(value),
            c => value.push(c),
        }
    }
    Err(ParseError::new("unterminated quoted value"))
}

#[cfg(test)]
mod tests {
    use super::{Token, tokens};

    fn words(condition: &str) -> Vec<Token> {
        tokens(condition).unwrap_or_default()
    }

    #[test]
    fn unspaced_comparisons_split_like_spaced_ones() {
        assert_eq!(words("evt.rawres>=0"), words("evt.rawres >= 0"));
        assert_eq!(words("evt.type=ptrace"), words("evt.type = ptrace"));
    }

    #[test]
    fn bracketed_bare_words_stay_whole() {
        assert_eq!(
            words("runc:[0:PARENT]"),
            vec![Token::Word("runc:[0:PARENT]".to_owned())]
        );
    }

    #[test]
    fn quotes_of_either_kind_and_escapes() {
        assert_eq!(
            words(r#""a b" 'c "d"' "e\"f""#),
            vec![
                Token::Quoted("a b".to_owned()),
                Token::Quoted("c \"d\"".to_owned()),
                Token::Quoted("e\"f".to_owned()),
            ]
        );
    }

    #[test]
    fn stray_symbols_and_unterminated_quotes_are_errors() {
        assert!(tokens("a ! b").is_err());
        assert!(tokens("'open").is_err());
        assert!(tokens(&"x".repeat(70_000)).is_err());
    }
}
