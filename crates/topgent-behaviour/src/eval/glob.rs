//! Shell-style patterns: `*` any run of characters (slashes included), `?`
//! one character, `[abc]` and `[a-z]` one of a set, `[!abc]` one not in it.
//!
//! Matched with two positions and one backtrack point, so the cost is linear
//! in practice and never exponential, whatever the pattern.

/// Whether `text` matches `pattern`.
pub(super) fn glob(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut p, mut t) = (0, 0);
    let mut backtrack: Option<(usize, usize)> = None;
    while t < text.len() {
        let here = text.get(t).copied();
        match pattern.get(p) {
            Some('*') => {
                backtrack = Some((p, t));
                p += 1;
            }
            Some(&token) => {
                let (matched, width) = one(&pattern, p, token, here);
                if matched {
                    p += width;
                    t += 1;
                } else if let Some((star, from)) = backtrack {
                    p = star + 1;
                    t = from + 1;
                    backtrack = Some((star, from + 1));
                } else {
                    return false;
                }
            }
            None => match backtrack {
                Some((star, from)) => {
                    p = star + 1;
                    t = from + 1;
                    backtrack = Some((star, from + 1));
                }
                None => return false,
            },
        }
    }
    pattern.iter().skip(p).all(|c| *c == '*')
}

/// Whether the pattern element at `p` matches `c`, and how many pattern
/// characters it spans.
fn one(pattern: &[char], p: usize, token: char, c: Option<char>) -> (bool, usize) {
    let Some(c) = c else {
        return (false, 1);
    };
    match token {
        '?' => (true, 1),
        '[' => class(pattern, p, c).unwrap_or((token == c, 1)),
        _ => (token == c, 1),
    }
}

/// A `[...]` class starting at `p`, or `None` if it is not closed.
fn class(pattern: &[char], p: usize, c: char) -> Option<(bool, usize)> {
    let mut at = p + 1;
    let negated = matches!(pattern.get(at), Some('!' | '^'));
    if negated {
        at += 1;
    }
    let mut matched = false;
    let mut first = true;
    loop {
        let current = *pattern.get(at)?;
        if current == ']' && !first {
            break;
        }
        first = false;
        if pattern.get(at + 1) == Some(&'-') && pattern.get(at + 2).is_some_and(|end| *end != ']') {
            let end = *pattern.get(at + 2)?;
            matched |= (current..=end).contains(&c);
            at += 3;
        } else {
            matched |= current == c;
            at += 1;
        }
    }
    Some((matched != negated, at + 1 - p))
}

#[cfg(test)]
mod tests {
    use super::glob;

    #[test]
    fn stars_questions_and_classes() {
        assert!(glob("/home/*/.ssh/*", "/home/u/.ssh/id"));
        assert!(glob("*", ""));
        assert!(!glob("?", ""));
        assert!(glob("a[bc]d", "acd"));
        assert!(!glob("a[!bc]d", "acd"));
        assert!(glob("[a-c]x", "bx"));
        assert!(!glob("/root/*", "/home/x"));
    }

    #[test]
    fn a_pathological_pattern_finishes_quickly() {
        let text = "a".repeat(5_000);
        let pattern = format!("{}b", "*a".repeat(50));
        assert!(!glob(&pattern, &text));
    }
}
