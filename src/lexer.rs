// https://www.postgresql.org/docs/current/sql-syntax-lexical.html
// TODO: the whole lexer is an ad-hoc implementation for now
// and may differ from the spec in many ways.
// A thorough review is needed once the rough implementation is done.

use std::{borrow::Cow, collections::HashMap, sync::LazyLock};

use num_bigint::BigInt;

#[cfg(test)]
use crate::diag::CodeError;
use crate::{
    diag::{CodeDiagnostic, CodeDiagnostics},
    pos::CodeRange,
    token::{Token, TokenKind},
};

#[cfg(test)]
pub(crate) fn lex(src: &str) -> Result<Vec<Token>, CodeError> {
    let mut diags = CodeDiagnostics::new();
    let tokens = lex_with_diags(src, &mut diags);
    diags.check_errors()?;
    Ok(tokens)
}

pub(crate) fn lex_with_diags(src: &str, diags: &mut CodeDiagnostics) -> Vec<Token> {
    let mut lexer = Lexer::new(src);
    let mut tokens = Vec::new();

    while let Some(token) = lexer.next_token(diags) {
        tokens.push(token);
    }

    tokens
}

#[derive(Debug)]
pub(crate) struct Lexer<'a> {
    src: &'a str,
    pos: usize,
    keyword_map: &'static HashMap<&'static str, TokenKind>,
}

impl<'a> Lexer<'a> {
    pub(crate) fn new(src: &'a str) -> Self {
        Self {
            src,
            pos: 0,
            keyword_map: &KEYWORD_MAP,
        }
    }

    pub(crate) fn next_token(&mut self, diags: &mut CodeDiagnostics) -> Option<Token> {
        self.skip_whitespace();

        if self.pos >= self.src.len() {
            return None;
        }

        let start = self.pos;

        if Self::is_ident_start(self.src.as_bytes()[self.pos]) {
            while self.pos < self.src.len()
                && Self::is_ident_continue(self.src.as_bytes()[self.pos])
            {
                self.pos += 1;
            }
            let identifier = &self.src[start..self.pos];
            let identifier = identifier.to_ascii_lowercase();
            let range = CodeRange {
                start,
                end: self.pos,
            };
            // TODO: handle keyword contexts correctly, such as:
            //
            // - statement/expression context
            // - function/type context
            // - implicit renaming context (e.g. `SELECT 1 x`)
            if let Some(keyword_kind) = self.keyword_map.get(&identifier[..]) {
                Some(Token {
                    kind: keyword_kind.clone(),
                    range,
                })
            } else {
                Some(Token {
                    kind: TokenKind::Identifier(identifier),
                    range,
                })
            }
        } else if self.src.as_bytes()[self.pos].is_ascii_digit() {
            while self.pos < self.src.len()
                && Self::is_ident_continue(self.src.as_bytes()[self.pos])
            {
                self.pos += 1;
            }
            let s = &self.src[start..self.pos];
            if Self::is_decimal_integer(s) {
                // TODO: check against invalid underscore occurrences
                let value = Self::remove_underscores(s).parse::<BigInt>().unwrap();
                Some(Token {
                    kind: TokenKind::Integer(value),
                    range: CodeRange {
                        start,
                        end: self.pos,
                    },
                })
            } else {
                let range = CodeRange {
                    start,
                    end: self.pos,
                };
                diags.add(CodeDiagnostic::UnknownToken { range });
                return Some(Token {
                    kind: TokenKind::Unknown,
                    range,
                });
            }
        } else {
            self.pos += 1;
            let range = CodeRange {
                start,
                end: self.pos,
            };
            diags.add(CodeDiagnostic::UnknownToken { range });
            Some(Token {
                kind: TokenKind::Unknown,
                range,
            })
        }
    }

    fn is_ident_start(b: u8) -> bool {
        b.is_ascii_alphabetic() || b == b'_' || b >= b'\x80'
    }

    fn is_ident_continue(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b >= b'\x80'
    }

    fn is_decimal_integer(s: &str) -> bool {
        s.bytes().all(|b| b.is_ascii_digit() || b == b'_')
    }

    fn remove_underscores(s: &str) -> Cow<'_, str> {
        if s.contains('_') {
            let filtered: String = s.chars().filter(|&c| c != '_').collect();
            Cow::Owned(filtered)
        } else {
            Cow::Borrowed(s)
        }
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.src.len()
            && self.src[self.pos..]
                .chars()
                .next()
                .map_or(false, |c| c.is_whitespace())
        {
            self.pos += 1;
        }
    }
}

static KEYWORD_MAP: LazyLock<HashMap<&'static str, TokenKind>> = LazyLock::new(|| {
    vec![("select", TokenKind::KeywordSelect)]
        .into_iter()
        .collect::<HashMap<_, _>>()
});

#[cfg(test)]
mod tests {
    use crate::{
        pos::{CodeRange, pos},
        token::TokenKind,
    };

    use super::*;

    fn tok(kind: TokenKind, range: CodeRange) -> Token {
        Token { kind, range }
    }

    #[test]
    fn test_lex_empty() {
        let src = "";
        assert_eq!(lex(src).unwrap(), vec![]);
    }

    #[test]
    fn test_lex_whitespace_only() {
        let src = "   \n\t  ";
        assert_eq!(lex(src).unwrap(), vec![]);
    }

    #[test]
    fn test_lex_whitespace_between_tokens() {
        let src = "  foo   bar  ";
        let tokens = lex(src).unwrap();
        assert_eq!(
            tokens,
            vec![
                tok(TokenKind::Identifier("foo".to_string()), pos(src, "foo", 0)),
                tok(TokenKind::Identifier("bar".to_string()), pos(src, "bar", 0)),
            ]
        );
    }

    #[test]
    fn test_lex_identifier_simple() {
        let src = "foo";
        let tokens = lex(src).unwrap();
        assert_eq!(
            tokens,
            vec![tok(
                TokenKind::Identifier("foo".to_string()),
                pos(src, "foo", 0)
            )]
        );
    }

    #[test]
    fn test_lex_identifier_with_ascii_uppercase() {
        let src = "FoO";
        let tokens = lex(src).unwrap();
        assert_eq!(
            tokens,
            vec![tok(
                TokenKind::Identifier("foo".to_string()),
                pos(src, "FoO", 0)
            )]
        );
    }

    #[test]
    fn test_lex_identifier_with_unicode_uppercase() {
        // Multibyte case folding is not implemented yet. See:
        // https://github.com/postgres/postgres/blob/REL_18_1/src/backend/parser/scansup.c#L55-L63
        let src = "FÖO";
        let tokens = lex(src).unwrap();
        assert_eq!(
            tokens,
            vec![tok(
                TokenKind::Identifier("fÖo".to_string()),
                pos(src, "FÖO", 0)
            )]
        );
    }

    #[test]
    fn test_lex_identifier_with_numbers() {
        let src = "foo123";
        let tokens = lex(src).unwrap();
        assert_eq!(
            tokens,
            vec![tok(
                TokenKind::Identifier("foo123".to_string()),
                pos(src, "foo123", 0)
            )]
        );
    }

    #[test]
    fn test_lex_identifier_with_underscore() {
        let src = "foo_bar";
        let tokens = lex(src).unwrap();
        assert_eq!(
            tokens,
            vec![tok(
                TokenKind::Identifier("foo_bar".to_string()),
                pos(src, "foo_bar", 0)
            )]
        );
    }

    #[test]
    fn test_lex_identifier_with_dollar() {
        let src = "foo$bar";
        let tokens = lex(src).unwrap();
        assert_eq!(
            tokens,
            vec![tok(
                TokenKind::Identifier("foo$bar".to_string()),
                pos(src, "foo$bar", 0)
            )]
        );
    }

    #[test]
    fn test_lex_identifier_with_non_ascii() {
        let src = "föo";
        let tokens = lex(src).unwrap();
        assert_eq!(
            tokens,
            vec![tok(
                TokenKind::Identifier("föo".to_string()),
                pos(src, "föo", 0)
            )]
        );
    }

    #[test]
    fn test_lex_keyword_simple() {
        let src = "select";
        let tokens = lex(src).unwrap();
        assert_eq!(
            tokens,
            vec![tok(TokenKind::KeywordSelect, pos(src, "select", 0))]
        );
    }

    #[test]
    fn test_lex_keyword_case_fold() {
        let src = "SeLeCt";
        let tokens = lex(src).unwrap();
        assert_eq!(
            tokens,
            vec![tok(TokenKind::KeywordSelect, pos(src, "SeLeCt", 0))]
        );
    }

    #[test]
    fn test_lex_integer_simple() {
        let src = "12345";
        let tokens = lex(src).unwrap();
        assert_eq!(
            tokens,
            vec![tok(
                TokenKind::Integer(BigInt::from(12345)),
                pos(src, "12345", 0)
            )]
        );
    }

    #[test]
    fn test_lex_integer_decimal_leading_zeros() {
        let src = "00012345";
        let tokens = lex(src).unwrap();
        assert_eq!(
            tokens,
            vec![tok(
                TokenKind::Integer(BigInt::from(12345)),
                pos(src, "00012345", 0)
            )]
        );
    }

    #[test]
    fn test_lex_integer_underscores() {
        let src = "12_345_678";
        let tokens = lex(src).unwrap();
        assert_eq!(
            tokens,
            vec![tok(
                TokenKind::Integer(BigInt::from(12345678)),
                pos(src, "12_345_678", 0)
            )]
        );
    }
}
