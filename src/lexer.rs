// https://www.postgresql.org/docs/current/sql-syntax-lexical.html
// TODO: the whole lexer is an ad-hoc implementation for now
// and may differ from the spec in many ways.
// A thorough review is needed once the rough implementation is done.

use crate::{
    pos::CodeRange,
    token::{Token, TokenKind},
};

pub(crate) fn lex(src: &str) -> Vec<Token> {
    let mut lexer = Lexer::new(src);
    let mut tokens = Vec::new();

    while let Some(token) = lexer.next_token() {
        tokens.push(token);
    }

    tokens
}

#[derive(Debug)]
struct Lexer<'a> {
    src: &'a str,
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Self { src, pos: 0 }
    }

    fn next_token(&mut self) -> Option<Token> {
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
            let range = CodeRange {
                start,
                end: self.pos,
            };
            Some(Token {
                kind: TokenKind::Identifier(identifier.to_ascii_lowercase()),
                range,
            })
        } else {
            // Unknown token
            self.pos += 1;
            let range = CodeRange {
                start,
                end: self.pos,
            };
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
        assert_eq!(lex(src), vec![]);
    }

    #[test]
    fn test_lex_whitespace_only() {
        let src = "   \n\t  ";
        assert_eq!(lex(src), vec![]);
    }

    #[test]
    fn test_lex_whitespace_between_tokens() {
        let src = "  foo   bar  ";
        let tokens = lex(src);
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
        let tokens = lex(src);
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
        let tokens = lex(src);
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
        let tokens = lex(src);
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
        let tokens = lex(src);
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
        let tokens = lex(src);
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
        let tokens = lex(src);
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
        let tokens = lex(src);
        assert_eq!(
            tokens,
            vec![tok(
                TokenKind::Identifier("föo".to_string()),
                pos(src, "föo", 0)
            )]
        );
    }
}
