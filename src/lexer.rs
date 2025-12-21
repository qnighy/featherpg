// https://www.postgresql.org/docs/current/sql-syntax-lexical.html
// TODO: the whole lexer is an ad-hoc implementation for now
// and may differ from the spec in many ways.
// A thorough review is needed once the rough implementation is done.

use std::borrow::Cow;

use num_bigint::BigInt;

#[cfg(test)]
use crate::diag::CodeError;
use crate::{
    Symbol,
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

#[cfg(test)]
pub(crate) fn lex_with_diags(src: &str, diags: &mut CodeDiagnostics) -> Vec<Token> {
    let mut lexer = Lexer::new(src);
    let mut tokens = Vec::new();

    loop {
        let token = lexer.next_token(diags);
        if token.kind == TokenKind::Eof {
            break;
        }
        tokens.push(token);
    }

    tokens
}

#[derive(Debug)]
pub(crate) struct Lexer<'a> {
    src: &'a str,
    pos: usize,
}

macro_rules! byte_pattern {
    (digit) => {
        b'0'..=b'9'
    };
    (ident_start) => {
        b'A'..=b'Z' | b'a'..=b'z' | b'_' | 0x80..=0xFF
    };
    (ident_continue) => {
        byte_pattern!(ident_start) | byte_pattern!(digit) | b'$'
    };
    (symbol_base) => {
        b'+' | b'-' | b'*' | b'/' | b'<' | b'>' | b'='
    };
    (symbol_extra) => {
        b'~' | b'!' | b'@' | b'#' | b'%' | b'^' | b'&' | b'|' | b'`' | b'?'
    };
    (symbol) => {
        byte_pattern!(symbol_base) | byte_pattern!(symbol_extra)
    };
}

impl<'a> Lexer<'a> {
    pub(crate) fn new(src: &'a str) -> Self {
        Self { src, pos: 0 }
    }

    pub(crate) fn next_token(&mut self, diags: &mut CodeDiagnostics) -> Token {
        let start_before_ws = self.pos;
        self.skip_whitespace();

        if self.pos >= self.src.len() {
            return Token {
                kind: TokenKind::Eof,
                range: self.range_from(start_before_ws),
            };
        }

        let start = self.pos;

        match self.src.as_bytes()[self.pos] {
            byte_pattern!(ident_start) => self.next_identifier_token(start, diags),
            byte_pattern!(digit) => self.next_numeric_token(start, diags),
            b'(' => {
                self.pos += 1;
                Token {
                    kind: TokenKind::LParen,
                    range: self.range_from(start),
                }
            }
            b')' => {
                self.pos += 1;
                Token {
                    kind: TokenKind::RParen,
                    range: self.range_from(start),
                }
            }
            b'[' => {
                self.pos += 1;
                Token {
                    kind: TokenKind::LBracket,
                    range: self.range_from(start),
                }
            }
            b']' => {
                self.pos += 1;
                Token {
                    kind: TokenKind::RBracket,
                    range: self.range_from(start),
                }
            }
            b'{' => {
                self.pos += 1;
                Token {
                    kind: TokenKind::LBrace,
                    range: self.range_from(start),
                }
            }
            b'}' => {
                self.pos += 1;
                Token {
                    kind: TokenKind::RBrace,
                    range: self.range_from(start),
                }
            }
            b'.' => {
                self.pos += 1;
                if self.pos < self.src.len() && self.src.as_bytes()[self.pos] == b'.' {
                    self.pos += 1;
                    Token {
                        kind: TokenKind::DotDot,
                        range: self.range_from(start),
                    }
                } else {
                    Token {
                        kind: TokenKind::Dot,
                        range: self.range_from(start),
                    }
                }
            }
            b',' => {
                self.pos += 1;
                Token {
                    kind: TokenKind::Comma,
                    range: self.range_from(start),
                }
            }
            b':' => {
                self.pos += 1;
                if self.pos < self.src.len() && self.src.as_bytes()[self.pos] == b':' {
                    self.pos += 1;
                    Token {
                        kind: TokenKind::ColonColon,
                        range: self.range_from(start),
                    }
                } else if self.pos < self.src.len() && self.src.as_bytes()[self.pos] == b'=' {
                    self.pos += 1;
                    Token {
                        kind: TokenKind::ColonEq,
                        range: self.range_from(start),
                    }
                } else {
                    Token {
                        kind: TokenKind::Colon,
                        range: self.range_from(start),
                    }
                }
            }
            b';' => {
                self.pos += 1;
                Token {
                    kind: TokenKind::Semicolon,
                    range: self.range_from(start),
                }
            }
            byte_pattern!(symbol) => self.next_operator_token(start, diags),
            _ => {
                self.pos += 1;
                let range = self.range_from(start);
                diags.add(CodeDiagnostic::UnknownToken { range });
                Token {
                    kind: TokenKind::Unknown,
                    range,
                }
            }
        }
    }

    fn next_identifier_token(&mut self, start: usize, _diags: &mut CodeDiagnostics) -> Token {
        while self.pos < self.src.len()
            && matches!(self.src.as_bytes()[self.pos], byte_pattern!(ident_continue))
        {
            self.pos += 1;
        }
        let identifier = &self.src[start..self.pos];
        let identifier = identifier.to_ascii_lowercase();
        let identifier = Symbol::from(identifier);
        let range = self.range_from(start);
        Token {
            kind: TokenKind::Identifier {
                name: identifier,
                quoted: false,
            },
            range,
        }
    }

    fn next_numeric_token(&mut self, start: usize, diags: &mut CodeDiagnostics) -> Token {
        while self.pos < self.src.len()
            && matches!(self.src.as_bytes()[self.pos], byte_pattern!(ident_continue))
        {
            self.pos += 1;
        }
        let s = &self.src[start..self.pos];
        if Self::is_decimal_integer(s) {
            // TODO: check against invalid underscore occurrences
            let value = Self::remove_underscores(s).parse::<BigInt>().unwrap();
            Token {
                kind: TokenKind::Integer(value),
                range: self.range_from(start),
            }
        } else {
            let range = self.range_from(start);
            diags.add(CodeDiagnostic::UnknownToken { range });
            return Token {
                kind: TokenKind::Unknown,
                range,
            };
        }
    }

    fn next_operator_token(&mut self, start: usize, _diags: &mut CodeDiagnostics) -> Token {
        self.pos += 1;
        while self.pos < self.src.len()
            && matches!(self.src.as_bytes()[self.pos], byte_pattern!(symbol))
        {
            self.pos += 1;
            if self.src.as_bytes()[self.pos - 2..self.pos] == b"--"[..]
                || self.src.as_bytes()[self.pos - 2..self.pos] == b"/*"[..]
            {
                // Break before comment start
                self.pos -= 2;
                break;
            }
        }
        if self.pos == start {
            // TODO: implement comment parsing and turn this check into `unreachable!()`
            unimplemented!("comment handling");
        }
        let sym = &self.src[start..self.pos];

        if sym.len() > 1
            && matches!(sym.as_bytes()[sym.len() - 1], b'+' | b'-')
            && sym.bytes().all(|b| matches!(b, byte_pattern!(symbol_base)))
        {
            // Break before trailing + or -
            self.pos -= 1;
        }
        let sym = &self.src[start..self.pos];

        let kind = match sym {
            "^" => TokenKind::Caret,
            "*" => TokenKind::Asterisk,
            "/" => TokenKind::Slash,
            "%" => TokenKind::Percent,
            "+" => TokenKind::Plus,
            "-" => TokenKind::Minus,
            "=" => TokenKind::Eq,
            "=>" => TokenKind::FatArrow,
            "<>" | "!=" => TokenKind::Neq,
            "<" => TokenKind::Lt,
            ">" => TokenKind::Gt,
            "<=" => TokenKind::Le,
            ">=" => TokenKind::Ge,
            _ => TokenKind::UserOp(sym.to_string()),
        };

        Token {
            kind,
            range: self.range_from(start),
        }
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

    fn range_from(&self, start: usize) -> CodeRange {
        CodeRange {
            start,
            end: self.pos,
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
                tok(
                    TokenKind::Identifier {
                        name: Symbol::from("foo"),
                        quoted: false
                    },
                    pos(src, "foo", 0)
                ),
                tok(
                    TokenKind::Identifier {
                        name: Symbol::from("bar"),
                        quoted: false
                    },
                    pos(src, "bar", 0)
                ),
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
                TokenKind::Identifier {
                    name: Symbol::from("foo"),
                    quoted: false
                },
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
                TokenKind::Identifier {
                    name: Symbol::from("foo"),
                    quoted: false
                },
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
                TokenKind::Identifier {
                    name: Symbol::from("fÖo"),
                    quoted: false
                },
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
                TokenKind::Identifier {
                    name: Symbol::from("foo123"),
                    quoted: false
                },
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
                TokenKind::Identifier {
                    name: Symbol::from("foo_bar"),
                    quoted: false
                },
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
                TokenKind::Identifier {
                    name: Symbol::from("foo$bar"),
                    quoted: false
                },
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
                TokenKind::Identifier {
                    name: Symbol::from("föo"),
                    quoted: false
                },
                pos(src, "föo", 0)
            )]
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

    #[test]
    fn test_lex_lparen() {
        let src = "(";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::LParen, pos(src, "(", 0))]);
    }

    #[test]
    fn test_lex_rparen() {
        let src = ")";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::RParen, pos(src, ")", 0))]);
    }

    #[test]
    fn test_lex_lbracket() {
        let src = "[";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::LBracket, pos(src, "[", 0))]);
    }

    #[test]
    fn test_lex_rbracket() {
        let src = "]";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::RBracket, pos(src, "]", 0))]);
    }

    #[test]
    fn test_lex_lbrace() {
        let src = "{";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::LBrace, pos(src, "{", 0))]);
    }

    #[test]
    fn test_lex_rbrace() {
        let src = "}";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::RBrace, pos(src, "}", 0))]);
    }

    #[test]
    fn test_lex_dot() {
        let src = ".";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::Dot, pos(src, ".", 0))]);
    }

    #[test]
    fn test_lex_dot_dot() {
        let src = "..";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::DotDot, pos(src, "..", 0))]);
    }

    #[test]
    fn test_lex_comma() {
        let src = ",";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::Comma, pos(src, ",", 0))]);
    }

    #[test]
    fn test_lex_colon() {
        let src = ":";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::Colon, pos(src, ":", 0))]);
    }

    #[test]
    fn test_lex_colon_colon() {
        let src = "::";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::ColonColon, pos(src, "::", 0))]);
    }

    #[test]
    fn test_lex_colon_eq() {
        let src = ":=";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::ColonEq, pos(src, ":=", 0))]);
    }

    #[test]
    fn test_lex_semicolon() {
        let src = ";";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::Semicolon, pos(src, ";", 0))]);
    }

    #[test]
    fn test_lex_caret() {
        let src = "^";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::Caret, pos(src, "^", 0))]);
    }

    #[test]
    fn test_lex_asterisk() {
        let src = "*";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::Asterisk, pos(src, "*", 0))]);
    }

    #[test]
    fn test_lex_slash() {
        let src = "/";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::Slash, pos(src, "/", 0))]);
    }

    #[test]
    fn test_lex_percent() {
        let src = "%";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::Percent, pos(src, "%", 0))]);
    }

    #[test]
    fn test_lex_plus() {
        let src = "+";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::Plus, pos(src, "+", 0))]);
    }

    #[test]
    fn test_lex_minus() {
        let src = "-";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::Minus, pos(src, "-", 0))]);
    }

    #[test]
    fn test_lex_eq() {
        let src = "=";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::Eq, pos(src, "=", 0))]);
    }

    #[test]
    fn test_lex_fat_arrow() {
        let src = "=>";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::FatArrow, pos(src, "=>", 0))]);
    }

    #[test]
    fn test_lex_neq_standard() {
        let src = "<>";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::Neq, pos(src, "<>", 0))]);
    }

    #[test]
    fn test_lex_neq_de_facto() {
        let src = "!=";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::Neq, pos(src, "!=", 0))]);
    }

    #[test]
    fn test_lex_lt() {
        let src = "<";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::Lt, pos(src, "<", 0))]);
    }

    #[test]
    fn test_lex_gt() {
        let src = ">";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::Gt, pos(src, ">", 0))]);
    }

    #[test]
    fn test_lex_le() {
        let src = "<=";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::Le, pos(src, "<=", 0))]);
    }

    #[test]
    fn test_lex_ge() {
        let src = ">=";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::Ge, pos(src, ">=", 0))]);
    }

    #[test]
    fn test_lex_user_op_all_symbols() {
        // Test an operator containing all possible operator symbols
        // Starting with @ (extra symbol) means no trailing breaks occur
        let src = "@~!#%^&|?+*/<=>-";
        let tokens = lex(src).unwrap();
        assert_eq!(
            tokens,
            vec![tok(
                TokenKind::UserOp("@~!#%^&|?+*/<=>-".to_string()),
                pos(src, "@~!#%^&|?+*/<=>-", 0)
            )]
        );
    }

    #[test]
    fn test_lex_user_op_breaks_before_trailing_plus() {
        // Base-only operator should break before trailing +
        let src = "=<+";
        let tokens = lex(src).unwrap();
        assert_eq!(
            tokens,
            vec![
                tok(TokenKind::UserOp("=<".to_string()), pos(src, "=<", 0)),
                tok(TokenKind::Plus, pos(src, "+", 0))
            ]
        );
    }

    #[test]
    fn test_lex_fat_arrow_before_plus() {
        // => should be carved out as FatArrow
        let src = "=>+";
        let tokens = lex(src).unwrap();
        assert_eq!(
            tokens,
            vec![
                tok(TokenKind::FatArrow, pos(src, "=>", 0)),
                tok(TokenKind::Plus, pos(src, "+", 0))
            ]
        );
    }

    #[test]
    fn test_lex_user_op_breaks_before_trailing_minus() {
        // Base-only operator should break before trailing -
        let src = "=<-";
        let tokens = lex(src).unwrap();
        assert_eq!(
            tokens,
            vec![
                tok(TokenKind::UserOp("=<".to_string()), pos(src, "=<", 0)),
                tok(TokenKind::Minus, pos(src, "-", 0))
            ]
        );
    }

    #[test]
    fn test_lex_user_op_no_break_with_extra_symbols() {
        // Should NOT break before trailing + if operator has extra symbols
        let src = "@+";
        let tokens = lex(src).unwrap();
        assert_eq!(
            tokens,
            vec![tok(TokenKind::UserOp("@+".to_string()), pos(src, "@+", 0))]
        );
    }

    #[test]
    fn test_lex_user_op_no_break_for_single_char() {
        // Should NOT break for single-character + or -
        let src = "+";
        let tokens = lex(src).unwrap();
        assert_eq!(tokens, vec![tok(TokenKind::Plus, pos(src, "+", 0))]);
    }
}
