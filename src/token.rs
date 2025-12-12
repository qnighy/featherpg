// https://www.postgresql.org/docs/current/sql-syntax-lexical.html

use num_bigint::BigInt;

use crate::pos::CodeRange;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Token {
    pub kind: TokenKind,
    pub range: CodeRange,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum TokenKind {
    Identifier(String),
    Integer(BigInt),
    Unknown,
}
