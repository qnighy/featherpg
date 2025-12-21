// https://www.postgresql.org/docs/current/sql-syntax-lexical.html

use num_bigint::BigInt;

use crate::{Symbol, pos::CodeRange};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Token {
    pub kind: TokenKind,
    pub range: CodeRange,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum TokenKind {
    /// A virtual token representing the end of the input stream.
    Eof,
    /// Keyword, unquoted identifier, or quoted identifier.
    ///
    /// - Unquoted (`foo`), always folded to lowercase.
    /// - Quoted(`"foo"`)
    Identifier {
        /// The name value.
        ///
        /// For unquoted identifiers, this is the value after folding to lowercase.
        ///
        /// For quoted identifiers, quotation marks have been removed, and escape sequences
        /// have been processed.
        name: Symbol,
        /// When false, the identifier may be treated as a keyword.
        quoted: bool,
    },
    /// A nonnegative integer literal. It ultimately results in one of:
    ///
    /// - integer (i32)
    /// - bigint (i64)
    /// - numeric (BigInt plus scale of 10^(-n))
    Integer(BigInt),
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `[`
    LBracket,
    /// `]`
    RBracket,
    /// `{` (currently unused in PostgreSQL SQL syntax)
    LBrace,
    /// `}` (currently unused in PostgreSQL SQL syntax)
    RBrace,
    /// `.`
    Dot,
    /// `..`
    DotDot,
    /// `,`
    Comma,
    /// `:`
    Colon,
    /// `:=`
    ColonEq,
    /// `::`
    ColonColon,
    /// `;`
    Semicolon,
    /// Operator `^`
    Caret,
    /// `*`, which either has a specific syntactic role or is an operator.
    Asterisk,
    /// Operator `/`
    Slash,
    /// Operator `%`
    Percent,
    /// Operator `+`
    Plus,
    /// Operator `-`
    Minus,
    /// Operator `=`
    Eq,
    /// `=>` (not an operator)
    FatArrow,
    /// Operator `<>` (or `!=`)
    Neq,
    /// Operator `<`
    Lt,
    /// Operator `>`
    Gt,
    /// Operator `<=`
    Le,
    /// Operator `>=`
    Ge,
    /// User-defined operator, such as `<->` or `@>`.
    UserOp(String),
    /// An unknown token. The error has already been reported.
    Unknown,
}
