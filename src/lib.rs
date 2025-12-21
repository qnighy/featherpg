pub use crate::diag::{CodeDiagnostic, CodeDiagnostics, CodeError};
pub use crate::parser::{
    parse_stmt, parse_stmt_with_diags, parse_stmtmulti, parse_stmtmulti_with_diags,
};
pub use crate::pos::CodeRange;
pub use crate::symbols::Symbol;

pub mod ast;
mod diag;
mod lexer;
mod parser;
mod pos;
mod symbols;
mod token;
