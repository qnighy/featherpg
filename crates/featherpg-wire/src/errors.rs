use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("PostgreSQL error: {0}")]
    PgError(#[from] DiagnosticMessage),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, Error, Clone, PartialEq, Eq, Hash)]
#[error("{message}")]
pub struct DiagnosticMessage {
    severity: DiagnosticSeverity,
    localized_severity: String,
    code: String,
    message: String,
    detail: Option<String>,
    hint: Option<String>,
    position: Option<i32>,
    internal_position: Option<i32>,
    internal_query: Option<String>,
    where_: Option<String>,
    schema_name: Option<String>,
    table_name: Option<String>,
    column_name: Option<String>,
    data_type_name: Option<String>,
    constraint_name: Option<String>,
    file: Option<String>,
    line: Option<i32>,
    routine: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DiagnosticSeverity {
    Debug,
    Log,
    Info,
    Notice,
    Warning,
    Error,
    Fatal,
    Panic,
}
