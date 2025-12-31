use std::{ffi::CString, fmt, io};

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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DiagnosticMessage2 {
    severity: DiagnosticSeverity,
    localized_severity: CString,
    code: CString,
    message: CString,
    detail: Option<CString>,
    hint: Option<CString>,
    position: Option<i32>,
    internal_position: Option<i32>,
    internal_query: Option<CString>,
    where_: Option<CString>,
    schema_name: Option<CString>,
    table_name: Option<CString>,
    column_name: Option<CString>,
    data_type_name: Option<CString>,
    constraint_name: Option<CString>,
    file: Option<CString>,
    line: Option<i32>,
    routine: Option<CString>,
}

impl fmt::Display for DiagnosticMessage2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message.to_string_lossy())
    }
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
