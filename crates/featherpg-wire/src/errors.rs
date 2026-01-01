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
pub struct DiagnosticMessage {
    pub severity: DiagnosticSeverity,
    pub localized_severity: CString,
    pub code: CString,
    pub message: CString,
    pub detail: Option<CString>,
    pub hint: Option<CString>,
    pub position: Option<i32>,
    pub internal_position: Option<i32>,
    pub internal_query: Option<CString>,
    pub where_: Option<CString>,
    pub schema_name: Option<CString>,
    pub table_name: Option<CString>,
    pub column_name: Option<CString>,
    pub data_type_name: Option<CString>,
    pub constraint_name: Option<CString>,
    pub file: Option<CString>,
    pub line: Option<i32>,
    pub routine: Option<CString>,
}

impl fmt::Display for DiagnosticMessage {
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
