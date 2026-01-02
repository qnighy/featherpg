use std::{
    ffi::CString,
    fmt,
    io::{Error as IoError, ErrorKind as IoErrorKind},
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("PostgreSQL error: {0}")]
    PgError(#[from] DiagnosticMessage),
    #[error("I/O error: {0}")]
    Io(#[from] IoError),
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

#[derive(Debug, Error)]
pub(crate) enum WireFormatError {
    #[error("unexpected EOF while reading InitialRequest length")]
    InitialRequestIncompleteLength,
    #[error("found negative length {length} in InitialRequest")]
    InitialRequestNegativeLength { length: isize },
    #[error("InitialRequest too large (found {length}, limit {max_length})")]
    InitialRequestTooLarge { length: usize, max_length: usize },
    #[error("unexpected EOF while reading InitialRequest body")]
    InitialRequestIncompleteBody,
    #[error("packet too short for InitialRequest version")]
    InitialRequestIncompleteVersion,

    #[error("unterminated option name in StartupMessage")]
    StartupMessageUnterminatedOptionName,
    #[error("unterminated option value in StartupMessage")]
    StartupMessageUnterminatedOptionValue,
    #[error("invalid value for parameter \"replication\": \"{}\"", value.to_string_lossy())]
    StartupMessageInvalidReplicationParameter { value: CString },
    #[error("extra bytes found in StartupMessage")]
    StartupMessageExtraBytes,
    #[error("missing or empty user option in StartupMessage")]
    StartupMessageMissingUserName,

    #[error("extra bytes found in SSLRequest")]
    SSLRequestExtraBytes,

    #[error("extra bytes found in GSSENCRequest")]
    GSSENCRequestExtraBytes,

    #[error("packet too short for CancelRequest process_id")]
    CancelRequestIncompleteProcessId,
    #[error("secret key must not be empty in CancelRequest")]
    CancelRequestEmptySecretKey,
    #[error("secret key too long in CancelRequest (found {length}, limit {max_length})")]
    CancelRequestSecretKeyTooLong { length: usize, max_length: usize },

    #[error("unknown type byte for SSL response: {} (expected S, N, or E)", describe_byte(*type_byte))]
    SSLResponseUnknownTypeByte { type_byte: u8 },

    #[error("unknown type byte for GSSENC response: {} (expected G, N, or E)", describe_byte(*type_byte))]
    GSSENCResponseUnknownTypeByte { type_byte: u8 },

    #[error("unexpected EOF while reading ErrorResponse/NoticeResponse length")]
    ErrorOrNoticeResponseIncompleteLength,
    #[error("found negative length {length} in ErrorResponse/NoticeResponse")]
    ErrorOrNoticeResponseNegativeLength { length: isize },
    #[error("ErrorResponse/NoticeResponse too large (found {length}, limit {max_length})")]
    ErrorOrNoticeResponseTooLarge { length: usize, max_length: usize },
    #[error("unexpected EOF while reading ErrorResponse/NoticeResponse body")]
    ErrorOrNoticeResponseIncompleteBody,
    #[error("unterminated field list in ErrorResponse/NoticeResponse")]
    ErrorOrNoticeResponseUnterminatedFieldList,
    #[error("unterminated field value in ErrorResponse/NoticeResponse")]
    ErrorOrNoticeResponseUnterminatedFieldValue,
    #[error("unknown diagnostic severity in ErrorResponse/NoticeResponse (found {})", severity.to_string_lossy())]
    ErrorOrNoticeResponseUnknownDiagnosticSeverity { severity: CString },
    #[error("invalid integer field in ErrorResponse/NoticeResponse message (field {name}, found {})", value.to_string_lossy())]
    ErrorOrNoticeResponseInvalidInteger { name: String, value: CString },
    #[error("missing severity field in ErrorResponse/NoticeResponse")]
    ErrorOrNoticeResponseMissingSeverity,
    #[error("missing localized severity field in ErrorResponse/NoticeResponse")]
    ErrorOrNoticeResponseMissingLocalizedSeverity,
    #[error("missing code field in ErrorResponse/NoticeResponse")]
    ErrorOrNoticeResponseMissingCode,
    #[error("missing message field in ErrorResponse/NoticeResponse")]
    ErrorOrNoticeResponseMissingMessage,
}

impl WireFormatError {
    pub fn is_eof_error(&self) -> bool {
        matches!(
            self,
            // Only include errors that indicate EOF in the message stream,
            // not EOF in the message body.
            WireFormatError::InitialRequestIncompleteLength
                | WireFormatError::InitialRequestIncompleteBody
                | WireFormatError::ErrorOrNoticeResponseIncompleteLength
                | WireFormatError::ErrorOrNoticeResponseIncompleteBody
        )
    }
}

impl From<WireFormatError> for IoError {
    fn from(err: WireFormatError) -> Self {
        let kind = if err.is_eof_error() {
            IoErrorKind::UnexpectedEof
        } else {
            IoErrorKind::InvalidData
        };
        IoError::new(kind, err)
    }
}

fn describe_byte(byte: u8) -> String {
    match byte {
        b'\'' => "'\\''".to_owned(),
        b'\\' => "'\\\\'".to_owned(),
        0x20..=0x7E => format!("'{}'", byte as char),
        _ => format!("'\\x{:02X}'", byte),
    }
}
