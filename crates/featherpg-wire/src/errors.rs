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
    // Found in backend_startup.c, ProcessStartupPacket
    #[error("incomplete startup packet")]
    StartupIncompleteLength,
    #[error("invalid length of startup packet")]
    StartupTooShort,
    #[error("invalid length of startup packet")]
    StartupTooLong,
    #[error("invalid length of startup packet")]
    StartupIncompleteBody,
    #[error("invalid length of startup packet")]
    StartupIncompleteVersion,
    #[error("invalid startup packet layout: expected terminator as last byte")]
    StartupPacketExtraBytes,
    #[error("invalid startup packet layout: expected terminator as last byte")]
    StartupPacketUnterminatedString,
    #[error("invalid value for parameter \"replication\": \"{value}\"")]
    InvalidReplicationParameter { value: String },
    #[error("no PostgreSQL user name specified in startup packet")]
    MissingUserName,
    // Not found in PostgreSQL
    #[error("invalid SSL/TLS request packet layout: expected empty body")]
    SSLRequestExtraBytes,
    // Not found in PostgreSQL
    #[error("invalid GSSENC request packet layout: expected empty body")]
    GSSENCRequestExtraBytes,
    #[error("invalid length of cancel request packet")]
    CancelRequestIncompleteProcessId,
    #[error("invalid length of cancel key in cancel request packet")]
    CancelRequestMissingSecretKey,
    #[error("invalid length of cancel key in cancel request packet")]
    CancelRequestSecretKeyTooLong { length: usize, max_length: usize },

    #[error("unterminated ErrorResponse or NoticeResponse message")]
    ErrorOrNoticeUnterminated,
    #[error("unknown diagnostic severity in ErrorResponse or NoticeResponse message")]
    ErrorOrNoticeUnknownDiagnosticSeverity { severity: CString },
    #[error("invalid integer field in ErrorResponse or NoticeResponse message")]
    ErrorOrNoticeInvalidInteger { position_str: CString },
    #[error("missing severity field in ErrorResponse or NoticeResponse message")]
    ErrorOrNoticeMissingSeverity,
    #[error("missing localized severity field in ErrorResponse or NoticeResponse message")]
    ErrorOrNoticeMissingLocalizedSeverity,
    #[error("missing code field in ErrorResponse or NoticeResponse message")]
    ErrorOrNoticeMissingCode,
    #[error("missing message field in ErrorResponse or NoticeResponse message")]
    ErrorOrNoticeMissingMessage,

    #[error("message too short")]
    MessageTooShort,
    #[error("message too long")]
    MessageTooLong,
    #[error("incomplete message body")]
    IncompleteMessageBody,

    #[error("unknown type byte for SSL response: {type_byte:02X}")]
    InvalidSSLResponseTypeByte { type_byte: u8 },
    #[error("unknown type byte for GSSENC response: {type_byte:02X}")]
    InvalidGSSENCResponseTypeByte { type_byte: u8 },
}

impl From<WireFormatError> for IoError {
    fn from(err: WireFormatError) -> Self {
        IoError::new(IoErrorKind::InvalidData, err)
    }
}
