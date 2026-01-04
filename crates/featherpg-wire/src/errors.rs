use std::{
    ffi::CString,
    fmt,
    io::{Error as IoError, ErrorKind as IoErrorKind},
};

use thiserror::Error;

use crate::message::ProtocolVersion;

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

    #[error(
        "unsupported version {version} in StartupMessage (expected 3.x, 1234.5678, 1234.5679, or 1234.5680)"
    )]
    StartupMessageUnsupportedMajorVersion { version: ProtocolVersion },
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

    #[error("server connection closed before StartupResponse")]
    StartupResponseMissingTypeByte,
    #[error("unknown type byte for StartupResponse: {} (expected R or v)", describe_byte(*type_byte))]
    StartupResponseUnknownTypeByte { type_byte: u8 },

    #[error("unexpected EOF while reading NegotiateProtocolVersion length")]
    NegotiateProtocolVersionIncompleteLength,
    #[error("found negative length {length} in NegotiateProtocolVersion")]
    NegotiateProtocolVersionNegativeLength { length: isize },
    #[error("NegotiateProtocolVersion too large (found {length}, limit {max_length})")]
    NegotiateProtocolVersionTooLarge { length: usize, max_length: usize },
    #[error("unexpected EOF while reading NegotiateProtocolVersion body")]
    NegotiateProtocolVersionIncompleteBody,
    #[error("packet too short for NegotiateProtocolVersion version")]
    NegotiateProtocolVersionIncompleteVersion,
    #[error("unterminated option name in NegotiateProtocolVersion")]
    NegotiateProtocolVersionIncompleteOptionName,

    #[error("unexpected EOF while reading Authentication length")]
    AuthenticationIncompleteLength,
    #[error("found negative length {length} in Authentication")]
    AuthenticationNegativeLength { length: isize },
    #[error("Authentication too large (found {length}, limit {max_length})")]
    AuthenticationTooLarge { length: usize, max_length: usize },
    #[error("unexpected EOF while reading Authentication body")]
    AuthenticationIncompleteBody,
    #[error("packet too short for Authentication type")]
    AuthenticationIncompleteType,
    #[error("unknown authentication type: {auth_type} (expected 0, 3, 5, 7, 8, 9, 10, 11, or 12)")]
    AuthenticationUnknownType { auth_type: u32 },

    #[error("extra bytes found in AuthenticationOk")]
    AuthenticationOkExtraBytes,
    #[error("extra bytes found in AuthenticationCleartextPassword")]
    AuthenticationCleartextPasswordExtraBytes,
    #[error("packet too short for AuthenticationMD5Password salt")]
    AuthenticationMD5PasswordIncompleteSalt,
    #[error("extra bytes found in AuthenticationMD5Password")]
    AuthenticationMD5PasswordExtraBytes,
    #[error("extra bytes found in AuthenticationGSS")]
    AuthenticationGSSExtraBytes,
    #[error("extra bytes found in AuthenticationSSPI")]
    AuthenticationSSPIExtraBytes,
    #[error("unterminated authentication mechanism name in AuthenticationSASL")]
    AuthenticationSASLUnterminatedAuthenticationMechanismName,
    #[error("extra bytes found in AuthenticationSASL")]
    AuthenticationSASLExtraBytes,

    #[error("unknown type byte for CleartextPasswordClientResponse: {} (expected R or v)", describe_byte(*type_byte))]
    CleartextPasswordClientResponseUnknownTypeByte { type_byte: u8 },

    #[error("unexpected EOF while reading CleartextPasswordMessage length")]
    CleartextPasswordMessageIncompleteLength,
    #[error("found negative length {length} in CleartextPasswordMessage")]
    CleartextPasswordMessageNegativeLength { length: isize },
    #[error("CleartextPasswordMessage too large (found {length}, limit {max_length})")]
    CleartextPasswordMessageTooLarge { length: usize, max_length: usize },
    #[error("unexpected EOF while reading CleartextPasswordMessage body")]
    CleartextPasswordMessageIncompleteBody,
    #[error("unterminated password in CleartextPasswordMessage")]
    CleartextPasswordMessageUnterminatedCString,
    #[error("extra bytes found in CleartextPasswordMessage")]
    CleartextPasswordMessageExtraBytes,

    #[error("unknown type byte for MD5PasswordClientResponse: {} (expected R or v)", describe_byte(*type_byte))]
    MD5PasswordClientResponseUnknownTypeByte { type_byte: u8 },

    #[error("unexpected EOF while reading MD5PasswordMessage length")]
    MD5PasswordMessageIncompleteLength,
    #[error("found negative length {length} in MD5PasswordMessage")]
    MD5PasswordMessageNegativeLength { length: isize },
    #[error("MD5PasswordMessage too large (found {length}, limit {max_length})")]
    MD5PasswordMessageTooLarge { length: usize, max_length: usize },
    #[error("unexpected EOF while reading MD5PasswordMessage body")]
    MD5PasswordMessageIncompleteBody,
    #[error("unterminated password in MD5PasswordMessage")]
    MD5PasswordMessageUnterminatedCString,
    #[error("extra bytes found in MD5PasswordMessage")]
    MD5PasswordMessageExtraBytes,

    #[error("server connection closed before BackendStartupResponse")]
    BackendStartupResponseMissingTypeByte,
    #[error("unknown type byte for BackendStartupResponse: {} (expected K, S, Z, E, or N)", describe_byte(*type_byte))]
    BackendStartupResponseUnknownTypeByte { type_byte: u8 },

    #[error("unexpected EOF while reading BackendKeyData length")]
    BackendKeyDataIncompleteLength,
    #[error("found negative length {length} in BackendKeyData")]
    BackendKeyDataNegativeLength { length: isize },
    #[error("BackendKeyData too large (found {length}, limit {max_length})")]
    BackendKeyDataTooLarge { length: usize, max_length: usize },
    #[error("unexpected EOF while reading BackendKeyData body")]
    BackendKeyDataIncompleteBody,
    #[error("packet too short for BackendKeyData process_id")]
    BackendKeyDataIncompleteProcessId,
    #[error("secret key must not be empty in BackendKeyData")]
    BackendKeyDataEmptySecretKey,
    #[error("secret key too long in BackendKeyData (found {length}, limit {max_length})")]
    BackendKeyDataSecretKeyTooLong { length: usize, max_length: usize },

    #[error("unexpected EOF while reading ParameterStatus length")]
    ParameterStatusIncompleteLength,
    #[error("found negative length {length} in ParameterStatus")]
    ParameterStatusNegativeLength { length: isize },
    #[error("ParameterStatus too large (found {length}, limit {max_length})")]
    ParameterStatusTooLarge { length: usize, max_length: usize },
    #[error("unexpected EOF while reading ParameterStatus body")]
    ParameterStatusIncompleteBody,
    #[error("unterminated parameter name in ParameterStatus")]
    ParameterStatusUnterminatedName,
    #[error("unterminated parameter value in ParameterStatus")]
    ParameterStatusUnterminatedValue,
    #[error("extra bytes found in ParameterStatus")]
    ParameterStatusExtraBytes,

    #[error("unexpected EOF while reading ReadyForQuery length")]
    ReadyForQueryIncompleteLength,
    #[error("found negative length {length} in ReadyForQuery")]
    ReadyForQueryNegativeLength { length: isize },
    #[error("ReadyForQuery too large (found {length}, limit {max_length})")]
    ReadyForQueryTooLarge { length: usize, max_length: usize },
    #[error("unexpected EOF while reading ReadyForQuery body")]
    ReadyForQueryIncompleteBody,
    #[error("packet too short for ReadyForQuery status")]
    ReadyForQueryIncompleteStatus,
    #[error("invalid transaction status in ReadyForQuery: {} (expected I, T, or E)", describe_byte(*status_byte))]
    ReadyForQueryInvalidStatus { status_byte: u8 },
    #[error("extra bytes found in ReadyForQuery")]
    ReadyForQueryExtraBytes,

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

fn describe_byte(byte: u8) -> String {
    match byte {
        b'\'' => "'\\''".to_owned(),
        b'\\' => "'\\\\'".to_owned(),
        0x20..=0x7E => format!("'{}'", byte as char),
        _ => format!("'\\x{:02X}'", byte),
    }
}

impl WireFormatError {
    pub(crate) fn is_eof_error(&self) -> bool {
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

    pub(crate) fn try_extract_ref(err: &IoError) -> Option<&WireFormatError> {
        err.get_ref()
            .and_then(|e| e.downcast_ref::<WireFormatError>())
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

impl<'a> From<&'a WireFormatError> for DiagnosticMessage {
    fn from(err: &'a WireFormatError) -> Self {
        DiagnosticMessage {
            severity: DiagnosticSeverity::Fatal,
            localized_severity: CString::new("FATAL").unwrap(),
            code: CString::new("08P01").unwrap(), // protocol_violation
            message: CString::new(err.to_string()).unwrap(),
            detail: None,
            hint: None,
            position: None,
            internal_position: None,
            internal_query: None,
            where_: None,
            schema_name: None,
            table_name: None,
            column_name: None,
            data_type_name: None,
            constraint_name: None,
            file: None,
            line: None,
            routine: None,
        }
    }
}
