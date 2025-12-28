// https://www.postgresql.org/docs/current/protocol.html
// https://www.postgresql.org/docs/current/protocol-message-formats.html

use crate::wire::{
    io_util::ByteQueue,
    message_common::{
        ByteQueueWriteExt, LengthReservation, ProtocolVersion, Scanner, WireFormatError,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum WireState {
    /// Ordinary message exchange state
    Ordinary,
    /// A special state when the server receives the startup message
    BackendStartup,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum WireMessage {
    // Startup messages (frontend)
    /// Startup message (frontend) -- the initial message to initiate a connection
    /// without encryption negotiation.
    StartupMessage {
        version: ProtocolVersion,
        parameters: Vec<StartupParameter>,
    },
    /// Startup message (frontend) -- the initial message to initiate a connection
    /// with SSL encryption negotiation.
    SSLRequest,
    /// Startup message (frontend) -- the initial message to initiate a connection
    /// with GSSAPI encryption negotiation.
    GSSENCRequest,
    /// Startup-like message (frontend) -- used to cancel a running query.
    CancelRequest {
        process_id: i32,
        secret_key: Vec<u8>,
    },

    // Startup responses (backend)
    /// Startup response (backend) -- successful authentication
    AuthenticationOk,
    /// Startup response (backend) -- request for cleartext password
    AuthenticationCleartextPassword,
    /// Startup response (backend) -- request for MD5-hashed password
    AuthenticationMD5Password { salt: [u8; 4] },
    /// Startup response (backend) -- part of Kerberos V5 authentication.
    /// No longer supported by the current version of PostgreSQL.
    AuthenticationKerberosV5,
    /// Startup response (backend) -- part of GSSAPI authentication.
    AuthenticationGSS,
    /// Startup response (backend) -- part of SSPI authentication.
    AuthenticationSSPI,
    /// Startup response (backend) -- request for SASL authentication
    AuthenticationSASL { mechanisms: Vec<String> },
    NegotiateProtocolVersion {
        version: ProtocolVersion,
        unrecognized_options: Vec<String>,
    },

    // Continuation of authentication (backend)
    /// Authentication continuation (backend) -- part of GSSAPI authentication.
    AuthenticationGSSContinue { data: Vec<u8> },
    /// Authentication continuation (backend) -- part of SSPI authentication.
    AuthenticationSASLContinue { data: Vec<u8> },
    /// Authentication continuation (backend) -- part of SASL authentication.
    AuthenticationSASLFinal { data: Vec<u8> },

    // Authentication continuation (frontend)
    /// Authentication continuation (frontend) -- cleartext or MD5-hashed password
    PasswordMessage { password: String },
    /// Authentication continuation (frontend) -- part of GSSAPI or SSPI authentication.
    GSSResponse { data: Vec<u8> },
    /// Authentication continuation (frontend) -- part of SASL authentication.
    SASLInitialResponse {
        mechanism: String,
        initial_response: Option<Vec<u8>>,
    },
    /// Authentication continuation (frontend) -- part of SASL authentication.
    SASLResponse { data: Vec<u8> },

    // Backend startup (backend)
    /// Backend startup (backend) -- secret key data for canceling a running query
    BackendKeyData {
        process_id: i32,
        secret_key: Vec<u8>,
    },
    /// Backend startup (backend) -- indicates that the backend is ready for queries.
    /// Also issued after each command.
    ReadyForQuery {
        transaction_status: TransactionStatus,
    },

    // Simple query (frontend)
    /// Issues a simple query (frontend)
    Query { query: String },
    /// Issues a legacy function call (frontend)
    FunctionCall {
        function_oid: u32,
        parameters: Vec<BindParameter>,
        result_format: ColumnFormat,
    },

    // Query responses (backend)
    /// Query response (backend) -- description of the rows returned by a query.
    /// Also issued after Describe messages.
    RowDescription { fields: Vec<RowDescriptionField> },
    /// Query response (backend) -- a single row of data returned by a query.
    DataRow { columns: Vec<Option<Vec<u8>>> },
    /// Query response (backend) -- command completion notification
    CommandComplete { command: String, rows: Option<i64> },
    /// Query response (backend) -- indicates that the query is empty.
    EmptyQueryResponse,
    /// Kind of query response (backend) -- result of a legacy function call
    /// request.
    FunctionCallResponse { result: Option<Vec<u8>> },

    // Copy responses (backend)
    /// Query response (backend) -- indicates that the query will copy data
    /// to the server.
    CopyInResponse {
        overall_format: OverallCopyFormat,
        column_formats: Vec<ColumnFormat>,
    },
    /// Query response (backend) -- indicates that the query will copy data
    /// from the server.
    CopyOutResponse {
        overall_format: OverallCopyFormat,
        column_formats: Vec<ColumnFormat>,
    },
    /// Query response (backend) -- indicates that the query will copy data
    /// in both directions.
    CopyBothResponse {
        overall_format: OverallCopyFormat,
        column_formats: Vec<ColumnFormat>,
    },

    // Copy messages (frontend & backend)
    /// Copy data message (frontend & backend) -- a chunk of data being copied
    CopyData { data: Vec<u8> },
    /// Copy done message (frontend & backend) -- indicates the end of a copy operation
    CopyDone,
    /// Copy fail message (frontend) -- indicates that a copy operation failed
    CopyFail { message: String },

    // Extended query protocol (frontend)
    /// Prepares a statement for execution
    Parse {
        statement_name: String,
        query: String,
        parameter_types: Vec<u32>,
    },
    /// Binds a prepared statement to a portal for execution
    Bind {
        portal: String,
        statement_name: String,
        parameters: Vec<BindParameter>,
    },
    /// Executes a portal
    Execute { portal: String, max_rows: i32 },
    /// Describes a prepared statement or portal
    Describe {
        target: DescribeTarget,
        name: String,
    },
    /// Indicates the end of a series of extended query messages
    Sync,
    /// Forces the server to send all pending results
    Flush,
    /// Closes a prepared statement or portal
    Close { target: CloseTarget, name: String },

    // Extended query protocol support (backend)
    /// Extended query (backend) -- parse completion notification
    ParseComplete,
    /// Extended query (backend) -- bind completion notification
    BindComplete,
    /// Extended query (backend) -- portal suspended notification
    PortalSuspended,
    /// Extended query (backend) -- description of a prepared statement
    ParameterDescription { parameter_types: Vec<u32> },
    /// Extended query (backend) -- description of a prepared statement
    NoData,
    /// Extended query (backend) -- close completion notification
    CloseComplete,

    // Connection termination
    /// Terminates the connection
    Terminate,

    // Asynchronous messages and general responses (backend)
    /// Asynchronous message (backend) -- server parameter status update
    ParameterStatus { parameter: String, value: String },
    /// General error response (backend).
    ErrorResponse { error: DiagnosticMessage },
    /// Asynchronous message (backend) -- non-error notice from the server
    NoticeResponse { notice: DiagnosticMessage },
    /// Asynchronous message (backend) -- notification of an event
    /// that the client has LISTENed for by another session
    /// issueing a NOTIFY command.
    NotificationResponse {
        process_id: i32,
        channel: String,
        payload: String,
    },
}

const NO_TYPE_BYTE: u8 = b'\0';
const TYPE_BYTE_AUTHENTICATION: u8 = b'R';
const TYPE_BYTE_NEGOTIATE_PROTOCOL_VERSION: u8 = b'v';
const TYPE_BYTE_BACKEND_KEY_DATA: u8 = b'K';
const TYPE_BYTE_READY_FOR_QUERY: u8 = b'Z';
const TYPE_BYTE_ROW_DESCRIPTION: u8 = b'T';
const TYPE_BYTE_DATA_ROW: u8 = b'D';
const TYPE_BYTE_COMMAND_COMPLETE: u8 = b'C';
const TYPE_BYTE_EMPTY_QUERY_RESPONSE: u8 = b'I';
const TYPE_BYTE_FUNCTION_CALL_RESPONSE: u8 = b'V';
const TYPE_BYTE_COPY_IN_RESPONSE: u8 = b'G';
const TYPE_BYTE_COPY_OUT_RESPONSE: u8 = b'H';
const TYPE_BYTE_COPY_BOTH_RESPONSE: u8 = b'W';
const TYPE_BYTE_COPY_DATA: u8 = b'd';
const TYPE_BYTE_COPY_DONE: u8 = b'c';
const TYPE_BYTE_PARSE_COMPLETE: u8 = b'1';
const TYPE_BYTE_BIND_COMPLETE: u8 = b'2';
const TYPE_BYTE_PORTAL_SUSPENDED: u8 = b's';
const TYPE_BYTE_PARAMETER_DESCRIPTION: u8 = b't';
const TYPE_BYTE_NO_DATA: u8 = b'n';
const TYPE_BYTE_CLOSE_COMPLETE: u8 = b'3';
const TYPE_BYTE_PARAMETER_STATUS: u8 = b'S';
const TYPE_BYTE_ERROR_RESPONSE: u8 = b'E';
const TYPE_BYTE_NOTICE_RESPONSE: u8 = b'N';
const TYPE_BYTE_NOTIFICATION_RESPONSE: u8 = b'A';

const VERSION_SSL_REQUEST: ProtocolVersion = ProtocolVersion::new(1234, 5679);
const VERSION_GSSENC_REQUEST: ProtocolVersion = ProtocolVersion::new(1234, 5680);
const VERSION_CANCEL_REQUEST: ProtocolVersion = ProtocolVersion::new(1234, 5678);

const AUTH_TYPE_OK: u32 = 0;
const AUTH_TYPE_CLEARTEXT_PASSWORD: u32 = 3;
const AUTH_TYPE_MD5_PASSWORD: u32 = 5;
const AUTH_TYPE_KERBEROS_V5: u32 = 2;
const AUTH_TYPE_GSS: u32 = 7;
const AUTH_TYPE_GSS_CONTINUE: u32 = 8;
const AUTH_TYPE_SSPI: u32 = 9;
const AUTH_TYPE_SASL: u32 = 10;
const AUTH_TYPE_SASL_CONTINUE: u32 = 11;
const AUTH_TYPE_SASL_FINAL: u32 = 12;

impl WireMessage {
    fn write_to(&self, writer: &mut ByteQueue) {
        let mut res: LengthReservation;
        match self {
            // Startup messages
            WireMessage::StartupMessage {
                version,
                parameters,
            } => {
                res = writer.write_length_placeholder();
                writer.write_version(*version);
                for param in parameters {
                    writer.write_cstring(&param.name);
                    writer.write_cstring(&param.value);
                }
                writer.write_cstring("");
            }
            WireMessage::SSLRequest => {
                res = writer.write_length_placeholder();
                writer.write_version(VERSION_SSL_REQUEST);
            }
            WireMessage::GSSENCRequest => {
                res = writer.write_length_placeholder();
                writer.write_version(VERSION_GSSENC_REQUEST);
            }
            WireMessage::CancelRequest {
                process_id,
                secret_key,
            } => {
                res = writer.write_length_placeholder();
                writer.write_version(VERSION_CANCEL_REQUEST);
                writer.write_u32(*process_id as u32);
                writer.write_bytes(secret_key);
            }

            // Startup responses
            WireMessage::AuthenticationOk => {
                writer.write_u8(TYPE_BYTE_AUTHENTICATION);
                res = writer.write_length_placeholder();
                writer.write_u32(AUTH_TYPE_OK);
            }
            WireMessage::AuthenticationCleartextPassword => {
                writer.write_u8(TYPE_BYTE_AUTHENTICATION);
                res = writer.write_length_placeholder();
                writer.write_u32(AUTH_TYPE_CLEARTEXT_PASSWORD);
            }
            WireMessage::AuthenticationMD5Password { salt } => {
                writer.write_u8(TYPE_BYTE_AUTHENTICATION);
                res = writer.write_length_placeholder();
                writer.write_u32(AUTH_TYPE_MD5_PASSWORD);
                writer.write_bytes(salt);
            }
            WireMessage::AuthenticationKerberosV5 => {
                writer.write_u8(TYPE_BYTE_AUTHENTICATION);
                res = writer.write_length_placeholder();
                writer.write_u32(AUTH_TYPE_KERBEROS_V5);
            }
            WireMessage::AuthenticationGSS => {
                writer.write_u8(TYPE_BYTE_AUTHENTICATION);
                res = writer.write_length_placeholder();
                writer.write_u32(AUTH_TYPE_GSS);
            }
            WireMessage::AuthenticationSSPI => {
                writer.write_u8(TYPE_BYTE_AUTHENTICATION);
                res = writer.write_length_placeholder();
                writer.write_u32(AUTH_TYPE_SSPI);
            }
            WireMessage::AuthenticationSASL { mechanisms } => {
                writer.write_u8(TYPE_BYTE_AUTHENTICATION);
                res = writer.write_length_placeholder();
                writer.write_u32(AUTH_TYPE_SASL);
                for mechanism in mechanisms {
                    assert!(!mechanism.is_empty(), "SASL mechanism cannot be empty");
                    writer.write_cstring(mechanism);
                }
                writer.write_cstring("");
            }
            WireMessage::NegotiateProtocolVersion {
                version,
                unrecognized_options,
            } => {
                writer.write_u8(TYPE_BYTE_NEGOTIATE_PROTOCOL_VERSION);
                res = writer.write_length_placeholder();
                writer.write_version(*version);
                writer.write_u32(u32::try_from(unrecognized_options.len()).unwrap());
                for option in unrecognized_options {
                    writer.write_cstring(option);
                }
            }

            // Continuation of authentication
            WireMessage::AuthenticationGSSContinue { data } => {
                writer.write_u8(TYPE_BYTE_AUTHENTICATION);
                res = writer.write_length_placeholder();
                writer.write_u32(AUTH_TYPE_GSS_CONTINUE);
                writer.write_bytes(data);
            }
            WireMessage::AuthenticationSASLContinue { data } => {
                writer.write_u8(TYPE_BYTE_AUTHENTICATION);
                res = writer.write_length_placeholder();
                writer.write_u32(AUTH_TYPE_SASL_CONTINUE);
                writer.write_bytes(data);
            }
            WireMessage::AuthenticationSASLFinal { data } => {
                writer.write_u8(TYPE_BYTE_AUTHENTICATION);
                res = writer.write_length_placeholder();
                writer.write_u32(AUTH_TYPE_SASL_FINAL);
                writer.write_bytes(data);
            }

            _ => unimplemented!("write_body_to not implemented for {:?}", self),
        }

        writer.write_length_back(res);
    }

    fn parse(buf: &[u8], state: WireState) -> Result<Self, WireFormatError> {
        let (msg, consumed) = Self::parse_prefix(buf, state)?;
        if consumed < buf.len() {
            return Err(WireFormatError::ExtraBytes);
        }
        Ok(msg)
    }

    fn bytes_required(buf: &[u8], state: WireState) -> usize {
        let offset = match state {
            WireState::Ordinary => 1,
            WireState::BackendStartup => 0,
        };
        if buf.len() < offset + 4 {
            return offset + 4;
        }
        let bufoff = &buf[offset..];
        let len = u32::from_be_bytes(bufoff[..4].try_into().unwrap()) as usize;
        offset + len.max(4)
    }

    /// Parses a server wire message at the start of `buf`.
    /// Expects that `buf.len() >= bytes_required(buf)`.
    fn parse_prefix(buf: &[u8], state: WireState) -> Result<(Self, usize), WireFormatError> {
        let offset = match state {
            WireState::Ordinary => 1,
            WireState::BackendStartup => 0,
        };
        if buf.len() < offset + 4 {
            return Err(WireFormatError::UnexpectedEof);
        }
        let type_byte = match state {
            WireState::Ordinary => buf[0],
            WireState::BackendStartup => NO_TYPE_BYTE,
        };
        let bufoff = &buf[offset..];
        let length = u32::from_be_bytes(bufoff[..4].try_into().unwrap()) as usize;
        if length < 4 {
            return Err(WireFormatError::LengthTooShort);
        }
        if bufoff.len() < length {
            return Err(WireFormatError::UnexpectedEof);
        }
        let body = &bufoff[4..length];
        let msg = Self::parse_body(type_byte, body, state)?;
        Ok((msg, offset + length))
    }

    fn parse_body(type_byte: u8, body: &[u8], state: WireState) -> Result<Self, WireFormatError> {
        let mut scanner = Scanner::new(body);
        let msg = match type_byte {
            NO_TYPE_BYTE if state == WireState::BackendStartup => {
                let version = scanner.read_version()?;
                match version {
                    VERSION_SSL_REQUEST => WireMessage::SSLRequest,
                    VERSION_GSSENC_REQUEST => WireMessage::GSSENCRequest,
                    VERSION_CANCEL_REQUEST => {
                        let process_id = scanner.read_u32()? as i32;
                        let secret_key = scanner.read_remaining_bytes().to_owned();
                        WireMessage::CancelRequest {
                            process_id,
                            secret_key,
                        }
                    }
                    _ => {
                        let mut parameters = Vec::new();
                        loop {
                            let name = scanner.read_cstring()?;
                            if name.is_empty() {
                                break;
                            }
                            let value = scanner.read_cstring()?;
                            parameters.push(StartupParameter { name, value });
                        }
                        WireMessage::StartupMessage {
                            version,
                            parameters,
                        }
                    }
                }
            }
            TYPE_BYTE_AUTHENTICATION => {
                let auth_type = scanner.read_u32()?;
                match auth_type {
                    AUTH_TYPE_OK => WireMessage::AuthenticationOk,
                    AUTH_TYPE_CLEARTEXT_PASSWORD => WireMessage::AuthenticationCleartextPassword,
                    AUTH_TYPE_MD5_PASSWORD => {
                        let salt = scanner.read_bytes(4)?;
                        let salt = <[u8; 4]>::try_from(salt).unwrap();
                        WireMessage::AuthenticationMD5Password { salt }
                    }
                    AUTH_TYPE_KERBEROS_V5 => WireMessage::AuthenticationKerberosV5,
                    AUTH_TYPE_GSS => WireMessage::AuthenticationGSS,
                    AUTH_TYPE_GSS_CONTINUE => {
                        let data = scanner.read_remaining_bytes().to_owned();
                        WireMessage::AuthenticationGSSContinue { data }
                    }
                    AUTH_TYPE_SSPI => WireMessage::AuthenticationSSPI,
                    AUTH_TYPE_SASL => {
                        let mut mechanisms = Vec::new();
                        loop {
                            let mechanism = scanner.read_cstring()?;
                            if mechanism.is_empty() {
                                break;
                            }
                            mechanisms.push(mechanism);
                        }
                        WireMessage::AuthenticationSASL { mechanisms }
                    }
                    AUTH_TYPE_SASL_CONTINUE => {
                        let data = scanner.read_remaining_bytes().to_owned();
                        WireMessage::AuthenticationSASLContinue { data }
                    }
                    AUTH_TYPE_SASL_FINAL => {
                        let data = scanner.read_remaining_bytes().to_owned();
                        WireMessage::AuthenticationSASLFinal { data }
                    }
                    _ => return Err(WireFormatError::UnknownAuthType { auth_type }),
                }
            }
            TYPE_BYTE_NEGOTIATE_PROTOCOL_VERSION => {
                let version = scanner.read_version()?;
                let option_count = scanner.read_u32()?;
                let mut unrecognized_options = Vec::with_capacity(option_count as usize);
                for _ in 0..option_count {
                    let option = scanner.read_cstring()?;
                    unrecognized_options.push(option);
                }
                WireMessage::NegotiateProtocolVersion {
                    version,
                    unrecognized_options,
                }
            }
            _ => return Err(WireFormatError::UnknownTypeByte { type_byte }),
        };
        scanner.read_eof()?;
        Ok(msg)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct StartupParameter {
    name: String,
    value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum TransactionStatus {
    Idle,
    InTransaction,
    InFailedTransaction,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum BindParameter {
    Text(String),
    Binary(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ColumnFormat {
    Text,
    Binary,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RowDescriptionField {
    name: String,
    table_oid: u32,
    column_attr_number: u16,
    data_type_oid: u32,
    data_type_size: i16,
    type_modifier: i32,
    format: ColumnFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum OverallCopyFormat {
    Text,
    Binary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum DescribeTarget {
    Statement,
    Portal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum CloseTarget {
    Statement,
    Portal,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DiagnosticMessage {
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
enum DiagnosticSeverity {
    Debug,
    Log,
    Info,
    Notice,
    Warning,
    Error,
    Fatal,
    Panic,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_msg(msg: &WireMessage) -> Vec<u8> {
        let mut buf = ByteQueue::new();
        msg.write_to(&mut buf);
        Vec::from(&*buf)
    }

    fn parse_msg(buf: &[u8], state: WireState) -> WireMessage {
        WireMessage::parse(buf, state).unwrap()
    }

    #[test]
    fn test_write_startup_message_simple() {
        assert_eq!(
            write_msg(&WireMessage::StartupMessage {
                version: ProtocolVersion::new(3, 2),
                parameters: vec![
                    StartupParameter {
                        name: "user".to_string(),
                        value: "testuser".to_string(),
                    },
                    StartupParameter {
                        name: "database".to_string(),
                        value: "testdb".to_string(),
                    },
                ],
            }),
            b"\x00\x00\x00\x27\x00\x03\x00\x02user\x00testuser\x00database\x00testdb\x00\x00"
        );
    }

    #[test]
    fn test_parse_startup_message_simple() {
        assert_eq!(
            parse_msg(
                b"\x00\x00\x00\x27\x00\x03\x00\x02user\x00testuser\x00database\x00testdb\x00\x00",
                WireState::BackendStartup
            ),
            WireMessage::StartupMessage {
                version: ProtocolVersion::new(3, 2),
                parameters: vec![
                    StartupParameter {
                        name: "user".to_string(),
                        value: "testuser".to_string(),
                    },
                    StartupParameter {
                        name: "database".to_string(),
                        value: "testdb".to_string(),
                    },
                ],
            }
        );
    }

    #[test]
    fn test_write_ssl_request() {
        assert_eq!(
            write_msg(&WireMessage::SSLRequest),
            b"\x00\x00\x00\x08\x04\xd2\x16\x2f"
        );
    }

    #[test]
    fn test_parse_ssl_request() {
        assert_eq!(
            parse_msg(
                b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
                WireState::BackendStartup
            ),
            WireMessage::SSLRequest
        );
    }

    #[test]
    fn test_write_gssenc_request() {
        assert_eq!(
            write_msg(&WireMessage::GSSENCRequest),
            b"\x00\x00\x00\x08\x04\xd2\x16\x30"
        );
    }

    #[test]
    fn test_parse_gssenc_request() {
        assert_eq!(
            parse_msg(
                b"\x00\x00\x00\x08\x04\xd2\x16\x30",
                WireState::BackendStartup
            ),
            WireMessage::GSSENCRequest
        );
    }

    #[test]
    fn test_write_cancel_request() {
        assert_eq!(
            write_msg(&WireMessage::CancelRequest {
                process_id: 12345,
                secret_key: vec![
                    0x7F, 0xCF, 0xA8, 0x12, 0x98, 0x69, 0x4A, 0x34, 0x19, 0x18, 0x64, 0x4D, 0x05,
                    0x37, 0x1A, 0xC7, 0xCB, 0x71, 0x5D, 0x2A, 0x12, 0xA6, 0xEF, 0x55, 0x04, 0x43,
                    0x07, 0xDE, 0xBC, 0x4E, 0xEB, 0x2E
                ],
            }),
            b"\x00\x00\x00\x2C\x04\xD2\x16\x2E\x00\x00\x30\x39\
              \x7F\xCF\xA8\x12\x98\x69\x4A\x34\
              \x19\x18\x64\x4D\x05\x37\x1A\xC7\
              \xCB\x71\x5D\x2A\x12\xA6\xEF\x55\
              \x04\x43\x07\xDE\xBC\x4E\xEB\x2E"
        );
    }

    #[test]
    fn test_parse_cancel_request() {
        assert_eq!(
            parse_msg(
                b"\x00\x00\x00\x2C\x04\xD2\x16\x2E\x00\x00\x30\x39\
                  \x7F\xCF\xA8\x12\x98\x69\x4A\x34\
                  \x19\x18\x64\x4D\x05\x37\x1A\xC7\
                  \xCB\x71\x5D\x2A\x12\xA6\xEF\x55\
                  \x04\x43\x07\xDE\xBC\x4E\xEB\x2E",
                WireState::BackendStartup
            ),
            WireMessage::CancelRequest {
                process_id: 12345,
                secret_key: vec![
                    0x7F, 0xCF, 0xA8, 0x12, 0x98, 0x69, 0x4A, 0x34, 0x19, 0x18, 0x64, 0x4D, 0x05,
                    0x37, 0x1A, 0xC7, 0xCB, 0x71, 0x5D, 0x2A, 0x12, 0xA6, 0xEF, 0x55, 0x04, 0x43,
                    0x07, 0xDE, 0xBC, 0x4E, 0xEB, 0x2E
                ],
            }
        );
    }

    #[test]
    fn test_write_authentication_ok() {
        assert_eq!(
            write_msg(&WireMessage::AuthenticationOk),
            b"R\x00\x00\x00\x08\x00\x00\x00\x00"
        );
    }

    #[test]
    fn test_parse_authentication_ok() {
        assert_eq!(
            parse_msg(b"R\x00\x00\x00\x08\x00\x00\x00\x00", WireState::Ordinary),
            WireMessage::AuthenticationOk
        );
    }

    #[test]
    fn test_write_authentication_md5_password() {
        assert_eq!(
            write_msg(&WireMessage::AuthenticationMD5Password { salt: [1, 2, 3, 4] }),
            b"R\x00\x00\x00\x0c\x00\x00\x00\x05\x01\x02\x03\x04"
        );
    }

    #[test]
    fn test_parse_authentication_md5_password() {
        assert_eq!(
            parse_msg(
                b"R\x00\x00\x00\x0c\x00\x00\x00\x05\x01\x02\x03\x04",
                WireState::Ordinary
            ),
            WireMessage::AuthenticationMD5Password { salt: [1, 2, 3, 4] }
        );
    }

    #[test]
    fn test_write_authentication_kerberos_v5() {
        assert_eq!(
            write_msg(&WireMessage::AuthenticationKerberosV5),
            b"R\x00\x00\x00\x08\x00\x00\x00\x02"
        );
    }

    #[test]
    fn test_parse_authentication_kerberos_v5() {
        assert_eq!(
            parse_msg(b"R\x00\x00\x00\x08\x00\x00\x00\x02", WireState::Ordinary),
            WireMessage::AuthenticationKerberosV5
        );
    }

    #[test]
    fn test_write_authentication_gss() {
        assert_eq!(
            write_msg(&WireMessage::AuthenticationGSS),
            b"R\x00\x00\x00\x08\x00\x00\x00\x07"
        );
    }

    #[test]
    fn test_parse_authentication_gss() {
        assert_eq!(
            parse_msg(b"R\x00\x00\x00\x08\x00\x00\x00\x07", WireState::Ordinary),
            WireMessage::AuthenticationGSS
        );
    }

    #[test]
    fn test_write_authentication_gss_continue() {
        assert_eq!(
            write_msg(&WireMessage::AuthenticationGSSContinue {
                data: vec![1, 2, 3, 4, 5]
            }),
            b"R\x00\x00\x00\r\x00\x00\x00\x08\x01\x02\x03\x04\x05"
        );
    }

    #[test]
    fn test_parse_authentication_gss_continue() {
        assert_eq!(
            parse_msg(
                b"R\x00\x00\x00\r\x00\x00\x00\x08\x01\x02\x03\x04\x05",
                WireState::Ordinary
            ),
            WireMessage::AuthenticationGSSContinue {
                data: vec![1, 2, 3, 4, 5]
            }
        );
    }

    #[test]
    fn test_write_authentication_sspi() {
        assert_eq!(
            write_msg(&WireMessage::AuthenticationSSPI),
            b"R\x00\x00\x00\x08\x00\x00\x00\x09"
        );
    }

    #[test]
    fn test_parse_authentication_sspi() {
        assert_eq!(
            parse_msg(b"R\x00\x00\x00\x08\x00\x00\x00\x09", WireState::Ordinary),
            WireMessage::AuthenticationSSPI
        );
    }

    #[test]
    fn test_write_authentication_sasl() {
        assert_eq!(
            write_msg(&WireMessage::AuthenticationSASL {
                mechanisms: vec!["SCRAM-SHA-256".to_string(), "PLAIN".to_string()]
            }),
            b"R\x00\x00\x00\x1d\x00\x00\x00\nSCRAM-SHA-256\x00PLAIN\x00\x00"
        );
    }

    #[test]
    fn test_parse_authentication_sasl() {
        assert_eq!(
            parse_msg(
                b"R\x00\x00\x00\x1d\x00\x00\x00\nSCRAM-SHA-256\x00PLAIN\x00\x00",
                WireState::Ordinary
            ),
            WireMessage::AuthenticationSASL {
                mechanisms: vec!["SCRAM-SHA-256".to_string(), "PLAIN".to_string()]
            }
        );
    }

    #[test]
    fn test_write_authentication_sasl_continue() {
        assert_eq!(
            write_msg(&WireMessage::AuthenticationSASLContinue {
                data: vec![1, 2, 3, 4, 5]
            }),
            b"R\x00\x00\x00\r\x00\x00\x00\x0b\x01\x02\x03\x04\x05"
        );
    }

    #[test]
    fn test_parse_authentication_sasl_continue() {
        assert_eq!(
            parse_msg(
                b"R\x00\x00\x00\r\x00\x00\x00\x0b\x01\x02\x03\x04\x05",
                WireState::Ordinary
            ),
            WireMessage::AuthenticationSASLContinue {
                data: vec![1, 2, 3, 4, 5]
            }
        );
    }

    #[test]
    fn test_write_authentication_sasl_final() {
        assert_eq!(
            write_msg(&WireMessage::AuthenticationSASLFinal {
                data: vec![1, 2, 3, 4, 5]
            }),
            b"R\x00\x00\x00\x0D\x00\x00\x00\x0C\x01\x02\x03\x04\x05"
        );
    }

    #[test]
    fn test_parse_authentication_sasl_final() {
        assert_eq!(
            parse_msg(
                b"R\x00\x00\x00\x0D\x00\x00\x00\x0C\x01\x02\x03\x04\x05",
                WireState::Ordinary
            ),
            WireMessage::AuthenticationSASLFinal {
                data: vec![1, 2, 3, 4, 5]
            }
        );
    }
}
