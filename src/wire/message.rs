// https://www.postgresql.org/docs/current/protocol.html
// https://www.postgresql.org/docs/current/protocol-message-formats.html

use std::io;

use crate::wire::message_common::{
    ColumnFormat, LengthCounter, Scanner, WireFormatError, WriteExt,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum WireMessage {
    // Startup responses
    /// Startup response -- successful authentication
    AuthenticationOk,
    /// Startup response -- request for cleartext password
    AuthenticationCleartextPassword,
    /// Startup response -- request for MD5-hashed password
    AuthenticationMD5Password { salt: [u8; 4] },
    /// Startup response -- part of Kerberos V5 authentication.
    /// No longer supported by the current version of PostgreSQL.
    AuthenticationKerberosV5,
    /// Startup response -- part of GSSAPI authentication.
    AuthenticationGSS,
    /// Startup response -- part of SSPI authentication.
    AuthenticationSSPI,
    /// Startup response -- request for SASL authentication
    AuthenticationSASL { mechanisms: Vec<String> },
    NegotiateProtocolVersion {
        major: u16,
        minor: u16,
        unrecognized_options: Vec<String>,
    },

    // Continuation of authentication
    /// Authentication continuation -- part of GSSAPI authentication.
    AuthenticationGSSContinue { data: Vec<u8> },
    /// Authentication continuation -- part of SSPI authentication.
    AuthenticationSASLContinue { data: Vec<u8> },
    /// Authentication continuation -- part of SASL authentication.
    AuthenticationSASLFinal { data: Vec<u8> },

    // Backend startup
    /// Backend startup -- secret key data for canceling a running query
    BackendKeyData {
        process_id: i32,
        secret_key: Vec<u8>,
    },
    /// Backend startup -- indicates that the backend is ready for queries.
    /// Also issued after each command.
    ReadyForQuery {
        transaction_status: TransactionStatus,
    },

    // Query responses
    /// Query response -- description of the rows returned by a query.
    /// Also issued after Describe messages.
    RowDescription { fields: Vec<RowDescriptionField> },
    /// Query response -- a single row of data returned by a query.
    DataRow { columns: Vec<Option<Vec<u8>>> },
    /// Query response -- command completion notification
    CommandComplete { command: String, rows: Option<i64> },
    /// Query response -- indicates that the query is empty.
    EmptyQueryResponse,
    /// Kind of query response -- result of a legacy function call
    /// request.
    FunctionCallResponse { result: Option<Vec<u8>> },

    // Copy responses
    /// Query response -- indicates that the query will copy data
    /// to the server.
    CopyInResponse {
        overall_format: OverallCopyFormat,
        column_formats: Vec<ColumnFormat>,
    },
    /// Query response -- indicates that the query will copy data
    /// from the server.
    CopyOutResponse {
        overall_format: OverallCopyFormat,
        column_formats: Vec<ColumnFormat>,
    },
    /// Query response -- indicates that the query will copy data
    /// in both directions.
    CopyBothResponse {
        overall_format: OverallCopyFormat,
        column_formats: Vec<ColumnFormat>,
    },
    /// Copy data message -- a chunk of data being copied
    CopyData { data: Vec<u8> },
    /// Copy done message -- indicates the end of a copy operation
    CopyDone,

    // Extended query protocol support
    /// Extended query -- parse completion notification
    ParseComplete,
    /// Extended query -- bind completion notification
    BindComplete,
    /// Extended query -- portal suspended notification
    PortalSuspended,
    /// Extended query -- description of a prepared statement
    ParameterDescription { parameter_types: Vec<u32> },
    /// Extended query -- description of a prepared statement
    NoData,
    /// Extended query -- close completion notification
    CloseComplete,

    // Asynchronous messages and general responses
    /// Asynchronous message -- server parameter status update
    ParameterStatus { parameter: String, value: String },
    /// General error response.
    ErrorResponse { error: DiagnosticMessage },
    /// Asynchronous message -- non-error notice from the server
    NoticeResponse { notice: DiagnosticMessage },
    /// Asynchronous message -- notification of an event
    /// that the client has LISTENed for by another session
    /// issueing a NOTIFY command.
    NotificationResponse {
        process_id: i32,
        channel: String,
        payload: String,
    },
}

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
    fn write_to<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        let mut length_counter = LengthCounter::new();
        let type_byte = self.write_body_to(&mut length_counter)?;
        let total_length = u32::try_from(length_counter.length() + 4).unwrap();

        writer.write_all(&[type_byte])?;
        writer.write_all(&total_length.to_be_bytes())?;
        self.write_body_to(writer)?;

        Ok(())
    }

    fn write_body_to<W: io::Write>(&self, writer: &mut W) -> io::Result<u8> {
        match self {
            // Startup responses
            WireMessage::AuthenticationOk => {
                let type_byte = TYPE_BYTE_AUTHENTICATION;
                writer.write_u32(AUTH_TYPE_OK)?;
                Ok(type_byte)
            }
            WireMessage::AuthenticationCleartextPassword => {
                let type_byte = TYPE_BYTE_AUTHENTICATION;
                writer.write_u32(AUTH_TYPE_CLEARTEXT_PASSWORD)?;
                Ok(type_byte)
            }
            WireMessage::AuthenticationMD5Password { salt } => {
                let type_byte = TYPE_BYTE_AUTHENTICATION;
                writer.write_u32(AUTH_TYPE_MD5_PASSWORD)?;
                writer.write_all(salt)?;
                Ok(type_byte)
            }
            WireMessage::AuthenticationKerberosV5 => {
                let type_byte = TYPE_BYTE_AUTHENTICATION;
                writer.write_u32(AUTH_TYPE_KERBEROS_V5)?;
                Ok(type_byte)
            }
            WireMessage::AuthenticationGSS => {
                let type_byte = TYPE_BYTE_AUTHENTICATION;
                writer.write_u32(AUTH_TYPE_GSS)?;
                Ok(type_byte)
            }
            WireMessage::AuthenticationSSPI => {
                let type_byte = TYPE_BYTE_AUTHENTICATION;
                writer.write_u32(AUTH_TYPE_SSPI)?;
                Ok(type_byte)
            }
            WireMessage::AuthenticationSASL { mechanisms } => {
                let type_byte = TYPE_BYTE_AUTHENTICATION;
                writer.write_u32(AUTH_TYPE_SASL)?;
                for mechanism in mechanisms {
                    if mechanism == "" {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "SASL mechanism cannot be empty",
                        ));
                    }
                    writer.write_cstring(mechanism)?;
                }
                writer.write_cstring("")?;
                Ok(type_byte)
            }
            WireMessage::NegotiateProtocolVersion {
                major,
                minor,
                unrecognized_options,
            } => {
                let type_byte = TYPE_BYTE_NEGOTIATE_PROTOCOL_VERSION;
                writer.write_version(*major, *minor)?;
                writer.write_u32(u32::try_from(unrecognized_options.len()).unwrap())?;
                for option in unrecognized_options {
                    writer.write_cstring(option)?;
                }
                Ok(type_byte)
            }

            // Continuation of authentication
            WireMessage::AuthenticationGSSContinue { data } => {
                let type_byte = TYPE_BYTE_AUTHENTICATION;
                writer.write_u32(AUTH_TYPE_GSS_CONTINUE)?;
                writer.write_all(data)?;
                Ok(type_byte)
            }
            WireMessage::AuthenticationSASLContinue { data } => {
                let type_byte = TYPE_BYTE_AUTHENTICATION;
                writer.write_u32(AUTH_TYPE_SASL_CONTINUE)?;
                writer.write_all(data)?;
                Ok(type_byte)
            }
            WireMessage::AuthenticationSASLFinal { data } => {
                let type_byte = TYPE_BYTE_AUTHENTICATION;
                writer.write_u32(AUTH_TYPE_SASL_FINAL)?;
                writer.write_all(data)?;
                Ok(type_byte)
            }

            _ => unimplemented!("write_body_to not implemented for {:?}", self),
        }
    }

    fn parse(buf: &[u8]) -> Result<Self, WireFormatError> {
        let (msg, consumed) = Self::parse_prefix(buf)?;
        if consumed < buf.len() {
            return Err(WireFormatError::ExtraBytes);
        }
        Ok(msg)
    }

    fn bytes_required(buf: &[u8]) -> usize {
        if buf.len() < 5 {
            return 5;
        }
        let len = u32::from_be_bytes(buf[1..5].try_into().unwrap()) as usize;
        len.max(4) + 1
    }

    /// Parses a server wire message at the start of `buf`.
    /// Expects that `buf.len() >= bytes_required(buf)`.
    fn parse_prefix(buf: &[u8]) -> Result<(Self, usize), WireFormatError> {
        if buf.len() < 5 {
            return Err(WireFormatError::UnexpectedEof);
        }
        let type_byte = buf[0];
        let length = u32::from_be_bytes(buf[1..5].try_into().unwrap()) as usize;
        if length < 4 {
            return Err(WireFormatError::LengthTooShort);
        }
        if buf.len() < length + 1 {
            return Err(WireFormatError::UnexpectedEof);
        }
        let body = &buf[5..length + 1];
        let msg = Self::parse_body(type_byte, body)?;
        Ok((msg, length + 1))
    }

    fn parse_body(type_byte: u8, body: &[u8]) -> Result<Self, WireFormatError> {
        let mut scanner = Scanner::new(body);
        let msg = match type_byte {
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
                let (major, minor) = scanner.read_version()?;
                let option_count = scanner.read_u32()?;
                let mut unrecognized_options = Vec::with_capacity(option_count as usize);
                for _ in 0..option_count {
                    let option = scanner.read_cstring()?;
                    unrecognized_options.push(option);
                }
                WireMessage::NegotiateProtocolVersion {
                    major,
                    minor,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum TransactionStatus {
    Idle,
    InTransaction,
    InFailedTransaction,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn write_msg(msg: &WireMessage) -> Vec<u8> {
        let mut buf = Vec::new();
        msg.write_to(&mut buf).unwrap();
        buf
    }

    fn parse_msg(buf: &[u8]) -> WireMessage {
        WireMessage::parse(buf).unwrap()
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
            parse_msg(b"R\x00\x00\x00\x08\x00\x00\x00\x00"),
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
            parse_msg(b"R\x00\x00\x00\x0c\x00\x00\x00\x05\x01\x02\x03\x04"),
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
            parse_msg(b"R\x00\x00\x00\x08\x00\x00\x00\x02"),
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
            parse_msg(b"R\x00\x00\x00\x08\x00\x00\x00\x07"),
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
            parse_msg(b"R\x00\x00\x00\r\x00\x00\x00\x08\x01\x02\x03\x04\x05"),
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
            parse_msg(b"R\x00\x00\x00\x08\x00\x00\x00\x09"),
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
            parse_msg(b"R\x00\x00\x00\x1d\x00\x00\x00\nSCRAM-SHA-256\x00PLAIN\x00\x00"),
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
            parse_msg(b"R\x00\x00\x00\r\x00\x00\x00\x0b\x01\x02\x03\x04\x05"),
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
            parse_msg(b"R\x00\x00\x00\x0D\x00\x00\x00\x0C\x01\x02\x03\x04\x05"),
            WireMessage::AuthenticationSASLFinal {
                data: vec![1, 2, 3, 4, 5]
            }
        );
    }
}
