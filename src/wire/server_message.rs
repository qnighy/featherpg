// https://www.postgresql.org/docs/current/protocol.html
// https://www.postgresql.org/docs/current/protocol-message-formats.html

use std::io;

use crate::wire::{
    auth_message::{
        AuthenticationCleartextPassword, AuthenticationGSS, AuthenticationKerberosV5,
        AuthenticationMD5Password, AuthenticationOk, AuthenticationSASL,
        AuthenticationSASLContinue, AuthenticationSASLFinal,
    },
    message_common::{ColumnFormat, WritableWireMessage},
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ServerWireMessage {
    AuthenticationOk(AuthenticationOk),
    AuthenticationCleartextPassword(AuthenticationCleartextPassword),
    AuthenticationMD5Password(AuthenticationMD5Password),
    AuthenticationKerberosV5(AuthenticationKerberosV5),
    AuthenticationGSS(AuthenticationGSS),
    AuthenticationSASL(AuthenticationSASL),
    AuthenticationSASLContinue(AuthenticationSASLContinue),
    AuthenticationSASLFinal(AuthenticationSASLFinal),
}

impl WritableWireMessage for ServerWireMessage {
    fn type_byte(&self) -> u8 {
        match self {
            ServerWireMessage::AuthenticationOk(x) => x.type_byte(),
            ServerWireMessage::AuthenticationCleartextPassword(x) => x.type_byte(),
            ServerWireMessage::AuthenticationMD5Password(x) => x.type_byte(),
            ServerWireMessage::AuthenticationKerberosV5(x) => x.type_byte(),
            ServerWireMessage::AuthenticationGSS(x) => x.type_byte(),
            ServerWireMessage::AuthenticationSASL(x) => x.type_byte(),
            ServerWireMessage::AuthenticationSASLContinue(x) => x.type_byte(),
            ServerWireMessage::AuthenticationSASLFinal(x) => x.type_byte(),
        }
    }

    fn write_body_to<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        match self {
            ServerWireMessage::AuthenticationOk(x) => x.write_body_to(writer),
            ServerWireMessage::AuthenticationCleartextPassword(x) => x.write_body_to(writer),
            ServerWireMessage::AuthenticationMD5Password(x) => x.write_body_to(writer),
            ServerWireMessage::AuthenticationKerberosV5(x) => x.write_body_to(writer),
            ServerWireMessage::AuthenticationGSS(x) => x.write_body_to(writer),
            ServerWireMessage::AuthenticationSASL(x) => x.write_body_to(writer),
            ServerWireMessage::AuthenticationSASLContinue(x) => x.write_body_to(writer),
            ServerWireMessage::AuthenticationSASLFinal(x) => x.write_body_to(writer),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ServerWireMessageOld {
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
