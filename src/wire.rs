// https://www.postgresql.org/docs/current/protocol.html

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ServerWireMessage {
    AuthenticationOk,
    AuthenticationKerberosV5,
    AuthenticationCleartextPassword,
    AuthenticationMD5Password {
        salt: [u8; 4],
    },
    AuthenticationGSS,
    AuthenticationGSSContinue {
        data: Vec<u8>,
    },
    AuthenticationSSPI,
    AuthenticationSASL {
        mechanisms: Vec<String>,
    },
    AuthenticationSASLContinue {
        data: Vec<u8>,
    },
    AuthenticationSASLFinal {
        data: Vec<u8>,
    },
    BackendKeyData {
        process_id: i32,
        secret_key: Vec<u8>,
    },
    BindComplete,
    CloseComplete,
    CommandComplete {
        command: String,
        rows: Option<i64>,
    },
    CopyData {
        data: Vec<u8>,
    },
    CopyDone,
    CopyInResponse {
        overall_format: OverallCopyFormat,
        column_formats: Vec<ColumnFormat>,
    },
    CopyOutResponse {
        overall_format: OverallCopyFormat,
        column_formats: Vec<ColumnFormat>,
    },
    CopyBothResponse {
        overall_format: OverallCopyFormat,
        column_formats: Vec<ColumnFormat>,
    },
    DataRow {
        columns: Vec<Option<Vec<u8>>>,
    },
    EmptyQueryResponse,
    ErrorResponse {
        error: DiagnosticMessage,
    },
    FunctionCallResponse {
        result: Option<Vec<u8>>,
    },
    NegotiateProtocolVersion {
        major: u16,
        minor: u16,
        unrecognized_options: Vec<String>,
    },
    NoData,
    NoticeResponse {
        notice: DiagnosticMessage,
    },
    NotificationResponse {
        process_id: i32,
        channel: String,
        payload: String,
    },
    ParameterDescription {
        parameter_types: Vec<u32>,
    },
    ParameterStatus {
        parameter: String,
        value: String,
    },
    ParseComplete,
    PortalSuspended,
    ReadyForQuery {
        transaction_status: TransactionStatus,
    },
    RowDescription {
        fields: Vec<RowDescriptionField>,
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ClientWireMessage {
    Bind {
        portal: String,
        statement_name: String,
        parameters: Vec<BindParameter>,
    },
    CancelRequest {
        process_id: i32,
        secret_key: Vec<u8>,
    },
    Close {
        target: CloseTarget,
        name: String,
    },
    CopyData {
        data: Vec<u8>,
    },
    CopyDone,
    CopyFail {
        message: String,
    },
    Describe {
        target: DescribeTarget,
        name: String,
    },
    Execute {
        portal: String,
        max_rows: i32,
    },
    Flush,
    FunctionCall {
        function_oid: u32,
        parameters: Vec<BindParameter>,
        result_format: ColumnFormat,
    },
    GSSENCRequest,
    GSSResponse {
        data: Vec<u8>,
    },
    Parse {
        statement_name: String,
        query: String,
        parameter_types: Vec<u32>,
    },
    PasswordMessage {
        password: String,
    },
    Query {
        query: String,
    },
    SASLInitialResponse {
        mechanism: String,
        initial_response: Option<Vec<u8>>,
    },
    SASLResponse {
        data: Vec<u8>,
    },
    SSLRequest,
    StartupMessage {
        major: u16,
        minor: u16,
        parameters: Vec<StartupParameter>,
    },
    Sync,
    Terminate,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum BindParameter {
    Text(String),
    Binary(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum CloseTarget {
    Statement,
    Portal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum OverallCopyFormat {
    Text,
    Binary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ColumnFormat {
    Text,
    Binary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum DescribeTarget {
    Statement,
    Portal,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct StartupParameter {
    name: String,
    value: String,
}
