use crate::wire::message_common::ColumnFormat;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ClientWireMessage {
    // Startup messages
    /// Startup message -- the initial message to initiate a connection
    /// without encryption negotiation.
    StartupMessage {
        major: u16,
        minor: u16,
        parameters: Vec<StartupParameter>,
    },
    /// Startup message -- the initial message to initiate a connection
    /// with SSL encryption negotiation.
    SSLRequest,
    /// Startup message -- the initial message to initiate a connection
    /// with GSSAPI encryption negotiation.
    GSSENCRequest,
    /// Startup-like message -- used to cancel a running query.
    CancelRequest {
        process_id: i32,
        secret_key: Vec<u8>,
    },

    // Authentication continuation
    /// Authentication continuation -- cleartext or MD5-hashed password
    PasswordMessage { password: String },
    /// Authentication continuation -- part of GSSAPI or SSPI authentication.
    GSSResponse { data: Vec<u8> },
    /// Authentication continuation -- part of SASL authentication.
    SASLInitialResponse {
        mechanism: String,
        initial_response: Option<Vec<u8>>,
    },
    /// Authentication continuation -- part of SASL authentication.
    SASLResponse { data: Vec<u8> },

    // Queries
    /// Issues a simple query
    Query { query: String },
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
    /// Issues a legacy function call
    FunctionCall {
        function_oid: u32,
        parameters: Vec<BindParameter>,
        result_format: ColumnFormat,
    },
    /// Closes a prepared statement or portal
    Close { target: CloseTarget, name: String },

    // Copy commands
    /// Copy data message -- a chunk of data being copied
    CopyData { data: Vec<u8> },
    /// Copy done message -- indicates the end of a copy operation
    CopyDone,
    /// Copy fail message -- indicates that a copy operation failed
    CopyFail { message: String },

    // Connection termination
    /// Terminates the connection
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
enum DescribeTarget {
    Statement,
    Portal,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct StartupParameter {
    name: String,
    value: String,
}
