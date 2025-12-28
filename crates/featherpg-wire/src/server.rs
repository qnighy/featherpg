use std::io::{self, Read, Write};

use crate::errors::ServerError;

/// Defines an interface that a PostgreSQL wire protocol server must implement
/// using the synchronous I/O model.
pub trait Serve<S: Read + Write> {
    /// Handles a startup request from a client.
    ///
    /// It is always called exactly once before any commands except:
    ///
    /// - SSLRequest
    /// - GSSENCRequest
    /// - CancelRequest
    fn startup(&mut self, req: StartupRequest) -> Result<(), ServerError>;

    /// Handles a request to upgrade the connection to use SSL.
    /// Calls to this method may only occur before the `startup` method.
    ///
    /// When it returns UseSSL, the current server loop terminates,
    /// and the caller is expected to upgrade the connection to SSL/TLS
    /// and then re-enter the server loop with the upgraded connection.
    ///
    /// When it returns NoSSL, the server continues the normal startup process.
    fn use_ssl(&mut self) -> Result<SSLResponse, io::Error>;

    /// Handles a request to upgrade the connection to use GSSENC.
    /// Calls to this method may only occur before the `startup` method.
    ///
    /// When it returns UseGSSENC, the current server loop terminates,
    /// and the caller is expected to upgrade the connection to GSSENC
    /// and then re-enter the server loop with the upgraded connection.
    ///
    /// When it returns NoGSSENC, the server continues the normal startup process.
    fn use_gssenc(&mut self) -> Result<GSSENCResponse, io::Error>;

    /// Handles a cancel request from a client.
    /// Calls to this method may only occur before the `startup` method.
    ///
    /// When it is called, this connection will never go to
    /// the normal startup process, and the server loop will terminate
    /// after this method returns.
    fn cancel(&mut self, req: CancelRequest) -> Result<(), io::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StartupRequest {
    pub user: String,
    pub database: String,
    // TODO: options, replication, _pq_, etc.
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SSLResponse {
    UseSSL,
    NoSSL,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GSSENCResponse {
    UseGSSENC,
    NoGSSENC,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CancelRequest {
    pub process_id: i32,
    pub secret_key: Vec<u8>,
}
