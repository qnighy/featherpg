use std::io::{self, Read, Write};

use thiserror::Error;

use crate::{
    common::CarriedStream,
    errors::{HandleConnectionError, ServerError},
    io_util::ByteQueue,
};

/// Defines an interface that a PostgreSQL wire protocol server must implement
/// using the synchronous I/O model.
pub trait Serve {
    /// Handles a startup request from a client.
    ///
    /// It is always called exactly once before any commands except:
    ///
    /// - SSLRequest
    /// - GSSENCRequest
    /// - CancelRequest
    fn startup(&mut self, req: StartupRequest) -> Result<StartupResponse, ServerError>;

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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StartupResponse {
    /// Sucessfull authentication.
    /// The connection goes to the normal command processing state.
    Ok,
    /// Require the client to send a cleartext password.
    RequestCleartextPassword,
    /// Require the client to send an MD5-hashed password.
    RequestMD5Password { salt: [u8; 4] },
    // TODO: other authentication methods.
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

/// Runs a PostgreSQL wire protocol server on the given stream.
pub fn handle_connection<Sv, St>(
    server: &mut Sv,
    stream: St,
) -> Result<(), HandleConnectionError<St>>
where
    Sv: Serve + ?Sized,
    St: Read + Write,
{
    let mut read_queue = ByteQueue::new();
    let mut read_tmp = vec![0u8; 1024];
    Ok(())
}
