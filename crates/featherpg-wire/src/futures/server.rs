use std::future::Future;
use std::io;

use futures::io::{AsyncRead, AsyncWrite};

use crate::server::{CancelRequest, GSSENCResponse, SSLResponse, StartupRequest, StartupResponse};
use crate::{
    errors::{HandleConnectionError, ServerError},
    io_util::ByteQueue,
};

/// Defines an interface that a PostgreSQL wire protocol server must implement
/// using the asynchronous I/O model.
pub trait AsyncServe {
    /// Handles a startup request from a client.
    ///
    /// It is always called exactly once before any commands except:
    ///
    /// - SSLRequest
    /// - GSSENCRequest
    /// - CancelRequest
    fn startup(
        &mut self,
        req: StartupRequest,
    ) -> impl Future<Output = Result<StartupResponse, ServerError>> + Send;

    /// Handles a request to upgrade the connection to use SSL.
    /// Calls to this method may only occur before the `startup` method.
    ///
    /// When it returns UseSSL, the current server loop terminates,
    /// and the caller is expected to upgrade the connection to SSL/TLS
    /// and then re-enter the server loop with the upgraded connection.
    ///
    /// When it returns NoSSL, the server continues the normal startup process.
    fn use_ssl(
        &mut self,
    ) -> impl std::future::Future<Output = Result<SSLResponse, io::Error>> + Send;

    /// Handles a request to upgrade the connection to use GSSENC.
    /// Calls to this method may only occur before the `startup` method.
    ///
    /// When it returns UseGSSENC, the current server loop terminates,
    /// and the caller is expected to upgrade the connection to GSSENC
    /// and then re-enter the server loop with the upgraded connection.
    ///
    /// When it returns NoGSSENC, the server continues the normal startup process.
    fn use_gssenc(
        &mut self,
    ) -> impl std::future::Future<Output = Result<GSSENCResponse, io::Error>> + Send;

    /// Handles a cancel request from a client.
    /// Calls to this method may only occur before the `startup` method.
    ///
    /// When it is called, this connection will never go to
    /// the normal startup process, and the server loop will terminate
    /// after this method returns.
    fn cancel(
        &mut self,
        req: CancelRequest,
    ) -> impl std::future::Future<Output = Result<(), io::Error>> + Send;
}

/// Runs a PostgreSQL wire protocol server on the given stream.
pub fn handle_async_futures_connection<Sv, St>(
    server: &mut Sv,
    stream: St,
) -> Result<(), HandleConnectionError<St>>
where
    Sv: AsyncServe + ?Sized,
    St: AsyncRead + AsyncWrite,
{
    let mut read_queue = ByteQueue::new();
    let mut read_tmp = vec![0u8; 1024];
    Ok(())
}
