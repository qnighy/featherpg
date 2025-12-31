use std::io::{Read, Result as IoResult, Write};

use crate::{
    common::{BytesReader, WithExcess},
    errors::ServerError,
    io_util::{BufStream, GrowableBuffer, WriteBuffer},
    message::{WireMessage, WireState},
    message_common::WriteWireExt,
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
    fn use_ssl(&mut self) -> IoResult<SSLResponse>;

    /// Handles a request to upgrade the connection to use GSSENC.
    /// Calls to this method may only occur before the `startup` method.
    ///
    /// When it returns UseGSSENC, the current server loop terminates,
    /// and the caller is expected to upgrade the connection to GSSENC
    /// and then re-enter the server loop with the upgraded connection.
    ///
    /// When it returns NoGSSENC, the server continues the normal startup process.
    fn use_gssenc(&mut self) -> IoResult<GSSENCResponse>;

    /// Handles a cancel request from a client.
    /// Calls to this method may only occur before the `startup` method.
    ///
    /// When it is called, this connection will never go to
    /// the normal startup process, and the server loop will terminate
    /// after this method returns.
    fn cancel(&mut self, req: CancelRequest) -> IoResult<()>;
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EncryptionCapabilities {
    /// Allows upgrading the connection to SSL/TLS if true.
    pub ssl: bool,
    /// Allows upgrading the connection to GSSENC if true.
    pub gssenc: bool,
}

#[derive(Debug)]
pub enum NegotiatedEncryption<S> {
    /// Continue the protocol in cleartext.
    Cleartext(ConnectionKind),
    /// You need to upgrade the connection to SSL/TLS.
    UseSSL(WithExcess<S>),
    /// You need to upgrade the connection to GSSENC.
    UseGSSENC(WithExcess<S>),
}

#[derive(Debug)]
pub enum ConnectionKind {
    /// Ordinary connection startup.
    Startup(()),
    /// An asynchronous cancel request.
    Cancel(CancelRequest),
}

pub fn negotiate_encryption<S>(
    stream: S,
    capabilities: &EncryptionCapabilities,
) -> IoResult<NegotiatedEncryption<S>>
where
    S: Read + Write,
{
    let mut stream = BufStream::new(stream);

    let mut msg = WireMessage::read_from(&mut stream, WireState::BackendStartup)?;

    loop {
        match msg {
            WireMessage::SSLRequest => {
                if capabilities.ssl {
                    stream.write_u8(b'S')?;
                    stream.flush()?;
                    let (stream, read_buf, _) = stream.into_parts();
                    return Ok(NegotiatedEncryption::UseSSL(WithExcess {
                        stream,
                        excess_read: BytesReader::from(Vec::from(read_buf)),
                    }));
                } else {
                    stream.write_u8(b'N')?;
                    msg = WireMessage::read_from(&mut stream, WireState::BackendStartup)?;
                }
            }
            WireMessage::GSSENCRequest => {
                if capabilities.gssenc {
                    stream.write_u8(b'G')?;
                    stream.flush()?;
                    let (stream, read_buf, _) = stream.into_parts();
                    return Ok(NegotiatedEncryption::UseGSSENC(WithExcess {
                        stream,
                        excess_read: BytesReader::from(Vec::from(read_buf)),
                    }));
                } else {
                    stream.write_u8(b'N')?;
                    msg = WireMessage::read_from(&mut stream, WireState::BackendStartup)?;
                }
            }
            WireMessage::StartupMessage {
                version,
                parameters,
            } => {
                return Ok(NegotiatedEncryption::Cleartext(ConnectionKind::Startup(())));
            }
            WireMessage::CancelRequest {
                process_id,
                secret_key,
            } => {
                return Ok(NegotiatedEncryption::Cleartext(ConnectionKind::Cancel(
                    CancelRequest {
                        process_id,
                        secret_key,
                    },
                )));
            }
            _ => unreachable!("Impossible due to parser state: {:?}", msg),
        }
    }
}

pub fn without_encryption<S>(stream: S) -> IoResult<ConnectionKind>
where
    S: Read + Write,
{
    match negotiate_encryption(
        stream,
        &EncryptionCapabilities {
            ssl: false,
            gssenc: false,
        },
    )? {
        NegotiatedEncryption::Cleartext(connection_kind) => Ok(connection_kind),
        NegotiatedEncryption::UseSSL(_) => unreachable!(),
        NegotiatedEncryption::UseGSSENC(_) => unreachable!(),
    }
}
