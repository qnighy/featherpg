use std::io::{Error as IoError, ErrorKind as IoErrorKind, Read, Result as IoResult, Write};

use crate::{
    ProtocolVersion,
    common::{BytesReader, GetReadBuf, VoidIO, WithExcess},
    io_util::{BufReaderWriter, Encryptable},
    message::{
        AuthenticationOk, CancelRequest, GSSENCResponse as RawGSSENCResponse, InitialRequest,
        NegotiateProtocolVersion, NoGSSENC, NoSSL, SSLResponse as RawSSLResponse, StartupMessage,
        StartupResponse, UseGSSENC, UseSSL,
    },
};

/// A trait representing the ability to negotiate encryption.
pub trait NegotiateEncryption<S> {
    type UpgradeToTLS: UpgradeToTLS<S>;
    type UpgradeToGSSENC: UpgradeToGSSENC<S>;
    type InitializeBackend: InitializeBackend;

    /// Handles an SSLRequest or direct TLS from the client.
    fn tls(&mut self) -> IoResult<TLSResponse<Self::UpgradeToTLS>>;

    /// Handles a GSSENCRequest from the client.
    fn gssenc(&mut self) -> IoResult<GSSENCResponse<Self::UpgradeToGSSENC>>;

    /// Concludes the encryption negotiation and proceeds to authentication.
    fn start(
        self,
        req: StartupMessage,
        auth: &mut Authenticator<'_>,
    ) -> IoResult<Self::InitializeBackend>;

    /// Processes a CancelRequest from the client.
    fn process_cancel(self, req: CancelRequest) -> IoResult<()>;
}

#[derive(Debug)]
pub enum TLSResponse<UpgradeToTLS> {
    /// Upgrade the connection to SSL/TLS.
    UseTLS(UpgradeToTLS),
    /// Do not use SSL/TLS.
    NoTLS,
}

/// A trait representing the ability to upgrade a stream to TLS.
pub trait UpgradeToTLS<S> {
    /// Type for upgraded SSL/TLS connections.
    type TLSConn: GetReadBuf + Write;

    /// Upgrades the given stream to TLS.
    fn upgrade_to_tls(self, stream: WithExcess<S>, alpn_mode: ALPNMode) -> IoResult<Self::TLSConn>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ALPNMode {
    /// The use of ALPN is optional.
    Optional,
    /// Require "postgresql" to be selected via ALPN.
    RequireALPN,
}

#[derive(Debug)]
pub struct NoTLSUpgrade {
    inner: Void,
}

impl<S> UpgradeToTLS<S> for NoTLSUpgrade {
    type TLSConn = VoidIO;

    fn upgrade_to_tls(
        self,
        _stream: WithExcess<S>,
        _alpn_mode: ALPNMode,
    ) -> IoResult<Self::TLSConn> {
        match self.inner {}
    }
}

#[derive(Debug)]
pub enum GSSENCResponse<UpgradeToGSSENC> {
    /// Upgrade the connection to GSSENC.
    UseGSSENC(UpgradeToGSSENC),
    /// Do not use GSSENC.
    NoGSSENC,
}

/// A trait representing the ability to upgrade a stream to GSSENC.
pub trait UpgradeToGSSENC<S> {
    /// Type for upgraded GSSENC connections.
    type GSSENCConn: GetReadBuf + Write;

    /// Upgrades the given stream to GSSENC.
    fn upgrade_to_gssenc(self, stream: WithExcess<S>) -> IoResult<Self::GSSENCConn>;
}

#[derive(Debug)]
pub struct NoGSSENCUpgrade {
    inner: Void,
}

impl<S> UpgradeToGSSENC<S> for NoGSSENCUpgrade {
    type GSSENCConn = VoidIO;

    fn upgrade_to_gssenc(self, _stream: WithExcess<S>) -> IoResult<Self::GSSENCConn> {
        match self.inner {}
    }
}

#[derive(Debug)]
enum Void {}

/// A handle for performing authentication.
#[derive(Debug)]
pub struct Authenticator<'a> {
    // TODO: put the actual handle here
    _marker: std::marker::PhantomData<&'a ()>,
}

/// A trait representing the ability to report initialization statuses
/// of the backend server.
pub trait InitializeBackend {
    type Session: Session;

    fn initialize_backend(
        self,
        notifier: &mut InitializationNotifier<'_>,
    ) -> IoResult<Self::Session>;
}

/// A handle for reporting initialization statuses.
#[derive(Debug)]
pub struct InitializationNotifier<'a> {
    // TODO: put the actual handle here
    _marker: std::marker::PhantomData<&'a ()>,
}

/// A trait representing the established session.
pub trait Session {}

pub fn handle_session<S, Startup>(stream: S, mut server: Startup) -> IoResult<()>
where
    S: Read + Write,
    Startup: NegotiateEncryption<S>,
{
    let mut stream = BufReaderWriter::new(Encryptable::Cleartext(stream));

    let mut msg = InitialRequest::read_from(&mut stream)?;

    match msg {
        InitialRequest::SSLRequest(_) => match server.tls()? {
            TLSResponse::UseTLS(upgrade) => {
                RawSSLResponse::UseSSL(UseSSL).write_to(&mut stream)?;
                stream.flush()?;
                let with_excess = prepare_upgrade(stream)?;
                let tls_conn = upgrade.upgrade_to_tls(with_excess, ALPNMode::Optional)?;
                stream = BufReaderWriter::new(Encryptable::UseSSL(tls_conn));
                msg = InitialRequest::read_from(&mut stream)?;
            }
            TLSResponse::NoTLS => {
                RawSSLResponse::NoSSL(NoSSL).write_to(&mut stream)?;
                stream.flush()?;
                msg = InitialRequest::read_from(&mut stream)?;
            }
        },
        InitialRequest::DirectTLS(_) => match server.tls()? {
            TLSResponse::UseTLS(upgrade) => {
                let with_excess = prepare_upgrade(stream)?;
                let tls_conn = upgrade.upgrade_to_tls(with_excess, ALPNMode::RequireALPN)?;
                stream = BufReaderWriter::new(Encryptable::UseSSL(tls_conn));
                msg = InitialRequest::read_from(&mut stream)?;
            }
            TLSResponse::NoTLS => {
                return Err(IoError::new(
                    IoErrorKind::Other,
                    "Direct TLS connection attempted but not supported by server",
                ));
            }
        },
        InitialRequest::GSSENCRequest(_) => match server.gssenc()? {
            GSSENCResponse::UseGSSENC(upgrade) => {
                RawGSSENCResponse::UseGSSENC(UseGSSENC).write_to(&mut stream)?;
                stream.flush()?;
                let with_excess = prepare_upgrade(stream)?;
                let gssenc_conn = upgrade.upgrade_to_gssenc(with_excess)?;
                stream = BufReaderWriter::new(Encryptable::UseGSSENC(gssenc_conn));
                msg = InitialRequest::read_from(&mut stream)?;
            }
            GSSENCResponse::NoGSSENC => {
                RawGSSENCResponse::NoGSSENC(NoGSSENC).write_to(&mut stream)?;
                stream.flush()?;
                msg = InitialRequest::read_from(&mut stream)?;
            }
        },
        _ => {}
    }

    loop {
        match msg {
            InitialRequest::StartupMessage(msg) => {
                let backend_init = server.start(
                    msg,
                    &mut Authenticator {
                        _marker: std::marker::PhantomData,
                    },
                )?;
                StartupResponse::AuthenticationOk(AuthenticationOk).write_to(&mut stream)?;
                stream.flush()?;
                let mut notifier = InitializationNotifier {
                    _marker: std::marker::PhantomData,
                };
                let _session = backend_init.initialize_backend(&mut notifier)?;
                // Session established; in a real server, we would now enter the main loop
                break;
            }
            InitialRequest::SSLRequest(_) => {
                RawSSLResponse::NoSSL(NoSSL).write_to(&mut stream)?;
                stream.flush()?;
                msg = InitialRequest::read_from(&mut stream)?;
            }
            InitialRequest::DirectTLS(_) => {
                return Err(IoError::new(
                    IoErrorKind::Other,
                    "Direct TLS connection attempted but not supported by server",
                ));
            }
            InitialRequest::GSSENCRequest(_) => {
                RawGSSENCResponse::NoGSSENC(NoGSSENC).write_to(&mut stream)?;
                stream.flush()?;
                msg = InitialRequest::read_from(&mut stream)?;
            }
            InitialRequest::CancelRequest(msg) => {
                server.process_cancel(msg)?;
                return Ok(());
            }
        }
    }

    Ok(())
}

fn prepare_upgrade<S, TLSConn, GSSENCConn>(
    stream: BufReaderWriter<Encryptable<S, TLSConn, GSSENCConn>>,
) -> IoResult<WithExcess<S>>
where
    S: Read + Write,
    TLSConn: Read + Write,
    GSSENCConn: Read + Write,
{
    let read_buf = stream.read_buffer().to_owned();
    let (stream, write_buf) = stream.into_parts();

    let stream = match stream {
        Encryptable::Cleartext(stream) => stream,
        Encryptable::UseSSL(_) => unreachable!("do not call prepare_upgrade on TLS streams"),
        Encryptable::UseGSSENC(_) => unreachable!("do not call prepare_upgrade on GSSENC streams"),
    };
    let write_buf = write_buf.map_err(|e| IoError::new(IoErrorKind::Other, e))?;
    assert!(write_buf.is_empty(), "flush before upgrade");

    Ok(WithExcess {
        stream,
        excess_read: BytesReader::from(read_buf),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EncryptionCapabilities {
    /// Allows upgrading the connection to SSL/TLS if true.
    pub ssl: bool,
    /// Allows upgrading the connection to GSSENC if true.
    pub gssenc: bool,
}

#[derive(Debug)]
pub enum NegotiatedEncryption<S>
where
    S: Write,
{
    /// Continue the protocol in cleartext.
    Cleartext(ConnectionKind<S>),
    /// You need to upgrade the connection to SSL/TLS.
    UseSSL {
        stream: WithExcess<S>,
        /// If true, the caller must ensure that ALPN negotiation selects "postgresql".
        require_alpn: bool,
    },
    /// You need to upgrade the connection to GSSENC.
    UseGSSENC(WithExcess<S>),
}

#[derive(Debug)]
pub enum ConnectionKind<S>
where
    S: Write,
{
    /// Ordinary connection startup.
    Startup(Authentication<S>),
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
    let mut stream = BufReaderWriter::new(stream);
    let mut msg = InitialRequest::read_from(&mut stream)?;

    loop {
        match msg {
            InitialRequest::SSLRequest(_) => {
                if capabilities.ssl {
                    RawSSLResponse::UseSSL(UseSSL).write_to(&mut stream)?;
                    stream.flush()?;
                    let read_buf = stream.read_buffer().to_owned();
                    let stream = stream.into_inner().ok().unwrap();
                    return Ok(NegotiatedEncryption::UseSSL {
                        stream: WithExcess {
                            stream,
                            excess_read: BytesReader::from(read_buf),
                        },
                        require_alpn: false,
                    });
                } else {
                    RawSSLResponse::NoSSL(NoSSL).write_to(&mut stream)?;
                    stream.flush()?;
                    msg = InitialRequest::read_from(&mut stream)?;
                }
            }
            InitialRequest::DirectTLS(_) => {
                if capabilities.ssl {
                    // No write so far, so we don't need to flush
                    let read_buf = stream.read_buffer().to_owned();
                    let stream = stream.into_inner().ok().unwrap();
                    return Ok(NegotiatedEncryption::UseSSL {
                        stream: WithExcess {
                            stream,
                            excess_read: BytesReader::from(read_buf),
                        },
                        require_alpn: true,
                    });
                } else {
                    return Err(IoError::new(
                        IoErrorKind::Other,
                        "Direct TLS connection attempted but not supported by server",
                    ));
                }
            }
            InitialRequest::GSSENCRequest(_) => {
                if capabilities.gssenc {
                    RawGSSENCResponse::UseGSSENC(UseGSSENC).write_to(&mut stream)?;
                    stream.flush()?;
                    let read_buf = stream.read_buffer().to_owned();
                    let stream = stream.into_inner().ok().unwrap();
                    return Ok(NegotiatedEncryption::UseGSSENC(WithExcess {
                        stream,
                        excess_read: BytesReader::from(read_buf),
                    }));
                } else {
                    RawGSSENCResponse::NoGSSENC(NoGSSENC).write_to(&mut stream)?;
                    stream.flush()?;
                    msg = InitialRequest::read_from(&mut stream)?;
                }
            }
            InitialRequest::StartupMessage(mut msg) => {
                negotiate_protocol(&mut stream, &mut msg)?;
                return Ok(NegotiatedEncryption::Cleartext(ConnectionKind::Startup(
                    Authentication {
                        session: InternalSession {
                            stream,
                            params: msg,
                        },
                    },
                )));
            }
            InitialRequest::CancelRequest(msg) => {
                return Ok(NegotiatedEncryption::Cleartext(ConnectionKind::Cancel(msg)));
            }
        }
    }
}

pub fn without_encryption<S>(stream: S) -> IoResult<ConnectionKind<S>>
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
        NegotiatedEncryption::UseSSL { .. } => unreachable!(),
        NegotiatedEncryption::UseGSSENC(_) => unreachable!(),
    }
}

fn negotiate_protocol<S>(
    stream: &mut BufReaderWriter<S>,
    params: &mut StartupMessage,
) -> IoResult<()>
where
    S: Read + Write,
{
    let new_version = if params.version >= ProtocolVersion::new(3, 2) {
        ProtocolVersion::new(3, 2)
    } else {
        // TODO: reject requests for versions < 3.0
        ProtocolVersion::new(3, 0)
    };
    let mut unrecognized_options = Vec::new();
    for (name, _) in &params.other_protocol_options {
        if name.as_bytes().starts_with(b"_pq_.") {
            unrecognized_options.push(name.clone());
        }
    }

    if new_version != params.version || !unrecognized_options.is_empty() {
        let msg: StartupResponse = NegotiateProtocolVersion {
            version: new_version,
            unrecognized_options,
        }
        .into();
        msg.write_to(stream)?;
    }

    Ok(())
}

#[derive(Debug)]
struct InternalSession<S>
where
    S: Write,
{
    stream: BufReaderWriter<S>,
    // TODO: expose version and parameters
    params: StartupMessage,
}

#[derive(Debug)]
pub struct Authentication<S>
where
    S: Write,
{
    session: InternalSession<S>,
}
