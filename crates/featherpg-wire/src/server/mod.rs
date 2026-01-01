use std::io::{Error as IoError, ErrorKind as IoErrorKind, Read, Result as IoResult, Write};

use crate::{
    common::{BytesReader, GetReadBuf, VoidIO, WithExcess},
    io_util::{BufReaderWriter, Encryptable},
    message::{
        AuthenticationOk, CancelRequest, GSSENCResponse as RawGSSENCResponse, InitialRequest,
        InitialRequestLimits, NoGSSENC, NoSSL, SSLResponse as RawSSLResponse, StartupMessage,
        StartupResponse, UseGSSENC, UseSSL,
    },
};

const MAX_STARTUP_PACKET_LENGTH: usize = 10000;

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

    let limits = InitialRequestLimits {
        max_length: MAX_STARTUP_PACKET_LENGTH,
    };
    let mut msg = InitialRequest::read_with_tls_lookahead(&mut stream, &limits)?;

    match msg {
        InitialRequest::SSLRequest(_) => match server.tls()? {
            TLSResponse::UseTLS(upgrade) => {
                RawSSLResponse::UseSSL(UseSSL).write_to(&mut stream)?;
                stream.flush()?;
                let with_excess = prepare_upgrade(stream)?;
                let tls_conn = upgrade.upgrade_to_tls(with_excess, ALPNMode::Optional)?;
                stream = BufReaderWriter::new(Encryptable::UseSSL(tls_conn));
                msg = InitialRequest::read_from(&mut stream, &limits)?;
            }
            TLSResponse::NoTLS => {
                RawSSLResponse::NoSSL(NoSSL).write_to(&mut stream)?;
                stream.flush()?;
                msg = InitialRequest::read_from(&mut stream, &limits)?;
            }
        },
        InitialRequest::DirectTLS(_) => match server.tls()? {
            TLSResponse::UseTLS(upgrade) => {
                let with_excess = prepare_upgrade(stream)?;
                let tls_conn = upgrade.upgrade_to_tls(with_excess, ALPNMode::RequireALPN)?;
                stream = BufReaderWriter::new(Encryptable::UseSSL(tls_conn));
                msg = InitialRequest::read_from(&mut stream, &limits)?;
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
                msg = InitialRequest::read_from(&mut stream, &limits)?;
            }
            GSSENCResponse::NoGSSENC => {
                RawGSSENCResponse::NoGSSENC(NoGSSENC).write_to(&mut stream)?;
                stream.flush()?;
                msg = InitialRequest::read_from(&mut stream, &limits)?;
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
                msg = InitialRequest::read_from(&mut stream, &limits)?;
            }
            InitialRequest::DirectTLS(_) => unreachable!("cannot receive DirectTLS here"),
            InitialRequest::GSSENCRequest(_) => {
                RawGSSENCResponse::NoGSSENC(NoGSSENC).write_to(&mut stream)?;
                stream.flush()?;
                msg = InitialRequest::read_from(&mut stream, &limits)?;
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
