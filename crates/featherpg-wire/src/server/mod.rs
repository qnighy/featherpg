use std::io::{
    BufRead, Error as IoError, ErrorKind as IoErrorKind, Read, Result as IoResult, Write,
};

use crate::{
    ProtocolVersion,
    common::{BytesReader, WithExcess},
    io_util::BufReaderWriter,
    message::{
        CancelRequest, GSSENCResponse, InitialRequest, NegotiateProtocolVersion, NoGSSENC, NoSSL,
        SSLResponse, StartupMessage, StartupResponse, UseGSSENC, UseSSL,
    },
};

const TLS_HANDSHAKE_SIGNATURE: u8 = 0x16;

pub trait Serve {}

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

    // Check for direct SSL/TLS handshake attempt (>= PostgreSQL 17)
    if stream.fill_buf()?.get(0) == Some(&TLS_HANDSHAKE_SIGNATURE) {
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
                "SSL/TLS connection attempted but not supported by server",
            ));
        }
    }

    let mut msg = InitialRequest::read_from(&mut stream)?;

    loop {
        match msg {
            InitialRequest::SSLRequest(_) => {
                if capabilities.ssl {
                    SSLResponse::UseSSL(UseSSL).write_to(&mut stream)?;
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
                    SSLResponse::NoSSL(NoSSL).write_to(&mut stream)?;
                    stream.flush()?;
                    msg = InitialRequest::read_from(&mut stream)?;
                }
            }
            InitialRequest::GSSENCRequest(_) => {
                if capabilities.gssenc {
                    GSSENCResponse::UseGSSENC(UseGSSENC).write_to(&mut stream)?;
                    stream.flush()?;
                    let read_buf = stream.read_buffer().to_owned();
                    let stream = stream.into_inner().ok().unwrap();
                    return Ok(NegotiatedEncryption::UseGSSENC(WithExcess {
                        stream,
                        excess_read: BytesReader::from(read_buf),
                    }));
                } else {
                    GSSENCResponse::NoGSSENC(NoGSSENC).write_to(&mut stream)?;
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
