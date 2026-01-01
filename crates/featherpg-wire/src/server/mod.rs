use std::io::{
    BufRead, Error as IoError, ErrorKind as IoErrorKind, Read, Result as IoResult, Write,
};

use crate::{
    ProtocolVersion,
    common::{BytesReader, WithExcess},
    errors::DiagnosticMessage,
    io_util::BufStream,
    message::{
        CancelRequest, GSSENCResponse, NoGSSENC, NoSSL, SSLResponse, StartupLikeMessage,
        StartupMessage, UseGSSENC, UseSSL, WireMessage, WireState,
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
pub enum NegotiatedEncryption<S> {
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
pub enum ConnectionKind<S> {
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
    let mut stream = BufStream::new(stream);

    // Check for direct SSL/TLS handshake attempt (>= PostgreSQL 17)
    if stream.fill_buf()?.get(0) == Some(&TLS_HANDSHAKE_SIGNATURE) {
        if capabilities.ssl {
            // No write so far, so we don't need to flush
            let (stream, read_buf, _) = stream.into_parts();
            return Ok(NegotiatedEncryption::UseSSL {
                stream: WithExcess {
                    stream,
                    excess_read: BytesReader::from(Vec::from(read_buf)),
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

    let mut msg = StartupLikeMessage::read_from(&mut stream)?;

    loop {
        match msg {
            StartupLikeMessage::SSLRequest(_) => {
                if capabilities.ssl {
                    SSLResponse::UseSSL(UseSSL).write_to(&mut stream)?;
                    stream.flush()?;
                    let (stream, read_buf, _) = stream.into_parts();
                    return Ok(NegotiatedEncryption::UseSSL {
                        stream: WithExcess {
                            stream,
                            excess_read: BytesReader::from(Vec::from(read_buf)),
                        },
                        require_alpn: false,
                    });
                } else {
                    SSLResponse::NoSSL(NoSSL).write_to(&mut stream)?;
                    stream.flush()?;
                    msg = StartupLikeMessage::read_from(&mut stream)?;
                }
            }
            StartupLikeMessage::GSSENCRequest(_) => {
                if capabilities.gssenc {
                    GSSENCResponse::UseGSSENC(UseGSSENC).write_to(&mut stream)?;
                    stream.flush()?;
                    let (stream, read_buf, _) = stream.into_parts();
                    return Ok(NegotiatedEncryption::UseGSSENC(WithExcess {
                        stream,
                        excess_read: BytesReader::from(Vec::from(read_buf)),
                    }));
                } else {
                    GSSENCResponse::NoGSSENC(NoGSSENC).write_to(&mut stream)?;
                    stream.flush()?;
                    msg = StartupLikeMessage::read_from(&mut stream)?;
                }
            }
            StartupLikeMessage::Startup(mut msg) => {
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
            StartupLikeMessage::CancelRequest(msg) => {
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

fn negotiate_protocol<S>(stream: &mut BufStream<S>, params: &mut StartupMessage) -> IoResult<()>
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
        let msg = WireMessage::NegotiateProtocolVersion {
            version: new_version,
            // TODO: use CString
            unrecognized_options: unrecognized_options
                .into_iter()
                .map(|s| s.to_string_lossy().into_owned())
                .collect(),
        };
        msg.write_to(stream)?;
    }

    Ok(())
}

#[derive(Debug)]
struct InternalSession<S> {
    stream: BufStream<S>,
    // TODO: expose version and parameters
    params: StartupMessage,
}

#[derive(Debug)]
pub struct Authentication<S> {
    session: InternalSession<S>,
}

impl<S> Authentication<S>
where
    S: Read + Write,
{
    pub fn authentication_ok(mut self) -> IoResult<BackendStartup<S>> {
        let msg = WireMessage::AuthenticationOk;
        msg.write_to(&mut self.session.stream)?;
        Ok(BackendStartup {
            session: self.session,
        })
    }

    // TODO: other authentication methods
}

#[derive(Debug)]
pub struct BackendStartup<S> {
    session: InternalSession<S>,
}

impl<S> BackendStartup<S>
where
    S: Read + Write,
{
    pub fn send_backend_key(&mut self, process_id: i32, secret_key: &[u8]) -> IoResult<()> {
        let msg = WireMessage::BackendKeyData {
            process_id,
            secret_key: secret_key.to_owned(),
        };
        msg.write_to(&mut self.session.stream)?;

        Ok(())
    }

    pub fn send_parameter_status(&mut self, name: &str, value: &str) -> IoResult<()> {
        let msg = WireMessage::ParameterStatus {
            parameter: name.to_owned(),
            value: value.to_owned(),
        };
        msg.write_to(&mut self.session.stream)?;

        Ok(())
    }

    pub fn send_notice(&mut self, notice: DiagnosticMessage) -> IoResult<()> {
        let msg = WireMessage::NoticeResponse { notice };
        msg.write_to(&mut self.session.stream)?;

        Ok(())
    }

    pub fn send_error(mut self, error: DiagnosticMessage) -> IoResult<()> {
        let msg = WireMessage::ErrorResponse { error };
        msg.write_to(&mut self.session.stream)?;
        self.session.stream.flush()?;

        Ok(())
    }

    pub fn ready(mut self) -> IoResult<Ready<S>> {
        let msg = WireMessage::ReadyForQuery {
            transaction_status: crate::message::TransactionStatus::Idle,
        };
        msg.write_to(&mut self.session.stream)?;
        self.session.stream.flush()?;

        Ok(Ready {
            session: self.session,
        })
    }
}

#[derive(Debug)]
pub struct Ready<S> {
    session: InternalSession<S>,
}

impl<S> Ready<S>
where
    S: Read + Write,
{
    pub fn serve<Sv>(mut self, server: &mut Sv) -> IoResult<()>
    where
        Sv: Serve + ?Sized,
    {
        let msg = WireMessage::read_from(&mut self.session.stream, WireState::Ordinary)?;
        match msg {
            _ => unimplemented!("serve not implemented for {:?}", msg),
        }
    }
}
