use std::io::{Read, Result as IoResult, Write};

use crate::{
    ProtocolVersion,
    common::{BytesReader, WithExcess},
    errors::DiagnosticMessage,
    io_util::BufStream,
    message::{StartupParameter, WireMessage, WireState},
    message_common::WriteWireExt,
};

pub trait Serve {}

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
    Cleartext(ConnectionKind<S>),
    /// You need to upgrade the connection to SSL/TLS.
    UseSSL(WithExcess<S>),
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
                mut version,
                mut parameters,
            } => {
                negotiate_protocol(&mut stream, &mut version, &mut parameters)?;
                return Ok(NegotiatedEncryption::Cleartext(ConnectionKind::Startup(
                    Authentication {
                        session: InternalSession {
                            stream,
                            version,
                            parameters,
                        },
                    },
                )));
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
        NegotiatedEncryption::UseSSL(_) => unreachable!(),
        NegotiatedEncryption::UseGSSENC(_) => unreachable!(),
    }
}

fn negotiate_protocol<S>(
    stream: &mut BufStream<S>,
    version: &mut ProtocolVersion,
    parameters: &mut Vec<StartupParameter>,
) -> IoResult<()>
where
    S: Read + Write,
{
    let new_version = if *version >= ProtocolVersion::new(3, 2) {
        ProtocolVersion::new(3, 2)
    } else {
        // TODO: reject requests for versions < 3.0
        ProtocolVersion::new(3, 0)
    };
    let mut unrecognized_options = Vec::new();
    for param in &*parameters {
        if param.name.starts_with("_pq_.") {
            unrecognized_options.push(param.name.clone());
        }
    }
    if !unrecognized_options.is_empty() {
        parameters.retain(|param| !param.name.starts_with("_pq_."));
    }

    if new_version != *version || !unrecognized_options.is_empty() {
        let msg = WireMessage::NegotiateProtocolVersion {
            version: new_version,
            unrecognized_options,
        };
        msg.write_to(stream)?;
    }

    Ok(())
}

#[derive(Debug)]
pub(crate) struct InternalSession<S> {
    pub(crate) stream: BufStream<S>,
    // TODO: expose version and parameters
    pub(crate) version: ProtocolVersion,
    pub(crate) parameters: Vec<StartupParameter>,
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
