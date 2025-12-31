use std::io::{Read, Result as IoResult, Write};

use crate::{
    common::{BytesReader, WithExcess},
    io_util::BufStream,
    message::{WireMessage, WireState},
    message_common::WriteWireExt,
};

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
