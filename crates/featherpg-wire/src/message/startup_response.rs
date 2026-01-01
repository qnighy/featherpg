use std::{
    ffi::CString,
    io::{Result as IoResult, Write},
};

use crate::{ProtocolVersion, message::ErrorResponse, message_common::WriteWireExt};

/// A response to a StartupMessage, sent by the server.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StartupResponse {
    NegotiateProtocolVersion(NegotiateProtocolVersion),
    AuthenticationOk(AuthenticationOk),
    // TODO: other authentication methods
    /// Indicates an unrecoverable error during startup.
    ///
    /// Next state: connection close
    ErrorResponse(ErrorResponse),
}

impl From<NegotiateProtocolVersion> for StartupResponse {
    fn from(value: NegotiateProtocolVersion) -> Self {
        StartupResponse::NegotiateProtocolVersion(value)
    }
}

impl From<AuthenticationOk> for StartupResponse {
    fn from(value: AuthenticationOk) -> Self {
        StartupResponse::AuthenticationOk(value)
    }
}

impl From<ErrorResponse> for StartupResponse {
    fn from(value: ErrorResponse) -> Self {
        StartupResponse::ErrorResponse(value)
    }
}

impl StartupResponse {
    pub fn write_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write,
    {
        match self {
            StartupResponse::NegotiateProtocolVersion(msg) => {
                writer.write_all(&[NegotiateProtocolVersion::TYPE_BYTE])?;
                msg.write_to(writer)?;
            }
            StartupResponse::AuthenticationOk(_) => {
                writer.write_all(&[AuthenticationOk::TYPE_BYTE])?;
                writer.write_all(b"\x00\x00\x00\x08\x00\x00\x00\x00")?;
            }
            StartupResponse::ErrorResponse(err) => {
                writer.write_all(&[ErrorResponse::TYPE_BYTE])?;
                err.write_to(writer)?;
            }
        }
        Ok(())
    }
}

/// Instructs the client to switch to a different protocol version.
///
/// Next state: continue in StartupResponse (server active)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NegotiateProtocolVersion {
    pub version: ProtocolVersion,
    pub unrecognized_options: Vec<CString>,
}

impl NegotiateProtocolVersion {
    pub const TYPE_BYTE: u8 = b'v';
}

impl NegotiateProtocolVersion {
    pub fn write_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write,
    {
        let mut buf = Vec::new();
        self.write_body_to(&mut buf)?;
        writer.write_usize32(buf.len() + 4)?;
        writer.write_all(&buf)?;
        Ok(())
    }

    pub fn write_body_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write,
    {
        writer.write_version(self.version)?;
        // TODO: validate non-emptiness of options
        for option in &self.unrecognized_options {
            writer.write_cstring(option)?;
        }
        writer.write_u8(0)?; // Terminating null byte
        Ok(())
    }
}

/// Indicates that authentication was successful.
///
/// Next state: BackendStartupResponse (server active)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthenticationOk;

impl AuthenticationOk {
    pub const TYPE_BYTE: u8 = b'R';
    pub const AUTH_TYPE: u32 = 0;
}
