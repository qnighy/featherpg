use std::{
    io::{Result as IoResult, Write},
    slice,
};

use crate::{
    common::GetReadBuf, errors::WireFormatError, message::ErrorResponse,
    message_common::WriteWireExt,
};

/// A response to an SSLRequest message, sent by the server.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SSLResponse {
    UseSSL(UseSSL),
    NoSSL(NoSSL),
    ErrorResponse(ErrorResponse),
}

impl SSLResponse {
    pub fn write_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        match self {
            SSLResponse::UseSSL(msg) => {
                msg.write_to(writer)?;
            }
            SSLResponse::NoSSL(msg) => {
                msg.write_to(writer)?;
            }
            SSLResponse::ErrorResponse(err) => {
                err.write_to(writer)?;
            }
        }
        Ok(())
    }

    pub fn read_from<R>(reader: &mut R) -> IoResult<Self>
    where
        R: GetReadBuf + ?Sized,
    {
        let mut type_byte = b'\0';
        reader.read_exact(slice::from_mut(&mut type_byte))?;

        match type_byte {
            UseSSL::TYPE_BYTE => Ok(SSLResponse::UseSSL(UseSSL)),
            NoSSL::TYPE_BYTE => Ok(SSLResponse::NoSSL(NoSSL)),
            ErrorResponse::TYPE_BYTE => {
                let error = ErrorResponse::read_after_type_byte(reader)?;
                Ok(SSLResponse::ErrorResponse(error))
            }
            _ => Err(WireFormatError::SSLResponseUnknownTypeByte { type_byte }.into()),
        }
    }
}

/// Indicates that the server is willing to switch to SSL/TLS.
///
/// Next state: connection is upgraded to SSL/TLS,
///             then continue with InitialRequest (client active)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UseSSL;

impl UseSSL {
    pub const TYPE_BYTE: u8 = b'S';

    pub fn write_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        writer.write_u8(Self::TYPE_BYTE)?;
        Ok(())
    }
}

/// Indicates that the server is not willing to switch to SSL/TLS.
///
/// Next state: continue with InitialRequest (client active)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NoSSL;

impl NoSSL {
    pub const TYPE_BYTE: u8 = b'N';

    pub fn write_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        writer.write_u8(Self::TYPE_BYTE)?;
        Ok(())
    }
}
