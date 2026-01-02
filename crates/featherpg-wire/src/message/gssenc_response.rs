use std::{
    io::{Result as IoResult, Write},
    slice,
};

use crate::{
    common::GetReadBuf, errors::WireFormatError, message::ErrorResponse,
    message_common::WriteWireExt,
};

/// A response to a GSSENCRequest message, sent by the server.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GSSENCResponse {
    UseGSSENC(UseGSSENC),
    NoGSSENC(NoGSSENC),
    ErrorResponse(ErrorResponse),
}

impl GSSENCResponse {
    pub fn write_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write,
    {
        match self {
            GSSENCResponse::UseGSSENC(msg) => {
                msg.write_to(writer)?;
            }
            GSSENCResponse::NoGSSENC(msg) => {
                msg.write_to(writer)?;
            }
            GSSENCResponse::ErrorResponse(err) => {
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
            UseGSSENC::TYPE_BYTE => Ok(GSSENCResponse::UseGSSENC(UseGSSENC)),
            NoGSSENC::TYPE_BYTE => Ok(GSSENCResponse::NoGSSENC(NoGSSENC)),
            ErrorResponse::TYPE_BYTE => {
                let error = ErrorResponse::read_after_type_byte(reader)?;
                Ok(GSSENCResponse::ErrorResponse(error))
            }
            _ => Err(WireFormatError::GSSENCResponseUnknownTypeByte { type_byte }.into()),
        }
    }
}

/// Indicates that the server is willing to switch to GSSENC.
///
/// Next state: connection is upgraded to GSSENC,
///             then continue with InitialRequest (client active)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UseGSSENC;

impl UseGSSENC {
    pub const TYPE_BYTE: u8 = b'G';

    pub fn write_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        writer.write_u8(Self::TYPE_BYTE)?;
        Ok(())
    }
}

/// Indicates that the server is not willing to switch to GSSENC.
///
/// Next state: continue with InitialRequest (client active)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NoGSSENC;

impl NoGSSENC {
    pub const TYPE_BYTE: u8 = b'N';

    pub fn write_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        writer.write_u8(Self::TYPE_BYTE)?;
        Ok(())
    }
}
