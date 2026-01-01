use std::{
    io::{BufRead, Result as IoResult, Write},
    slice,
};

use crate::{message::ErrorResponse, message_common::WireFormatError};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SSLResponse {
    UseSSL(UseSSL),
    NoSSL(NoSSL),
    ErrorResponse(ErrorResponse),
}

impl SSLResponse {
    pub fn write_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write,
    {
        match self {
            SSLResponse::UseSSL(_) => {
                writer.write_all(&[UseSSL::TYPE_BYTE])?;
            }
            SSLResponse::NoSSL(_) => {
                writer.write_all(&[NoSSL::TYPE_BYTE])?;
            }
            SSLResponse::ErrorResponse(err) => {
                writer.write_all(&[ErrorResponse::TYPE_BYTE])?;
                err.write_to(writer)?;
            }
        }
        Ok(())
    }

    pub fn read_from<R>(reader: &mut R) -> IoResult<Self>
    where
        R: BufRead,
    {
        let mut type_byte = b'\0';
        reader.read_exact(slice::from_mut(&mut type_byte))?;

        match type_byte {
            UseSSL::TYPE_BYTE => Ok(SSLResponse::UseSSL(UseSSL)),
            NoSSL::TYPE_BYTE => Ok(SSLResponse::NoSSL(NoSSL)),
            ErrorResponse::TYPE_BYTE => {
                let error = ErrorResponse::read_from(reader)?;
                Ok(SSLResponse::ErrorResponse(error))
            }
            _ => Err(WireFormatError::InvalidSSLResponseTypeByte { type_byte }.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UseSSL;

impl UseSSL {
    pub const TYPE_BYTE: u8 = b'S';
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NoSSL;

impl NoSSL {
    pub const TYPE_BYTE: u8 = b'N';
}
