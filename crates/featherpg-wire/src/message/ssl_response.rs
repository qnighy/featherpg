use std::{
    io::{Result as IoResult, Write},
    slice,
};

use crate::{
    errors::WireFormatError, io_util::BufReadPeek, message::ErrorResponse,
    message_common::WriteWireExt,
};

/// A response to an SSLRequest message, sent by the server.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SSLResponse {
    UseSSL(UseSSL),
    NoSSL(NoSSL),
    ErrorResponse(ErrorResponse),
}

impl From<UseSSL> for SSLResponse {
    fn from(msg: UseSSL) -> Self {
        SSLResponse::UseSSL(msg)
    }
}

impl From<NoSSL> for SSLResponse {
    fn from(msg: NoSSL) -> Self {
        SSLResponse::NoSSL(msg)
    }
}

impl From<ErrorResponse> for SSLResponse {
    fn from(msg: ErrorResponse) -> Self {
        SSLResponse::ErrorResponse(msg)
    }
}

impl SSLResponse {
    pub fn write_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        match self {
            SSLResponse::UseSSL(msg) => msg.write_to(writer),
            SSLResponse::NoSSL(msg) => msg.write_to(writer),
            SSLResponse::ErrorResponse(err) => err.write_to(writer),
        }
    }

    pub fn read_from<R>(reader: &mut R) -> IoResult<Self>
    where
        R: BufReadPeek + ?Sized,
    {
        let mut type_byte = b'\0';
        reader.read_exact(slice::from_mut(&mut type_byte))?;

        match type_byte {
            UseSSL::TYPE_BYTE => UseSSL::read_after_type_byte(reader, type_byte).map(Into::into),
            NoSSL::TYPE_BYTE => NoSSL::read_after_type_byte(reader, type_byte).map(Into::into),
            ErrorResponse::TYPE_BYTE => {
                ErrorResponse::read_after_type_byte(reader, type_byte).map(Into::into)
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

    fn write_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        writer.write_u8(Self::TYPE_BYTE)?;
        Ok(())
    }

    fn read_after_type_byte<R>(_reader: &mut R, type_byte: u8) -> IoResult<Self>
    where
        R: BufReadPeek + ?Sized,
    {
        assert_eq!(type_byte, Self::TYPE_BYTE);

        Ok(UseSSL)
    }
}

/// Indicates that the server is not willing to switch to SSL/TLS.
///
/// Next state: continue with InitialRequest (client active)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NoSSL;

impl NoSSL {
    pub const TYPE_BYTE: u8 = b'N';

    fn write_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        writer.write_u8(Self::TYPE_BYTE)?;
        Ok(())
    }

    fn read_after_type_byte<R>(_reader: &mut R, type_byte: u8) -> IoResult<Self>
    where
        R: BufReadPeek + ?Sized,
    {
        assert_eq!(type_byte, Self::TYPE_BYTE);

        Ok(NoSSL)
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use crate::errors::{DiagnosticMessage, DiagnosticSeverity};

    use super::*;

    fn to_bytes(msg: &SSLResponse) -> IoResult<Vec<u8>> {
        let mut buf = Vec::new();
        msg.write_to(&mut buf)?;
        Ok(buf)
    }

    fn from_bytes(data: &[u8]) -> IoResult<SSLResponse> {
        let mut reader = data;
        let msg = SSLResponse::read_from(&mut reader)?;
        assert_eq!(reader, b"", "inexact read");
        Ok(msg)
    }

    #[test]
    fn test_use_ssl_writing_packet() {
        let msg = SSLResponse::UseSSL(UseSSL);
        assert_eq!(to_bytes(&msg).unwrap(), b"S");
    }

    #[test]
    fn test_use_ssl_parsing_packet() {
        let msg = from_bytes(b"S").unwrap();
        assert_eq!(msg, SSLResponse::UseSSL(UseSSL));
    }

    #[test]
    fn test_no_ssl_writing_packet() {
        let msg = SSLResponse::NoSSL(NoSSL);
        assert_eq!(to_bytes(&msg).unwrap(), b"N");
    }

    #[test]
    fn test_no_ssl_parsing_packet() {
        let msg = from_bytes(b"N").unwrap();
        assert_eq!(msg, SSLResponse::NoSSL(NoSSL));
    }

    #[test]
    fn test_error_response_writing_packet() {
        let err = DiagnosticMessage {
            severity: DiagnosticSeverity::Error,
            localized_severity: CStr::from_bytes_with_nul(b"ERROR\0").unwrap().to_owned(),
            code: CStr::from_bytes_with_nul(b"28000\0").unwrap().to_owned(),
            message: CStr::from_bytes_with_nul(b"authentication failed\0")
                .unwrap()
                .to_owned(),
            detail: None,
            hint: None,
            position: None,
            internal_position: None,
            internal_query: None,
            where_: None,
            schema_name: None,
            table_name: None,
            column_name: None,
            data_type_name: None,
            constraint_name: None,
            file: None,
            line: None,
            routine: None,
        };
        let msg = SSLResponse::ErrorResponse(ErrorResponse { error: err });
        assert_eq!(
            to_bytes(&msg).unwrap(),
            b"E\x00\x00\x00\x31SERROR\0VERROR\0C28000\0Mauthentication failed\0\0"
        );
    }

    #[test]
    fn test_error_response_parsing_packet() {
        let msg =
            from_bytes(b"E\x00\x00\x00\x31SERROR\0VERROR\0C28000\0Mauthentication failed\0\0")
                .unwrap();
        let expected_err = DiagnosticMessage {
            severity: DiagnosticSeverity::Error,
            localized_severity: CStr::from_bytes_with_nul(b"ERROR\0").unwrap().to_owned(),
            code: CStr::from_bytes_with_nul(b"28000\0").unwrap().to_owned(),
            message: CStr::from_bytes_with_nul(b"authentication failed\0")
                .unwrap()
                .to_owned(),
            detail: None,
            hint: None,
            position: None,
            internal_position: None,
            internal_query: None,
            where_: None,
            schema_name: None,
            table_name: None,
            column_name: None,
            data_type_name: None,
            constraint_name: None,
            file: None,
            line: None,
            routine: None,
        };
        let expected_msg = SSLResponse::ErrorResponse(ErrorResponse {
            error: expected_err,
        });
        assert_eq!(msg, expected_msg);
    }
}
