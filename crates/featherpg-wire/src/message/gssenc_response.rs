use std::{
    io::{Result as IoResult, Write},
    slice,
};

use crate::{
    errors::WireFormatError, io_util::BufReadPeek, message::ErrorResponse,
    message_common::WriteWireExt,
};

/// A response to a GSSENCRequest message, sent by the server.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GSSENCResponse {
    UseGSSENC(UseGSSENC),
    NoGSSENC(NoGSSENC),
    ErrorResponse(ErrorResponse),
}

impl From<UseGSSENC> for GSSENCResponse {
    fn from(msg: UseGSSENC) -> Self {
        GSSENCResponse::UseGSSENC(msg)
    }
}

impl From<NoGSSENC> for GSSENCResponse {
    fn from(msg: NoGSSENC) -> Self {
        GSSENCResponse::NoGSSENC(msg)
    }
}

impl From<ErrorResponse> for GSSENCResponse {
    fn from(msg: ErrorResponse) -> Self {
        GSSENCResponse::ErrorResponse(msg)
    }
}

impl GSSENCResponse {
    pub fn write_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        match self {
            GSSENCResponse::UseGSSENC(msg) => msg.write_to(writer),
            GSSENCResponse::NoGSSENC(msg) => msg.write_to(writer),
            GSSENCResponse::ErrorResponse(err) => err.write_to(writer),
        }
    }

    pub fn read_from<R>(reader: &mut R) -> IoResult<Self>
    where
        R: BufReadPeek + ?Sized,
    {
        let mut type_byte = b'\0';
        reader.read_exact(slice::from_mut(&mut type_byte))?;

        match type_byte {
            UseGSSENC::TYPE_BYTE => {
                UseGSSENC::read_after_type_byte(reader, type_byte).map(Into::into)
            }
            NoGSSENC::TYPE_BYTE => {
                NoGSSENC::read_after_type_byte(reader, type_byte).map(Into::into)
            }
            ErrorResponse::TYPE_BYTE => {
                ErrorResponse::read_after_type_byte(reader, type_byte).map(Into::into)
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

        Ok(UseGSSENC)
    }
}

/// Indicates that the server is not willing to switch to GSSENC.
///
/// Next state: continue with InitialRequest (client active)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NoGSSENC;

impl NoGSSENC {
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

        Ok(NoGSSENC)
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use crate::errors::{DiagnosticMessage, DiagnosticSeverity};

    use super::*;

    fn to_bytes(msg: &GSSENCResponse) -> IoResult<Vec<u8>> {
        let mut buf = Vec::new();
        msg.write_to(&mut buf)?;
        Ok(buf)
    }

    fn from_bytes(data: &[u8]) -> IoResult<GSSENCResponse> {
        let mut reader = data;
        let msg = GSSENCResponse::read_from(&mut reader)?;
        assert_eq!(reader, b"", "inexact read");
        Ok(msg)
    }

    #[test]
    fn test_use_gssenc_writing_packet() {
        let msg = GSSENCResponse::UseGSSENC(UseGSSENC);
        assert_eq!(to_bytes(&msg).unwrap(), b"G");
    }

    #[test]
    fn test_use_gssenc_parsing_packet() {
        let msg = from_bytes(b"G").unwrap();
        assert_eq!(msg, GSSENCResponse::UseGSSENC(UseGSSENC));
    }

    #[test]
    fn test_no_gssenc_writing_packet() {
        let msg = GSSENCResponse::NoGSSENC(NoGSSENC);
        assert_eq!(to_bytes(&msg).unwrap(), b"N");
    }

    #[test]
    fn test_no_gssenc_parsing_packet() {
        let msg = from_bytes(b"N").unwrap();
        assert_eq!(msg, GSSENCResponse::NoGSSENC(NoGSSENC));
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
        let msg = GSSENCResponse::ErrorResponse(ErrorResponse { error: err });
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
        let expected_msg = GSSENCResponse::ErrorResponse(ErrorResponse {
            error: expected_err,
        });
        assert_eq!(msg, expected_msg);
    }
}
