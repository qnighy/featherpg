use std::{
    ffi::CString,
    io::{BufRead, Read, Result as IoResult, Write},
};

use crate::{
    errors::{ErrorPacketType, WireFormatError},
    message::ImplicitTerminate,
    message_common::{ReadWireExt, WriteWireExt},
};

/// A message sent by the client in response to an AuthenticationCleartextPassword.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CleartextPasswordClientResponse {
    CleartextPasswordMessage(CleartextPasswordMessage),
    ImplicitTerminate(ImplicitTerminate),
}

impl From<CleartextPasswordMessage> for CleartextPasswordClientResponse {
    fn from(msg: CleartextPasswordMessage) -> Self {
        CleartextPasswordClientResponse::CleartextPasswordMessage(msg)
    }
}

impl From<ImplicitTerminate> for CleartextPasswordClientResponse {
    fn from(msg: ImplicitTerminate) -> Self {
        CleartextPasswordClientResponse::ImplicitTerminate(msg)
    }
}

impl CleartextPasswordClientResponse {
    pub fn write_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        match self {
            CleartextPasswordClientResponse::CleartextPasswordMessage(msg) => msg.write_to(writer),
            CleartextPasswordClientResponse::ImplicitTerminate(msg) => msg.write_to(writer),
        }
    }

    pub fn read_from<R>(
        reader: &mut R,
        limits: &CleartextPasswordClientResponseLimits,
    ) -> IoResult<Self>
    where
        R: Read + ?Sized,
    {
        let Some(type_byte) = reader.read_u8_opt()? else {
            return Ok(ImplicitTerminate.into());
        };

        match type_byte {
            CleartextPasswordMessage::TYPE_BYTE => {
                CleartextPasswordMessage::read_after_type_byte(reader, type_byte, limits)
                    .map(Into::into)
            }
            _ => Err(
                WireFormatError::CleartextPasswordClientResponseUnknownTypeByte { type_byte }
                    .into(),
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CleartextPasswordClientResponseLimits {
    pub max_length: usize,
}

/// A message sent by the client containing the cleartext password.
///
/// It is called PasswordMessage in the spec.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CleartextPasswordMessage {
    pub password: CString,
}

impl CleartextPasswordMessage {
    pub const TYPE_BYTE: u8 = b'p';

    fn write_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        writer.write_u8(Self::TYPE_BYTE)?;
        writer.write_sized(|writer| self.write_body_to(writer))?;
        Ok(())
    }

    fn write_body_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        writer.write_cstring(&self.password)?;
        Ok(())
    }

    fn read_after_type_byte<R>(
        reader: &mut R,
        type_byte: u8,
        limits: &CleartextPasswordClientResponseLimits,
    ) -> IoResult<Self>
    where
        R: Read + ?Sized,
    {
        assert_eq!(type_byte, Self::TYPE_BYTE);

        reader.read_sized(
            limits.max_length,
            ErrorPacketType::CleartextPasswordMessage,
            |reader| Self::read_body(reader),
        )
    }

    fn read_body<R>(reader: &mut R) -> IoResult<Self>
    where
        R: BufRead + ?Sized,
    {
        let password = reader
            .read_cstring(&|| WireFormatError::CleartextPasswordMessageUnterminatedCString)?;

        reader.read_eof(ErrorPacketType::CleartextPasswordMessage)?;

        Ok(CleartextPasswordMessage { password })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_bytes(msg: &CleartextPasswordClientResponse) -> IoResult<Vec<u8>> {
        let mut buf = Vec::new();
        msg.write_to(&mut buf)?;
        Ok(buf)
    }

    /// Helper function to focus on the packet body only.
    ///
    /// Use this in most tests, but include one test per type_byte
    /// to test the full packet writing.
    #[track_caller]
    fn decompose_packet(bytes: Vec<u8>) -> (u8, Vec<u8>) {
        assert!(bytes.len() >= 5, "packet too short to contain length");
        let type_byte = bytes[0];
        let len = <[u8; 4]>::try_from(&bytes[1..5]).unwrap();
        let len = u32::from_be_bytes(len) as usize;
        assert_eq!(len + 1, bytes.len(), "length field mismatch");

        (type_byte, bytes[5..].to_vec())
    }

    #[track_caller]
    fn to_body_bytes(msg: &CleartextPasswordClientResponse) -> IoResult<(u8, Vec<u8>)> {
        Ok(decompose_packet(to_bytes(msg)?))
    }

    fn from_bytes(
        data: &[u8],
        limits: &CleartextPasswordClientResponseLimits,
    ) -> IoResult<CleartextPasswordClientResponse> {
        let mut reader = data;
        let msg = CleartextPasswordClientResponse::read_from(&mut reader, limits)?;
        assert_eq!(reader, b"", "inexact read");
        Ok(msg)
    }

    /// Helper function to focus on the packet body only.
    ///
    /// Use this in most tests, but include one test per type_byte
    /// to test the full packet writing.
    fn compose_packet(type_byte: u8, data: &[u8]) -> Vec<u8> {
        let len = (data.len() + 4) as u32;
        let mut packet = vec![type_byte];
        packet.extend_from_slice(&len.to_be_bytes());
        packet.extend_from_slice(data);
        packet
    }

    fn from_body_bytes(type_byte: u8, data: &[u8]) -> IoResult<CleartextPasswordClientResponse> {
        from_bytes(
            &compose_packet(type_byte, data),
            &CleartextPasswordClientResponseLimits { max_length: 10000 },
        )
    }

    #[test]
    fn test_cleartext_password_message_writing_packet() {
        let msg =
            CleartextPasswordClientResponse::CleartextPasswordMessage(CleartextPasswordMessage {
                password: CString::new("mypassword").unwrap(),
            });
        assert_eq!(to_bytes(&msg).unwrap(), b"p\x00\x00\x00\x0Fmypassword\x00");
    }

    #[test]
    fn test_cleartext_password_message_parsing_packet() {
        let msg = from_bytes(
            b"p\x00\x00\x00\x0Fmypassword\x00",
            &CleartextPasswordClientResponseLimits { max_length: 10000 },
        )
        .unwrap();
        assert_eq!(
            msg,
            CleartextPasswordClientResponse::CleartextPasswordMessage(CleartextPasswordMessage {
                password: CString::new("mypassword").unwrap(),
            })
        );
    }

    #[test]
    fn test_cleartext_password_message_writing_simple() {
        let msg =
            CleartextPasswordClientResponse::CleartextPasswordMessage(CleartextPasswordMessage {
                password: CString::new("mypassword").unwrap(),
            });
        assert_eq!(
            to_body_bytes(&msg).unwrap(),
            (b'p', b"mypassword\x00".to_vec())
        );
    }

    #[test]
    fn test_cleartext_password_message_parsing_simple() {
        let msg = from_body_bytes(b'p', b"mypassword\x00").unwrap();
        assert_eq!(
            msg,
            CleartextPasswordClientResponse::CleartextPasswordMessage(CleartextPasswordMessage {
                password: CString::new("mypassword").unwrap(),
            })
        );
    }

    #[test]
    fn test_cleartext_password_message_parse_error_incomplete_password() {
        let data = &b"mypassword"[..];
        let err = from_body_bytes(b'p', data).unwrap_err();
        assert_eq!(
            err.to_string(),
            "unterminated password in CleartextPasswordMessage"
        );
    }

    #[test]
    fn test_cleartext_password_message_parse_error_extra_bytes() {
        let data = &b"mypassword\x00extra"[..];
        let err = from_body_bytes(b'p', data).unwrap_err();
        assert_eq!(
            err.to_string(),
            "extra bytes found in CleartextPasswordMessage"
        );
    }

    #[test]
    fn test_implicit_terminate_writing_packet() {
        let msg = ImplicitTerminate.into();
        assert_eq!(to_bytes(&msg).unwrap(), b"");
    }

    #[test]
    fn test_implicit_terminate_parsing_packet() {
        let data = b"";
        let msg = from_bytes(
            data,
            &CleartextPasswordClientResponseLimits { max_length: 10000 },
        )
        .unwrap();

        assert_eq!(msg, ImplicitTerminate.into());
    }
}
