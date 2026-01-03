use std::{
    ffi::CString,
    io::{Result as IoResult, Write},
};

use crate::{
    common::GetReadBuf,
    errors::WireFormatError,
    message::ImplicitTerminate,
    message_common::{ReadSizedErrors, ReadWireExt, WriteWireExt},
};

/// A message sent by the client in response to an AuthenticationMD5Password.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MD5PasswordClientResponse {
    MD5PasswordMessage(MD5PasswordMessage),
    ImplicitTerminate(ImplicitTerminate),
}

impl From<MD5PasswordMessage> for MD5PasswordClientResponse {
    fn from(msg: MD5PasswordMessage) -> Self {
        MD5PasswordClientResponse::MD5PasswordMessage(msg)
    }
}

impl From<ImplicitTerminate> for MD5PasswordClientResponse {
    fn from(msg: ImplicitTerminate) -> Self {
        MD5PasswordClientResponse::ImplicitTerminate(msg)
    }
}

impl MD5PasswordClientResponse {
    pub fn write_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        match self {
            MD5PasswordClientResponse::MD5PasswordMessage(msg) => msg.write_to(writer),
            MD5PasswordClientResponse::ImplicitTerminate(msg) => msg.write_to(writer),
        }
    }

    pub fn read_from<R>(reader: &mut R, limits: &MD5PasswordClientResponseLimits) -> IoResult<Self>
    where
        R: GetReadBuf + ?Sized,
    {
        let is_eof = reader.read_is_eof()?;
        if is_eof {
            return Ok(ImplicitTerminate.into());
        }

        // EOF should have been caught above.
        let type_byte = reader.read_u8(&|| unreachable!())?;

        match type_byte {
            MD5PasswordMessage::TYPE_BYTE => {
                MD5PasswordMessage::read_after_type_byte(reader, type_byte, limits).map(Into::into)
            }
            _ => {
                Err(WireFormatError::MD5PasswordClientResponseUnknownTypeByte { type_byte }.into())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MD5PasswordClientResponseLimits {
    pub max_length: usize,
}

/// A message sent by the client containing the password
/// hashed using MD5.
///
/// It is called PasswordMessage in the spec.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MD5PasswordMessage {
    pub password: CString,
}

impl MD5PasswordMessage {
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
        limits: &MD5PasswordClientResponseLimits,
    ) -> IoResult<Self>
    where
        R: GetReadBuf + ?Sized,
    {
        assert_eq!(type_byte, Self::TYPE_BYTE);

        reader.read_sized(
            limits.max_length,
            ReadSizedErrors {
                on_incomplete_length: &|| WireFormatError::MD5PasswordMessageIncompleteLength,
                on_negative_length: &|length| WireFormatError::MD5PasswordMessageNegativeLength {
                    length,
                },
                on_length_limit_exceeded: &|length, max_length| {
                    WireFormatError::MD5PasswordMessageTooLarge { length, max_length }
                },
                on_incomplete_body: &|| WireFormatError::MD5PasswordMessageIncompleteBody,
            },
            |reader| Self::read_body(reader),
        )
    }

    fn read_body<R>(reader: &mut R) -> IoResult<Self>
    where
        R: GetReadBuf + ?Sized,
    {
        let password =
            reader.read_cstring(&|| WireFormatError::MD5PasswordMessageUnterminatedCString)?;

        reader.read_eof(&|| WireFormatError::MD5PasswordMessageExtraBytes)?;

        Ok(MD5PasswordMessage { password })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_bytes(msg: &MD5PasswordClientResponse) -> IoResult<Vec<u8>> {
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
    fn to_body_bytes(msg: &MD5PasswordClientResponse) -> IoResult<(u8, Vec<u8>)> {
        Ok(decompose_packet(to_bytes(msg)?))
    }

    fn from_bytes(
        data: &[u8],
        limits: &MD5PasswordClientResponseLimits,
    ) -> IoResult<MD5PasswordClientResponse> {
        let mut reader = data;
        let msg = MD5PasswordClientResponse::read_from(&mut reader, limits)?;
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

    fn from_body_bytes(type_byte: u8, data: &[u8]) -> IoResult<MD5PasswordClientResponse> {
        from_bytes(
            &compose_packet(type_byte, data),
            &MD5PasswordClientResponseLimits { max_length: 10000 },
        )
    }

    #[test]
    fn test_md5_password_message_writing_packet() {
        let msg = MD5PasswordClientResponse::MD5PasswordMessage(MD5PasswordMessage {
            password: CString::new("mypassword").unwrap(),
        });
        assert_eq!(to_bytes(&msg).unwrap(), b"p\x00\x00\x00\x0Fmypassword\x00");
    }

    #[test]
    fn test_md5_password_message_parsing_packet() {
        let msg = from_bytes(
            b"p\x00\x00\x00\x0Fmypassword\x00",
            &MD5PasswordClientResponseLimits { max_length: 10000 },
        )
        .unwrap();
        assert_eq!(
            msg,
            MD5PasswordClientResponse::MD5PasswordMessage(MD5PasswordMessage {
                password: CString::new("mypassword").unwrap(),
            })
        );
    }

    #[test]
    fn test_md5_password_message_writing_simple() {
        let msg = MD5PasswordClientResponse::MD5PasswordMessage(MD5PasswordMessage {
            password: CString::new("mypassword").unwrap(),
        });
        assert_eq!(
            to_body_bytes(&msg).unwrap(),
            (b'p', b"mypassword\x00".to_vec())
        );
    }

    #[test]
    fn test_md5_password_message_parsing_simple() {
        let msg = from_body_bytes(b'p', b"mypassword\x00").unwrap();
        assert_eq!(
            msg,
            MD5PasswordClientResponse::MD5PasswordMessage(MD5PasswordMessage {
                password: CString::new("mypassword").unwrap(),
            })
        );
    }

    #[test]
    fn test_md5_password_message_parse_error_incomplete_password() {
        let data = &b"mypassword"[..];
        let err = from_body_bytes(b'p', data).unwrap_err();
        assert_eq!(
            err.to_string(),
            "unterminated password in MD5PasswordMessage"
        );
    }

    #[test]
    fn test_md5_password_message_parse_error_extra_bytes() {
        let data = &b"mypassword\x00extra"[..];
        let err = from_body_bytes(b'p', data).unwrap_err();
        assert_eq!(err.to_string(), "extra bytes found in MD5PasswordMessage");
    }

    #[test]
    fn test_implicit_terminate_writing_packet() {
        let msg = ImplicitTerminate.into();
        assert_eq!(to_bytes(&msg).unwrap(), b"");
    }

    #[test]
    fn test_implicit_terminate_parsing_packet() {
        let data = b"";
        let msg = from_bytes(data, &MD5PasswordClientResponseLimits { max_length: 10000 }).unwrap();

        assert_eq!(msg, ImplicitTerminate.into());
    }
}
