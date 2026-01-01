use std::{
    ffi::{CStr, CString},
    io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult, Write},
};

use thiserror::Error;

use crate::common::GetReadBuf;

/// Represents a protocol version with major and minor numbers.
///
/// PostgreSQL uses the versions 3.0 to 3.2 for the frontend/backend protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }
}

pub(crate) trait WriteWireExt: Write {
    fn write_bytes(&mut self, bytes: &[u8]) -> IoResult<()> {
        self.write_all(bytes)
    }
    fn write_u8(&mut self, value: u8) -> IoResult<()> {
        self.write_all(&[value])
    }
    fn write_u16(&mut self, value: u16) -> IoResult<()> {
        self.write_all(&value.to_be_bytes())
    }
    fn write_u32(&mut self, value: u32) -> IoResult<()> {
        self.write_all(&value.to_be_bytes())
    }
    fn write_usize32(&mut self, value: usize) -> IoResult<()> {
        self.write_u32(u32::try_from(value).unwrap())
    }
    fn write_sized<F>(&mut self, f: F) -> IoResult<()>
    where
        F: FnOnce(&mut Vec<u8>) -> IoResult<()>,
    {
        let mut buffer: Vec<u8> = Vec::new();
        f(&mut buffer)?;
        self.write_usize32(4 + buffer.len())?;
        self.write_bytes(&buffer)?;
        Ok(())
    }
    fn write_version(&mut self, version: ProtocolVersion) -> IoResult<()> {
        self.write_u16(version.major)?;
        self.write_u16(version.minor)?;

        Ok(())
    }
    fn write_cstring(&mut self, s: &CStr) -> IoResult<()> {
        self.write_all(s.to_bytes_with_nul())
    }
}

impl<T: Write + ?Sized> WriteWireExt for T {}

pub(crate) trait ReadWireExt: GetReadBuf {
    fn read_u8(&mut self) -> IoResult<u8> {
        let mut buf = [0u8; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }
    fn read_u16(&mut self) -> IoResult<u16> {
        let mut buf = [0u8; 2];
        self.read_exact(&mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }
    fn read_u32(&mut self) -> IoResult<u32> {
        let mut buf = [0u8; 4];
        self.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }
    fn read_version(&mut self) -> IoResult<ProtocolVersion> {
        let major = self.read_u16()?;
        let minor = self.read_u16()?;
        Ok(ProtocolVersion { major, minor })
    }
    fn read_cstring(&mut self) -> IoResult<CString> {
        let mut all_buf: Vec<u8> = Vec::new();
        loop {
            let buf = self.read_buffer();
            if let Some(pos) = buf.iter().position(|&b| b == 0) {
                all_buf.extend_from_slice(&buf[..pos + 1]);
                self.consume(pos + 1);
                break;
            } else {
                all_buf.extend_from_slice(buf);
                let len = buf.len();
                self.consume(len);

                let new_len = self.fill_buf()?.len();
                if new_len == 0 {
                    return Err(IoError::new(
                        IoErrorKind::UnexpectedEof,
                        "unterminated C string",
                    ));
                }
            }
        }
        Ok(CString::from_vec_with_nul(all_buf).unwrap())
    }
    fn read_sized<T, F>(&mut self, limit: usize, f: F) -> IoResult<T>
    where
        F: FnOnce(&mut &[u8]) -> IoResult<T>,
    {
        let length = self.read_u32()? as usize;
        if length < 4 {
            return Err(IoError::new(
                IoErrorKind::InvalidData,
                "message length must be at least 4",
            ));
        } else if length - 4 > limit {
            // `limit` above may be usize::MAX

            return Err(IoError::new(
                IoErrorKind::InvalidData,
                "message length exceeds limit",
            ));
        }
        let body_length = length - 4;

        let mut buf = vec![0u8; body_length];
        self.read_exact(&mut buf)?;

        let mut slice: &[u8] = &buf;
        let result = f(&mut slice)?;

        Ok(result)
    }

    fn read_remaining_bytes(&mut self) -> IoResult<Vec<u8>> {
        let mut buf: Vec<u8> = Vec::new();
        self.read_to_end(&mut buf)?;
        Ok(buf)
    }

    fn read_eof(&mut self) -> IoResult<()> {
        if !self.read_is_eof()? {
            return Err(IoError::new(
                IoErrorKind::InvalidData,
                "extra bytes found where none were expected",
            ));
        }
        Ok(())
    }

    fn read_is_eof(&mut self) -> IoResult<bool> {
        let buf = self.read_buffer();
        if !buf.is_empty() {
            return Ok(false);
        }
        let buf = self.fill_buf()?;
        if !buf.is_empty() {
            return Ok(false);
        }
        Ok(true)
    }
}

impl<T: GetReadBuf + ?Sized> ReadWireExt for T {}

#[derive(Debug, Error)]
pub(crate) enum WireFormatError {
    // Found in backend_startup.c, ProcessStartupPacket
    #[error("incomplete startup packet")]
    StartupIncompleteLength,
    #[error("invalid length of startup packet")]
    StartupTooShort,
    #[error("invalid length of startup packet")]
    StartupTooLong,
    #[error("invalid length of startup packet")]
    StartupIncompleteBody,
    #[error("invalid length of startup packet")]
    StartupIncompleteVersion,
    #[error("invalid startup packet layout: expected terminator as last byte")]
    StartupPacketExtraBytes,
    #[error("invalid startup packet layout: expected terminator as last byte")]
    StartupPacketUnterminatedString,
    #[error("invalid value for parameter \"replication\": \"{value}\"")]
    InvalidReplicationParameter { value: String },
    #[error("no PostgreSQL user name specified in startup packet")]
    MissingUserName,
    // Not found in PostgreSQL
    #[error("invalid SSL/TLS request packet layout: expected empty body")]
    SSLRequestExtraBytes,
    // Not found in PostgreSQL
    #[error("invalid GSSENC request packet layout: expected empty body")]
    GSSENCRequestExtraBytes,
    #[error("invalid length of cancel request packet")]
    CancelRequestIncompleteProcessId,
    #[error("invalid length of cancel key in cancel request packet")]
    CancelRequestMissingSecretKey,
    #[error("invalid length of cancel key in cancel request packet")]
    CancelRequestSecretKeyTooLong { length: usize, max_length: usize },

    #[error("unterminated ErrorResponse or NoticeResponse message")]
    ErrorOrNoticeUnterminated,
    #[error("unknown diagnostic severity in ErrorResponse or NoticeResponse message")]
    ErrorOrNoticeUnknownDiagnosticSeverity { severity: CString },
    #[error("invalid integer field in ErrorResponse or NoticeResponse message")]
    ErrorOrNoticeInvalidInteger { position_str: CString },
    #[error("missing severity field in ErrorResponse or NoticeResponse message")]
    ErrorOrNoticeMissingSeverity,
    #[error("missing localized severity field in ErrorResponse or NoticeResponse message")]
    ErrorOrNoticeMissingLocalizedSeverity,
    #[error("missing code field in ErrorResponse or NoticeResponse message")]
    ErrorOrNoticeMissingCode,
    #[error("missing message field in ErrorResponse or NoticeResponse message")]
    ErrorOrNoticeMissingMessage,

    #[error("message too short")]
    MessageTooShort,
    #[error("message too long")]
    MessageTooLong,
    #[error("incomplete message body")]
    IncompleteMessageBody,

    #[error("unknown type byte for SSL response: {type_byte:02X}")]
    InvalidSSLResponseTypeByte { type_byte: u8 },
    #[error("unknown type byte for GSSENC response: {type_byte:02X}")]
    InvalidGSSENCResponseTypeByte { type_byte: u8 },
}

impl From<WireFormatError> for IoError {
    fn from(err: WireFormatError) -> Self {
        IoError::new(IoErrorKind::InvalidData, err)
    }
}
