use std::{
    ffi::{CStr, CString},
    io::{self, Result as IoResult, Write},
    str::Utf8Error,
};

use thiserror::Error;

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

/// A `Write` implementation that just counts the number of bytes written.
#[derive(Debug)]
pub(crate) struct LengthCounter {
    len: usize,
}

impl LengthCounter {
    pub(crate) fn new() -> Self {
        Self { len: 0 }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }
}

impl Write for LengthCounter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = buf.len();
        self.len += n;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
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
    fn write_version(&mut self, version: ProtocolVersion) -> IoResult<()> {
        self.write_u16(version.major)?;
        self.write_u16(version.minor)?;

        Ok(())
    }
    fn write_cstring_old(&mut self, s: &str) -> IoResult<()> {
        assert!(!s.contains('\0'), "CString cannot contain null bytes");
        self.write_all(s.as_bytes())?;
        self.write_u8(0)
    }
    fn write_cstring(&mut self, s: &CStr) -> IoResult<()> {
        self.write_all(s.to_bytes_with_nul())
    }
}

impl<T: Write + ?Sized> WriteWireExt for T {}

pub(super) struct Scanner<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Scanner<'a> {
    pub(super) fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    pub(super) fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], EofError> {
        if self.position + count > self.data.len() {
            return Err(EofError);
        }

        let start = self.position;
        self.position += count;
        Ok(&self.data[start..self.position])
    }

    pub(super) fn read_remaining_bytes(&mut self) -> &'a [u8] {
        let start = self.position;
        self.position = self.data.len();
        &self.data[start..]
    }

    pub(super) fn read_cstring_old(&mut self) -> Result<String, WireFormatError> {
        let start = self.position;
        while self.position < self.data.len() && self.data[self.position] != 0 {
            self.position += 1;
        }

        if self.position >= self.data.len() {
            return Err(WireFormatError::UnexpectedEof);
        }

        let string_bytes = &self.data[start..self.position];
        self.position += 1; // Skip the null terminator

        let s = str::from_utf8(string_bytes)?.to_owned();
        Ok(s)
    }

    pub(super) fn read_cstring(&mut self) -> Result<CString, EofError> {
        let s = CStr::from_bytes_until_nul(&self.data[self.position..]).map_err(|_| EofError)?;
        self.position += s.to_bytes_with_nul().len();
        Ok(s.to_owned())
    }

    pub(super) fn read_u32(&mut self) -> Result<u32, EofError> {
        let bytes = self.read_bytes(4)?;
        let value = u32::from_be_bytes(bytes.try_into().unwrap());
        Ok(value)
    }

    pub(super) fn read_version(&mut self) -> Result<ProtocolVersion, EofError> {
        let major_bytes = self.read_bytes(2)?;
        let minor_bytes = self.read_bytes(2)?;

        let major = u16::from_be_bytes(major_bytes.try_into().unwrap());
        let minor = u16::from_be_bytes(minor_bytes.try_into().unwrap());

        Ok(ProtocolVersion { major, minor })
    }

    pub(super) fn read_eof(&self) -> Result<(), ExtraByteError> {
        if self.position < self.data.len() {
            return Err(ExtraByteError);
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
#[error("end of file reached before completing read")]
pub(super) struct EofError;

#[derive(Debug, Error)]
#[error("extra bytes found where none were expected")]
pub(super) struct ExtraByteError;

#[derive(Debug, Error)]
pub(super) enum WireFormatError {
    // Found in backend_startup.c, ProcessStartupPacket
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

    #[error("unknown type byte: {type_byte:02X}")]
    UnknownTypeByte { type_byte: u8 },
    #[error("unknown authentication type: {auth_type}")]
    UnknownAuthType { auth_type: u32 },
    #[error("got message length less than 4")]
    LengthTooShort,
    #[error("unexpected end of message")]
    UnexpectedEof,
    #[error("invalid UTF-8 sequence")]
    InvalidUtf8(#[from] Utf8Error),
    #[error("Trailing bytes in message")]
    ExtraBytes,
}
