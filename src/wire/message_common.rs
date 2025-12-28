use std::{
    io::{self, Write},
    str::Utf8Error,
};

use thiserror::Error;

use crate::wire::io_util::ByteQueue;

/// Represents a protocol version with major and minor numbers.
///
/// PostgreSQL uses the versions 3.0 to 3.2 for the frontend/backend protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct ProtocolVersion {
    pub(super) major: u16,
    pub(super) minor: u16,
}

impl ProtocolVersion {
    pub(super) const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }
}

pub(in crate::wire) struct LengthReservation {
    position: usize,
}

pub(in crate::wire) trait ByteQueueWriteExt {
    fn write_bytes(&mut self, bytes: &[u8]);
    fn write_u8(&mut self, value: u8);
    fn write_u16(&mut self, value: u16);
    fn write_u32(&mut self, value: u32);
    fn write_version(&mut self, version: ProtocolVersion);
    fn write_cstring(&mut self, s: &str);

    fn write_length_placeholder(&mut self) -> LengthReservation;
    fn write_length_back(&mut self, reservation: LengthReservation);
}

impl ByteQueueWriteExt for ByteQueue {
    fn write_bytes(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }

    fn write_u8(&mut self, value: u8) {
        self.extend_from_slice(&[value]);
    }

    fn write_u16(&mut self, value: u16) {
        self.extend_from_slice(&value.to_be_bytes());
    }

    fn write_u32(&mut self, value: u32) {
        self.extend_from_slice(&value.to_be_bytes());
    }

    fn write_version(&mut self, version: ProtocolVersion) {
        self.write_u16(version.major);
        self.write_u16(version.minor);
    }

    fn write_cstring(&mut self, s: &str) {
        assert!(!s.contains('\0'), "CString cannot contain null bytes");
        self.extend_from_slice(s.as_bytes());
        self.write_u8(0);
    }

    fn write_length_placeholder(&mut self) -> LengthReservation {
        let position = self.len();
        self.write_u32(0); // Placeholder
        LengthReservation { position }
    }

    fn write_length_back(&mut self, reservation: LengthReservation) {
        let LengthReservation { position } = reservation;
        let len = u32::try_from(self.len() - position).unwrap();
        self[position..position + 4].copy_from_slice(&len.to_be_bytes());
    }
}

pub(super) struct Scanner<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Scanner<'a> {
    pub(super) fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    pub(super) fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], WireFormatError> {
        if self.position + count > self.data.len() {
            return Err(WireFormatError::UnexpectedEof);
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

    pub(super) fn read_cstring(&mut self) -> Result<String, WireFormatError> {
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

    pub(super) fn read_u32(&mut self) -> Result<u32, WireFormatError> {
        let bytes = self.read_bytes(4)?;
        let value = u32::from_be_bytes(bytes.try_into().unwrap());
        Ok(value)
    }

    pub(super) fn read_version(&mut self) -> Result<ProtocolVersion, WireFormatError> {
        let major_bytes = self.read_bytes(2)?;
        let minor_bytes = self.read_bytes(2)?;

        let major = u16::from_be_bytes(major_bytes.try_into().unwrap());
        let minor = u16::from_be_bytes(minor_bytes.try_into().unwrap());

        Ok(ProtocolVersion { major, minor })
    }

    pub(super) fn read_eof(&self) -> Result<(), WireFormatError> {
        if self.position < self.data.len() {
            return Err(WireFormatError::ExtraBytes);
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub(super) enum WireFormatError {
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
