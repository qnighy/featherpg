use std::{
    io::{self, Write},
    str::Utf8Error,
};

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum ColumnFormat {
    Text,
    Binary,
}

pub(super) trait WriteExt: Write {
    fn write_cstring(&mut self, s: &str) -> io::Result<()> {
        if s.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "CString cannot contain null bytes",
            ));
        }
        self.write_all(s.as_bytes())?;
        self.write_all(&[0])?;
        Ok(())
    }

    fn write_u32(&mut self, value: u32) -> io::Result<()> {
        self.write_all(&value.to_be_bytes())?;
        Ok(())
    }

    fn write_version(&mut self, major: u16, minor: u16) -> io::Result<()> {
        self.write_all(&major.to_be_bytes())?;
        self.write_all(&minor.to_be_bytes())?;
        Ok(())
    }
}

impl<T: Write + ?Sized> WriteExt for T {}

pub(super) trait WritableWireMessage {
    fn type_byte(&self) -> u8;

    fn write_body_to<W>(&self, writer: &mut W) -> io::Result<()>
    where
        W: io::Write;
}

pub(super) trait WritableWireMessageExt: WritableWireMessage {
    fn write_message_to<W>(&self, writer: &mut W) -> io::Result<()>
    where
        W: io::Write,
    {
        writer.write_all(&[self.type_byte()])?;

        let mut length_counter = LengthCounter { length: 0 };
        self.write_body_to(&mut length_counter)?;
        let total_length = u32::try_from(length_counter.length + 4).unwrap();

        writer.write_all(&total_length.to_be_bytes())?;
        self.write_body_to(writer)?;

        Ok(())
    }
}

impl<T: WritableWireMessage + ?Sized> WritableWireMessageExt for T {}

#[derive(Debug, Clone)]
pub(super) struct LengthCounter {
    length: usize,
}

impl LengthCounter {
    pub(super) fn new() -> Self {
        Self { length: 0 }
    }

    pub(super) fn length(&self) -> usize {
        self.length
    }
}

impl io::Write for LengthCounter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.length += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
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
        Ok(&self.data[start..start + self.position])
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

    pub(super) fn read_version(&mut self) -> Result<(u16, u16), WireFormatError> {
        let major_bytes = self.read_bytes(2)?;
        let minor_bytes = self.read_bytes(2)?;

        let major = u16::from_be_bytes(major_bytes.try_into().unwrap());
        let minor = u16::from_be_bytes(minor_bytes.try_into().unwrap());

        Ok((major, minor))
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
    #[error("unexpected end of message")]
    UnexpectedEof,
    #[error("invalid UTF-8 sequence")]
    InvalidUtf8(#[from] Utf8Error),
    #[error("Trailing bytes in message")]
    ExtraBytes,
}
