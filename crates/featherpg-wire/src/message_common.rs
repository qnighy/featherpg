use std::{
    ffi::{CStr, CString},
    io::{ErrorKind as IoErrorKind, Result as IoResult, Write},
};

use crate::{common::GetReadBuf, errors::WireFormatError};

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
    fn read_bytes(&mut self, buf: &mut [u8], on_eof: &dyn Fn() -> WireFormatError) -> IoResult<()> {
        self.read_exact(buf).map_err(|e| {
            if e.kind() == IoErrorKind::UnexpectedEof {
                on_eof().into()
            } else {
                e
            }
        })
    }
    fn read_u8(&mut self, on_eof: &dyn Fn() -> WireFormatError) -> IoResult<u8> {
        let mut buf = [0u8; 1];
        self.read_bytes(&mut buf, on_eof)?;
        Ok(buf[0])
    }
    fn read_u16(&mut self, on_eof: &dyn Fn() -> WireFormatError) -> IoResult<u16> {
        let mut buf = [0u8; 2];
        self.read_bytes(&mut buf, on_eof)?;
        Ok(u16::from_be_bytes(buf))
    }
    fn read_u32(&mut self, on_eof: &dyn Fn() -> WireFormatError) -> IoResult<u32> {
        let mut buf = [0u8; 4];
        self.read_bytes(&mut buf, on_eof)?;
        Ok(u32::from_be_bytes(buf))
    }
    fn read_version(&mut self, on_eof: &dyn Fn() -> WireFormatError) -> IoResult<ProtocolVersion> {
        let major = self.read_u16(on_eof)?;
        let minor = self.read_u16(on_eof)?;
        Ok(ProtocolVersion { major, minor })
    }
    fn read_cstring(&mut self, on_eof: &dyn Fn() -> WireFormatError) -> IoResult<CString> {
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
                    return Err(on_eof().into());
                }
            }
        }
        Ok(CString::from_vec_with_nul(all_buf).unwrap())
    }
    fn read_sized<T, F>(&mut self, limit: usize, on_eof: ReadSizedErrors<'_>, f: F) -> IoResult<T>
    where
        F: FnOnce(&mut &[u8]) -> IoResult<T>,
    {
        let length_plus_4 = self.read_u32(on_eof.on_incomplete_length)? as usize;
        if length_plus_4 < 4 {
            return Err((on_eof.on_negative_length)(length_plus_4 as isize - 4).into());
        }
        let length = length_plus_4 - 4;
        if length > limit {
            // `limit` above may be usize::MAX

            return Err((on_eof.on_length_limit_exceeded)(length, limit).into());
        }

        let mut buf = vec![0u8; length];
        self.read_bytes(&mut buf, on_eof.on_incomplete_body)?;

        let mut slice: &[u8] = &buf;
        let result = f(&mut slice)?;

        Ok(result)
    }

    fn read_remaining_bytes(&mut self) -> IoResult<Vec<u8>> {
        let mut buf: Vec<u8> = Vec::new();
        self.read_to_end(&mut buf)?;
        Ok(buf)
    }

    fn read_eof(&mut self, on_extra_bytes: &dyn Fn() -> WireFormatError) -> IoResult<()> {
        if !self.read_is_eof()? {
            return Err(on_extra_bytes().into());
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

#[derive(Clone, Copy)]
pub(crate) struct ReadSizedErrors<'a> {
    pub(crate) on_incomplete_length: &'a dyn Fn() -> WireFormatError,
    pub(crate) on_negative_length: &'a dyn Fn(/* length */ isize) -> WireFormatError,
    pub(crate) on_length_limit_exceeded:
        &'a dyn Fn(/* length_found */ usize, /* max_length */ usize) -> WireFormatError,
    pub(crate) on_incomplete_body: &'a dyn Fn() -> WireFormatError,
}
