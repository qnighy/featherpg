use std::{
    ffi::{CStr, CString},
    io::{BufRead, Error as IoError, ErrorKind as IoErrorKind, Read, Result as IoResult, Write},
};

use crate::{
    errors::{ErrorPacketType, WireFormatError},
    message::ProtocolVersion,
};

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
        self.write_u16(version.major())?;
        self.write_u16(version.minor())?;

        Ok(())
    }
    fn write_cstring(&mut self, s: &CStr) -> IoResult<()> {
        self.write_all(s.to_bytes_with_nul())
    }
}

impl<T: Write + ?Sized> WriteWireExt for T {}

pub(crate) trait ReadWireExt: Read {
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
    fn read_u8_opt(&mut self) -> IoResult<Option<u8>> {
        let mut buf = [0u8; 1];
        let num_read = self.read(&mut buf)?;
        if num_read == 0 {
            Ok(None)
        } else {
            Ok(Some(buf[0]))
        }
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
    fn read_u32_opt(&mut self, on_eof: &dyn Fn() -> WireFormatError) -> IoResult<Option<u32>> {
        let mut buf = [0u8; 4];
        let num_read = self.read(&mut buf[..1])?;
        if num_read == 0 {
            return Ok(None);
        }
        self.read_bytes(&mut buf[1..], on_eof)?;
        Ok(Some(u32::from_be_bytes(buf)))
    }
    fn read_version(&mut self, on_eof: &dyn Fn() -> WireFormatError) -> IoResult<ProtocolVersion> {
        let major = self.read_u16(on_eof)?;
        let minor = self.read_u16(on_eof)?;
        Ok(ProtocolVersion::new(major, minor))
    }
    fn read_cstring(&mut self, on_eof: &dyn Fn() -> WireFormatError) -> IoResult<CString>
    where
        Self: BufRead,
    {
        let mut all_buf: Vec<u8> = Vec::new();
        loop {
            let buf = self.fill_buf()?;
            if buf.is_empty() {
                return Err(on_eof().into());
            }

            if let Some(pos) = buf.iter().position(|&b| b == 0) {
                all_buf.extend_from_slice(&buf[..pos + 1]);
                self.consume(pos + 1);
                break;
            } else {
                all_buf.extend_from_slice(buf);
                let len = buf.len();
                self.consume(len);
            }
        }
        Ok(CString::from_vec_with_nul(all_buf).unwrap())
    }
    fn read_sized<T, F>(&mut self, limit: usize, packet_type: ErrorPacketType, f: F) -> IoResult<T>
    where
        F: FnOnce(&mut &[u8]) -> IoResult<T>,
    {
        let length_plus_4 =
            self.read_u32(&|| WireFormatError::IncompletePacketLength { packet_type })? as usize;
        self.read_sized_after_size(length_plus_4, limit, packet_type, f)
    }
    fn read_sized_opt<T, F>(
        &mut self,
        limit: usize,
        packet_type: ErrorPacketType,
        f: F,
    ) -> IoResult<Option<T>>
    where
        F: FnOnce(&mut &[u8]) -> IoResult<T>,
    {
        let Some(length_plus_4) =
            self.read_u32_opt(&|| WireFormatError::IncompletePacketLength { packet_type })?
        else {
            return Ok(None);
        };
        let length_plus_4 = length_plus_4 as usize;
        let result = self.read_sized_after_size(length_plus_4, limit, packet_type, f)?;
        Ok(Some(result))
    }
    fn read_sized_after_size<T, F>(
        &mut self,
        length_plus_4: usize,
        limit: usize,
        packet_type: ErrorPacketType,
        f: F,
    ) -> IoResult<T>
    where
        F: FnOnce(&mut &[u8]) -> IoResult<T>,
    {
        if length_plus_4 < 4 {
            return Err(WireFormatError::NegativePacketLength {
                packet_type,
                length: length_plus_4 as isize - 4,
            }
            .into());
        }
        let length = length_plus_4 - 4;
        if length > limit {
            // `limit` above may be usize::MAX

            return Err(WireFormatError::PacketTooLarge {
                packet_type,
                length,
                max_length: limit,
            }
            .into());
        }

        let mut buf = vec![0u8; length];
        self.read_bytes(&mut buf, &|| WireFormatError::IncompletePacketBody {
            packet_type,
        })?;

        let mut slice: &[u8] = &buf;
        let result = f(&mut slice)?;

        Ok(result)
    }

    fn read_remaining_bytes(&mut self) -> IoResult<Vec<u8>> {
        let mut buf: Vec<u8> = Vec::new();
        self.read_to_end(&mut buf)?;
        Ok(buf)
    }

    fn read_eof(&mut self, on_extra_bytes: &dyn Fn() -> WireFormatError) -> IoResult<()>
    where
        Self: BufRead,
    {
        if !self.read_is_eof()? {
            return Err(on_extra_bytes().into());
        }
        Ok(())
    }

    fn read_is_eof(&mut self) -> IoResult<bool>
    where
        Self: BufRead,
    {
        let buf = self.fill_buf()?;
        if !buf.is_empty() {
            return Ok(false);
        }
        Ok(true)
    }
}

impl<T: Read + ?Sized> ReadWireExt for T {}

/// Validates a parameter passed from caller code.
///
/// Do not use this for validating data received from the network.
pub(crate) fn assert_param<F>(condition: bool, on_error: F) -> IoResult<()>
where
    F: FnOnce() -> String,
{
    if !condition {
        return Err(IoError::new(IoErrorKind::InvalidInput, on_error()));
    }
    Ok(())
}
