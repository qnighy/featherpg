use std::{
    ffi::{CStr, CString},
    io::{BufRead, Error as IoError, ErrorKind as IoErrorKind, Result as IoResult, Write},
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
    fn write_cstring(&mut self, s: &CStr) -> IoResult<()> {
        self.write_all(s.to_bytes_with_nul())
    }
}

impl<T: Write + ?Sized> WriteWireExt for T {}

pub(crate) struct Scanner<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Scanner<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    pub(crate) fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], EofError> {
        if self.position + count > self.data.len() {
            return Err(EofError);
        }

        let start = self.position;
        self.position += count;
        Ok(&self.data[start..self.position])
    }

    pub(crate) fn read_remaining_bytes(&mut self) -> &'a [u8] {
        let start = self.position;
        self.position = self.data.len();
        &self.data[start..]
    }

    pub(crate) fn read_cstr(&mut self) -> Result<&'a CStr, EofError> {
        let s = CStr::from_bytes_until_nul(&self.data[self.position..]).map_err(|_| EofError)?;
        self.position += s.to_bytes_with_nul().len();
        Ok(s)
    }

    pub(crate) fn read_cstring(&mut self) -> Result<CString, EofError> {
        let s = CStr::from_bytes_until_nul(&self.data[self.position..]).map_err(|_| EofError)?;
        self.position += s.to_bytes_with_nul().len();
        Ok(s.to_owned())
    }

    pub(crate) fn read_u8(&mut self) -> Result<u8, EofError> {
        let bytes = self.read_bytes(1)?;
        Ok(bytes[0])
    }

    pub(crate) fn read_u32(&mut self) -> Result<u32, EofError> {
        let bytes = self.read_bytes(4)?;
        let value = u32::from_be_bytes(bytes.try_into().unwrap());
        Ok(value)
    }

    pub(crate) fn read_version(&mut self) -> Result<ProtocolVersion, EofError> {
        let major_bytes = self.read_bytes(2)?;
        let minor_bytes = self.read_bytes(2)?;

        let major = u16::from_be_bytes(major_bytes.try_into().unwrap());
        let minor = u16::from_be_bytes(minor_bytes.try_into().unwrap());

        Ok(ProtocolVersion { major, minor })
    }

    pub(crate) fn read_eof(&self) -> Result<(), ExtraByteError> {
        if self.position < self.data.len() {
            return Err(ExtraByteError);
        }
        Ok(())
    }
}

pub(crate) fn read_streamed<R, T, E, F>(reader: &mut R, mut f: F) -> IoResult<T>
where
    R: BufRead + ?Sized,
    F: FnMut(&mut StreamScanner<'_>) -> Result<T, StreamError<E>>,
    E: Into<IoError>,
{
    let mut last_len = 0;
    let mut last_demand = 1;

    // First loop: use the built-in buffer of the BufRead
    loop {
        let buf = reader.fill_buf()?;
        if buf.len() <= last_len {
            break;
        }

        let mut scanner = StreamScanner::new_prefix(buf);
        match f(&mut scanner) {
            Ok(value) => {
                let consumed = scanner.consumed();
                reader.consume(consumed);
                return Ok(value);
            }
            Err(StreamError::MoreDataNeeded { needed }) => {
                last_len = buf.len();
                last_demand = scanner.consumed() + needed;
                continue;
            }
            Err(StreamError::Other(e)) => {
                return Err(e.into());
            }
        }
    }

    // Second loop: allocate our own buffer and read into it
    let mut buffer: Vec<u8> = vec![0; last_demand];
    let mut pos = 0;
    'outer: loop {
        while pos < buffer.len() {
            let n = reader.read(&mut buffer[pos..])?;
            if n == 0 {
                break 'outer;
            }
            pos += n;
        }

        let mut scanner = StreamScanner::new_prefix(&buffer[..pos]);
        match f(&mut scanner) {
            Ok(value) => {
                // It should have consumed pos bytes (= buffer.len() bytes)
                return Ok(value);
            }
            Err(StreamError::MoreDataNeeded { needed }) => {
                buffer.resize(pos + needed, 0);
                continue;
            }
            Err(StreamError::Other(e)) => {
                return Err(e.into());
            }
        }
    }

    // Final attempt at EOF
    let mut scanner = StreamScanner::new_all(&buffer[..pos]);
    match f(&mut scanner) {
        Ok(value) => {
            return Ok(value);
        }
        Err(StreamError::MoreDataNeeded { .. }) => {
            return Err(IoError::new(
                IoErrorKind::UnexpectedEof,
                "unexpected end of stream",
            ));
        }
        Err(StreamError::Other(e)) => {
            return Err(e.into());
        }
    }
}

pub(crate) struct StreamScanner<'a> {
    data: &'a [u8],
    position: usize,
    is_eof: bool,
}

impl<'a> StreamScanner<'a> {
    pub(crate) fn new_prefix(data: &'a [u8]) -> Self {
        Self {
            data,
            position: 0,
            is_eof: false,
        }
    }

    pub(crate) fn new_all(data: &'a [u8]) -> Self {
        Self {
            data,
            position: 0,
            is_eof: true,
        }
    }

    pub(crate) fn consumed(&self) -> usize {
        self.position
    }

    pub(crate) fn reserve_bytes(&mut self, count: usize) -> Result<(), StreamError<EofError>> {
        if self.position + count > self.data.len() {
            if self.is_eof {
                return Err(EofError.into());
            } else {
                return Err(StreamError::MoreDataNeeded {
                    needed: self.position + count - self.data.len(),
                });
            }
        }

        Ok(())
    }

    pub(super) fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], StreamError<EofError>> {
        self.reserve_bytes(count)?;

        let start = self.position;
        self.position += count;
        Ok(&self.data[start..self.position])
    }

    pub(crate) fn read_u32(&mut self) -> Result<u32, StreamError<EofError>> {
        let bytes = self.read_bytes(4)?;
        let value = u32::from_be_bytes(bytes.try_into().unwrap());
        Ok(value)
    }
}

#[derive(Debug, Error)]
#[error("end of file reached before completing read")]
pub(crate) struct EofError;

#[derive(Debug, Error)]
pub(crate) enum StreamError<E> {
    #[error("more data needed to complete read")]
    MoreDataNeeded { needed: usize },
    #[error(transparent)]
    Other(#[from] E),
}

impl<E> StreamError<E> {
    pub(crate) fn map<F, O>(self, f: F) -> StreamError<O>
    where
        F: FnOnce(E) -> O,
    {
        match self {
            StreamError::MoreDataNeeded { needed } => StreamError::MoreDataNeeded { needed },
            StreamError::Other(e) => StreamError::Other(f(e)),
        }
    }
}

#[derive(Debug, Error)]
#[error("extra bytes found where none were expected")]
pub(crate) struct ExtraByteError;

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
