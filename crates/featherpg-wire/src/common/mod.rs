// Public API for both server and client

use std::{
    fmt,
    io::{BufRead, BufReader, Cursor, IoSlice, IoSliceMut, Read, Result as IoResult, Write},
    ops::{Deref, DerefMut},
};

#[cfg(any(feature = "futures", feature = "tokio"))]
use pin_project::pin_project;

#[cfg(feature = "futures")]
mod futures;
#[cfg(feature = "tokio")]
mod tokio;

// See: https://internals.rust-lang.org/t/add-bufwriter-bufreader-buffer-to-bufread-trait/13668
/// Like [std::io::BufRead], but exposes the internal read buffer.
pub trait GetReadBuf: BufRead {
    /// Returns the internal read buffer, like [std::io::BufReader::buffer].
    fn read_buffer(&self) -> &[u8];
}

impl GetReadBuf for &[u8] {
    fn read_buffer(&self) -> &[u8] {
        self
    }
}

impl GetReadBuf for std::io::Empty {
    fn read_buffer(&self) -> &[u8] {
        &[]
    }
}

impl<R> GetReadBuf for &mut R
where
    R: GetReadBuf + ?Sized,
{
    fn read_buffer(&self) -> &[u8] {
        <R as GetReadBuf>::read_buffer(self)
    }
}

impl<R> GetReadBuf for Box<R>
where
    R: GetReadBuf + ?Sized,
{
    fn read_buffer(&self) -> &[u8] {
        <R as GetReadBuf>::read_buffer(self)
    }
}

impl<R> GetReadBuf for BufReader<R>
where
    R: Read,
{
    fn read_buffer(&self) -> &[u8] {
        self.buffer()
    }
}

impl<R> GetReadBuf for Cursor<R>
where
    R: AsRef<[u8]>,
{
    fn read_buffer(&self) -> &[u8] {
        let slice = self.get_ref().as_ref();
        let pos = self.position().min(slice.len() as u64);
        &slice[pos as usize..]
    }
}

impl<R> GetReadBuf for std::io::Take<R>
where
    R: GetReadBuf,
{
    fn read_buffer(&self) -> &[u8] {
        if self.limit() == 0 {
            return &[];
        }

        let buf = self.get_ref().read_buffer();
        let cap = (buf.len() as u64).min(self.limit()) as usize;
        &buf[..cap]
    }
}

/// A stream for reading from Vec<u8>.
///
/// Roughly equivalent to `Cursor<Vec<u8>>`, but:
///
/// - Frees the buffer when all data is consumed.
pub struct BytesReader {
    bytes: Vec<u8>,
    pos: usize,
}

impl From<Vec<u8>> for BytesReader {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes, pos: 0 }
    }
}

impl From<&[u8]> for BytesReader {
    fn from(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_owned(),
            pos: 0,
        }
    }
}

impl From<BytesReader> for Vec<u8> {
    fn from(reader: BytesReader) -> Self {
        let mut vec = reader.bytes;
        vec.drain(..reader.pos);
        vec
    }
}

impl Deref for BytesReader {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes[self.pos..]
    }
}

impl DerefMut for BytesReader {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes[self.pos..]
    }
}

impl fmt::Debug for BytesReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <[u8] as fmt::Debug>::fmt(self, f)
    }
}

impl Clone for BytesReader {
    fn clone(&self) -> Self {
        Self::from(self as &[u8])
    }
}

impl Read for BytesReader {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.do_borrowed(|this| this.read(buf))
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> IoResult<usize> {
        self.do_borrowed(|this| this.read_vectored(bufs))
    }
}

impl BufRead for BytesReader {
    fn fill_buf(&mut self) -> IoResult<&[u8]> {
        Ok(self)
    }

    fn consume(&mut self, amt: usize) {
        self.do_borrowed(|this| this.consume(amt));
    }
}

impl GetReadBuf for BytesReader {
    fn read_buffer(&self) -> &[u8] {
        &self
    }
}

impl BytesReader {
    fn do_borrowed<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut &[u8]) -> R,
    {
        let mut inner = self as &[u8];
        let result = f(&mut inner);

        self.truncate_front(inner.len());
        result
    }

    fn truncate_front(&mut self, new_len: usize) {
        self.pos = self.pos.max(self.bytes.len().saturating_sub(new_len));
        self.cleanup();
    }

    fn cleanup(&mut self) {
        if self.pos >= self.bytes.len() {
            // Free the buffer
            self.bytes = Vec::new();
            self.pos = 0;
        }
    }
}

/// A stream equipped with previous data that was not consumed.
///
/// Roughly equivalent to `Chain<Cursor<Vec<u8>>, S>`, but:
///
/// - Implements Write, forwarding it to the underlying stream.
#[derive(Debug)]
#[cfg_attr(any(feature = "futures", feature = "tokio"), pin_project)]
pub struct WithExcess<S> {
    pub excess_read: BytesReader,
    #[cfg_attr(any(feature = "futures", feature = "tokio"), pin)]
    pub stream: S,
}

impl<S: Read> Read for WithExcess<S> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        if !self.excess_read.is_empty() {
            self.excess_read.read(buf)
        } else {
            self.stream.read(buf)
        }
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> IoResult<usize> {
        if !self.excess_read.is_empty() {
            self.excess_read.read_vectored(bufs)
        } else {
            self.stream.read_vectored(bufs)
        }
    }

    // fn is_read_vectored(&self) -> bool {
    //     self.stream.is_read_vectored()
    // }
}

impl<S: BufRead> BufRead for WithExcess<S> {
    fn fill_buf(&mut self) -> IoResult<&[u8]> {
        if !self.excess_read.is_empty() {
            self.excess_read.fill_buf()
        } else {
            self.stream.fill_buf()
        }
    }

    fn consume(&mut self, amt: usize) {
        if !self.excess_read.is_empty() {
            self.excess_read.consume(amt);
        } else {
            self.stream.consume(amt);
        }
    }
}

impl<S: GetReadBuf> GetReadBuf for WithExcess<S> {
    fn read_buffer(&self) -> &[u8] {
        if !self.excess_read.is_empty() {
            self.excess_read.read_buffer()
        } else {
            self.stream.read_buffer()
        }
    }
}

impl<S: Write> Write for WithExcess<S> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        self.stream.flush()
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> IoResult<usize> {
        self.stream.write_vectored(bufs)
    }

    // fn is_write_vectored(&self) -> bool {
    //     self.stream.is_write_vectored()
    // }

    fn write_all(&mut self, buf: &[u8]) -> IoResult<()> {
        self.stream.write_all(buf)
    }

    // fn write_all_vectored(&mut self, bufs: &[IoSlice<'_>]) -> IoResult<()> {
    //     self.stream.write_all_vectored(bufs)
    // }

    fn write_fmt(&mut self, fmt: fmt::Arguments<'_>) -> IoResult<()> {
        self.stream.write_fmt(fmt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_reader_read_simple() {
        let mut reader = BytesReader::from(&b"hello"[..]);

        let mut buf = vec![0u8; 3];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hel");
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"lo");
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"");
    }

    #[test]
    fn test_bytes_reader_bufread() {
        let mut reader = BytesReader::from(&b"hello"[..]);

        let buf = reader.fill_buf().unwrap();
        assert_eq!(buf, b"hello");
        reader.consume(3);
        let buf = reader.fill_buf().unwrap();
        assert_eq!(buf, b"lo");
        reader.consume(2);
        let buf = reader.fill_buf().unwrap();
        assert_eq!(buf, b"");
    }

    #[test]
    fn test_with_excess_read() {
        let mut stream = WithExcess {
            excess_read: BytesReader::from(&b"excess"[..]),
            stream: BytesReader::from(&b"stream"[..]),
        };

        let mut buf = vec![0u8; 4];
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"exce");
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ss");
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"stre");
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"am");
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"");
    }

    #[test]
    fn test_with_excess_read_to_end() {
        let mut stream = WithExcess {
            excess_read: BytesReader::from(&b"excess"[..]),
            stream: BytesReader::from(&b"stream"[..]),
        };

        let mut all = Vec::new();
        stream.read_to_end(&mut all).unwrap();
        assert_eq!(&all[..], b"excessstream");
    }

    #[test]
    fn test_with_excess_bufread() {
        let mut stream = WithExcess {
            excess_read: BytesReader::from(&b"excess"[..]),
            stream: BytesReader::from(&b"stream"[..]),
        };

        let buf = stream.fill_buf().unwrap();
        assert_eq!(buf, b"excess");
        stream.consume(4);
        let buf = stream.fill_buf().unwrap();
        assert_eq!(buf, b"ss");
        stream.consume(2);
        let buf = stream.fill_buf().unwrap();
        assert_eq!(buf, b"stream");
        stream.consume(6);
        let buf = stream.fill_buf().unwrap();
        assert_eq!(buf, b"");
    }
}
