use std::{
    fmt,
    io::{
        BufRead, BufReader, BufWriter, Error as IoError, IoSlice, IoSliceMut, Read,
        Result as IoResult, Seek, SeekFrom, Write, WriterPanicked,
    },
};

use thiserror::Error;

use crate::common::GetReadBuf;

/// BufReader and BufWriter, combined into a single type.
pub(crate) struct BufReaderWriter<S>
where
    S: Write + ?Sized,
{
    inner: BufWriter<BufReaderWrapper<S>>,
}

impl<S> BufReaderWriter<S>
where
    S: Read + Write,
{
    pub(crate) fn new(inner: S) -> Self {
        Self {
            inner: BufWriter::new(BufReaderWrapper::new(inner)),
        }
    }

    pub(crate) fn with_read_capacity(read_capacity: usize, inner: S) -> Self {
        Self {
            inner: BufWriter::new(BufReaderWrapper::with_capacity(read_capacity, inner)),
        }
    }

    pub(crate) fn with_write_capacity(write_capacity: usize, inner: S) -> Self {
        Self {
            inner: BufWriter::with_capacity(write_capacity, BufReaderWrapper::new(inner)),
        }
    }

    pub(crate) fn with_read_write_capacity(
        read_capacity: usize,
        write_capacity: usize,
        inner: S,
    ) -> Self {
        Self {
            inner: BufWriter::with_capacity(
                write_capacity,
                BufReaderWrapper::with_capacity(read_capacity, inner),
            ),
        }
    }

    pub(crate) fn into_inner(self) -> Result<S, IntoInnerError<BufReaderWriter<S>>> {
        match self.inner.into_inner() {
            Ok(buf_reader) => Ok(buf_reader.into_inner()),
            Err(e) => {
                let (error, inner) = e.into_parts();
                Err(IntoInnerError {
                    inner: BufReaderWriter { inner },
                    error,
                })
            }
        }
    }

    pub(crate) fn into_parts(self) -> (S, Result<Vec<u8>, WriterPanicked>) {
        let (reader, writer_buf) = self.inner.into_parts();
        (reader.into_inner(), writer_buf)
    }
}

impl<S> BufReaderWriter<S>
where
    S: Read + Write + ?Sized,
{
    pub(crate) fn get_ref(&self) -> &S {
        self.inner.get_ref().get_ref()
    }

    pub(crate) fn get_mut(&mut self) -> &mut S {
        self.inner.get_mut().get_mut()
    }

    pub(crate) fn read_buffer(&self) -> &[u8] {
        self.inner.get_ref().buffer()
    }

    pub(crate) fn read_capacity(&self) -> usize {
        self.inner.get_ref().capacity()
    }

    pub(crate) fn write_buffer(&self) -> &[u8] {
        self.inner.buffer()
    }

    pub(crate) fn write_capacity(&self) -> usize {
        self.inner.capacity()
    }
}

impl<S> fmt::Debug for BufReaderWriter<S>
where
    S: fmt::Debug + Write + ?Sized,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <BufWriter<BufReaderWrapper<S>> as fmt::Debug>::fmt(&self.inner, f)
    }
}

impl<S> Read for BufReaderWriter<S>
where
    S: Read + Write + ?Sized,
{
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.inner.get_mut().read(buf)
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> IoResult<usize> {
        self.inner.get_mut().read_vectored(bufs)
    }

    // fn is_read_vectored(&self) -> bool {
    //     self.inner.get_ref().is_read_vectored()
    // }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> IoResult<usize> {
        self.inner.get_mut().read_to_end(buf)
    }

    fn read_to_string(&mut self, buf: &mut String) -> IoResult<usize> {
        self.inner.get_mut().read_to_string(buf)
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> IoResult<()> {
        self.inner.get_mut().read_exact(buf)
    }

    // fn read_buf(&mut self, buf: BorrowedCursor<'_>) -> IoResult<()> {
    //     self.inner.get_mut().read_buf(buf)
    // }

    // fn read_buf_exact(&mut self, cursor: BorrowedCursor<'_>) -> IoResult<()> {
    //     self.inner.get_mut().read_buf_exact(cursor)
    // }
}

impl<S> BufRead for BufReaderWriter<S>
where
    S: Read + Write + ?Sized,
{
    fn fill_buf(&mut self) -> IoResult<&[u8]> {
        self.inner.get_mut().fill_buf()
    }

    fn consume(&mut self, amount: usize) {
        self.inner.get_mut().consume(amount);
    }

    // fn has_data_left(&mut self) -> IoResult<bool> {
    //     self.inner.get_mut().has_data_left()
    // }

    fn read_until(&mut self, byte: u8, buf: &mut Vec<u8>) -> IoResult<usize> {
        self.inner.get_mut().read_until(byte, buf)
    }

    fn skip_until(&mut self, byte: u8) -> IoResult<usize> {
        self.inner.get_mut().skip_until(byte)
    }

    fn read_line(&mut self, buf: &mut String) -> IoResult<usize> {
        self.inner.get_mut().read_line(buf)
    }
}

impl<S> GetReadBuf for BufReaderWriter<S>
where
    S: Read + Write + ?Sized,
{
    fn read_buffer(&self) -> &[u8] {
        self.inner.get_ref().read_buffer()
    }
}

impl<S> Write for BufReaderWriter<S>
where
    S: Write + ?Sized,
{
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        self.inner.flush()
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> IoResult<usize> {
        self.inner.write_vectored(bufs)
    }

    // fn is_write_vectored(&self) -> bool {
    //     self.inner.is_write_vectored()
    // }

    fn write_all(&mut self, buf: &[u8]) -> IoResult<()> {
        self.inner.write_all(buf)
    }

    // fn write_all_vectored(&mut self, bufs: &mut [IoSlice<'_>]) -> IoResult<()> {
    //     self.inner.write_all_vectored(bufs)
    // }

    fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> IoResult<()> {
        self.inner.write_fmt(args)
    }
}

impl<S> Seek for BufReaderWriter<S>
where
    S: Seek + Write + ?Sized,
{
    fn seek(&mut self, pos: SeekFrom) -> IoResult<u64> {
        self.inner.seek(pos)
    }

    fn rewind(&mut self) -> IoResult<()> {
        self.inner.rewind()
    }

    // fn stream_len(&mut self) -> IoResult<u64> {
    //     self.inner.stream_len()
    // }

    fn stream_position(&mut self) -> IoResult<u64> {
        self.inner.stream_position()
    }

    fn seek_relative(&mut self, offset: i64) -> IoResult<()> {
        self.inner.seek_relative(offset)
    }
}

#[derive(Debug, Error)]
#[error("{}", error)]
pub(crate) struct IntoInnerError<S> {
    pub(crate) error: IoError,
    pub(crate) inner: S,
}

pub(crate) struct BufReaderWrapper<S: ?Sized> {
    inner: BufReader<S>,
}

impl<S> BufReaderWrapper<S>
where
    S: Read,
{
    pub(crate) fn new(inner: S) -> Self {
        Self {
            inner: BufReader::new(inner),
        }
    }

    pub(crate) fn with_capacity(capacity: usize, inner: S) -> Self {
        Self {
            inner: BufReader::with_capacity(capacity, inner),
        }
    }
}

// impl<S> BufReaderWrapper<S>
// where
//     S: Read + ?Sized,
// {
//     pub(crate) fn peek(&mut self, n: usize) -> IoResult<&[u8]> {
//         self.inner.peek(n)
//     }
// }

impl<S: ?Sized> BufReaderWrapper<S> {
    pub(crate) fn get_ref(&self) -> &S {
        self.inner.get_ref()
    }

    pub(crate) fn get_mut(&mut self) -> &mut S {
        self.inner.get_mut()
    }

    pub(crate) fn buffer(&self) -> &[u8] {
        self.inner.buffer()
    }

    pub(crate) fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    pub(crate) fn into_inner(self) -> S
    where
        S: Sized,
    {
        self.inner.into_inner()
    }
}

impl<S> fmt::Debug for BufReaderWrapper<S>
where
    S: fmt::Debug + ?Sized,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <BufReader<S> as fmt::Debug>::fmt(&self.inner, f)
    }
}

impl<S> Read for BufReaderWrapper<S>
where
    S: Read + ?Sized,
{
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.inner.read(buf)
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> IoResult<usize> {
        self.inner.read_vectored(bufs)
    }

    // fn is_read_vectored(&self) -> bool {
    //     self.inner.is_read_vectored()
    // }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> IoResult<usize> {
        self.inner.read_to_end(buf)
    }

    fn read_to_string(&mut self, buf: &mut String) -> IoResult<usize> {
        self.inner.read_to_string(buf)
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> IoResult<()> {
        self.inner.read_exact(buf)
    }

    // fn read_buf(&mut self, buf: BorrowedCursor<'_>) -> IoResult<()> {
    //     self.inner.read_buf(buf)
    // }

    // fn read_buf_exact(&mut self, cursor: BorrowedCursor<'_>) -> IoResult<()> {
    //     self.inner.read_buf_exact(cursor)
    // }
}

impl<S> BufRead for BufReaderWrapper<S>
where
    S: Read + ?Sized,
{
    fn fill_buf(&mut self) -> IoResult<&[u8]> {
        self.inner.fill_buf()
    }

    fn consume(&mut self, amount: usize) {
        self.inner.consume(amount);
    }

    // fn has_data_left(&mut self) -> IoResult<bool> {
    //     self.inner.has_data_left()
    // }

    fn read_until(&mut self, byte: u8, buf: &mut Vec<u8>) -> IoResult<usize> {
        self.inner.read_until(byte, buf)
    }

    fn skip_until(&mut self, byte: u8) -> IoResult<usize> {
        self.inner.skip_until(byte)
    }

    fn read_line(&mut self, buf: &mut String) -> IoResult<usize> {
        self.inner.read_line(buf)
    }
}

impl<S> GetReadBuf for BufReaderWrapper<S>
where
    S: Read + ?Sized,
{
    fn read_buffer(&self) -> &[u8] {
        self.inner.buffer()
    }
}

impl<S> Write for BufReaderWrapper<S>
where
    S: Write + ?Sized,
{
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.inner.get_mut().write(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        self.inner.get_mut().flush()
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> IoResult<usize> {
        self.inner.get_mut().write_vectored(bufs)
    }

    // fn is_write_vectored(&self) -> bool {
    //     self.inner.get_ref().is_write_vectored()
    // }

    fn write_all(&mut self, buf: &[u8]) -> IoResult<()> {
        self.inner.get_mut().write_all(buf)
    }

    // fn write_all_vectored(&mut self, bufs: &mut [IoSlice<'_>]) -> IoResult<()> {
    //     self.inner.get_mut().write_all_vectored(bufs)
    // }

    fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> IoResult<()> {
        self.inner.get_mut().write_fmt(args)
    }
}

impl<S> Seek for BufReaderWrapper<S>
where
    S: Seek + ?Sized,
{
    fn seek(&mut self, pos: SeekFrom) -> IoResult<u64> {
        self.inner.seek(pos)
    }

    fn rewind(&mut self) -> IoResult<()> {
        self.inner.rewind()
    }

    // fn stream_len(&mut self) -> IoResult<u64> {
    //     self.inner.stream_len()
    // }

    fn stream_position(&mut self) -> IoResult<u64> {
        self.inner.stream_position()
    }

    fn seek_relative(&mut self, offset: i64) -> IoResult<()> {
        self.inner.seek_relative(offset)
    }
}
