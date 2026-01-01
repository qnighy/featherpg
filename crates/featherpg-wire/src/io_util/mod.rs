use std::{
    fmt,
    io::{
        BufRead, BufReader, BufWriter, Error as IoError, IoSlice, IoSliceMut, Read,
        Result as IoResult, Seek, SeekFrom, Write, WriterPanicked,
    },
};

use thiserror::Error;

#[cfg(feature = "futures")]
mod futures;
#[cfg(feature = "tokio")]
mod tokio;

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

/// A buffer for reading, such as BufReader, but which can grow as needed.
#[derive(Debug)]
pub(crate) struct GrowableBuffer {
    // Always buf.len() == buf.capacity().
    // Therefore it is technically Box<[u8]> but Vec<u8> is easier to work with.
    buf: Vec<u8>,
    start_pos: usize,
    end_pos: usize,
    unit_size: usize,
}

impl GrowableBuffer {
    pub(crate) fn new() -> Self {
        Self::with_unit_size(8192)
    }

    /// Creates a new GrowableBuffer with the specified unit size.
    ///
    /// The unit size controls how much data is read at a time
    /// from the underlying reader.
    pub(crate) fn with_unit_size(unit_size: usize) -> Self {
        Self {
            buf: vec![0; unit_size * 2],
            start_pos: 0,
            end_pos: 0,
            unit_size,
        }
    }

    pub(crate) fn read<R>(&mut self, reader: &mut R, buf: &mut [u8]) -> IoResult<usize>
    where
        R: Read + ?Sized,
    {
        if self.buffer().is_empty() {
            self.fill_buf(reader)?;
        }
        let num_read = buf.len().min(self.buffer().len());
        buf[..num_read].copy_from_slice(&self.buffer()[..num_read]);
        self.consume(num_read);
        Ok(num_read)
    }

    pub(crate) fn fill_buf<R>(&mut self, reader: &mut R) -> IoResult<&[u8]>
    where
        R: Read + ?Sized,
    {
        self.before_fill_buf();

        let num_read = reader.read(self.spare_capacity_mut())?;
        self.mark_filled(num_read);

        Ok(self.buffer())
    }

    fn before_fill_buf(&mut self) {
        if self.start_pos > 0 {
            self.buf.copy_within(self.start_pos..self.end_pos, 0);
            self.end_pos -= self.start_pos;
            self.start_pos = 0;

            if self.buf.len() > self.unit_size * 4 {
                self.buf.truncate(self.unit_size * 2);
                self.buf.shrink_to_fit();
            }
        }

        self.reserve(self.unit_size);
    }

    fn spare_capacity_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.end_pos..]
    }

    fn mark_filled(&mut self, num_bytes: usize) {
        self.end_pos += num_bytes;
    }

    /// Consumes `count` bytes from the front of the buffer.
    pub(crate) fn consume(&mut self, count: usize) {
        assert!(self.start_pos + count <= self.end_pos);
        self.start_pos += count;
    }

    /// Returns the contents of the buffer that have not yet been consumed.
    pub(crate) fn buffer(&self) -> &[u8] {
        &self.buf[self.start_pos..self.end_pos]
    }

    /// Returns the contents of the buffer, reusing the internal buffer.
    pub(crate) fn into_buffer(self) -> Vec<u8> {
        let mut buf = self.buf;
        buf.truncate(self.end_pos);
        buf.drain(0..self.start_pos);
        buf
    }

    fn reserve(&mut self, additional: usize) {
        if self.end_pos + additional <= self.buf.len() {
            return;
        }

        let new_cap = (self.end_pos + additional).max(self.buf.len() * 2);

        self.buf.reserve_exact(new_cap - self.buf.len());
        self.buf.resize(self.buf.capacity(), 0);
    }
}

impl From<Vec<u8>> for GrowableBuffer {
    fn from(mut vec: Vec<u8>) -> Self {
        let end_pos = vec.len();
        vec.resize(vec.capacity(), 0);
        GrowableBuffer {
            buf: vec,
            start_pos: 0,
            end_pos,
            unit_size: 8192,
        }
    }
}

impl From<GrowableBuffer> for Vec<u8> {
    fn from(buffer: GrowableBuffer) -> Self {
        buffer.into_buffer()
    }
}

/// A buffer for writing, such as BufWriter, but can be managed independently
/// of an underlying writer.
#[derive(Debug)]
pub(crate) struct WriteBuffer {
    buf: Vec<u8>,
}

impl WriteBuffer {
    pub(crate) fn new() -> Self {
        Self::with_capacity(8192)
    }

    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    pub(crate) fn write<W>(&mut self, writer: &mut W, data: &[u8]) -> IoResult<usize>
    where
        W: Write + ?Sized,
    {
        if data.len() < self.spare_capacity() {
            self.buf.extend_from_slice(data);
            Ok(data.len())
        } else {
            self.write_cold(writer, data)
        }
    }

    #[inline(never)]
    fn write_cold<W>(&mut self, writer: &mut W, data: &[u8]) -> IoResult<usize>
    where
        W: Write + ?Sized,
    {
        if data.len() > self.spare_capacity() {
            self.flush_buf(writer)?;
        }

        if data.len() >= self.buf.capacity() {
            // Write directly to the underlying writer.
            writer.write(data)
        } else {
            self.buf.extend_from_slice(data);
            Ok(data.len())
        }
    }

    pub(crate) fn write_all<W>(&mut self, writer: &mut W, data: &[u8]) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        if data.len() < self.spare_capacity() {
            self.buf.extend_from_slice(data);
            Ok(())
        } else {
            self.write_all_cold(writer, data)
        }
    }

    #[inline(never)]
    fn write_all_cold<W>(&mut self, writer: &mut W, data: &[u8]) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        if data.len() > self.spare_capacity() {
            self.flush_buf(writer)?;
        }

        if data.len() >= self.buf.capacity() {
            // Write directly to the underlying writer.
            writer.write_all(data)
        } else {
            self.buf.extend_from_slice(data);
            Ok(())
        }
    }

    fn spare_capacity(&self) -> usize {
        self.buf.capacity() - self.buf.len()
    }

    fn flush_buf<W>(&mut self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        writer.write_all(&self.buf)?;
        self.buf.clear();
        Ok(())
    }

    fn flush<W>(&mut self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        self.flush_buf(writer)?;
        writer.flush()?;
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct BufStream<S: ?Sized> {
    read_buf: GrowableBuffer,
    write_buf: WriteBuffer,
    stream: S,
}

impl<S: ?Sized> BufStream<S> {
    pub(crate) fn new(stream: S) -> Self
    where
        S: Sized,
    {
        Self {
            read_buf: GrowableBuffer::new(),
            write_buf: WriteBuffer::new(),
            stream,
        }
    }

    pub(crate) fn get_ref(&self) -> &S {
        &self.stream
    }

    pub(crate) fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub(crate) fn into_parts(self) -> (S, GrowableBuffer, WriteBuffer)
    where
        S: Sized,
    {
        (self.stream, self.read_buf, self.write_buf)
    }

    pub(crate) fn read_buffer(&self) -> &[u8] {
        self.read_buf.buffer()
    }
}

impl<S> Read for BufStream<S>
where
    S: Read + ?Sized,
{
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.read_buf.read(&mut self.stream, buf)
    }
}

impl<S> BufRead for BufStream<S>
where
    S: Read + ?Sized,
{
    fn fill_buf(&mut self) -> IoResult<&[u8]> {
        self.read_buf.fill_buf(&mut self.stream)
    }

    fn consume(&mut self, amt: usize) {
        self.read_buf.consume(amt);
    }
}

impl<S> Write for BufStream<S>
where
    S: Write + ?Sized,
{
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.write_buf.write(&mut self.stream, buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        self.write_buf.flush(&mut self.stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_growable_buffer() {
        let mut buffer = GrowableBuffer::with_unit_size(4);

        // Using Chain to simulate a reader with multiple reads
        let mut reader = b"Hello, world!\n"[..]
            .chain(&b"Next line\n"[..])
            .chain(&b"Final line\n"[..]);

        let current = buffer.fill_buf(&mut reader).unwrap();
        // Read of two units
        assert_eq!(current, b"Hello, w");

        buffer.consume(b"Hello, ".len());
        assert_eq!(buffer.buffer(), b"w");

        // Enough capacity. Read to the next boundary.
        let current = buffer.fill_buf(&mut reader).unwrap();
        assert_eq!(current, b"world!\n");

        buffer.consume(b"world!\n".len());
        assert_eq!(buffer.buffer(), b"");

        let current = buffer.fill_buf(&mut reader).unwrap();
        assert_eq!(current, b"Next lin");
        // Extends the buffer and reads more.
        let current = buffer.fill_buf(&mut reader).unwrap();
        assert_eq!(current, b"Next line\n");

        let current = buffer.fill_buf(&mut reader).unwrap();
        // Still not enough capacity (four units)
        assert_eq!(current, b"Next line\nFinal ");
        let current = buffer.fill_buf(&mut reader).unwrap();
        assert_eq!(current, b"Next line\nFinal line\n");

        buffer.consume(b"Next line\nFinal line\n".len());
        assert_eq!(buffer.buffer(), b"");
    }
}
