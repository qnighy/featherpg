use std::{
    fmt,
    hash::Hash,
    io::{BufRead, Read, Result as IoResult, Write},
    ops::{Deref, DerefMut},
};

#[cfg(feature = "futures")]
mod futures;
#[cfg(feature = "tokio")]
mod tokio;

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

    pub(crate) fn before_fill_buf(&mut self) {
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

    pub(crate) fn spare_capacity_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.end_pos..]
    }

    pub(crate) fn mark_filled(&mut self, num_bytes: usize) {
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

/// A contiguous queue of bytes for reading and writing.
///
/// Like `VecDeque<u8>`, but:
///
/// - The buffer is contiguous in memory.
/// - Append to the back and pop from the front only.
/// - Automatically shrinks when a lot of data has been consumed.
///
/// This queue is deliberately unbounded in size to accommodate large messages.
/// You need to implement your own backpressure mechanism at a higher level
/// in the protocol.
pub(crate) struct ByteQueue {
    buf: Vec<u8>,
    position: usize,
    /// Controls auto-shrinking behavior.
    default_capacity: usize,
}

impl ByteQueue {
    pub(crate) fn new() -> Self {
        Self::with_capacity(1024)
    }

    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
            position: 0,
            default_capacity: capacity,
        }
    }

    /// Appends data to the back of the queue.
    pub(crate) fn extend_from_slice(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Removes `count` bytes from the front of the queue.
    ///
    /// To read data, dereference the queue.
    ///
    /// ## Panics
    ///
    /// Panics if `count` is greater than the current length of the queue.
    pub(crate) fn consume(&mut self, count: usize) {
        assert!(count <= self.len());

        self.position += count;
        self.cleanup();
    }

    /// Cleans up the internal buffer if a lot of data has been consumed.
    fn cleanup(&mut self) {
        if self.position >= self.buf.len() / 2 && self.buf.capacity() > self.default_capacity {
            // Shrink to default capacity if possible.
            self.buf.drain(0..self.position);
            self.position = 0;
            self.buf.shrink_to(self.default_capacity);
        } else if self.position >= self.buf.len() / 2 {
            // Move data to the front without shrinking.
            self.buf.drain(0..self.position);
            self.position = 0;
        }
    }
}

impl Deref for ByteQueue {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.buf[self.position..]
    }
}

impl DerefMut for ByteQueue {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buf[self.position..]
    }
}

impl fmt::Debug for ByteQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <[u8] as fmt::Debug>::fmt(&*self, f)
    }
}

impl Clone for ByteQueue {
    fn clone(&self) -> Self {
        let mut new_queue = Self::with_capacity(self.default_capacity);
        new_queue.extend_from_slice(&*self);
        new_queue
    }
}

impl PartialEq for ByteQueue {
    fn eq(&self, other: &Self) -> bool {
        <[u8] as PartialEq>::eq(&*self, &*other)
    }
}

impl Eq for ByteQueue {}

impl PartialOrd for ByteQueue {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        <[u8] as PartialOrd>::partial_cmp(&*self, &*other)
    }
}

impl Ord for ByteQueue {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        <[u8] as Ord>::cmp(&*self, &*other)
    }
}

impl Hash for ByteQueue {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        <[u8] as Hash>::hash(&*self, state);
    }
}

impl From<Vec<u8>> for ByteQueue {
    fn from(vec: Vec<u8>) -> Self {
        ByteQueue {
            buf: vec,
            position: 0,
            default_capacity: 1024,
        }
    }
}

impl From<&[u8]> for ByteQueue {
    fn from(slice: &[u8]) -> Self {
        ByteQueue {
            buf: slice.to_owned(),
            position: 0,
            default_capacity: 1024,
        }
    }
}

impl From<ByteQueue> for Vec<u8> {
    fn from(mut queue: ByteQueue) -> Self {
        queue.buf.drain(0..queue.position);
        queue.buf
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

    #[test]
    fn test_extend_and_consume() {
        let mut queue = ByteQueue::with_capacity(4);
        queue.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        assert_eq!(&*queue, &[1, 2, 3, 4, 5, 6]);

        queue.consume(4);
        assert_eq!(&*queue, &[5, 6]);
    }

    #[test]
    fn test_convert_consume_convert() {
        let mut queue = ByteQueue::from(b"foobar"[..].to_owned());
        assert_eq!(&*queue, b"foobar");
        queue.consume(3);
        let vec: Vec<u8> = queue.into();
        assert_eq!(&vec, b"bar");
    }
}
