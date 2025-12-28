use std::ops::{Deref, DerefMut};

/// A contiguous queue of bytes for reading and writing.
///
/// Like `VecDeque<u8>`, but:
///
/// - The buffer is contiguous in memory.
/// - Append to the back and pop from the front only.
/// - Automatically shrinks when a lot of data has been consumed.
pub(in crate::wire) struct ByteQueue {
    buf: Vec<u8>,
    position: usize,
    /// Controls auto-shrinking behavior.
    default_capacity: usize,
}

impl ByteQueue {
    pub(in crate::wire) fn new() -> Self {
        Self::with_capacity(1024)
    }

    pub(in crate::wire) fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
            position: 0,
            default_capacity: capacity,
        }
    }

    /// Appends data to the back of the queue.
    pub(in crate::wire) fn extend_from_slice(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Removes `count` bytes from the front of the queue.
    ///
    /// To read data, dereference the queue.
    ///
    /// ## Panics
    ///
    /// Panics if `count` is greater than the current length of the queue.
    pub(in crate::wire) fn consume(&mut self, count: usize) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extend_and_consume() {
        let mut queue = ByteQueue::with_capacity(4);
        queue.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        assert_eq!(&*queue, &[1, 2, 3, 4, 5, 6]);

        queue.consume(4);
        assert_eq!(&*queue, &[5, 6]);
    }
}
