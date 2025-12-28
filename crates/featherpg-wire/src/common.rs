// Public API for both server and client

use std::{
    fmt,
    io::{self, BufRead, IoSlice, IoSliceMut, Read, Write},
};

/// A stream equipped with previous data that was not consumed.
///
/// Roughly equivalent to `Chain<Cursor<Vec<u8>>, S>`, but:
///
/// - Implements Write, forwarding it to the underlying stream.
/// - Simplifies the buffer as the carried data is expected to be small.
#[derive(Debug)]
pub struct CarriedStream<S> {
    pub carried: Vec<u8>,
    pub stream: S,
}

impl<S> CarriedStream<S> {
    fn read_carried(&mut self, buf: &mut [u8]) -> usize {
        if buf.len() >= self.carried.len() {
            let len = self.carried.len();
            buf[..len].copy_from_slice(&self.carried);
            // Deallocate the buffer altogether
            self.carried = Vec::new();
            len
        } else {
            let len = buf.len();
            buf.copy_from_slice(&self.carried[..len]);
            self.carried.drain(..len);
            len
        }
    }
}

impl<S: Read> Read for CarriedStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.carried.is_empty() {
            let result = self.read_carried(buf);
            return Ok(result);
        }
        self.stream.read(buf)
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        if !self.carried.is_empty() {
            let buf = bufs
                .iter_mut()
                .find(|b| !b.is_empty())
                .map_or(&mut [][..], |b| &mut **b);
            return self.read(buf);
        }
        self.stream.read_vectored(bufs)
    }

    // fn is_read_vectored(&self) -> bool {
    //     self.stream.is_read_vectored()
    // }
}

impl<S: BufRead> BufRead for CarriedStream<S> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if !self.carried.is_empty() {
            return Ok(&self.carried);
        }
        self.stream.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        if !self.carried.is_empty() {
            // We can assume amt <= carried.len()
            if amt >= self.carried.len() {
                self.carried = Vec::new();
            } else {
                self.carried.drain(..amt);
            }
            return;
        }
        self.stream.consume(amt);
    }
}

impl<S: Write> Write for CarriedStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.stream.write_vectored(bufs)
    }

    // fn is_write_vectored(&self) -> bool {
    //     self.stream.is_write_vectored()
    // }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.stream.write_all(buf)
    }

    // fn write_all_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<()> {
    //     self.stream.write_all_vectored(bufs)
    // }

    fn write_fmt(&mut self, fmt: fmt::Arguments<'_>) -> io::Result<()> {
        self.stream.write_fmt(fmt)
    }
}
