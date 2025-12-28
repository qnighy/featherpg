// Public API for both server and client

use std::{
    fmt,
    io::{self, BufRead, IoSlice, IoSliceMut, Read, Write},
};
#[cfg(any(feature = "futures", feature = "tokio"))]
use std::{
    pin::Pin,
    task::{Context, Poll},
};

#[cfg(feature = "futures")]
use futures::io::{
    AsyncBufRead as FuturesAsyncBufRead, AsyncRead as FuturesAsyncRead,
    AsyncWrite as FuturesAsyncWrite,
};
#[cfg(any(feature = "futures", feature = "tokio"))]
use pin_project::pin_project;
#[cfg(feature = "tokio")]
use tokio::io::{
    AsyncBufRead as TokioAsyncBufRead, AsyncRead as TokioAsyncRead, AsyncWrite as TokioAsyncWrite,
};

/// A stream equipped with previous data that was not consumed.
///
/// Roughly equivalent to `Chain<Cursor<Vec<u8>>, S>`, but:
///
/// - Implements Write, forwarding it to the underlying stream.
/// - Simplifies the buffer as the carried data is expected to be small.
#[derive(Debug)]
#[cfg_attr(any(feature = "futures", feature = "tokio"), pin_project)]
pub struct CarriedStream<S> {
    pub carried: Vec<u8>,
    #[cfg_attr(any(feature = "futures", feature = "tokio"), pin)]
    pub stream: S,
}

fn read_from_vec(bytes: &mut Vec<u8>, buf: &mut [u8]) -> usize {
    if buf.len() >= bytes.len() {
        let len = bytes.len();
        buf[..len].copy_from_slice(&bytes);
        // Deallocate the buffer altogether
        *bytes = Vec::new();
        len
    } else {
        let len = buf.len();
        buf.copy_from_slice(&bytes[..len]);
        bytes.drain(..len);
        len
    }
}

impl<S: Read> Read for CarriedStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.carried.is_empty() {
            let result = read_from_vec(&mut self.carried, buf);
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

#[cfg(feature = "futures")]
impl<S: FuturesAsyncRead> FuturesAsyncRead for CarriedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.as_mut().project();
        if !this.carried.is_empty() {
            let result = read_from_vec(&mut this.carried, buf);
            return Poll::Ready(Ok(result));
        }
        this.stream.poll_read(cx, buf)
    }

    fn poll_read_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().project();
        if !this.carried.is_empty() {
            let buf = bufs
                .iter_mut()
                .find(|b| !b.is_empty())
                .map_or(&mut [][..], |b| &mut **b);
            return self.poll_read(cx, buf);
        }
        this.stream.poll_read_vectored(cx, bufs)
    }
}

#[cfg(feature = "tokio")]
impl<S: TokioAsyncRead> TokioAsyncRead for CarriedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut this = self.as_mut().project();
        if !this.carried.is_empty() {
            let filled = read_from_vec(&mut this.carried, buf.initialize_unfilled());
            buf.advance(filled);
            return Poll::Ready(Ok(()));
        }
        this.stream.poll_read(cx, buf)
    }
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

#[cfg(feature = "futures")]
impl<S: FuturesAsyncBufRead> FuturesAsyncBufRead for CarriedStream<S> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.project();
        if !this.carried.is_empty() {
            return Poll::Ready(Ok(this.carried));
        }
        this.stream.poll_fill_buf(cx)
    }

    fn consume(mut self: Pin<&mut Self>, amt: usize) {
        let this = self.as_mut().project();
        if !this.carried.is_empty() {
            // We can assume amt <= carried.len()
            if amt >= this.carried.len() {
                *this.carried = Vec::new();
            } else {
                this.carried.drain(..amt);
            }
            return;
        }
        this.stream.consume(amt);
    }
}

#[cfg(feature = "tokio")]
impl<S: TokioAsyncBufRead> TokioAsyncBufRead for CarriedStream<S> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.project();
        if !this.carried.is_empty() {
            return Poll::Ready(Ok(this.carried));
        }
        this.stream.poll_fill_buf(cx)
    }

    fn consume(mut self: Pin<&mut Self>, amt: usize) {
        let this = self.as_mut().project();
        if !this.carried.is_empty() {
            // We can assume amt <= carried.len()
            if amt >= this.carried.len() {
                *this.carried = Vec::new();
            } else {
                this.carried.drain(..amt);
            }
            return;
        }
        this.stream.consume(amt);
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

#[cfg(feature = "futures")]
impl<S: FuturesAsyncWrite> FuturesAsyncWrite for CarriedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().stream.poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.project().stream.poll_write_vectored(cx, bufs)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_close(cx)
    }
}

#[cfg(feature = "tokio")]
impl<S: TokioAsyncWrite> TokioAsyncWrite for CarriedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.project().stream.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().stream.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        let buf = bufs
            .iter()
            .find(|b| !b.is_empty())
            .map_or(&[][..], |b| &**b);
        self.poll_write(cx, buf)
    }

    fn is_write_vectored(&self) -> bool {
        false
    }
}
