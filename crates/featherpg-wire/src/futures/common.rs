// Public API for both server and client -- async futures version

use std::io::{self, IoSlice, IoSliceMut};
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::io::{
    AsyncBufRead as FuturesAsyncBufRead, AsyncRead as FuturesAsyncRead,
    AsyncWrite as FuturesAsyncWrite,
};

use crate::common::{CarriedStream, read_from_vec};

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
