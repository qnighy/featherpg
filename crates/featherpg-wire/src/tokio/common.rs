// Public API for both server and client -- async tokio version

use std::io::{self, IoSlice};
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{
    AsyncBufRead as TokioAsyncBufRead, AsyncRead as TokioAsyncRead, AsyncWrite as TokioAsyncWrite,
};

use crate::common::{CarriedStream, read_from_vec};

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
