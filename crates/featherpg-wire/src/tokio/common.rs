// Public API for both server and client -- async tokio version

use std::io::{IoSlice, Result as IoResult};
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

use crate::common::{CarriedStream, read_from_vec};

impl<S: AsyncRead> AsyncRead for CarriedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IoResult<()>> {
        let mut this = self.as_mut().project();
        if !this.carried.is_empty() {
            let filled = read_from_vec(&mut this.carried, buf.initialize_unfilled());
            buf.advance(filled);
            return Poll::Ready(Ok(()));
        }
        this.stream.poll_read(cx, buf)
    }
}

impl<S: AsyncBufRead> AsyncBufRead for CarriedStream<S> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<&[u8]>> {
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

impl<S: AsyncWrite> AsyncWrite for CarriedStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        self.project().stream.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.project().stream.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<IoResult<usize>> {
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
