// Public API for both server and client -- async futures version

use std::io::{IoSlice, IoSliceMut, Result as IoResult};
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::io::{AsyncBufRead, AsyncRead, AsyncWrite};

use crate::common::{BytesReader, WithExcess};

impl AsyncRead for BytesReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        self.get_mut()
            .do_borrowed(|this| Pin::new(this).poll_read(cx, buf))
    }

    fn poll_read_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<IoResult<usize>> {
        self.get_mut()
            .do_borrowed(|this| Pin::new(this).poll_read_vectored(cx, bufs))
    }
}

impl AsyncBufRead for BytesReader {
    fn poll_fill_buf(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<IoResult<&[u8]>> {
        Poll::Ready(Ok(self.get_mut()))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        self.get_mut()
            .do_borrowed(|this| Pin::new(this).consume(amt));
    }
}

impl<S: AsyncRead> AsyncRead for WithExcess<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        let mut this = self.as_mut().project();
        if !this.excess_read.is_empty() {
            return Pin::new(&mut this.excess_read).poll_read(cx, buf);
        }
        this.stream.poll_read(cx, buf)
    }

    fn poll_read_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Poll<IoResult<usize>> {
        let this = self.as_mut().project();
        if !this.excess_read.is_empty() {
            let buf = bufs
                .iter_mut()
                .find(|b| !b.is_empty())
                .map_or(&mut [][..], |b| &mut **b);
            return self.poll_read(cx, buf);
        }
        this.stream.poll_read_vectored(cx, bufs)
    }
}

impl<S: AsyncBufRead> AsyncBufRead for WithExcess<S> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<&[u8]>> {
        let this = self.project();
        if !this.excess_read.is_empty() {
            return Poll::Ready(Ok(this.excess_read));
        }
        this.stream.poll_fill_buf(cx)
    }

    fn consume(mut self: Pin<&mut Self>, amt: usize) {
        let mut this = self.as_mut().project();
        if !this.excess_read.is_empty() {
            Pin::new(&mut this.excess_read).consume(amt);
            return;
        }
        this.stream.consume(amt);
    }
}

impl<S: AsyncWrite> AsyncWrite for WithExcess<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        self.project().stream.poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<IoResult<usize>> {
        self.project().stream.poll_write_vectored(cx, bufs)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.project().stream.poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use futures::{AsyncBufReadExt, AsyncReadExt};

    use super::*;

    #[futures_test::test]
    async fn test_bytes_reader_read_simple() {
        let mut reader = BytesReader::from(&b"hello"[..]);

        let mut buf = vec![0u8; 3];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hel");
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"lo");
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"");
    }

    #[futures_test::test]
    async fn test_bytes_reader_bufread() {
        let mut reader = BytesReader::from(&b"hello"[..]);

        let buf = reader.fill_buf().await.unwrap();
        assert_eq!(buf, b"hello");
        reader.consume_unpin(3);
        let buf = reader.fill_buf().await.unwrap();
        assert_eq!(buf, b"lo");
        reader.consume_unpin(2);
        let buf = reader.fill_buf().await.unwrap();
        assert_eq!(buf, b"");
    }
}
