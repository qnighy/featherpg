// Public API for both server and client -- async tokio version

use std::io::{IoSlice, Result as IoResult};
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

use crate::common::{BytesReader, WithExcess, read_from_vec};

impl AsyncRead for BytesReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IoResult<()>> {
        self.get_mut()
            .do_borrowed(|this| Pin::new(this).poll_read(cx, buf))
    }
}

impl AsyncBufRead for BytesReader {
    fn poll_fill_buf(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<&[u8]>> {
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
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IoResult<()>> {
        let mut this = self.as_mut().project();
        if !this.excess_read.is_empty() {
            let filled = read_from_vec(&mut this.excess_read, buf.initialize_unfilled());
            buf.advance(filled);
            return Poll::Ready(Ok(()));
        }
        this.stream.poll_read(cx, buf)
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
        let this = self.as_mut().project();
        if !this.excess_read.is_empty() {
            // We can assume amt <= carried.len()
            if amt >= this.excess_read.len() {
                *this.excess_read = Vec::new();
            } else {
                this.excess_read.drain(..amt);
            }
            return;
        }
        this.stream.consume(amt);
    }
}

impl<S: AsyncWrite> AsyncWrite for WithExcess<S> {
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

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::{AsyncBufReadExt, AsyncReadExt};

    #[tokio::test]
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

    #[tokio::test]
    async fn test_bytes_reader_bufread() {
        let mut reader = BytesReader::from(&b"hello"[..]);

        let buf = reader.fill_buf().await.unwrap();
        assert_eq!(buf, b"hello");
        reader.consume(3);
        let buf = reader.fill_buf().await.unwrap();
        assert_eq!(buf, b"lo");
        reader.consume(2);
        let buf = reader.fill_buf().await.unwrap();
        assert_eq!(buf, b"");
    }
}
