// Public API for both server and client -- async tokio version

use std::io::{IoSlice, Result as IoResult};
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

use crate::common::{BytesReader, WithExcess};

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
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IoResult<()>> {
        let this = self.project();
        if !this.excess_read.is_empty() {
            Pin::new(this.excess_read).poll_read(cx, buf)
        } else {
            this.stream.poll_read(cx, buf)
        }
    }
}

impl<S: AsyncBufRead> AsyncBufRead for WithExcess<S> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<&[u8]>> {
        let this = self.project();
        if !this.excess_read.is_empty() {
            Pin::new(this.excess_read).poll_fill_buf(cx)
        } else {
            this.stream.poll_fill_buf(cx)
        }
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let this = self.project();
        if !this.excess_read.is_empty() {
            Pin::new(this.excess_read).consume(amt);
        } else {
            this.stream.consume(amt);
        }
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

    #[tokio::test]
    async fn test_with_excess_read() {
        let mut stream = WithExcess {
            excess_read: BytesReader::from(&b"excess"[..]),
            stream: BytesReader::from(&b"stream"[..]),
        };

        let mut buf = vec![0u8; 4];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"exce");
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ss");
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"stre");
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"am");
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"");
    }

    #[tokio::test]
    async fn test_with_excess_read_to_end() {
        let mut stream = WithExcess {
            excess_read: BytesReader::from(&b"excess"[..]),
            stream: BytesReader::from(&b"stream"[..]),
        };

        let mut all = Vec::new();
        stream.read_to_end(&mut all).await.unwrap();
        assert_eq!(&all[..], b"excessstream");
    }

    #[tokio::test]
    async fn test_with_excess_bufread() {
        let mut stream = WithExcess {
            excess_read: BytesReader::from(&b"excess"[..]),
            stream: BytesReader::from(&b"stream"[..]),
        };

        let buf = stream.fill_buf().await.unwrap();
        assert_eq!(buf, b"excess");
        stream.consume(4);
        let buf = stream.fill_buf().await.unwrap();
        assert_eq!(buf, b"ss");
        stream.consume(2);
        let buf = stream.fill_buf().await.unwrap();
        assert_eq!(buf, b"stream");
        stream.consume(6);
        let buf = stream.fill_buf().await.unwrap();
        assert_eq!(buf, b"");
    }
}
