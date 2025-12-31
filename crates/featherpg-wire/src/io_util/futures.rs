use std::{
    io::Result as IoResult,
    pin::Pin,
    task::{Context, Poll},
};

use futures::AsyncRead;

use crate::io_util::GrowableBuffer;

impl GrowableBuffer {
    pub(crate) fn poll_fill_buf_futures<R>(
        &mut self,
        cx: &mut Context<'_>,
        reader: Pin<&mut R>,
    ) -> Poll<IoResult<&[u8]>>
    where
        R: AsyncRead + ?Sized,
    {
        self.before_fill_buf();

        let num_read = match reader.poll_read(cx, self.spare_capacity_mut())? {
            Poll::Ready(num_read) => num_read,
            Poll::Pending => return Poll::Pending,
        };
        self.mark_filled(num_read);

        Poll::Ready(Ok(self.buffer()))
    }
}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;

    use futures::AsyncReadExt;

    use super::*;

    async fn fill_buf<'a, R>(
        buffer: &'a mut GrowableBuffer,
        mut reader: Pin<&mut R>,
    ) -> IoResult<&'a [u8]>
    where
        R: AsyncRead + ?Sized,
    {
        // To workaround NLL-minus-polonius lifetimes,
        // we discard the slice and then get it again after await.
        poll_fn(
            |cx| match buffer.poll_fill_buf_futures(cx, reader.as_mut()) {
                Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            },
        )
        .await?;

        Ok(buffer.buffer())
    }

    #[futures_test::test]
    async fn test_growable_buffer() {
        let mut buffer = GrowableBuffer::with_unit_size(4);

        // Using Chain to simulate a reader with multiple reads
        let mut reader = b"Hello, world!\n"[..]
            .chain(&b"Next line\n"[..])
            .chain(&b"Final line\n"[..]);

        let current = fill_buf(&mut buffer, Pin::new(&mut reader)).await.unwrap();
        // Read of two units
        assert_eq!(current, b"Hello, w");

        buffer.consume(b"Hello, ".len());
        assert_eq!(buffer.buffer(), b"w");

        // Enough capacity. Read to the next boundary.
        let current = fill_buf(&mut buffer, Pin::new(&mut reader)).await.unwrap();
        assert_eq!(current, b"world!\n");

        buffer.consume(b"world!\n".len());
        assert_eq!(buffer.buffer(), b"");

        let current = fill_buf(&mut buffer, Pin::new(&mut reader)).await.unwrap();
        assert_eq!(current, b"Next lin");
        // Extends the buffer and reads more.
        let current = fill_buf(&mut buffer, Pin::new(&mut reader)).await.unwrap();
        assert_eq!(current, b"Next line\n");

        let current = fill_buf(&mut buffer, Pin::new(&mut reader)).await.unwrap();
        // Still not enough capacity (four units)
        assert_eq!(current, b"Next line\nFinal ");
        let current = fill_buf(&mut buffer, Pin::new(&mut reader)).await.unwrap();
        assert_eq!(current, b"Next line\nFinal line\n");

        buffer.consume(b"Next line\nFinal line\n".len());
        assert_eq!(buffer.buffer(), b"");
    }
}
