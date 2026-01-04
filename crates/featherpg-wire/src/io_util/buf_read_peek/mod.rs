use std::io::{BufRead, BufReader, Cursor, Read};

// See: https://internals.rust-lang.org/t/add-bufwriter-bufreader-buffer-to-bufread-trait/13668
/// Like [std::io::BufRead], but exposes the internal read buffer.
pub trait BufReadPeek: BufRead {
    /// Returns the internal read buffer, like [std::io::BufReader::buffer].
    ///
    /// Expected invariants are:
    ///
    /// - peek_buf is side-effect free.
    /// - [std::io::BufRead::fill_buf] followed by peek_buf returns the same data.
    /// - [std::io::BufRead::consume] shifts the peek_buf by the same amount.
    /// - peek_buf followed by [std::io::Read::read] behaves consistently.
    ///   If read reads shorter than peek_buf, it is the prefix of peek_buf,
    ///   and peek_buf is shifted by the same amount.
    ///   If read reads longer than peek_buf, peek_buf was the prefix of the read data.
    fn peek_buf(&self) -> &[u8];
}

impl BufReadPeek for &[u8] {
    fn peek_buf(&self) -> &[u8] {
        self
    }
}

impl BufReadPeek for std::io::Empty {
    fn peek_buf(&self) -> &[u8] {
        &[]
    }
}

impl<R> BufReadPeek for &mut R
where
    R: BufReadPeek + ?Sized,
{
    fn peek_buf(&self) -> &[u8] {
        <R as BufReadPeek>::peek_buf(self)
    }
}

impl<R> BufReadPeek for Box<R>
where
    R: BufReadPeek + ?Sized,
{
    fn peek_buf(&self) -> &[u8] {
        <R as BufReadPeek>::peek_buf(self)
    }
}

impl<R> BufReadPeek for BufReader<R>
where
    R: Read,
{
    fn peek_buf(&self) -> &[u8] {
        self.buffer()
    }
}

impl<R> BufReadPeek for Cursor<R>
where
    R: AsRef<[u8]>,
{
    fn peek_buf(&self) -> &[u8] {
        let slice = self.get_ref().as_ref();
        let pos = self.position().min(slice.len() as u64);
        &slice[pos as usize..]
    }
}

impl<R> BufReadPeek for std::io::Take<R>
where
    R: BufReadPeek,
{
    fn peek_buf(&self) -> &[u8] {
        if self.limit() == 0 {
            return &[];
        }

        let buf = self.get_ref().peek_buf();
        let cap = (buf.len() as u64).min(self.limit()) as usize;
        &buf[..cap]
    }
}
