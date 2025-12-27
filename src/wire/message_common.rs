use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum ColumnFormat {
    Text,
    Binary,
}

pub(super) trait WritableWireMessage {
    fn type_byte(&self) -> u8;

    fn write_body_to<W>(&self, writer: &mut W) -> io::Result<()>
    where
        W: io::Write;
}

pub(super) trait WritableWireMessageExt: WritableWireMessage {
    fn write_message_to<W>(&self, writer: &mut W) -> io::Result<()>
    where
        W: io::Write,
    {
        writer.write_all(&[self.type_byte()])?;

        let mut length_counter = LengthCounter { length: 0 };
        self.write_body_to(&mut length_counter)?;
        let total_length = u32::try_from(length_counter.length + 4).unwrap();

        writer.write_all(&total_length.to_be_bytes())?;
        self.write_body_to(writer)?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
struct LengthCounter {
    length: usize,
}

impl io::Write for LengthCounter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.length += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
