use std::io;

use crate::wire::message_common::{Scanner, WireFormatError, WritableWireMessage};

trait AuthenticationMessage: Sized {
    const CODE: u32;

    fn write_auth_body_to<W: io::Write>(&self, _writer: &mut W) -> io::Result<()>;

    fn read_auth_body(_scanner: &mut Scanner) -> Result<Self, WireFormatError>;
}

macro_rules! impl_authentication_message {
    ($type:ty) => {
        impl WritableWireMessage for $type {
            fn type_byte(&self) -> u8 {
                b'R'
            }

            fn write_body_to<W>(&self, writer: &mut W) -> io::Result<()>
            where
                W: io::Write,
            {
                writer.write_all(&Self::CODE.to_be_bytes())?;
                self.write_auth_body_to(writer)?;
                Ok(())
            }
        }
    };
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(in crate::wire) struct AuthenticationOk;

impl AuthenticationMessage for AuthenticationOk {
    const CODE: u32 = 0;

    fn write_auth_body_to<W: io::Write>(&self, _writer: &mut W) -> io::Result<()> {
        Ok(())
    }

    fn read_auth_body(_scanner: &mut Scanner) -> Result<Self, WireFormatError> {
        Ok(AuthenticationOk)
    }
}

impl_authentication_message!(AuthenticationOk);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(in crate::wire) struct AuthenticationCleartextPassword;

impl AuthenticationMessage for AuthenticationCleartextPassword {
    const CODE: u32 = 3;

    fn write_auth_body_to<W: io::Write>(&self, _writer: &mut W) -> io::Result<()> {
        Ok(())
    }

    fn read_auth_body(_scanner: &mut Scanner) -> Result<Self, WireFormatError> {
        Ok(AuthenticationCleartextPassword)
    }
}

impl_authentication_message!(AuthenticationCleartextPassword);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(in crate::wire) struct AuthenticationMD5Password {
    pub salt: [u8; 4],
}

impl AuthenticationMessage for AuthenticationMD5Password {
    const CODE: u32 = 5;

    fn write_auth_body_to<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.salt)?;
        Ok(())
    }

    fn read_auth_body(scanner: &mut Scanner) -> Result<Self, WireFormatError> {
        let salt = scanner.read_bytes(4)?;
        let salt = *<&[u8; 4]>::try_from(salt).unwrap();
        Ok(AuthenticationMD5Password { salt })
    }
}

impl_authentication_message!(AuthenticationMD5Password);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(in crate::wire) struct AuthenticationKerberosV5;

impl AuthenticationMessage for AuthenticationKerberosV5 {
    const CODE: u32 = 2;

    fn write_auth_body_to<W: io::Write>(&self, _writer: &mut W) -> io::Result<()> {
        Ok(())
    }

    fn read_auth_body(_scanner: &mut Scanner) -> Result<Self, WireFormatError> {
        Ok(AuthenticationKerberosV5)
    }
}

impl_authentication_message!(AuthenticationKerberosV5);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(in crate::wire) struct AuthenticationGSS;

impl AuthenticationMessage for AuthenticationGSS {
    const CODE: u32 = 7;

    fn write_auth_body_to<W: io::Write>(&self, _writer: &mut W) -> io::Result<()> {
        Ok(())
    }

    fn read_auth_body(_scanner: &mut Scanner) -> Result<Self, WireFormatError> {
        Ok(AuthenticationGSS)
    }
}

impl_authentication_message!(AuthenticationGSS);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(in crate::wire) struct AuthenticationGSSContinue;

impl AuthenticationGSSContinue {
    const CODE: u32 = 8;

    fn write_auth_body_to<W: io::Write>(&self, _writer: &mut W) -> io::Result<()> {
        Ok(())
    }

    fn read_auth_body(_scanner: &mut Scanner) -> Result<Self, WireFormatError> {
        Ok(AuthenticationGSSContinue)
    }
}

impl_authentication_message!(AuthenticationGSSContinue);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(in crate::wire) struct AuthenticationSSPI;

impl AuthenticationMessage for AuthenticationSSPI {
    const CODE: u32 = 9;

    fn write_auth_body_to<W: io::Write>(&self, _writer: &mut W) -> io::Result<()> {
        Ok(())
    }

    fn read_auth_body(_scanner: &mut Scanner) -> Result<Self, WireFormatError> {
        Ok(AuthenticationSSPI)
    }
}

impl_authentication_message!(AuthenticationSSPI);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(in crate::wire) struct AuthenticationSASL {
    pub mechanisms: Vec<String>,
}

impl AuthenticationMessage for AuthenticationSASL {
    const CODE: u32 = 10;

    fn write_auth_body_to<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        for mechanism in &self.mechanisms {
            writer.write_all(mechanism.as_bytes())?;
            writer.write_all(&[0])?;
        }
        Ok(())
    }

    fn read_auth_body(scanner: &mut Scanner) -> Result<Self, WireFormatError> {
        let mut mechanisms = Vec::new();
        loop {
            let s = scanner.read_cstring()?;
            if s.is_empty() {
                break;
            }
            mechanisms.push(s);
        }
        Ok(AuthenticationSASL { mechanisms })
    }
}

impl_authentication_message!(AuthenticationSASL);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(in crate::wire) struct AuthenticationSASLContinue {
    pub data: Vec<u8>,
}

impl AuthenticationMessage for AuthenticationSASLContinue {
    const CODE: u32 = 11;

    fn write_auth_body_to<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.data)?;
        Ok(())
    }

    fn read_auth_body(scanner: &mut Scanner) -> Result<Self, WireFormatError> {
        let data = scanner.read_remaining_bytes().to_owned();
        Ok(AuthenticationSASLContinue { data })
    }
}

impl_authentication_message!(AuthenticationSASLContinue);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(in crate::wire) struct AuthenticationSASLFinal {
    pub data: Vec<u8>,
}

impl AuthenticationMessage for AuthenticationSASLFinal {
    const CODE: u32 = 12;

    fn write_auth_body_to<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.data)?;
        Ok(())
    }

    fn read_auth_body(scanner: &mut Scanner) -> Result<Self, WireFormatError> {
        let data = scanner.read_remaining_bytes().to_owned();
        Ok(AuthenticationSASLFinal { data })
    }
}

impl_authentication_message!(AuthenticationSASLFinal);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::message_common::WritableWireMessageExt;

    fn write_msg<M: WritableWireMessage>(msg: &M) -> Vec<u8> {
        let mut buf = Vec::new();
        msg.write_message_to(&mut buf).unwrap();
        buf
    }

    #[test]
    fn test_write_authentication_ok() {
        assert_eq!(
            write_msg(&AuthenticationOk),
            b"R\x00\x00\x00\x08\x00\x00\x00\x00"
        );
    }
}
