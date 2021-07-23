use bstr::{BString, ByteSlice};
use std::collections::HashMap;
use std::convert::TryInto;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::PgError;

const CANCEL_REQUEST_VERSION: (u16, u16) = (1234, 5678);
const SSL_REQUEST_VERSION: (u16, u16) = (1234, 5679);
const GSSENC_REQUEST_VERSION: (u16, u16) = (1234, 5680);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientStartupMessage {
    StartupMessage(StartupPayload),
    CancelRequest(CancelPayload),
    SslRequest,
    GssEncRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupPayload {
    pub version: (u16, u16),
    pub params: HashMap<BString, BString>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelPayload {
    pub process_id: u32,
    pub secret_key: u32,
}

impl ClientStartupMessage {
    pub async fn read_from<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self, PgError> {
        let len = r.read_u32().await? as usize;
        if len < 4 {
            return Err(PgError::InvalidMessage);
        }
        let mut buf = vec![0_u8; len - 4];
        r.read_exact(&mut buf).await?;
        log::debug!("startup; len = {:#x}, buf = {:?}", len, buf.as_bstr());
        if buf.len() < 4 {
            return Err(PgError::InvalidMessage);
        }
        let version_major = u16::from_be_bytes(buf[0..2].try_into().unwrap());
        let version_minor = u16::from_be_bytes(buf[2..4].try_into().unwrap());
        let version = (version_major, version_minor);
        if version == CANCEL_REQUEST_VERSION {
            if buf.len() != 12 {
                return Err(PgError::InvalidMessage);
            }
            let process_id = u32::from_be_bytes(buf[4..8].try_into().unwrap());
            let secret_key = u32::from_be_bytes(buf[8..12].try_into().unwrap());
            return Ok(ClientStartupMessage::CancelRequest(CancelPayload {
                process_id,
                secret_key,
            }));
        } else if version == SSL_REQUEST_VERSION {
            if buf.len() != 4 {
                return Err(PgError::InvalidMessage);
            }
            return Ok(ClientStartupMessage::SslRequest);
        } else if version == GSSENC_REQUEST_VERSION {
            if buf.len() != 4 {
                return Err(PgError::InvalidMessage);
            }
            return Ok(ClientStartupMessage::GssEncRequest);
        }
        let params = parse_params(&buf[4..])?;
        Ok(ClientStartupMessage::StartupMessage(StartupPayload {
            version,
            params,
        }))
    }
}

fn parse_params(mut s: &[u8]) -> Result<HashMap<BString, BString>, PgError> {
    let mut params = HashMap::new();
    loop {
        let term = s.find_byte(b'\0').ok_or(PgError::InvalidMessage)?;
        if term == 0 {
            break;
        }
        let key = s[..term].as_bstr().to_owned();
        s = &s[term + 1..];

        let term = s.find_byte(b'\0').ok_or(PgError::InvalidMessage)?;
        let value = s[..term].as_bstr().to_owned();
        s = &s[term + 1..];

        params.insert(key, value);
    }
    if s != b"\0" {
        return Err(PgError::InvalidMessage);
    }
    Ok(params)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerMessage {
    AuthenticationOk,
    ReadyForQuery(TransactionStatus),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionStatus {
    Idle,
    InTransaction,
    InFailedTransaction,
}

impl From<TransactionStatus> for u8 {
    fn from(s: TransactionStatus) -> Self {
        match s {
            TransactionStatus::Idle => b'I',
            TransactionStatus::InTransaction => b'T',
            TransactionStatus::InFailedTransaction => b'F',
        }
    }
}

impl ServerMessage {
    pub fn msg_type(&self) -> u8 {
        use ServerMessage::*;
        match self {
            AuthenticationOk => b'R',
            ReadyForQuery(_) => b'Z',
        }
    }
    pub fn byte_len(&self) -> usize {
        use ServerMessage::*;
        match self {
            AuthenticationOk => 4,
            ReadyForQuery(_) => 1,
        }
    }
    pub async fn write_to<W: AsyncWrite + Unpin>(&self, w: &mut W) -> Result<(), PgError> {
        use ServerMessage::*;

        self.validate();

        w.write_all(&[self.msg_type()]).await?;
        w.write_all(&(self.byte_len() as u32 + 4).to_be_bytes())
            .await?;
        match self {
            AuthenticationOk => w.write_all(b"\x00\x00\x00\x00").await?,
            &ReadyForQuery(s) => w.write_all(&[u8::from(s)]).await?,
        }
        Ok(())
    }
    fn validate(&self) {
        // TODO
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use maplit::hashmap;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_read_startup1() {
        let mut src = Cursor::new(b"\x00\x00\x00\x08\x04\xD2\x16\x2F");
        let msg = ClientStartupMessage::read_from(&mut src).await.unwrap();
        assert_eq!(msg, ClientStartupMessage::SslRequest);
        assert_eq!(src.position(), src.get_ref().len() as u64);
    }

    #[tokio::test]
    async fn test_read_startup2() {
        let mut src = Cursor::new(b"\x00\x00\x00\x52\x00\x03\x00\x00user\0qnighy\0database\0database\0application_name\0psql\0client_encoding\0UTF8\0\0");
        let msg = ClientStartupMessage::read_from(&mut src).await.unwrap();
        assert_eq!(
            msg,
            ClientStartupMessage::StartupMessage(StartupPayload {
                version: (3, 0),
                params: hashmap![
                    B("client_encoding") => B("UTF8"),
                    B("database") => B("database"),
                    B("user") => B("qnighy"),
                    B("application_name") => B("psql"),
                ],
            })
        );
        assert_eq!(src.position(), src.get_ref().len() as u64);
    }

    #[allow(non_snake_case)]
    fn B<S>(s: S) -> BString
    where
        BString: From<S>,
    {
        BString::from(s)
    }
}
