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
pub enum ClientMessage {
    Query(BString),
    Terminate,
}

impl ClientMessage {
    pub async fn read_from<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self, PgError> {
        let msg_type = r.read_u8().await?;
        let len = r.read_u32().await? as usize;
        if len < 4 {
            return Err(PgError::InvalidMessage);
        }
        let mut buf = vec![0_u8; len - 4];
        r.read_exact(&mut buf).await?;
        log::debug!(
            "msg_type = {:?}, len = {:#x}, buf = {:?}",
            msg_type as char,
            len,
            buf.as_bstr()
        );
        match msg_type {
            b'Q' => {
                if buf.len() == 0
                    || buf[buf.len() - 1] != b'\0'
                    || buf[..buf.len() - 1].iter().any(|&ch| ch == b'\0')
                {
                    return Err(PgError::InvalidMessage);
                }
                let query = BString::from(&buf[..buf.len() - 1]);
                Ok(ClientMessage::Query(query))
            }
            b'X' => {
                if buf.len() != 0 {
                    return Err(PgError::InvalidMessage);
                }
                Ok(ClientMessage::Terminate)
            }
            _ => return Err(PgError::InvalidMessage),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerMessage {
    AuthenticationOk,
    ReadyForQuery(TransactionStatus),
    RowDescription(Vec<ColumnDescription>),
    DataRow(Vec<Option<BString>>),
    CommandComplete(BString),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnDescription {
    pub name: BString,
    pub table_oid: u32,
    pub column_attr_no: u16,
    pub data_type_oid: u32,
    pub data_type_size: u16,
    pub type_modifier: u32,
    pub format_code: u16,
}

impl ServerMessage {
    pub fn msg_type(&self) -> u8 {
        use ServerMessage::*;
        match self {
            AuthenticationOk => b'R',
            ReadyForQuery(_) => b'Z',
            RowDescription(_) => b'T',
            DataRow(_) => b'D',
            CommandComplete(_) => b'C',
        }
    }
    pub fn byte_len(&self) -> usize {
        use ServerMessage::*;
        match self {
            AuthenticationOk => 4,
            ReadyForQuery(_) => 1,
            RowDescription(columns) => {
                2 + columns
                    .iter()
                    .map(|column| 19 + column.name.len())
                    .sum::<usize>()
            }
            DataRow(fields) => {
                2 + fields
                    .iter()
                    .map(|field| {
                        if let Some(field) = field {
                            4 + field.len()
                        } else {
                            4
                        }
                    })
                    .sum::<usize>()
            }
            CommandComplete(tag) => tag.len() + 1,
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
            RowDescription(columns) => {
                w.write_all(&(columns.len() as u16).to_be_bytes()).await?;
                for column in columns {
                    w.write_all(column.name.as_bytes()).await?;
                    w.write_all(b"\0").await?;
                    w.write_all(&column.table_oid.to_be_bytes()).await?;
                    w.write_all(&column.column_attr_no.to_be_bytes()).await?;
                    w.write_all(&column.data_type_oid.to_be_bytes()).await?;
                    w.write_all(&column.data_type_size.to_be_bytes()).await?;
                    w.write_all(&column.type_modifier.to_be_bytes()).await?;
                    w.write_all(&column.format_code.to_be_bytes()).await?;
                }
            }
            DataRow(fields) => {
                w.write_all(&(fields.len() as u16).to_be_bytes()).await?;
                for field in fields {
                    if let Some(field) = field {
                        w.write_all(&(field.len() as u32).to_be_bytes()).await?;
                        w.write_all(field.as_bytes()).await?;
                    } else {
                        w.write_all(b"\xFF\xFF\xFF\xFF").await?;
                    };
                }
            }
            CommandComplete(tag) => {
                w.write_all(tag.as_bytes()).await?;
                w.write_all(b"\0").await?;
            }
        }
        Ok(())
    }
    fn validate(&self) {
        use ServerMessage::*;
        match self {
            AuthenticationOk | ReadyForQuery(_) => {}
            RowDescription(columns) => {
                assert!(columns.len() <= u16::MAX as usize);
                for column in columns {
                    assert!(is_null_free(&column.name));
                }
            }
            DataRow(fields) => {
                assert!(fields.len() <= u16::MAX as usize);
                for field in fields {
                    if let Some(field) = field {
                        assert!(field.len() < u32::MAX as usize);
                    }
                }
            }
            CommandComplete(tag) => assert!(is_null_free(tag)),
        }
    }
}

fn is_null_free(s: &[u8]) -> bool {
    s.iter().all(|&ch| ch != b'\0')
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

    #[tokio::test]
    async fn test_write_server1() {
        let msg = ServerMessage::AuthenticationOk;
        assert_eq!(to_bytes(&msg).await, b"R\x00\x00\x00\x08\x00\x00\x00\x00");
    }

    #[tokio::test]
    async fn test_write_server2() {
        let msg = ServerMessage::ReadyForQuery(TransactionStatus::Idle);
        assert_eq!(to_bytes(&msg).await, b"Z\x00\x00\x00\x05I");
    }

    async fn to_bytes(msg: &ServerMessage) -> Vec<u8> {
        let mut dst = Vec::<u8>::new();
        msg.write_to(&mut dst).await.unwrap();
        dst
    }

    #[allow(non_snake_case)]
    fn B<S>(s: S) -> BString
    where
        BString: From<S>,
    {
        BString::from(s)
    }
}
