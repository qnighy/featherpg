use bstr::{BString, ByteSlice};
use std::collections::HashMap;
use std::convert::TryInto;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::PgError;

const CANCEL_REQUEST_VERSION: (u16, u16) = (1234, 5678);
const SSL_REQUEST_VERSION: (u16, u16) = (1234, 5679);
const GSSENC_REQUEST_VERSION: (u16, u16) = (1234, 5680);

#[derive(Debug, Clone)]
pub enum ClientStartupMessage {
    StartupMessage(StartupPayload),
    CancelRequest(CancelPayload),
    SslRequest,
    GssEncRequest,
}

#[derive(Debug, Clone)]
pub struct StartupPayload {
    pub version: (u16, u16),
    pub params: HashMap<BString, BString>,
}

#[derive(Debug, Clone)]
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
