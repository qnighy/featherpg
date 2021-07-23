use bstr::{BString, ByteSlice};
use std::collections::HashMap;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpListener;

use crate::error::PgError;

mod error;

const SSL_REQUEST_VERSION: &[u8] = b"\x04\xD2\x16\x2F";
const GSSENC_REQUEST_VERSION: &[u8] = b"\x04\xD2\x16\x30";
const PROTOCOL_VERSION: &[u8] = b"\x00\x03\x00\x00";

#[tokio::main]
async fn main() -> Result<(), PgError> {
    env_logger::init();

    let listener = TcpListener::bind("127.0.0.1:5433").await?;

    loop {
        let (socket, _) = listener.accept().await?;
        let (reader, writer) = io::split(socket);
        let mut reader = BufReader::new(reader);
        let mut writer = BufWriter::new(writer);

        tokio::spawn(async move {
            let params = loop {
                let len = reader.read_u32().await? as usize;
                if len < 4 {
                    return Err(PgError::InvalidMessage);
                }
                let mut buf = vec![0_u8; len - 4];
                reader.read_exact(&mut buf).await?;
                if buf == SSL_REQUEST_VERSION || buf == GSSENC_REQUEST_VERSION {
                    writer.write_all(b"N").await?;
                    writer.flush().await?;
                    continue;
                }
                if buf.len() < 4 || &buf[..4] != PROTOCOL_VERSION {
                    // TODO: version negotiation
                    return Err(PgError::InvalidMessage);
                }
                let params = parse_params(&buf[4..])?;
                break params;
            };
            log::debug!("params = {:?}", params);

            // AuthenticationOk
            writer
                .write_all(b"R\x00\x00\x00\x08\x00\x00\x00\x00")
                .await?;

            // ReadyForQuery
            writer.write_all(b"Z\x00\x00\x00\x05I").await?;
            writer.flush().await?;

            reader.read(&mut [0; 16]).await?; // TODO: remove it later

            Ok(()) as Result<(), PgError>
        });
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
