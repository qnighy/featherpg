use bstr::{BString, ByteSlice};
use std::collections::HashMap;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpListener;

const SSL_REQUEST_VERSION: &[u8] = b"\x04\xD2\x16\x2F";
const GSSENC_REQUEST_VERSION: &[u8] = b"\x04\xD2\x16\x30";
const PROTOCOL_VERSION: &[u8] = b"\x00\x03\x00\x00";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
                assert!(len >= 4); // TODO: convert to an error
                let mut buf = vec![0_u8; len - 4];
                reader.read_exact(&mut buf).await?;
                if buf == SSL_REQUEST_VERSION || buf == GSSENC_REQUEST_VERSION {
                    writer.write_all(b"N").await?;
                    writer.flush().await?;
                    continue;
                }
                // TODO: check length
                assert_eq!(&buf[..4], PROTOCOL_VERSION); // TODO: convert to an error
                let params = parse_params(&buf[4..]);
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

            Ok(()) as Result<(), Box<dyn std::error::Error + Send + Sync>>
        });
    }
}

fn parse_params(mut s: &[u8]) -> HashMap<BString, BString> {
    let mut params = HashMap::new();
    loop {
        let term = s.find_byte(b'\0').expect("Invalid params"); // TODO: convert to an error
        if term == 0 {
            break;
        }
        let key = s[..term].as_bstr().to_owned();
        s = &s[term + 1..];

        let term = s.find_byte(b'\0').expect("Invalid params"); // TODO: convert to an error
        let value = s[..term].as_bstr().to_owned();
        s = &s[term + 1..];

        params.insert(key, value);
    }
    assert_eq!(s, b"\0"); // TODO: convert to an error
    params
}
