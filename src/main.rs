use tokio::io::{self, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpListener;

use crate::error::PgError;
use crate::message::ClientStartupMessage;

mod error;
mod message;

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
            let startup = loop {
                let msg = ClientStartupMessage::read_from(&mut reader).await?;
                match msg {
                    ClientStartupMessage::StartupMessage(payload) => break payload,
                    ClientStartupMessage::CancelRequest(_) => todo!(),
                    ClientStartupMessage::SslRequest => {
                        writer.write_all(b"N").await?;
                        writer.flush().await?;
                    }
                    ClientStartupMessage::GssEncRequest => {
                        writer.write_all(b"N").await?;
                        writer.flush().await?;
                    }
                }
            };
            log::debug!("params = {:?}", startup.params);

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
