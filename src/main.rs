use bstr::{BString, ByteSlice};
use tokio::io::{self, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpListener;

use crate::error::PgError;
use crate::message::{
    ClientMessage, ClientStartupMessage, ColumnDescription, ServerMessage, TransactionStatus,
};

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

            ServerMessage::AuthenticationOk
                .write_to(&mut writer)
                .await?;
            ServerMessage::ReadyForQuery(TransactionStatus::Idle)
                .write_to(&mut writer)
                .await?;
            writer.flush().await?;

            loop {
                let msg = ClientMessage::read_from(&mut reader).await?;

                match msg {
                    ClientMessage::Query(q) => {
                        if q.as_bytes() == b"SELECT 1;" {
                            ServerMessage::RowDescription(vec![ColumnDescription {
                                name: BString::from("?column?"),
                                table_oid: 0,
                                column_attr_no: 0,
                                data_type_oid: 23,
                                data_type_size: 4,
                                type_modifier: 0,
                                format_code: 0,
                            }])
                            .write_to(&mut writer)
                            .await?;
                            ServerMessage::DataRow(vec![Some(BString::from("1"))])
                                .write_to(&mut writer)
                                .await?;
                            ServerMessage::CommandComplete(BString::from("SELECT 1"))
                                .write_to(&mut writer)
                                .await?;
                        } else {
                            todo!("ClientMessage::Query({:?})", q);
                        }
                    }
                    ClientMessage::Terminate => break,
                }

                ServerMessage::ReadyForQuery(TransactionStatus::Idle)
                    .write_to(&mut writer)
                    .await?;
                writer.flush().await?;
            }

            Ok(()) as Result<(), PgError>
        });
    }
}
