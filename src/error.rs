use thiserror::Error;
use tokio::io;

#[derive(Debug, Error)]
pub enum PgError {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("Invalid message")]
    InvalidMessage,
}
