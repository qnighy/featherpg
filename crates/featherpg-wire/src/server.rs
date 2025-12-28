use crate::errors::ServerError;

/// Defines an interface that a PostgreSQL wire protocol server must implement
/// using the synchronous I/O model.
pub trait Serve {
    fn startup(&mut self, req: StartupRequest) -> Result<(), ServerError>;
    fn cancel(&mut self, req: CancelRequest) -> Result<(), ServerError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StartupRequest {
    pub user: String,
    pub database: String,
    // TODO: options, replication, _pq_, etc.
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CancelRequest {
    pub process_id: i32,
    pub secret_key: Vec<u8>,
}
