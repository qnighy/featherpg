// https://www.postgresql.org/docs/current/protocol.html

pub use crate::message_common::ProtocolVersion;

pub mod common;
pub mod errors;
#[cfg(feature = "futures")]
pub mod futures;
mod io_util;
mod message;
mod message_common;
pub mod server;
#[cfg(feature = "tokio")]
pub mod tokio;
