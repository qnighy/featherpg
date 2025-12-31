use std::ffi::CString;

use crate::{
    ProtocolVersion,
    message_common::{Scanner, WireFormatError},
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StartupLikeMessage {
    Startup(StartupMessage),
    SSLRequest(SSLRequest),
    GSSENCRequest(GSSENCRequest),
    CancelRequest(CancelRequest),
}

impl From<StartupMessage> for StartupLikeMessage {
    fn from(msg: StartupMessage) -> Self {
        StartupLikeMessage::Startup(msg)
    }
}

impl From<SSLRequest> for StartupLikeMessage {
    fn from(msg: SSLRequest) -> Self {
        StartupLikeMessage::SSLRequest(msg)
    }
}

impl From<GSSENCRequest> for StartupLikeMessage {
    fn from(msg: GSSENCRequest) -> Self {
        StartupLikeMessage::GSSENCRequest(msg)
    }
}

impl From<CancelRequest> for StartupLikeMessage {
    fn from(msg: CancelRequest) -> Self {
        StartupLikeMessage::CancelRequest(msg)
    }
}

impl StartupLikeMessage {
    pub fn parse_body(body: &[u8]) -> Result<Self, WireFormatError> {
        let mut scanner = Scanner::new(body);
        let version = scanner.read_version()?;

        match version {
            SSLRequest::VERSION => Ok(SSLRequest::parse_with_version(scanner, version)?.into()),
            GSSENCRequest::VERSION => {
                Ok(GSSENCRequest::parse_with_version(scanner, version)?.into())
            }
            CancelRequest::VERSION => {
                Ok(CancelRequest::parse_with_version(scanner, version)?.into())
            }
            _ => Ok(StartupMessage::parse_with_version(scanner, version)?.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StartupMessage {
    pub version: ProtocolVersion,
    pub database_name: CString,
    pub user_name: CString,
    pub cmdline_options: Option<CString>,
    pub replication: ReplicationMode,
    /// The options' names must start with "_pq_."
    pub other_protocol_options: Vec<(CString, CString)>,
    pub guc_options: Vec<(CString, CString)>,
}

impl StartupMessage {
    fn parse_with_version(
        mut scanner: Scanner<'_>,
        version: ProtocolVersion,
    ) -> Result<Self, WireFormatError> {
        // See: backend_startup.c, ProcessStartupPacket

        let mut database_name = None;
        let mut user_name = None;
        let mut cmdline_options = None;
        // Subtle edge-case difference from PostgreSQL:
        // PostgreSQL handles
        // `replication\0database\0replication\0false\0\0replication\0true\0`
        // inconsistently (equivalent to `replication\0database\0` rather than the last declaration),
        // where we do not.
        let mut replication = ReplicationMode::None;
        let mut other_protocol_options = Vec::new();
        let mut guc_options = Vec::new();

        loop {
            let name = scanner.read_cstring2(WireFormatError::StartupPacketUnterminatedString)?;
            if name.is_empty() {
                break;
            }
            let value = scanner.read_cstring2(WireFormatError::StartupPacketUnterminatedString)?;

            match name.as_bytes() {
                b"database" => database_name = Some(value),
                b"user" => user_name = Some(value),
                b"options" => cmdline_options = Some(value),
                b"replication" => match value.as_bytes() {
                    b"database" => replication = ReplicationMode::DatabaseReplication,
                    _ => match parse_pg_bool(value.as_bytes()) {
                        Some(false) => replication = ReplicationMode::None,
                        Some(true) => replication = ReplicationMode::Replication,
                        None => {
                            return Err(WireFormatError::InvalidReplicationParameter {
                                value: value.to_string_lossy().into_owned(),
                            });
                        }
                    },
                },
                _ if name.as_bytes().starts_with(b"_pq_.") => {
                    other_protocol_options.push((name, value));
                }
                _ => guc_options.push((name, value)),
            }
        }

        scanner
            .read_eof()
            .map_err(|_| WireFormatError::StartupPacketExtraBytes)?;

        let Some(user_name) = user_name else {
            return Err(WireFormatError::MissingUserName);
        };

        let database_name = database_name.unwrap_or_else(|| user_name.clone());

        Ok(StartupMessage {
            version,
            database_name,
            user_name,
            cmdline_options,
            replication,
            other_protocol_options,
            guc_options,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SSLRequest;

impl SSLRequest {
    const VERSION: ProtocolVersion = ProtocolVersion::new(1234, 5679);
    fn parse_with_version(
        scanner: Scanner<'_>,
        _version: ProtocolVersion,
    ) -> Result<Self, WireFormatError> {
        // See: backend_startup.c, ProcessStartupPacket

        // Subtle difference from PostgreSQL:
        // PostgreSQL does not check EOF here, but we do.
        scanner
            .read_eof()
            .map_err(|_| WireFormatError::SSLRequestExtraBytes)?;

        Ok(SSLRequest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GSSENCRequest;

impl GSSENCRequest {
    const VERSION: ProtocolVersion = ProtocolVersion::new(1234, 5680);
    fn parse_with_version(
        scanner: Scanner<'_>,
        _version: ProtocolVersion,
    ) -> Result<Self, WireFormatError> {
        // See: backend_startup.c, ProcessStartupPacket

        // Subtle difference from PostgreSQL:
        // PostgreSQL does not check EOF here, but we do.
        scanner
            .read_eof()
            .map_err(|_| WireFormatError::GSSENCRequestExtraBytes)?;

        Ok(GSSENCRequest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CancelRequest {
    pub process_id: i32,
    // 4 bytes in protocol 3.0, arbitrary length in protocol 3.2
    pub secret_key: Vec<u8>,
}

impl CancelRequest {
    const VERSION: ProtocolVersion = ProtocolVersion::new(1234, 5678);

    const MAX_SECRET_KEY_LENGTH: usize = 256;

    fn parse_with_version(
        mut scanner: Scanner<'_>,
        _version: ProtocolVersion,
    ) -> Result<Self, WireFormatError> {
        // See: backend_startup.c, ProcessCancelRequestPacket

        let process_id = scanner
            .read_u32()
            .map_err(|_| WireFormatError::CancelRequestIncompleteProcessId)?
            as i32;
        let secret_key = scanner.read_remaining_bytes();
        if secret_key.is_empty() {
            return Err(WireFormatError::CancelRequestMissingSecretKey);
        } else if secret_key.len() > Self::MAX_SECRET_KEY_LENGTH {
            return Err(WireFormatError::CancelRequestSecretKeyTooLong {
                length: secret_key.len(),
                max_length: Self::MAX_SECRET_KEY_LENGTH,
            });
        }

        Ok(CancelRequest {
            process_id,
            secret_key: secret_key.to_owned(),
        })
    }
}

fn parse_pg_bool(s: &[u8]) -> Option<bool> {
    if let Some(b) = parse_pg_bool_lowercase(s) {
        return Some(b);
    }
    let s = s.to_ascii_lowercase();
    parse_pg_bool_lowercase(&s)
}

fn parse_pg_bool_lowercase(s: &[u8]) -> Option<bool> {
    match s {
        b"true" => Some(true),
        b"false" => Some(false),
        b"yes" => Some(true),
        b"no" => Some(false),
        b"on" => Some(true),
        b"off" => Some(false),
        b"1" => Some(true),
        b"0" => Some(false),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReplicationMode {
    None,
    Replication,
    DatabaseReplication,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_startup_message_parsing_simple() {
        let data = &b"\x00\x03\x00\x00user\0testuser\0database\0testdb\0\0"[..];
        let msg = StartupLikeMessage::parse_body(data).unwrap();

        assert_eq!(
            msg,
            StartupMessage {
                version: ProtocolVersion::new(3, 0),
                database_name: CString::new("testdb").unwrap(),
                user_name: CString::new("testuser").unwrap(),
                cmdline_options: None,
                replication: ReplicationMode::None,
                other_protocol_options: vec![],
                guc_options: vec![],
            }
            .into()
        );
    }

    #[test]
    fn test_ssl_request_parsing() {
        // 0x04D2 = 1234, 0x162F = 5679
        let data = &b"\x04\xD2\x16\x2F"[..];
        let msg = StartupLikeMessage::parse_body(data).unwrap();

        assert_eq!(msg, SSLRequest.into());
    }

    #[test]
    fn test_gssenc_request_parsing() {
        // 0x04D2 = 1234, 0x1630 = 5680
        let data = &b"\x04\xD2\x16\x30"[..];
        let msg = StartupLikeMessage::parse_body(data).unwrap();

        assert_eq!(msg, GSSENCRequest.into());
    }

    #[test]
    fn test_cancel_request_parsing() {
        // 0x04D2 = 1234, 0x162E = 5678
        let data = &b"\x04\xD2\x16\x2E\x00\x00\x30\x39secretkeydata"[..];
        let msg = StartupLikeMessage::parse_body(data).unwrap();

        assert_eq!(
            msg,
            CancelRequest {
                process_id: 12345,
                secret_key: b"secretkeydata".to_vec(),
            }
            .into()
        );
    }
}
