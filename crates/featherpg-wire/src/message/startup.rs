use std::ffi::CString;

use crate::{
    ProtocolVersion,
    message_common::{Scanner, WireFormatError},
};

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
        let mut database_name = None;
        let mut user_name = None;
        let mut cmdline_options = None;
        // Having a separate bool to imitate PostgreSQL's behavior
        // on replication=database&replication=false
        let mut replication = false;
        let mut database_replication = false;
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
                    b"database" => {
                        replication = true;
                        database_replication = true;
                    }
                    _ => match parse_pg_bool(value.as_bytes()) {
                        Some(b) => replication = b,
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

        let replication = if replication && database_replication {
            ReplicationMode::DatabaseReplication
        } else if replication {
            ReplicationMode::Replication
        } else {
            ReplicationMode::None
        };

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
    use crate::message_common::Scanner;

    #[test]
    fn test_startup_message_parsing_simple() {
        let data = &b"user\0testuser\0database\0testdb\0\0"[..];
        let scanner = Scanner::new(data);
        let version = ProtocolVersion::new(3, 0);
        let msg = StartupMessage::parse_with_version(scanner, version).unwrap();

        assert_eq!(
            msg,
            StartupMessage {
                version,
                database_name: CString::new("testdb").unwrap(),
                user_name: CString::new("testuser").unwrap(),
                cmdline_options: None,
                replication: ReplicationMode::None,
                other_protocol_options: vec![],
                guc_options: vec![],
            }
        );
    }
}
