use std::{
    ffi::CString,
    io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult, Write},
};

use crate::{
    ProtocolVersion,
    common::GetReadBuf,
    message_common::{ReadWireExt, WireFormatError, WriteWireExt},
};

/// A message sent by the client as the first message on a new connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InitialRequest {
    StartupMessage(StartupMessage),
    SSLRequest(SSLRequest),
    GSSENCRequest(GSSENCRequest),
    CancelRequest(CancelRequest),
}

impl From<StartupMessage> for InitialRequest {
    fn from(msg: StartupMessage) -> Self {
        InitialRequest::StartupMessage(msg)
    }
}

impl From<SSLRequest> for InitialRequest {
    fn from(msg: SSLRequest) -> Self {
        InitialRequest::SSLRequest(msg)
    }
}

impl From<GSSENCRequest> for InitialRequest {
    fn from(msg: GSSENCRequest) -> Self {
        InitialRequest::GSSENCRequest(msg)
    }
}

impl From<CancelRequest> for InitialRequest {
    fn from(msg: CancelRequest) -> Self {
        InitialRequest::CancelRequest(msg)
    }
}

impl InitialRequest {
    const MAX_STARTUP_PACKET_LENGTH: usize = 10000;

    pub fn write_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        writer.write_sized(|writer| self.write_body_to(writer))
    }

    pub fn write_body_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        match self {
            InitialRequest::StartupMessage(msg) => msg.write_body_to(writer),
            InitialRequest::SSLRequest(msg) => msg.write_body_to(writer),
            InitialRequest::GSSENCRequest(msg) => msg.write_body_to(writer),
            InitialRequest::CancelRequest(msg) => msg.write_body_to(writer),
        }
    }

    pub fn read_from<R>(reader: &mut R) -> IoResult<Self>
    where
        R: GetReadBuf + ?Sized,
    {
        reader.read_sized(|reader| Self::read_body_from(reader))
    }

    pub fn read_body_from<R>(reader: &mut R) -> IoResult<Self>
    where
        R: GetReadBuf + ?Sized,
    {
        let version = reader.read_version()?;

        match version {
            SSLRequest::VERSION => Ok(SSLRequest::read_after_version(reader, version)?.into()),
            GSSENCRequest::VERSION => {
                Ok(GSSENCRequest::read_after_version(reader, version)?.into())
            }
            CancelRequest::VERSION => {
                Ok(CancelRequest::read_after_version(reader, version)?.into())
            }
            _ => Ok(StartupMessage::read_after_version(reader, version)?.into()),
        }
    }
}

/// A request to initiate an ordinary session.
///
/// Next state: StartupResponse (server active)
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
    fn write_body_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        // fe-protocol3.c, build_startup_packet

        writer.write_version(self.version)?;
        writer.write_bytes(b"user\0")?;
        writer.write_cstring(self.user_name.as_c_str())?;
        writer.write_bytes(b"database\0")?;
        writer.write_cstring(self.database_name.as_c_str())?;
        if let Some(options) = &self.cmdline_options {
            writer.write_bytes(b"options\0")?;
            writer.write_cstring(options)?;
        }
        self.write_replication_mode_to(writer)?;
        self.write_protocol_options_to(writer)?;
        self.write_guc_options_to(writer)?;
        writer.write_u8(0)?;

        Ok(())
    }

    fn write_replication_mode_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        match self.replication {
            ReplicationMode::DatabaseReplication => {
                writer.write_bytes(b"replication\0database\0")?;
            }
            ReplicationMode::Replication => {
                writer.write_bytes(b"replication\0true\0")?;
            }
            ReplicationMode::None => {}
        }

        Ok(())
    }

    fn write_protocol_options_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        for (name, value) in &self.other_protocol_options {
            Self::validate_protocol_option(name, value)?;
            writer.write_cstring(name.as_c_str())?;
            writer.write_cstring(value.as_c_str())?;
        }

        Ok(())
    }

    fn validate_protocol_option(name: &CString, _value: &CString) -> IoResult<()> {
        if !name.as_bytes().starts_with(b"_pq_.") {
            return Err(IoError::new(
                IoErrorKind::InvalidInput,
                "protocol option name must start with `_pq_.`",
            ));
        }
        Ok(())
    }

    fn write_guc_options_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        for (name, value) in &self.guc_options {
            Self::validate_guc_option(name, value)?;
            writer.write_cstring(name.as_c_str())?;
            writer.write_cstring(value.as_c_str())?;
        }

        Ok(())
    }

    fn validate_guc_option(name: &CString, _value: &CString) -> IoResult<()> {
        if name.as_bytes().is_empty() {
            return Err(IoError::new(
                IoErrorKind::InvalidInput,
                "GUC option name must not be empty",
            ));
        }
        if name.as_bytes().starts_with(b"_pq_.") {
            return Err(IoError::new(
                IoErrorKind::InvalidInput,
                "GUC option name must not start with `_pq_.`",
            ));
        }
        Ok(())
    }

    fn read_after_version<R>(reader: &mut R, version: ProtocolVersion) -> IoResult<Self>
    where
        R: GetReadBuf + ?Sized,
    {
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
            let name = reader
                .read_cstring()
                .map_err(|_| WireFormatError::StartupPacketUnterminatedString)?;
            if name.is_empty() {
                break;
            }
            let value = reader
                .read_cstring()
                .map_err(|_| WireFormatError::StartupPacketUnterminatedString)?;

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
                            }
                            .into());
                        }
                    },
                },
                _ if name.as_bytes().starts_with(b"_pq_.") => {
                    other_protocol_options.push((name, value));
                }
                _ => guc_options.push((name, value)),
            }
        }

        reader
            .read_eof()
            .map_err(|_| WireFormatError::StartupPacketExtraBytes)?;

        if user_name.as_ref().is_some_and(|s| s.is_empty()) {
            user_name = None;
        }

        let Some(user_name) = user_name else {
            return Err(WireFormatError::MissingUserName.into());
        };

        if database_name.as_ref().is_some_and(|s| s.is_empty()) {
            database_name = None;
        }

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

/// A request to initiate SSL-encrypted communication.
///
/// Next state: SSLResponse (server active)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SSLRequest;

impl SSLRequest {
    const VERSION: ProtocolVersion = ProtocolVersion::new(1234, 5679);

    fn write_body_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        writer.write_version(Self::VERSION)?;

        Ok(())
    }

    fn read_after_version<R>(reader: &mut R, version: ProtocolVersion) -> IoResult<Self>
    where
        R: GetReadBuf + ?Sized,
    {
        // See: backend_startup.c, ProcessStartupPacket

        assert_eq!(version, Self::VERSION);

        // Subtle difference from PostgreSQL:
        // PostgreSQL does not check EOF here, but we do.
        reader
            .read_eof()
            .map_err(|_| WireFormatError::SSLRequestExtraBytes)?;

        Ok(SSLRequest)
    }
}

/// A request to initiate GSSENC-encrypted communication.
///
/// Next state: GSSENCResponse (server active)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GSSENCRequest;

impl GSSENCRequest {
    const VERSION: ProtocolVersion = ProtocolVersion::new(1234, 5680);

    fn write_body_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        writer.write_version(Self::VERSION)?;

        Ok(())
    }

    fn read_after_version<R>(reader: &mut R, version: ProtocolVersion) -> IoResult<Self>
    where
        R: GetReadBuf + ?Sized,
    {
        // See: backend_startup.c, ProcessStartupPacket

        assert_eq!(version, Self::VERSION);

        // Subtle difference from PostgreSQL:
        // PostgreSQL does not check EOF here, but we do.
        reader
            .read_eof()
            .map_err(|_| WireFormatError::GSSENCRequestExtraBytes)?;

        Ok(GSSENCRequest)
    }
}

/// A request to cancel a running query on a different connection.
///
/// Next state: connection close
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CancelRequest {
    pub process_id: i32,
    // 4 bytes in protocol 3.0, arbitrary length in protocol 3.2
    pub secret_key: Vec<u8>,
}

impl CancelRequest {
    const VERSION: ProtocolVersion = ProtocolVersion::new(1234, 5678);

    const MAX_SECRET_KEY_LENGTH: usize = 256;

    fn write_body_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        self.validate_secret_key_length()?;
        writer.write_version(Self::VERSION)?;
        writer.write_u32(self.process_id as u32)?;
        writer.write_bytes(&self.secret_key)?;

        Ok(())
    }

    fn validate_secret_key_length(&self) -> IoResult<()> {
        let length = self.secret_key.len();
        if length > Self::MAX_SECRET_KEY_LENGTH {
            return Err(IoError::new(
                IoErrorKind::InvalidInput,
                "secret key too long",
            ));
        } else if length == 0 {
            return Err(IoError::new(
                IoErrorKind::InvalidInput,
                "secret key must not be empty",
            ));
        }
        Ok(())
    }

    fn read_after_version<R>(reader: &mut R, version: ProtocolVersion) -> IoResult<Self>
    where
        R: GetReadBuf + ?Sized,
    {
        // See: backend_startup.c, ProcessCancelRequestPacket

        assert_eq!(version, Self::VERSION);

        let process_id = reader
            .read_u32()
            .map_err(|_| WireFormatError::CancelRequestIncompleteProcessId)?
            as i32;
        let secret_key = reader.read_remaining_bytes()?;
        if secret_key.is_empty() {
            return Err(WireFormatError::CancelRequestMissingSecretKey.into());
        } else if secret_key.len() > Self::MAX_SECRET_KEY_LENGTH {
            return Err(WireFormatError::CancelRequestSecretKeyTooLong {
                length: secret_key.len(),
                max_length: Self::MAX_SECRET_KEY_LENGTH,
            }
            .into());
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

    fn to_bytes(msg: &InitialRequest) -> IoResult<Vec<u8>> {
        let mut buf = Vec::new();
        msg.write_body_to(&mut buf)?;
        Ok(buf)
    }

    fn from_bytes(data: &[u8]) -> IoResult<InitialRequest> {
        let mut reader = data;
        InitialRequest::read_body_from(&mut reader)
    }

    #[test]
    fn test_startup_message_writing_simple() {
        let msg = StartupMessage {
            version: ProtocolVersion::new(3, 0),
            database_name: CString::new("testdb").unwrap(),
            user_name: CString::new("testuser").unwrap(),
            cmdline_options: None,
            replication: ReplicationMode::None,
            other_protocol_options: vec![],
            guc_options: vec![],
        }
        .into();
        assert_eq!(
            to_bytes(&msg).unwrap(),
            b"\x00\x03\x00\x00user\0testuser\0database\0testdb\0\0"
        );
    }

    #[test]
    fn test_startup_message_writing_cmdline_options() {
        let msg = StartupMessage {
            version: ProtocolVersion::new(3, 0),
            database_name: CString::new("testdb").unwrap(),
            user_name: CString::new("testuser").unwrap(),
            cmdline_options: Some(CString::new("-S 8192").unwrap()),
            replication: ReplicationMode::None,
            other_protocol_options: vec![],
            guc_options: vec![],
        }
        .into();
        assert_eq!(
            to_bytes(&msg).unwrap(),
            b"\x00\x03\x00\x00user\0testuser\0database\0testdb\0options\0-S 8192\0\0"
        );
    }

    #[test]
    fn test_startup_message_writing_replication_database() {
        let msg = StartupMessage {
            version: ProtocolVersion::new(3, 0),
            database_name: CString::new("testdb").unwrap(),
            user_name: CString::new("testuser").unwrap(),
            cmdline_options: None,
            replication: ReplicationMode::DatabaseReplication,
            other_protocol_options: vec![],
            guc_options: vec![],
        }
        .into();
        assert_eq!(
            to_bytes(&msg).unwrap(),
            b"\x00\x03\x00\x00user\0testuser\0database\0testdb\0replication\0database\0\0"
        );
    }

    #[test]
    fn test_startup_message_writing_replication_true() {
        let msg = StartupMessage {
            version: ProtocolVersion::new(3, 0),
            database_name: CString::new("testdb").unwrap(),
            user_name: CString::new("testuser").unwrap(),
            cmdline_options: None,
            replication: ReplicationMode::Replication,
            other_protocol_options: vec![],
            guc_options: vec![],
        }
        .into();
        assert_eq!(
            to_bytes(&msg).unwrap(),
            b"\x00\x03\x00\x00user\0testuser\0database\0testdb\0replication\0true\0\0"
        );
    }

    #[test]
    fn test_startup_message_writing_protocol_options() {
        let msg = StartupMessage {
            version: ProtocolVersion::new(3, 0),
            database_name: CString::new("testdb").unwrap(),
            user_name: CString::new("testuser").unwrap(),
            cmdline_options: None,
            replication: ReplicationMode::None,
            other_protocol_options: vec![
                (
                    CString::new("_pq_.foo").unwrap(),
                    CString::new("bar").unwrap(),
                ),
                (
                    CString::new("_pq_.baz").unwrap(),
                    CString::new("qux").unwrap(),
                ),
            ],
            guc_options: vec![],
        }
        .into();
        assert_eq!(
            to_bytes(&msg).unwrap(),
            b"\x00\x03\x00\x00user\0testuser\0database\0testdb\0_pq_.foo\0bar\0_pq_.baz\0qux\0\0"
        );
    }

    #[test]
    fn test_startup_message_writing_guc_options() {
        let msg = StartupMessage {
            version: ProtocolVersion::new(3, 0),
            database_name: CString::new("testdb").unwrap(),
            user_name: CString::new("testuser").unwrap(),
            cmdline_options: None,
            replication: ReplicationMode::None,
            other_protocol_options: vec![],
            guc_options: vec![
                (
                    CString::new("search_path").unwrap(),
                    CString::new("public,custom").unwrap(),
                ),
                (
                    CString::new("application_name").unwrap(),
                    CString::new("myapp").unwrap(),
                ),
            ],
        }
        .into();
        assert_eq!(
            to_bytes(&msg).unwrap(),
            b"\x00\x03\x00\x00user\0testuser\0database\0testdb\0search_path\0public,custom\0application_name\0myapp\0\0"
        );
    }

    #[test]
    fn test_startup_message_parsing_simple() {
        let data = &b"\x00\x03\x00\x00user\0testuser\0database\0testdb\0\0"[..];
        let msg = from_bytes(data).unwrap();

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
    fn test_startup_message_parsing_missing_database_fallback() {
        let data = &b"\x00\x03\x00\x00user\0testuser\0\0"[..];
        let msg = from_bytes(data).unwrap();

        assert_eq!(
            msg,
            StartupMessage {
                version: ProtocolVersion::new(3, 0),
                database_name: CString::new("testuser").unwrap(),
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
    fn test_startup_message_parsing_empty_database_fallback() {
        let data = &b"\x00\x03\x00\x00user\0testuser\0database\0\0\0"[..];
        let msg = from_bytes(data).unwrap();

        assert_eq!(
            msg,
            StartupMessage {
                version: ProtocolVersion::new(3, 0),
                database_name: CString::new("testuser").unwrap(),
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
    fn test_startup_message_parsing_cmdline_options() {
        let data = &b"\x00\x03\x00\x00user\0testuser\0database\0testdb\0options\0-S 8192\0\0"[..];
        let msg = from_bytes(data).unwrap();

        assert_eq!(
            msg,
            StartupMessage {
                version: ProtocolVersion::new(3, 0),
                database_name: CString::new("testdb").unwrap(),
                user_name: CString::new("testuser").unwrap(),
                cmdline_options: Some(CString::new("-S 8192").unwrap()),
                replication: ReplicationMode::None,
                other_protocol_options: vec![],
                guc_options: vec![],
            }
            .into()
        );
    }

    #[test]
    fn test_startup_message_parsing_replication_database() {
        let data =
            &b"\x00\x03\x00\x00user\0testuser\0database\0testdb\0replication\0database\0\0"[..];
        let msg = from_bytes(data).unwrap();

        assert_eq!(
            msg,
            StartupMessage {
                version: ProtocolVersion::new(3, 0),
                database_name: CString::new("testdb").unwrap(),
                user_name: CString::new("testuser").unwrap(),
                cmdline_options: None,
                replication: ReplicationMode::DatabaseReplication,
                other_protocol_options: vec![],
                guc_options: vec![],
            }
            .into()
        );
    }

    #[test]
    fn test_startup_message_parsing_replication_true() {
        let data = &b"\x00\x03\x00\x00user\0testuser\0database\0testdb\0replication\0true\0\0"[..];
        let msg = from_bytes(data).unwrap();

        assert_eq!(
            msg,
            StartupMessage {
                version: ProtocolVersion::new(3, 0),
                database_name: CString::new("testdb").unwrap(),
                user_name: CString::new("testuser").unwrap(),
                cmdline_options: None,
                replication: ReplicationMode::Replication,
                other_protocol_options: vec![],
                guc_options: vec![],
            }
            .into()
        );
    }

    #[test]
    fn test_startup_message_parsing_replication_false() {
        let data = &b"\x00\x03\x00\x00user\0testuser\0database\0testdb\0replication\0false\0\0"[..];
        let msg = from_bytes(data).unwrap();

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
    fn test_startup_message_parsing_protocol_options() {
        let data =
            &b"\x00\x03\x00\x00user\0testuser\0database\0testdb\0_pq_.foo\0bar\0_pq_.baz\0qux\0\0"
                [..];
        let msg = from_bytes(data).unwrap();

        assert_eq!(
            msg,
            StartupMessage {
                version: ProtocolVersion::new(3, 0),
                database_name: CString::new("testdb").unwrap(),
                user_name: CString::new("testuser").unwrap(),
                cmdline_options: None,
                replication: ReplicationMode::None,
                other_protocol_options: vec![
                    (
                        CString::new("_pq_.foo").unwrap(),
                        CString::new("bar").unwrap()
                    ),
                    (
                        CString::new("_pq_.baz").unwrap(),
                        CString::new("qux").unwrap()
                    ),
                ],
                guc_options: vec![],
            }
            .into()
        );
    }

    #[test]
    fn test_startup_message_parsing_guc_options() {
        let data = &b"\x00\x03\x00\x00user\0testuser\0database\0testdb\0work_mem\04096\0search_path\0public\0\0"
            [..];
        let msg = from_bytes(data).unwrap();

        assert_eq!(
            msg,
            StartupMessage {
                version: ProtocolVersion::new(3, 0),
                database_name: CString::new("testdb").unwrap(),
                user_name: CString::new("testuser").unwrap(),
                cmdline_options: None,
                replication: ReplicationMode::None,
                other_protocol_options: vec![],
                guc_options: vec![
                    (
                        CString::new("work_mem").unwrap(),
                        CString::new("4096").unwrap()
                    ),
                    (
                        CString::new("search_path").unwrap(),
                        CString::new("public").unwrap()
                    ),
                ],
            }
            .into()
        );
    }

    #[test]
    fn test_startup_message_parse_error_unterminated_name() {
        let data = &b"\x00\x03\x00\x00user"[..];
        let err = from_bytes(data).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid startup packet layout: expected terminator as last byte"
        );
    }

    #[test]
    fn test_startup_message_parse_error_unterminated_value() {
        let data = &b"\x00\x03\x00\x00user\0testuser"[..];
        let err = from_bytes(data).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid startup packet layout: expected terminator as last byte"
        );
    }

    #[test]
    fn test_startup_message_parse_error_extra_bytes() {
        let data = &b"\x00\x03\x00\x00user\0testuser\0database\0testdb\0\0extra"[..];
        let err = from_bytes(data).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid startup packet layout: expected terminator as last byte"
        );
    }

    #[test]
    fn test_startup_message_parse_error_missing_username() {
        let data = &b"\x00\x03\x00\x00database\0testdb\0\0"[..];
        let err = from_bytes(data).unwrap_err();

        assert_eq!(
            err.to_string(),
            "no PostgreSQL user name specified in startup packet"
        );
    }

    #[test]
    fn test_startup_message_parse_error_empty_username() {
        let data = &b"\x00\x03\x00\x00user\0\0database\0testdb\0\0"[..];
        let err = from_bytes(data).unwrap_err();

        assert_eq!(
            err.to_string(),
            "no PostgreSQL user name specified in startup packet"
        );
    }

    #[test]
    fn test_ssl_request_writing() {
        let msg = SSLRequest.into();

        // 0x04D2 = 1234, 0x162F = 5679
        assert_eq!(to_bytes(&msg).unwrap(), b"\x04\xD2\x16\x2F");
    }

    #[test]
    fn test_ssl_request_parsing() {
        // 0x04D2 = 1234, 0x162F = 5679
        let data = &b"\x04\xD2\x16\x2F"[..];
        let msg = from_bytes(data).unwrap();

        assert_eq!(msg, SSLRequest.into());
    }

    #[test]
    fn test_ssl_request_parse_error_extra_bytes() {
        // 0x04D2 = 1234, 0x162F = 5679
        let data = &b"\x04\xD2\x16\x2Ffoo"[..];
        let err = from_bytes(data).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid SSL/TLS request packet layout: expected empty body"
        );
    }

    #[test]
    fn test_gssenc_request_writing() {
        let msg = GSSENCRequest.into();

        // 0x04D2 = 1234, 0x1630 = 5680
        assert_eq!(to_bytes(&msg).unwrap(), b"\x04\xD2\x16\x30");
    }

    #[test]
    fn test_gssenc_request_parsing() {
        // 0x04D2 = 1234, 0x1630 = 5680
        let data = &b"\x04\xD2\x16\x30"[..];
        let msg = from_bytes(data).unwrap();

        assert_eq!(msg, GSSENCRequest.into());
    }

    #[test]
    fn test_gssenc_request_parse_error_extra_bytes() {
        // 0x04D2 = 1234, 0x1630 = 5680
        let data = &b"\x04\xD2\x16\x30foo"[..];
        let err = from_bytes(data).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid GSSENC request packet layout: expected empty body"
        );
    }

    #[test]
    fn test_cancel_request_writing_simple() {
        let msg = CancelRequest {
            process_id: 12345,
            secret_key: b"secretkeydata".to_vec(),
        }
        .into();
        // 0x04D2 = 1234, 0x162E = 5678
        assert_eq!(
            to_bytes(&msg).unwrap(),
            b"\x04\xD2\x16\x2E\x00\x00\x30\x39secretkeydata"
        );
    }

    #[test]
    fn test_cancel_request_writing_min_length() {
        let msg = CancelRequest {
            process_id: 12345,
            secret_key: b"x".to_vec(),
        }
        .into();
        // 0x04D2 = 1234, 0x162E = 5678
        assert_eq!(
            to_bytes(&msg).unwrap(),
            b"\x04\xD2\x16\x2E\x00\x00\x30\x39x"
        );
    }

    #[test]
    fn test_cancel_request_writing_max_length() {
        let msg = CancelRequest {
            process_id: 12345,
            secret_key: b"a".repeat(256),
        }
        .into();
        // 0x04D2 = 1234, 0x162E = 5678
        assert_eq!(to_bytes(&msg).unwrap(), {
            let mut v = b"\x04\xD2\x16\x2E\x00\x00\x30\x39".to_vec();
            v.extend(b"a".repeat(256));
            v
        });
    }

    #[test]
    fn test_cancel_request_parsing_simple() {
        // 0x04D2 = 1234, 0x162E = 5678
        let data = &b"\x04\xD2\x16\x2E\x00\x00\x30\x39secretkeydata"[..];
        let msg = from_bytes(data).unwrap();

        assert_eq!(
            msg,
            CancelRequest {
                process_id: 12345,
                secret_key: b"secretkeydata".to_vec(),
            }
            .into()
        );
    }

    #[test]
    fn test_cancel_request_parsing_min_length() {
        // 0x04D2 = 1234, 0x162E = 5678
        let data = &b"\x04\xD2\x16\x2E\x00\x00\x30\x39x"[..];
        let msg = from_bytes(data).unwrap();

        assert_eq!(
            msg,
            CancelRequest {
                process_id: 12345,
                secret_key: b"x".to_vec(),
            }
            .into()
        );
    }

    #[test]
    fn test_cancel_request_parsing_max_length() {
        // 0x04D2 = 1234, 0x162E = 5678
        let mut data = b"\x04\xD2\x16\x2E\x00\x00\x30\x39".to_vec();
        data.extend(b"a".repeat(256));
        let msg = from_bytes(&data).unwrap();

        assert_eq!(
            msg,
            CancelRequest {
                process_id: 12345,
                secret_key: b"a".repeat(256),
            }
            .into()
        );
    }

    #[test]
    fn test_cancel_request_parse_error_incomplete_process_id() {
        // 0x04D2 = 1234, 0x162E = 5678
        let data = &b"\x04\xD2\x16\x2E\x00\x00\x30"[..];
        let err = from_bytes(data).unwrap_err();

        assert_eq!(err.to_string(), "invalid length of cancel request packet");
    }

    #[test]
    fn test_cancel_request_parse_error_missing_secret_key() {
        // 0x04D2 = 1234, 0x162E = 5678
        let data = &b"\x04\xD2\x16\x2E\x00\x00\x30\x39"[..];
        let err = from_bytes(data).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid length of cancel key in cancel request packet"
        );
    }

    #[test]
    fn test_cancel_request_parse_error_secret_key_too_long() {
        // 0x04D2 = 1234, 0x162E = 5678
        let mut data = b"\x04\xD2\x16\x2E\x00\x00\x30\x39".to_vec();
        data.extend(b"a".repeat(257));
        let err = from_bytes(&data).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid length of cancel key in cancel request packet",
        );
    }
}
