use std::{
    ffi::CString,
    io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult, Write},
};

use crate::{
    errors::WireFormatError,
    io_util::BufReadPeek,
    message::{ErrorResponse, NoticeResponse},
    message_common::{ReadSizedErrors, ReadWireExt, WriteWireExt},
};

/// A message sent by the server following AuthenticationOk
/// to notify the initialization status of the backend.
///
/// Historically, this message was the first message sent
/// by the backend process launched by the postmaster.
/// Messages before this step were sent by the postmaster itself.
/// Nowadays, all messages are processed by the backend process.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BackendStartupResponse {
    BackendKeyData(BackendKeyData),
    ParameterStatus(ParameterStatus),
    ReadyForQuery(ReadyForQuery),
    ErrorResponse(ErrorResponse),
    NoticeResponse(NoticeResponse),
}

impl From<BackendKeyData> for BackendStartupResponse {
    fn from(value: BackendKeyData) -> Self {
        BackendStartupResponse::BackendKeyData(value)
    }
}

impl From<ParameterStatus> for BackendStartupResponse {
    fn from(value: ParameterStatus) -> Self {
        BackendStartupResponse::ParameterStatus(value)
    }
}

impl From<ReadyForQuery> for BackendStartupResponse {
    fn from(value: ReadyForQuery) -> Self {
        BackendStartupResponse::ReadyForQuery(value)
    }
}

impl From<ErrorResponse> for BackendStartupResponse {
    fn from(value: ErrorResponse) -> Self {
        BackendStartupResponse::ErrorResponse(value)
    }
}

impl From<NoticeResponse> for BackendStartupResponse {
    fn from(value: NoticeResponse) -> Self {
        BackendStartupResponse::NoticeResponse(value)
    }
}

impl BackendStartupResponse {
    pub fn write_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write,
    {
        match self {
            BackendStartupResponse::BackendKeyData(msg) => msg.write_to(writer),
            BackendStartupResponse::ParameterStatus(msg) => msg.write_to(writer),
            BackendStartupResponse::ReadyForQuery(msg) => msg.write_to(writer),
            BackendStartupResponse::ErrorResponse(msg) => msg.write_to(writer),
            BackendStartupResponse::NoticeResponse(msg) => msg.write_to(writer),
        }
    }

    pub fn read_from<R>(reader: &mut R) -> IoResult<Self>
    where
        R: BufReadPeek + ?Sized,
    {
        let type_byte =
            reader.read_u8(&|| WireFormatError::BackendStartupResponseMissingTypeByte)?;
        match type_byte {
            BackendKeyData::TYPE_BYTE => {
                Ok(BackendKeyData::read_after_type_byte(reader, type_byte)?.into())
            }
            ParameterStatus::TYPE_BYTE => {
                Ok(ParameterStatus::read_after_type_byte(reader, type_byte)?.into())
            }
            ReadyForQuery::TYPE_BYTE => {
                Ok(ReadyForQuery::read_after_type_byte(reader, type_byte)?.into())
            }
            ErrorResponse::TYPE_BYTE => {
                Ok(ErrorResponse::read_after_type_byte(reader, type_byte)?.into())
            }
            NoticeResponse::TYPE_BYTE => {
                Ok(NoticeResponse::read_after_type_byte(reader, type_byte)?.into())
            }
            _ => Err(WireFormatError::BackendStartupResponseUnknownTypeByte { type_byte }.into()),
        }
    }
}

/// Contains cancellation key data for the backend.
///
/// Next state: continue in BackendStartupResponse (server active)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BackendKeyData {
    pub process_id: i32,
    // 4 bytes in protocol 3.0, arbitrary length in protocol 3.2
    pub secret_key: Vec<u8>,
}

impl BackendKeyData {
    pub const TYPE_BYTE: u8 = b'K';

    const MAX_SECRET_KEY_LENGTH: usize = 256;

    fn write_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write,
    {
        writer.write_u8(Self::TYPE_BYTE)?;
        writer.write_sized(|writer| self.write_body_to(writer))
    }

    fn write_body_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write,
    {
        self.validate_secret_key_length()?;
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

    fn read_after_type_byte<R>(reader: &mut R, type_byte: u8) -> IoResult<Self>
    where
        R: BufReadPeek + ?Sized,
    {
        assert_eq!(type_byte, Self::TYPE_BYTE);

        reader.read_sized(
            usize::MAX,
            ReadSizedErrors {
                on_incomplete_length: &|| WireFormatError::BackendKeyDataIncompleteLength,
                on_negative_length: &|length| WireFormatError::BackendKeyDataNegativeLength {
                    length,
                },
                on_length_limit_exceeded: &|length, max_length| {
                    WireFormatError::BackendKeyDataTooLarge { length, max_length }
                },
                on_incomplete_body: &|| WireFormatError::BackendKeyDataIncompleteBody,
            },
            |reader| Self::read_body(reader),
        )
    }

    fn read_body<R>(reader: &mut R) -> IoResult<Self>
    where
        R: BufReadPeek + ?Sized,
    {
        let process_id =
            reader.read_u32(&|| WireFormatError::BackendKeyDataIncompleteProcessId)? as i32;
        let secret_key = reader.read_remaining_bytes()?;
        if secret_key.is_empty() {
            return Err(WireFormatError::BackendKeyDataEmptySecretKey.into());
        } else if secret_key.len() > Self::MAX_SECRET_KEY_LENGTH {
            return Err(WireFormatError::BackendKeyDataSecretKeyTooLong {
                length: secret_key.len(),
                max_length: Self::MAX_SECRET_KEY_LENGTH,
            }
            .into());
        }

        Ok(BackendKeyData {
            process_id,
            secret_key,
        })
    }
}

/// Reports a runtime parameter status to the client.
///
/// Next state: continue in BackendStartupResponse (server active)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ParameterStatus {
    pub name: CString,
    pub value: CString,
}

impl ParameterStatus {
    pub const TYPE_BYTE: u8 = b'S';

    fn write_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write,
    {
        writer.write_u8(Self::TYPE_BYTE)?;
        writer.write_sized(|writer| self.write_body_to(writer))
    }

    fn write_body_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write,
    {
        writer.write_cstring(&self.name)?;
        writer.write_cstring(&self.value)?;
        Ok(())
    }

    fn read_after_type_byte<R>(reader: &mut R, type_byte: u8) -> IoResult<Self>
    where
        R: BufReadPeek + ?Sized,
    {
        assert_eq!(type_byte, Self::TYPE_BYTE);

        reader.read_sized(
            usize::MAX,
            ReadSizedErrors {
                on_incomplete_length: &|| WireFormatError::ParameterStatusIncompleteLength,
                on_negative_length: &|length| WireFormatError::ParameterStatusNegativeLength {
                    length,
                },
                on_length_limit_exceeded: &|length, max_length| {
                    WireFormatError::ParameterStatusTooLarge { length, max_length }
                },
                on_incomplete_body: &|| WireFormatError::ParameterStatusIncompleteBody,
            },
            |reader| Self::read_body(reader),
        )
    }

    fn read_body<R>(reader: &mut R) -> IoResult<Self>
    where
        R: BufReadPeek + ?Sized,
    {
        let name = reader.read_cstring(&|| WireFormatError::ParameterStatusUnterminatedName)?;
        let value = reader.read_cstring(&|| WireFormatError::ParameterStatusUnterminatedValue)?;
        reader.read_eof(&|| WireFormatError::ParameterStatusExtraBytes)?;
        Ok(ParameterStatus { name, value })
    }
}

/// Indicates readiness to accept new commands.
///
/// Next state: for startup sequence, this ends BackendStartupResponse,
///             and transitions to normal query cycle (client active)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReadyForQuery {
    pub status: TransactionStatus,
}

impl ReadyForQuery {
    pub const TYPE_BYTE: u8 = b'Z';

    fn write_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write,
    {
        writer.write_u8(Self::TYPE_BYTE)?;
        writer.write_sized(|writer| self.write_body_to(writer))
    }

    fn write_body_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write,
    {
        writer.write_u8(self.status.to_byte())?;
        Ok(())
    }

    fn read_after_type_byte<R>(reader: &mut R, type_byte: u8) -> IoResult<Self>
    where
        R: BufReadPeek + ?Sized,
    {
        assert_eq!(type_byte, Self::TYPE_BYTE);

        reader.read_sized(
            usize::MAX,
            ReadSizedErrors {
                on_incomplete_length: &|| WireFormatError::ReadyForQueryIncompleteLength,
                on_negative_length: &|length| WireFormatError::ReadyForQueryNegativeLength {
                    length,
                },
                on_length_limit_exceeded: &|length, max_length| {
                    WireFormatError::ReadyForQueryTooLarge { length, max_length }
                },
                on_incomplete_body: &|| WireFormatError::ReadyForQueryIncompleteBody,
            },
            |reader| Self::read_body(reader),
        )
    }

    fn read_body<R>(reader: &mut R) -> IoResult<Self>
    where
        R: BufReadPeek + ?Sized,
    {
        let status_byte = reader.read_u8(&|| WireFormatError::ReadyForQueryIncompleteStatus)?;
        let status = TransactionStatus::from_byte(status_byte)
            .ok_or_else(|| WireFormatError::ReadyForQueryInvalidStatus { status_byte })?;
        reader.read_eof(&|| WireFormatError::ReadyForQueryExtraBytes)?;
        Ok(ReadyForQuery { status })
    }
}

/// Transaction status indicator for ReadyForQuery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransactionStatus {
    /// Not in a transaction block (idle)
    Idle,
    /// In a transaction block
    InTransaction,
    /// In a failed transaction block (queries will be rejected until block is ended)
    Failed,
}

impl TransactionStatus {
    fn to_byte(self) -> u8 {
        match self {
            TransactionStatus::Idle => b'I',
            TransactionStatus::InTransaction => b'T',
            TransactionStatus::Failed => b'E',
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            b'I' => Some(TransactionStatus::Idle),
            b'T' => Some(TransactionStatus::InTransaction),
            b'E' => Some(TransactionStatus::Failed),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_bytes(msg: &BackendStartupResponse) -> IoResult<Vec<u8>> {
        let mut buf = Vec::new();
        msg.write_to(&mut buf)?;
        Ok(buf)
    }

    /// Helper function to focus on the packet body only.
    ///
    /// Use this in most tests, but include one test per type_byte
    /// to test the full packet writing.
    #[track_caller]
    fn decompose_packet(bytes: Vec<u8>) -> (u8, Vec<u8>) {
        assert!(!bytes.is_empty());
        let type_byte = bytes[0];
        let size = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
        assert_eq!(size, bytes.len() - 1);
        (type_byte, bytes[5..].to_vec())
    }

    #[track_caller]
    fn to_body_bytes(msg: &BackendStartupResponse) -> IoResult<(u8, Vec<u8>)> {
        Ok(decompose_packet(to_bytes(msg)?))
    }

    fn from_bytes(data: &[u8]) -> IoResult<BackendStartupResponse> {
        let mut reader = data;
        BackendStartupResponse::read_from(&mut reader)
    }

    /// Helper function to focus on the packet body only.
    ///
    /// Use this in most tests, but include one test per type_byte
    /// to test the full packet writing.
    fn compose_packet(type_byte: u8, data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(type_byte);
        buf.extend_from_slice(&((data.len() + 4) as u32).to_be_bytes());
        buf.extend_from_slice(data);
        buf
    }

    fn from_body_bytes(type_byte: u8, data: &[u8]) -> IoResult<BackendStartupResponse> {
        from_bytes(&compose_packet(type_byte, data))
    }

    // Packet tests for BackendKeyData (type byte 'K')
    #[test]
    fn test_backend_key_data_writing_packet() {
        let msg = BackendStartupResponse::BackendKeyData(BackendKeyData {
            process_id: 12345,
            secret_key: vec![0, 1, 9, 50],
        });
        let bytes = to_bytes(&msg).unwrap();
        assert_eq!(bytes[0], b'K');
        assert_eq!(&bytes[1..5], &[0, 0, 0, 12]); // size = 4 + 8
    }

    #[test]
    fn test_backend_key_data_parsing_packet() {
        let data = compose_packet(b'K', &[0, 0, 48, 57, 0, 1, 9, 50]);
        let msg = from_bytes(&data).unwrap();
        assert_eq!(
            msg,
            BackendStartupResponse::BackendKeyData(BackendKeyData {
                process_id: 12345,
                secret_key: vec![0, 1, 9, 50],
            })
        );
    }

    // Packet tests for ParameterStatus (type byte 'S')
    #[test]
    fn test_parameter_status_writing_packet() {
        let msg = BackendStartupResponse::ParameterStatus(ParameterStatus {
            name: CString::new("server_version").unwrap(),
            value: CString::new("14.1").unwrap(),
        });
        let bytes = to_bytes(&msg).unwrap();
        assert_eq!(bytes[0], b'S');
    }

    #[test]
    fn test_parameter_status_parsing_packet() {
        let mut body = Vec::new();
        body.extend_from_slice(b"server_version\0");
        body.extend_from_slice(b"14.1\0");
        let data = compose_packet(b'S', &body);
        let msg = from_bytes(&data).unwrap();
        assert_eq!(
            msg,
            BackendStartupResponse::ParameterStatus(ParameterStatus {
                name: CString::new("server_version").unwrap(),
                value: CString::new("14.1").unwrap(),
            })
        );
    }

    // Packet tests for ReadyForQuery (type byte 'Z')
    #[test]
    fn test_ready_for_query_writing_packet() {
        let msg = BackendStartupResponse::ReadyForQuery(ReadyForQuery {
            status: TransactionStatus::Idle,
        });
        let bytes = to_bytes(&msg).unwrap();
        assert_eq!(bytes[0], b'Z');
        assert_eq!(&bytes[1..5], &[0, 0, 0, 5]); // size = 4 + 1
    }

    #[test]
    fn test_ready_for_query_parsing_packet() {
        let data = compose_packet(b'Z', &[b'I']);
        let msg = from_bytes(&data).unwrap();
        assert_eq!(
            msg,
            BackendStartupResponse::ReadyForQuery(ReadyForQuery {
                status: TransactionStatus::Idle,
            })
        );
    }

    // Body tests for BackendKeyData
    #[test]
    fn test_backend_key_data_writing() {
        let msg = BackendStartupResponse::BackendKeyData(BackendKeyData {
            process_id: 12345,
            secret_key: vec![0, 1, 9, 50],
        });
        let (type_byte, body) = to_body_bytes(&msg).unwrap();
        assert_eq!(type_byte, b'K');
        assert_eq!(body, vec![0, 0, 48, 57, 0, 1, 9, 50]);
    }

    #[test]
    fn test_backend_key_data_parsing() {
        let msg = from_body_bytes(b'K', &[0, 0, 48, 57, 0, 1, 9, 50]).unwrap();
        assert_eq!(
            msg,
            BackendStartupResponse::BackendKeyData(BackendKeyData {
                process_id: 12345,
                secret_key: vec![0, 1, 9, 50],
            })
        );
    }

    // Body tests for ParameterStatus
    #[test]
    fn test_parameter_status_writing() {
        let msg = BackendStartupResponse::ParameterStatus(ParameterStatus {
            name: CString::new("server_version").unwrap(),
            value: CString::new("14.1").unwrap(),
        });
        let (type_byte, body) = to_body_bytes(&msg).unwrap();
        assert_eq!(type_byte, b'S');
        let mut expected = Vec::new();
        expected.extend_from_slice(b"server_version\0");
        expected.extend_from_slice(b"14.1\0");
        assert_eq!(body, expected);
    }

    #[test]
    fn test_parameter_status_parsing() {
        let mut body = Vec::new();
        body.extend_from_slice(b"server_version\0");
        body.extend_from_slice(b"14.1\0");
        let msg = from_body_bytes(b'S', &body).unwrap();
        assert_eq!(
            msg,
            BackendStartupResponse::ParameterStatus(ParameterStatus {
                name: CString::new("server_version").unwrap(),
                value: CString::new("14.1").unwrap(),
            })
        );
    }

    // Body tests for ReadyForQuery
    #[test]
    fn test_ready_for_query_idle_writing() {
        let msg = BackendStartupResponse::ReadyForQuery(ReadyForQuery {
            status: TransactionStatus::Idle,
        });
        let (type_byte, body) = to_body_bytes(&msg).unwrap();
        assert_eq!(type_byte, b'Z');
        assert_eq!(body, vec![b'I']);
    }

    #[test]
    fn test_ready_for_query_idle_parsing() {
        let msg = from_body_bytes(b'Z', &[b'I']).unwrap();
        assert_eq!(
            msg,
            BackendStartupResponse::ReadyForQuery(ReadyForQuery {
                status: TransactionStatus::Idle,
            })
        );
    }

    #[test]
    fn test_ready_for_query_in_transaction_writing() {
        let msg = BackendStartupResponse::ReadyForQuery(ReadyForQuery {
            status: TransactionStatus::InTransaction,
        });
        let (type_byte, body) = to_body_bytes(&msg).unwrap();
        assert_eq!(type_byte, b'Z');
        assert_eq!(body, vec![b'T']);
    }

    #[test]
    fn test_ready_for_query_in_transaction_parsing() {
        let msg = from_body_bytes(b'Z', &[b'T']).unwrap();
        assert_eq!(
            msg,
            BackendStartupResponse::ReadyForQuery(ReadyForQuery {
                status: TransactionStatus::InTransaction,
            })
        );
    }

    #[test]
    fn test_ready_for_query_failed_writing() {
        let msg = BackendStartupResponse::ReadyForQuery(ReadyForQuery {
            status: TransactionStatus::Failed,
        });
        let (type_byte, body) = to_body_bytes(&msg).unwrap();
        assert_eq!(type_byte, b'Z');
        assert_eq!(body, vec![b'E']);
    }

    #[test]
    fn test_ready_for_query_failed_parsing() {
        let msg = from_body_bytes(b'Z', &[b'E']).unwrap();
        assert_eq!(
            msg,
            BackendStartupResponse::ReadyForQuery(ReadyForQuery {
                status: TransactionStatus::Failed,
            })
        );
    }

    // Error tests
    #[test]
    fn test_parse_error_unknown_type_byte() {
        let data = compose_packet(b'X', &[]);
        let result = from_bytes(&data);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let wire_err = WireFormatError::try_extract_ref(&err).unwrap();
        assert!(matches!(
            wire_err,
            WireFormatError::BackendStartupResponseUnknownTypeByte { type_byte: b'X' }
        ));
    }

    #[test]
    fn test_parse_error_backend_key_data_incomplete_process_id() {
        let data = compose_packet(b'K', &[0, 0, 48]);
        let result = from_bytes(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_error_backend_key_data_empty_secret_key() {
        let data = compose_packet(b'K', &[0, 0, 48, 57]);
        let result = from_bytes(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_error_backend_key_data_secret_key_too_long() {
        let mut body = vec![0, 0, 48, 57];
        body.extend(vec![0u8; 257]); // 257 bytes > MAX_SECRET_KEY_LENGTH (256)
        let data = compose_packet(b'K', &body);
        let result = from_bytes(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_error_parameter_status_incomplete_name() {
        let data = compose_packet(b'S', b"server");
        let result = from_bytes(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_error_parameter_status_incomplete_value() {
        let data = compose_packet(b'S', b"server_version\014");
        let result = from_bytes(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_error_parameter_status_extra_bytes() {
        let mut body = Vec::new();
        body.extend_from_slice(b"server_version\0");
        body.extend_from_slice(b"14.1\0");
        body.push(99);
        let data = compose_packet(b'S', &body);
        let result = from_bytes(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_error_ready_for_query_invalid_status() {
        let data = compose_packet(b'Z', &[b'X']);
        let result = from_bytes(&data);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let wire_err = WireFormatError::try_extract_ref(&err).unwrap();
        assert!(matches!(
            wire_err,
            WireFormatError::ReadyForQueryInvalidStatus { status_byte: b'X' }
        ));
    }

    #[test]
    fn test_parse_error_ready_for_query_extra_bytes() {
        let data = compose_packet(b'Z', &[b'I', 99]);
        let result = from_bytes(&data);
        assert!(result.is_err());
    }
}
