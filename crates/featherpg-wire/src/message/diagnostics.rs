use std::{
    ffi::CString,
    io::{Result as IoResult, Write},
};

use crate::{
    common::GetReadBuf,
    errors::{DiagnosticMessage, DiagnosticSeverity, WireFormatError},
    message_common::{ReadSizedErrors, ReadWireExt, WriteWireExt},
};

/// Indicates an error that occurred during processing of a client message.
///
/// For session startup, this is an unrecoverable error and
/// the connection is closed afterwards.
///
/// For requests during an established session, this indicates
/// a failure to process the specific request, and the session
/// continues afterwards.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ErrorResponse {
    pub error: DiagnosticMessage,
}

impl ErrorResponse {
    pub const TYPE_BYTE: u8 = b'E';

    pub fn write_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        writer.write_u8(Self::TYPE_BYTE)?;
        let mut buf = Vec::new();
        self.write_body_to(&mut buf)?;
        writer.write_usize32(buf.len() + 4)?;
        writer.write_bytes(&buf)?;

        Ok(())
    }

    pub fn write_body_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        write_diagnostic_to(&self.error, writer)
    }

    pub fn read_after_type_byte<R>(reader: &mut R) -> IoResult<Self>
    where
        R: GetReadBuf + ?Sized,
    {
        let error = read_diagnostic(reader)?;
        Ok(ErrorResponse { error })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NoticeResponse {
    pub notice: DiagnosticMessage,
}

impl NoticeResponse {
    pub const TYPE_BYTE: u8 = b'N';

    pub fn write_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        let mut buf = Vec::new();
        self.write_body_to(&mut buf)?;
        writer.write_usize32(buf.len() + 4)?;
        writer.write_bytes(&buf)?;

        Ok(())
    }

    pub fn write_body_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        write_diagnostic_to(&self.notice, writer)
    }

    pub fn read_after_type_byte<R>(reader: &mut R) -> IoResult<Self>
    where
        R: GetReadBuf + ?Sized,
    {
        let notice = read_diagnostic(reader)?;
        Ok(NoticeResponse { notice })
    }
}

const FIELD_LOCALIZED_SEVERITY: u8 = b'S';
const FIELD_SEVERITY: u8 = b'V';
const FIELD_CODE: u8 = b'C';
const FIELD_MESSAGE: u8 = b'M';
const FIELD_DETAIL: u8 = b'D';
const FIELD_HINT: u8 = b'H';
const FIELD_CONTEXT: u8 = b'W';
const FIELD_SCHEMA_NAME: u8 = b's';
const FIELD_TABLE_NAME: u8 = b't';
const FIELD_COLUMN_NAME: u8 = b'c';
const FIELD_DATATYPE_NAME: u8 = b'd';
const FIELD_CONSTRAINT_NAME: u8 = b'n';
const FIELD_POSITION: u8 = b'P';
const FIELD_INTERNAL_POSITION: u8 = b'p';
const FIELD_INTERNAL_QUERY: u8 = b'q';
const FIELD_FILE: u8 = b'F';
const FIELD_LINE: u8 = b'L';
const FIELD_ROUTINE: u8 = b'R';

fn write_diagnostic_to<W>(diagnostic: &DiagnosticMessage, writer: &mut W) -> IoResult<()>
where
    W: Write + ?Sized,
{
    // elog.c, send_message_to_frontend

    writer.write_u8(FIELD_LOCALIZED_SEVERITY)?;
    writer.write_cstring(&diagnostic.localized_severity)?;

    writer.write_u8(FIELD_SEVERITY)?;
    writer.write_bytes(match diagnostic.severity {
        DiagnosticSeverity::Debug => b"DEBUG\0",
        DiagnosticSeverity::Log => b"LOG\0",
        DiagnosticSeverity::Info => b"INFO\0",
        DiagnosticSeverity::Notice => b"NOTICE\0",
        DiagnosticSeverity::Warning => b"WARNING\0",
        DiagnosticSeverity::Error => b"ERROR\0",
        DiagnosticSeverity::Fatal => b"FATAL\0",
        DiagnosticSeverity::Panic => b"PANIC\0",
    })?;

    writer.write_u8(FIELD_CODE)?;
    writer.write_cstring(&diagnostic.code)?;

    writer.write_u8(FIELD_MESSAGE)?;
    writer.write_cstring(&diagnostic.message)?;

    if let Some(detail) = &diagnostic.detail {
        writer.write_u8(FIELD_DETAIL)?;
        writer.write_cstring(detail)?;
    }

    if let Some(hint) = &diagnostic.hint {
        writer.write_u8(FIELD_HINT)?;
        writer.write_cstring(hint)?;
    }

    if let Some(where_) = &diagnostic.where_ {
        writer.write_u8(FIELD_CONTEXT)?;
        writer.write_cstring(where_)?;
    }

    if let Some(schema_name) = &diagnostic.schema_name {
        writer.write_u8(FIELD_SCHEMA_NAME)?;
        writer.write_cstring(schema_name)?;
    }

    if let Some(table_name) = &diagnostic.table_name {
        writer.write_u8(FIELD_TABLE_NAME)?;
        writer.write_cstring(table_name)?;
    }

    if let Some(column_name) = &diagnostic.column_name {
        writer.write_u8(FIELD_COLUMN_NAME)?;
        writer.write_cstring(column_name)?;
    }

    if let Some(data_type_name) = &diagnostic.data_type_name {
        writer.write_u8(FIELD_DATATYPE_NAME)?;
        writer.write_cstring(data_type_name)?;
    }

    if let Some(constraint_name) = &diagnostic.constraint_name {
        writer.write_u8(FIELD_CONSTRAINT_NAME)?;
        writer.write_cstring(constraint_name)?;
    }

    if let Some(position) = diagnostic.position {
        writer.write_u8(FIELD_POSITION)?;
        writer.write_fmt(format_args!("{}\0", position))?;
    }

    if let Some(internal_position) = diagnostic.internal_position {
        writer.write_u8(FIELD_INTERNAL_POSITION)?;
        writer.write_fmt(format_args!("{}\0", internal_position))?;
    }

    if let Some(internal_query) = &diagnostic.internal_query {
        writer.write_u8(FIELD_INTERNAL_QUERY)?;
        writer.write_cstring(internal_query)?;
    }

    if let Some(file) = &diagnostic.file {
        writer.write_u8(FIELD_FILE)?;
        writer.write_cstring(file)?;
    }

    if let Some(line) = diagnostic.line {
        writer.write_u8(FIELD_LINE)?;
        writer.write_fmt(format_args!("{}\0", line))?;
    }

    if let Some(routine) = &diagnostic.routine {
        writer.write_u8(FIELD_ROUTINE)?;
        writer.write_cstring(routine)?;
    }

    writer.write_u8(b'\0')?;

    Ok(())
}

fn read_diagnostic<R>(reader: &mut R) -> IoResult<DiagnosticMessage>
where
    R: GetReadBuf + ?Sized,
{
    reader.read_sized(
        usize::MAX,
        ReadSizedErrors {
            on_incomplete_length: &|| WireFormatError::ErrorOrNoticeResponseIncompleteLength,
            on_negative_length: &|length| WireFormatError::ErrorOrNoticeResponseNegativeLength {
                length,
            },
            on_length_limit_exceeded: &|length, max_length| {
                WireFormatError::ErrorOrNoticeResponseTooLarge { length, max_length }
            },
            on_incomplete_body: &|| WireFormatError::ErrorOrNoticeResponseIncompleteBody,
        },
        |reader| read_diagnostic_body(reader),
    )
}

fn read_diagnostic_body<R>(reader: &mut R) -> IoResult<DiagnosticMessage>
where
    R: GetReadBuf + ?Sized,
{
    let mut severity: Option<DiagnosticSeverity> = None;
    let mut localized_severity: Option<CString> = None;
    let mut code: Option<CString> = None;
    let mut message: Option<CString> = None;
    let mut detail: Option<CString> = None;
    let mut hint: Option<CString> = None;
    let mut position: Option<i32> = None;
    let mut internal_position: Option<i32> = None;
    let mut internal_query: Option<CString> = None;
    let mut where_: Option<CString> = None;
    let mut schema_name: Option<CString> = None;
    let mut table_name: Option<CString> = None;
    let mut column_name: Option<CString> = None;
    let mut data_type_name: Option<CString> = None;
    let mut constraint_name: Option<CString> = None;
    let mut file: Option<CString> = None;
    let mut line: Option<i32> = None;
    let mut routine: Option<CString> = None;

    loop {
        let field_type =
            reader.read_u8(&|| WireFormatError::ErrorOrNoticeResponseUnterminatedFieldList)?;

        if field_type == b'\0' {
            break;
        }

        let value = reader
            .read_cstring(&|| WireFormatError::ErrorOrNoticeResponseUnterminatedFieldValue)?;

        match field_type {
            FIELD_LOCALIZED_SEVERITY => {
                localized_severity = Some(value.to_owned());
            }
            FIELD_SEVERITY => {
                severity = Some(match value.to_bytes() {
                    b"DEBUG" => DiagnosticSeverity::Debug,
                    b"LOG" => DiagnosticSeverity::Log,
                    b"INFO" => DiagnosticSeverity::Info,
                    b"NOTICE" => DiagnosticSeverity::Notice,
                    b"WARNING" => DiagnosticSeverity::Warning,
                    b"ERROR" => DiagnosticSeverity::Error,
                    b"FATAL" => DiagnosticSeverity::Fatal,
                    b"PANIC" => DiagnosticSeverity::Panic,
                    _ => {
                        return Err(
                            WireFormatError::ErrorOrNoticeResponseUnknownDiagnosticSeverity {
                                severity: value,
                            }
                            .into(),
                        );
                    }
                });
            }
            FIELD_CODE => {
                code = Some(value.to_owned());
            }
            FIELD_MESSAGE => {
                message = Some(value.to_owned());
            }
            FIELD_DETAIL => {
                detail = Some(value.to_owned());
            }
            FIELD_HINT => {
                hint = Some(value.to_owned());
            }
            FIELD_POSITION => {
                let n = value
                    .to_str()
                    .map_err(|_| WireFormatError::ErrorOrNoticeResponseInvalidInteger {
                        name: "position".to_string(),
                        value: value.clone(),
                    })?
                    .parse::<i32>()
                    .map_err(|_| WireFormatError::ErrorOrNoticeResponseInvalidInteger {
                        name: "position".to_string(),
                        value: value.clone(),
                    })?;
                position = Some(n);
            }
            FIELD_INTERNAL_POSITION => {
                let n = value
                    .to_str()
                    .map_err(|_| WireFormatError::ErrorOrNoticeResponseInvalidInteger {
                        name: "internal_position".to_string(),
                        value: value.clone(),
                    })?
                    .parse::<i32>()
                    .map_err(|_| WireFormatError::ErrorOrNoticeResponseInvalidInteger {
                        name: "internal_position".to_string(),
                        value: value.clone(),
                    })?;
                internal_position = Some(n);
            }
            FIELD_INTERNAL_QUERY => {
                internal_query = Some(value.to_owned());
            }
            FIELD_CONTEXT => {
                where_ = Some(value.to_owned());
            }
            FIELD_SCHEMA_NAME => {
                schema_name = Some(value.to_owned());
            }
            FIELD_TABLE_NAME => {
                table_name = Some(value.to_owned());
            }
            FIELD_COLUMN_NAME => {
                column_name = Some(value.to_owned());
            }
            FIELD_DATATYPE_NAME => {
                data_type_name = Some(value.to_owned());
            }
            FIELD_CONSTRAINT_NAME => {
                constraint_name = Some(value.to_owned());
            }
            FIELD_FILE => {
                file = Some(value.to_owned());
            }
            FIELD_LINE => {
                let n = value
                    .to_str()
                    .map_err(|_| WireFormatError::ErrorOrNoticeResponseInvalidInteger {
                        name: "line".to_string(),
                        value: value.clone(),
                    })?
                    .parse::<i32>()
                    .map_err(|_| WireFormatError::ErrorOrNoticeResponseInvalidInteger {
                        name: "line".to_string(),
                        value: value.clone(),
                    })?;
                line = Some(n);
            }
            FIELD_ROUTINE => {
                routine = Some(value.to_owned());
            }
            _ => {
                // Ignore unknown fields
            }
        }
    }

    let Some(severity) = severity else {
        return Err(WireFormatError::ErrorOrNoticeResponseMissingSeverity.into());
    };
    let Some(localized_severity) = localized_severity else {
        return Err(WireFormatError::ErrorOrNoticeResponseMissingLocalizedSeverity.into());
    };
    let Some(code) = code else {
        return Err(WireFormatError::ErrorOrNoticeResponseMissingCode.into());
    };
    let Some(message) = message else {
        return Err(WireFormatError::ErrorOrNoticeResponseMissingMessage.into());
    };

    Ok(DiagnosticMessage {
        severity,
        localized_severity,
        code,
        message,
        detail,
        hint,
        position,
        internal_position,
        internal_query,
        where_,
        schema_name,
        table_name,
        column_name,
        data_type_name,
        constraint_name,
        file,
        line,
        routine,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error_bytes(msg: &ErrorResponse) -> IoResult<Vec<u8>> {
        let mut buf = Vec::new();
        msg.write_body_to(&mut buf)?;
        Ok(buf)
    }

    #[test]
    fn test_error_writing_simple() {
        let msg = ErrorResponse {
            error: DiagnosticMessage {
                severity: DiagnosticSeverity::Error,
                localized_severity: CString::new("ERROR").unwrap(),
                code: CString::new("12345").unwrap(),
                message: CString::new("Test error message").unwrap(),
                detail: None,
                hint: None,
                position: None,
                internal_position: None,
                internal_query: None,
                where_: None,
                schema_name: None,
                table_name: None,
                column_name: None,
                data_type_name: None,
                constraint_name: None,
                file: None,
                line: None,
                routine: None,
            },
        };
        assert_eq!(
            error_bytes(&msg).unwrap(),
            b"SERROR\0VERROR\0C12345\0MTest error message\0\0"
        );
    }

    #[test]
    fn test_error_parsing_simple() {
        let msg =
            read_diagnostic_body(&mut &b"SERROR\0VERROR\0C12345\0MTest error message\0\0"[..])
                .unwrap();
        assert_eq!(
            msg,
            DiagnosticMessage {
                severity: DiagnosticSeverity::Error,
                localized_severity: CString::new("ERROR").unwrap(),
                code: CString::new("12345").unwrap(),
                message: CString::new("Test error message").unwrap(),
                detail: None,
                hint: None,
                position: None,
                internal_position: None,
                internal_query: None,
                where_: None,
                schema_name: None,
                table_name: None,
                column_name: None,
                data_type_name: None,
                constraint_name: None,
                file: None,
                line: None,
                routine: None,
            }
        );
    }
}
