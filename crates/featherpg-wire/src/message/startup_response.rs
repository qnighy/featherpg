use std::{
    ffi::CString,
    io::{Result as IoResult, Write},
};

use crate::{
    common::GetReadBuf,
    errors::WireFormatError,
    message::{ErrorResponse, ProtocolVersion},
    message_common::{ReadSizedErrors, ReadWireExt, WriteWireExt},
};

/// A response to a StartupMessage, sent by the server.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StartupResponse {
    NegotiateProtocolVersion(NegotiateProtocolVersion),
    AuthenticationOk(AuthenticationOk),
    AuthenticationCleartextPassword(AuthenticationCleartextPassword),
    AuthenticationMD5Password(AuthenticationMD5Password),
    AuthenticationGSS(AuthenticationGSS),
    AuthenticationGSSContinue(AuthenticationGSSContinue),
    AuthenticationSSPI(AuthenticationSSPI),
    AuthenticationSASL(AuthenticationSASL),
    AuthenticationSASLContinue(AuthenticationSASLContinue),
    AuthenticationSASLFinal(AuthenticationSASLFinal),
    /// Indicates an unrecoverable error during startup.
    ///
    /// Next state: connection close
    ErrorResponse(ErrorResponse),
}

impl From<NegotiateProtocolVersion> for StartupResponse {
    fn from(value: NegotiateProtocolVersion) -> Self {
        StartupResponse::NegotiateProtocolVersion(value)
    }
}

impl From<AuthenticationOk> for StartupResponse {
    fn from(value: AuthenticationOk) -> Self {
        StartupResponse::AuthenticationOk(value)
    }
}

impl From<AuthenticationCleartextPassword> for StartupResponse {
    fn from(value: AuthenticationCleartextPassword) -> Self {
        StartupResponse::AuthenticationCleartextPassword(value)
    }
}

impl From<AuthenticationMD5Password> for StartupResponse {
    fn from(value: AuthenticationMD5Password) -> Self {
        StartupResponse::AuthenticationMD5Password(value)
    }
}

impl From<AuthenticationGSS> for StartupResponse {
    fn from(value: AuthenticationGSS) -> Self {
        StartupResponse::AuthenticationGSS(value)
    }
}

impl From<AuthenticationGSSContinue> for StartupResponse {
    fn from(value: AuthenticationGSSContinue) -> Self {
        StartupResponse::AuthenticationGSSContinue(value)
    }
}

impl From<AuthenticationSSPI> for StartupResponse {
    fn from(value: AuthenticationSSPI) -> Self {
        StartupResponse::AuthenticationSSPI(value)
    }
}

impl From<AuthenticationSASL> for StartupResponse {
    fn from(value: AuthenticationSASL) -> Self {
        StartupResponse::AuthenticationSASL(value)
    }
}

impl From<AuthenticationSASLContinue> for StartupResponse {
    fn from(value: AuthenticationSASLContinue) -> Self {
        StartupResponse::AuthenticationSASLContinue(value)
    }
}

impl From<AuthenticationSASLFinal> for StartupResponse {
    fn from(value: AuthenticationSASLFinal) -> Self {
        StartupResponse::AuthenticationSASLFinal(value)
    }
}

impl From<ErrorResponse> for StartupResponse {
    fn from(value: ErrorResponse) -> Self {
        StartupResponse::ErrorResponse(value)
    }
}

impl StartupResponse {
    pub fn write_to<W>(&self, writer: &mut W) -> IoResult<()>
    where
        W: Write,
    {
        match self {
            StartupResponse::NegotiateProtocolVersion(msg) => {
                msg.write_to(writer)?;
            }
            StartupResponse::AuthenticationOk(msg) => {
                msg.write_to(writer)?;
            }
            StartupResponse::AuthenticationCleartextPassword(msg) => {
                msg.write_to(writer)?;
            }
            StartupResponse::AuthenticationMD5Password(msg) => {
                msg.write_to(writer)?;
            }
            StartupResponse::AuthenticationGSS(msg) => {
                msg.write_to(writer)?;
            }
            StartupResponse::AuthenticationGSSContinue(msg) => {
                msg.write_to(writer)?;
            }
            StartupResponse::AuthenticationSSPI(msg) => {
                msg.write_to(writer)?;
            }
            StartupResponse::AuthenticationSASL(msg) => {
                msg.write_to(writer)?;
            }
            StartupResponse::AuthenticationSASLContinue(msg) => {
                msg.write_to(writer)?;
            }
            StartupResponse::AuthenticationSASLFinal(msg) => {
                msg.write_to(writer)?;
            }
            StartupResponse::ErrorResponse(err) => {
                err.write_to(writer)?;
            }
        }
        Ok(())
    }

    pub fn read_from<R>(reader: &mut R) -> IoResult<Self>
    where
        R: GetReadBuf + ?Sized,
    {
        let type_byte = reader.read_u8(&|| WireFormatError::StartupResponseMissingTypeByte)?;
        match type_byte {
            NegotiateProtocolVersion::TYPE_BYTE => {
                NegotiateProtocolVersion::read_after_type_byte(reader, type_byte).map(Into::into)
            }
            AUTH_TYPE_BYTE => read_authentication_after_type_byte(reader, type_byte),
            ErrorResponse::TYPE_BYTE => {
                ErrorResponse::read_after_type_byte(reader, type_byte).map(Into::into)
            }
            _ => Err(WireFormatError::StartupResponseUnknownTypeByte { type_byte }.into()),
        }
    }
}

/// Instructs the client to switch to a different protocol version.
///
/// Next state: continue in StartupResponse (server active)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NegotiateProtocolVersion {
    pub version: ProtocolVersion,
    pub unrecognized_options: Vec<CString>,
}

impl NegotiateProtocolVersion {
    pub const TYPE_BYTE: u8 = b'v';
}

impl NegotiateProtocolVersion {
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
        writer.write_version(self.version)?;
        // TODO: validate non-emptiness of options
        for option in &self.unrecognized_options {
            writer.write_cstring(option)?;
        }
        writer.write_u8(0)?; // Terminating null byte
        Ok(())
    }

    fn read_after_type_byte<R>(reader: &mut R, type_byte: u8) -> IoResult<Self>
    where
        R: GetReadBuf + ?Sized,
    {
        assert_eq!(type_byte, Self::TYPE_BYTE);

        reader.read_sized(
            usize::MAX,
            ReadSizedErrors {
                on_incomplete_length: &|| WireFormatError::NegotiateProtocolVersionIncompleteLength,
                on_negative_length: &|length| {
                    WireFormatError::NegotiateProtocolVersionNegativeLength { length }
                },
                on_length_limit_exceeded: &|length, max_length| {
                    WireFormatError::NegotiateProtocolVersionTooLarge { length, max_length }
                },
                on_incomplete_body: &|| WireFormatError::NegotiateProtocolVersionIncompleteBody,
            },
            |reader| Self::read_body(reader),
        )
    }

    fn read_body<R>(reader: &mut R) -> IoResult<Self>
    where
        R: GetReadBuf + ?Sized,
    {
        let version =
            reader.read_version(&|| WireFormatError::NegotiateProtocolVersionIncompleteVersion)?;
        let mut unrecognized_options = Vec::new();
        loop {
            let option = reader
                .read_cstring(&|| WireFormatError::NegotiateProtocolVersionIncompleteOptionName)?;
            if option.is_empty() {
                break;
            }
            unrecognized_options.push(option);
        }
        Ok(NegotiateProtocolVersion {
            version,
            unrecognized_options,
        })
    }
}

const AUTH_TYPE_BYTE: u8 = b'R';

fn read_authentication_after_type_byte<R>(
    reader: &mut R,
    type_byte: u8,
) -> IoResult<StartupResponse>
where
    R: GetReadBuf + ?Sized,
{
    assert_eq!(type_byte, AUTH_TYPE_BYTE);

    reader.read_sized(
        usize::MAX,
        ReadSizedErrors {
            on_incomplete_length: &|| WireFormatError::AuthenticationIncompleteLength,
            on_negative_length: &|length| WireFormatError::AuthenticationNegativeLength { length },
            on_length_limit_exceeded: &|length, max_length| {
                WireFormatError::AuthenticationTooLarge { length, max_length }
            },
            on_incomplete_body: &|| WireFormatError::AuthenticationIncompleteBody,
        },
        |reader| read_authentication_body(reader, type_byte),
    )
}

fn read_authentication_body<R>(reader: &mut R, type_byte: u8) -> IoResult<StartupResponse>
where
    R: GetReadBuf + ?Sized,
{
    let auth_type = reader.read_u32(&|| WireFormatError::AuthenticationIncompleteType)?;
    match auth_type {
        AuthenticationOk::AUTH_TYPE => {
            AuthenticationOk::read_after_auth_type(reader, type_byte, auth_type).map(Into::into)
        }
        AuthenticationCleartextPassword::AUTH_TYPE => {
            AuthenticationCleartextPassword::read_after_auth_type(reader, type_byte, auth_type)
                .map(Into::into)
        }
        AuthenticationMD5Password::AUTH_TYPE => {
            AuthenticationMD5Password::read_after_auth_type(reader, type_byte, auth_type)
                .map(Into::into)
        }
        AuthenticationGSS::AUTH_TYPE => {
            AuthenticationGSS::read_after_auth_type(reader, type_byte, auth_type).map(Into::into)
        }
        AuthenticationGSSContinue::AUTH_TYPE => {
            AuthenticationGSSContinue::read_after_auth_type(reader, type_byte, auth_type)
                .map(Into::into)
        }
        AuthenticationSSPI::AUTH_TYPE => {
            AuthenticationSSPI::read_after_auth_type(reader, type_byte, auth_type).map(Into::into)
        }
        AuthenticationSASL::AUTH_TYPE => {
            AuthenticationSASL::read_after_auth_type(reader, type_byte, auth_type).map(Into::into)
        }
        AuthenticationSASLContinue::AUTH_TYPE => {
            AuthenticationSASLContinue::read_after_auth_type(reader, type_byte, auth_type)
                .map(Into::into)
        }
        AuthenticationSASLFinal::AUTH_TYPE => {
            AuthenticationSASLFinal::read_after_auth_type(reader, type_byte, auth_type)
                .map(Into::into)
        }
        _ => Err(WireFormatError::AuthenticationUnknownType { auth_type }.into()),
    }
}

/// Indicates that authentication was successful.
///
/// Next state: BackendStartupResponse (server active)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthenticationOk;

impl AuthenticationOk {
    pub const TYPE_BYTE: u8 = b'R';
    pub const AUTH_TYPE: u32 = 0;

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
        writer.write_u32(Self::AUTH_TYPE)?; // Auth type
        Ok(())
    }

    fn read_after_auth_type<R>(reader: &mut R, type_byte: u8, auth_type: u32) -> IoResult<Self>
    where
        R: GetReadBuf + ?Sized,
    {
        assert_eq!(type_byte, Self::TYPE_BYTE);
        assert_eq!(auth_type, Self::AUTH_TYPE);
        reader.read_eof(&|| WireFormatError::AuthenticationOkExtraBytes)?;
        Ok(AuthenticationOk)
    }
}

/// Indicates that a cleartext password is required.
///
/// Next state: CleartextPasswordMessage (client active)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthenticationCleartextPassword;

impl AuthenticationCleartextPassword {
    pub const TYPE_BYTE: u8 = b'R';
    pub const AUTH_TYPE: u32 = 3;

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
        writer.write_u32(Self::AUTH_TYPE)?;
        Ok(())
    }

    fn read_after_auth_type<R>(reader: &mut R, type_byte: u8, auth_type: u32) -> IoResult<Self>
    where
        R: GetReadBuf + ?Sized,
    {
        assert_eq!(type_byte, Self::TYPE_BYTE);
        assert_eq!(auth_type, Self::AUTH_TYPE);
        reader.read_eof(&|| WireFormatError::AuthenticationCleartextPasswordExtraBytes)?;
        Ok(AuthenticationCleartextPassword)
    }
}

/// Indicates that MD5-hashed password authentication is required.
///
/// Next state: MD5PasswordMessage (client active)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthenticationMD5Password {
    pub salt: [u8; 4],
}

impl AuthenticationMD5Password {
    pub const TYPE_BYTE: u8 = b'R';
    pub const AUTH_TYPE: u32 = 5;

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
        writer.write_u32(Self::AUTH_TYPE)?;
        writer.write_all(&self.salt)?;
        Ok(())
    }

    fn read_after_auth_type<R>(reader: &mut R, type_byte: u8, auth_type: u32) -> IoResult<Self>
    where
        R: GetReadBuf + ?Sized,
    {
        assert_eq!(type_byte, Self::TYPE_BYTE);
        assert_eq!(auth_type, Self::AUTH_TYPE);
        let mut salt = [0u8; 4];
        reader.read_bytes(&mut salt, &|| {
            WireFormatError::AuthenticationMD5PasswordIncompleteSalt
        })?;
        reader.read_eof(&|| WireFormatError::AuthenticationMD5PasswordExtraBytes)?;
        Ok(AuthenticationMD5Password { salt })
    }
}

/// Indicates that GSS authentication is required.
///
/// Next state: GSSResponse (client active)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthenticationGSS;

impl AuthenticationGSS {
    pub const TYPE_BYTE: u8 = b'R';
    pub const AUTH_TYPE: u32 = 7;

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
        writer.write_u32(Self::AUTH_TYPE)?;
        Ok(())
    }

    fn read_after_auth_type<R>(reader: &mut R, type_byte: u8, auth_type: u32) -> IoResult<Self>
    where
        R: GetReadBuf + ?Sized,
    {
        assert_eq!(type_byte, Self::TYPE_BYTE);
        assert_eq!(auth_type, Self::AUTH_TYPE);
        reader.read_eof(&|| WireFormatError::AuthenticationGSSExtraBytes)?;
        Ok(AuthenticationGSS)
    }
}

/// Contains GSS or SSPI authentication data.
///
/// Next state: GSSResponse (client active)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthenticationGSSContinue {
    pub data: Vec<u8>,
}

impl AuthenticationGSSContinue {
    pub const TYPE_BYTE: u8 = b'R';
    pub const AUTH_TYPE: u32 = 8;

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
        writer.write_u32(Self::AUTH_TYPE)?;
        writer.write_all(&self.data)?;
        Ok(())
    }

    fn read_after_auth_type<R>(reader: &mut R, type_byte: u8, auth_type: u32) -> IoResult<Self>
    where
        R: GetReadBuf + ?Sized,
    {
        assert_eq!(type_byte, Self::TYPE_BYTE);
        assert_eq!(auth_type, Self::AUTH_TYPE);
        let data = reader.read_remaining_bytes()?;
        Ok(AuthenticationGSSContinue { data })
    }
}

/// Indicates that SSPI authentication is required.
///
/// Next state: GSSResponse (client active)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthenticationSSPI;

impl AuthenticationSSPI {
    pub const TYPE_BYTE: u8 = b'R';
    pub const AUTH_TYPE: u32 = 9;

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
        writer.write_u32(Self::AUTH_TYPE)?;
        Ok(())
    }

    fn read_after_auth_type<R>(reader: &mut R, type_byte: u8, auth_type: u32) -> IoResult<Self>
    where
        R: GetReadBuf + ?Sized,
    {
        assert_eq!(type_byte, Self::TYPE_BYTE);
        assert_eq!(auth_type, Self::AUTH_TYPE);
        reader.read_eof(&|| WireFormatError::AuthenticationSSPIExtraBytes)?;
        Ok(AuthenticationSSPI)
    }
}

/// Indicates that SASL authentication is required and provides supported mechanisms.
///
/// Next state: SASLInitialResponse (client active)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthenticationSASL {
    pub mechanisms: Vec<CString>,
}

impl AuthenticationSASL {
    pub const TYPE_BYTE: u8 = b'R';
    pub const AUTH_TYPE: u32 = 10;

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
        writer.write_u32(Self::AUTH_TYPE)?;
        // TODO: validate non-emptiness of mechanisms
        for mechanism in &self.mechanisms {
            writer.write_cstring(mechanism)?;
        }
        writer.write_u8(0)?; // Terminating null byte
        Ok(())
    }

    fn read_after_auth_type<R>(reader: &mut R, type_byte: u8, auth_type: u32) -> IoResult<Self>
    where
        R: GetReadBuf + ?Sized,
    {
        assert_eq!(type_byte, Self::TYPE_BYTE);
        assert_eq!(auth_type, Self::AUTH_TYPE);
        let mut mechanisms = Vec::new();
        loop {
            let mechanism = reader.read_cstring(&|| {
                WireFormatError::AuthenticationSASLUnterminatedAuthenticationMechanismName
            })?;
            if mechanism.is_empty() {
                break;
            }
            mechanisms.push(mechanism);
        }
        reader.read_eof(&|| WireFormatError::AuthenticationSASLExtraBytes)?;
        Ok(AuthenticationSASL { mechanisms })
    }
}

/// Contains SASL challenge data.
///
/// Next state: SASLResponse (client active)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthenticationSASLContinue {
    pub data: Vec<u8>,
}

impl AuthenticationSASLContinue {
    pub const TYPE_BYTE: u8 = b'R';
    pub const AUTH_TYPE: u32 = 11;

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
        writer.write_u32(Self::AUTH_TYPE)?;
        writer.write_all(&self.data)?;
        Ok(())
    }

    fn read_after_auth_type<R>(reader: &mut R, type_byte: u8, auth_type: u32) -> IoResult<Self>
    where
        R: GetReadBuf + ?Sized,
    {
        assert_eq!(type_byte, Self::TYPE_BYTE);
        assert_eq!(auth_type, Self::AUTH_TYPE);
        let data = reader.read_remaining_bytes()?;
        Ok(AuthenticationSASLContinue { data })
    }
}

/// Contains SASL final server data.
///
/// Next state: backend sends AuthenticationOk following it,
///             and continue with BackendStartupResponse (server active)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthenticationSASLFinal {
    pub data: Vec<u8>,
}

impl AuthenticationSASLFinal {
    pub const TYPE_BYTE: u8 = b'R';
    pub const AUTH_TYPE: u32 = 12;

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
        writer.write_u32(Self::AUTH_TYPE)?;
        writer.write_all(&self.data)?;
        Ok(())
    }

    fn read_after_auth_type<R>(reader: &mut R, type_byte: u8, auth_type: u32) -> IoResult<Self>
    where
        R: GetReadBuf + ?Sized,
    {
        assert_eq!(type_byte, Self::TYPE_BYTE);
        assert_eq!(auth_type, Self::AUTH_TYPE);
        let data = reader.read_remaining_bytes()?;
        Ok(AuthenticationSASLFinal { data })
    }
}
