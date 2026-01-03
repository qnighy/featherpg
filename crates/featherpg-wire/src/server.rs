use std::{
    ffi::{CStr, CString},
    io::{Error as IoError, ErrorKind as IoErrorKind, Read, Result as IoResult, Write},
};

use crate::{
    errors::{DiagnosticMessage, DiagnosticSeverity, WireFormatError},
    io_util::BufReaderWriter,
    message::{
        AuthenticationOk, CancelRequest, DirectTLS, ErrorResponse, GSSENCRequest, GSSENCResponse,
        ImplicitTerminate, InitialRequest, InitialRequestLimits, InitialRequestState,
        NegotiateProtocolVersion, NoGSSENC, NoSSL, ProtocolVersion, SSLRequest, SSLResponse,
        StartupMessage, StartupResponse,
    },
};

const MAX_STARTUP_PACKET_LENGTH: usize = 10000;

/// A struct containing the underlying stream and buffers for a connection
/// as seen from the server side.
///
/// You are expected to use ServerStream and ServerIn\* structs together
/// to maintain protocol state.
#[derive(Debug)]
pub struct ServerStream<S>
where
    S: Write + ?Sized,
{
    stream: BufReaderWriter<S>,
}

impl<S> ServerStream<S>
where
    S: Read + Write,
{
    /// Creates a new ServerStream from the given stream.
    pub fn new(stream: S) -> (Self, ServerInInitialRequest) {
        let this = Self {
            stream: BufReaderWriter::new(stream),
        };
        (this, ServerInInitialRequest::new())
    }
}

/// A server in the InitialRequest state.
///
/// You need to read an InitialRequest from the client.
#[derive(Debug)]
pub struct ServerInInitialRequest {
    initial_request_state: InitialRequestState,
}

impl ServerInInitialRequest {
    /// Creates a new ServerInInitialRequest.
    ///
    /// It is usually the only way to initialize the protocol state.
    ///
    /// The subsequent states will be derived from the previous state
    /// values, rather than being created directly using `new_unchecked`
    /// methods.
    pub fn new() -> Self {
        Self {
            initial_request_state: InitialRequestState::ConnectionStart,
        }
    }

    /// Creates a new ServerInInitialRequest with the given state.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn new_unchecked(initial_request_state: InitialRequestState) -> Self {
        Self {
            initial_request_state,
        }
    }

    /// Creats its clone.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn clone_unchecked(&self) -> Self {
        Self {
            initial_request_state: self.initial_request_state,
        }
    }

    pub fn initial_request_state(&self) -> InitialRequestState {
        self.initial_request_state
    }

    pub fn read_initial_request<S>(self, s: &mut ServerStream<S>) -> IoResult<TypedInitialRequest>
    where
        S: Read + Write,
    {
        let msg = loop {
            let msg = reporting_format_error(&mut s.stream, |stream| {
                InitialRequest::read_from(
                    stream,
                    &InitialRequestLimits {
                        max_length: MAX_STARTUP_PACKET_LENGTH,
                    },
                    self.initial_request_state,
                )
            })?;

            break msg;
        };

        let msg = match msg {
            InitialRequest::StartupMessage(mut msg) => {
                let (protocol, negotiation) = match negotiate_protocol(&mut msg) {
                    Ok((version, negotiation)) => (version, negotiation),
                    Err(err) => {
                        err.write_to(&mut s.stream)?;
                        return Err(IoError::new(
                            IoErrorKind::InvalidData,
                            "protocol version negotiation failed",
                        ));
                    }
                };
                if let Some(negotiation) = negotiation {
                    let response = StartupResponse::NegotiateProtocolVersion(negotiation);
                    response.write_to(&mut s.stream)?;
                }
                TypedInitialRequest::StartupMessage(msg, ServerInStartupResponse { protocol })
            }
            InitialRequest::SSLRequest(msg) => TypedInitialRequest::SSLRequest(
                msg,
                ServerInTLSResponse {
                    is_direct_tls: false,
                },
            ),
            InitialRequest::DirectTLS(msg) => TypedInitialRequest::DirectTLS(
                msg,
                ServerInTLSResponse {
                    is_direct_tls: true,
                },
            ),
            InitialRequest::GSSENCRequest(msg) => {
                TypedInitialRequest::GSSENCRequest(msg, ServerInGSSENCResponse { _private: () })
            }
            InitialRequest::CancelRequest(msg) => TypedInitialRequest::CancelRequest(msg),
            InitialRequest::ImplicitTerminate(msg) => TypedInitialRequest::ImplicitTerminate(msg),
        };

        Ok(msg)
    }
}

/// Like [InitialRequest] but includes a typed next state.
pub enum TypedInitialRequest {
    StartupMessage(StartupMessage, ServerInStartupResponse),
    SSLRequest(SSLRequest, ServerInTLSResponse),
    DirectTLS(DirectTLS, ServerInTLSResponse),
    GSSENCRequest(GSSENCRequest, ServerInGSSENCResponse),
    CancelRequest(CancelRequest),
    ImplicitTerminate(ImplicitTerminate),
}

/// Represents the negotiated protocol version and options.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NegotiatedProtocol {
    version: NegotiatedVersion,
}

const V3_0: ProtocolVersion = ProtocolVersion::new(3, 0);
const V3_1: ProtocolVersion = ProtocolVersion::new(3, 1);
const V3_2: ProtocolVersion = ProtocolVersion::new(3, 2);

impl NegotiatedProtocol {
    pub fn new(version: ProtocolVersion) -> Self {
        let version = match version {
            V3_0 | V3_1 => NegotiatedVersion::V3_0,
            V3_2 => NegotiatedVersion::V3_2,
            _ => panic!("unsupported protocol version"),
        };

        Self { version }
    }

    pub fn version(&self) -> ProtocolVersion {
        self.version.into()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum NegotiatedVersion {
    /// Protocol version 3.0 (default in PostgreSQL 7.4+)
    ///
    /// When the protocol is negotiated to v3.1, it is treated as v3.0.
    V3_0,
    /// Protocol version 3.2 (available in PostgreSQL 18+)
    V3_2,
}

impl From<NegotiatedVersion> for ProtocolVersion {
    fn from(version: NegotiatedVersion) -> Self {
        match version {
            NegotiatedVersion::V3_0 => ProtocolVersion::new(3, 0),
            NegotiatedVersion::V3_2 => ProtocolVersion::new(3, 2),
        }
    }
}

fn negotiate_protocol(
    request: &mut StartupMessage,
) -> Result<(NegotiatedProtocol, Option<NegotiateProtocolVersion>), ErrorResponse> {
    if request.version.major() != 3 {
        let message = format!(
            "unsupported frontend protocol {}: server supports 3.0 to 3.2",
            request.version
        );
        return Err(ErrorResponse {
            error: DiagnosticMessage {
                severity: DiagnosticSeverity::Fatal,
                localized_severity: CStr::from_bytes_with_nul(b"FATAL\0").unwrap().to_owned(),
                code: CStr::from_bytes_with_nul(b"08P01\0").unwrap().to_owned(),
                message: CString::new(message).unwrap(),
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
        });
    }

    let negotiated_version_number = request.version.min(ProtocolVersion::new(3, 2));
    let negotiated_protocol = NegotiatedProtocol::new(negotiated_version_number);

    let negotiate_protocol_version = if negotiated_version_number != request.version
        || !request.other_protocol_options.is_empty()
    {
        Some(NegotiateProtocolVersion {
            version: negotiated_version_number,
            unrecognized_options: request
                .other_protocol_options
                .iter()
                .map(|(k, _)| k.clone())
                .collect(),
        })
    } else {
        None
    };

    request.version = negotiated_version_number;
    request.other_protocol_options.clear();

    Ok((negotiated_protocol, negotiate_protocol_version))
}

/// A server in the SSLResponse state.
///
/// You need to write an SSLResponse to the client.
#[derive(Debug)]
pub struct ServerInTLSResponse {
    is_direct_tls: bool,
}

impl ServerInTLSResponse {
    /// Creates a new ServerInTLSResponse.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn new_unchecked(is_direct_tls: bool) -> Self {
        Self { is_direct_tls }
    }

    /// Creats its clone.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn clone_unchecked(&self) -> Self {
        Self {
            is_direct_tls: self.is_direct_tls,
        }
    }

    pub fn is_direct_tls(&self) -> bool {
        self.is_direct_tls
    }

    // // TODO: allow stream upgrading
    // pub fn use_tls<S>(
    //     self,
    //     s: &mut ServerStream<S>,
    // ) -> IoResult<()>
    // where
    //     S: Read + Write,
    // {}

    pub fn no_tls<S>(self, s: &mut ServerStream<S>) -> IoResult<ServerInInitialRequest>
    where
        S: Read + Write,
    {
        if self.is_direct_tls {
            return Err(IoError::new(
                IoErrorKind::Other,
                "Direct TLS connection attempted but not supported by server",
            ));
        }

        let response = SSLResponse::NoSSL(NoSSL);
        response.write_to(&mut s.stream)?;
        s.stream.flush()?;

        Ok(ServerInInitialRequest {
            initial_request_state: InitialRequestState::Other,
        })
    }

    pub fn error_response<S>(self, s: &mut ServerStream<S>, msg: ErrorResponse) -> IoResult<()>
    where
        S: Read + Write,
    {
        let response = SSLResponse::ErrorResponse(msg);
        response.write_to(&mut s.stream)?;
        s.stream.flush()?;
        Ok(())
    }
}

/// A server in the GSSENCResponse state.
///
/// You need to write a GSSENCResponse to the client.
#[derive(Debug)]
pub struct ServerInGSSENCResponse {
    _private: (),
}

impl ServerInGSSENCResponse {
    /// Creates a new ServerInGSSENCResponse.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn new_unchecked() -> Self {
        Self { _private: () }
    }

    /// Creats its clone.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn clone_unchecked(&self) -> Self {
        Self { _private: () }
    }

    // // TODO: implement GSSENC handling
    // pub fn use_gssenc<S>(self, s: &mut ServerStream<S>) -> IoResult<()>
    // where
    //     S: Read + Write,
    // {
    //     let response = GSSENCResponse::UseGSSENC(UseGSSENC);
    //     response.write_to(&mut s.stream)?;
    //     Ok(())
    // }

    pub fn no_gssenc<S>(self, s: &mut ServerStream<S>) -> IoResult<ServerInInitialRequest>
    where
        S: Read + Write,
    {
        let response = GSSENCResponse::NoGSSENC(NoGSSENC);
        response.write_to(&mut s.stream)?;
        s.stream.flush()?;

        Ok(ServerInInitialRequest {
            initial_request_state: InitialRequestState::Other,
        })
    }

    pub fn error_response<S>(self, s: &mut ServerStream<S>, msg: ErrorResponse) -> IoResult<()>
    where
        S: Read + Write,
    {
        let response = GSSENCResponse::ErrorResponse(msg);
        response.write_to(&mut s.stream)?;
        s.stream.flush()?;
        Ok(())
    }
}

/// A server in the StartupResponse state.
///
/// You need to write a StartupResponse to the client.
#[derive(Debug)]
pub struct ServerInStartupResponse {
    protocol: NegotiatedProtocol,
}

impl ServerInStartupResponse {
    /// Creates a new ServerInStartupResponse.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn new_unchecked(protocol: NegotiatedProtocol) -> Self {
        Self { protocol }
    }

    /// Creats its clone.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn clone_unchecked(&self) -> Self {
        Self {
            protocol: self.protocol.clone(),
        }
    }

    pub fn protocol(&self) -> &NegotiatedProtocol {
        &self.protocol
    }

    pub fn authentication_ok<S>(
        self,
        s: &mut ServerStream<S>,
    ) -> IoResult<ServerInBackendStartupMessage>
    where
        S: Read + Write,
    {
        let response = StartupResponse::AuthenticationOk(AuthenticationOk);
        response.write_to(&mut s.stream)?;
        s.stream.flush()?;

        Ok(ServerInBackendStartupMessage {
            protocol: self.protocol,
        })
    }
}

/// A server in the CleartextPasswordMessage state.
///
/// You need to read a CleartextPasswordMessage from the client.
#[derive(Debug)]
pub struct ServerInCleartextPasswordMessage {
    protocol: NegotiatedProtocol,
}

impl ServerInCleartextPasswordMessage {
    /// Creates a new ServerInCleartextPasswordMessage.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn new_unchecked(protocol: NegotiatedProtocol) -> Self {
        Self { protocol }
    }

    /// Creats its clone.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn clone_unchecked(&self) -> Self {
        Self {
            protocol: self.protocol.clone(),
        }
    }

    pub fn protocol(&self) -> &NegotiatedProtocol {
        &self.protocol
    }
}

/// A server in the MD5PasswordMessage state.
///
/// You need to read an MD5PasswordMessage from the client.
#[derive(Debug)]
pub struct ServerInMD5PasswordMessage {
    protocol: NegotiatedProtocol,
}

impl ServerInMD5PasswordMessage {
    /// Creates a new ServerInMD5PasswordMessage.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn new_unchecked(protocol: NegotiatedProtocol) -> Self {
        Self { protocol }
    }

    /// Creats its clone.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn clone_unchecked(&self) -> Self {
        Self {
            protocol: self.protocol.clone(),
        }
    }

    pub fn protocol(&self) -> &NegotiatedProtocol {
        &self.protocol
    }
}

/// A server in the GSSResponse state.
///
/// You need to read a GSSResponse from the client.
#[derive(Debug)]
pub struct ServerInGSSResponse {
    protocol: NegotiatedProtocol,
}

impl ServerInGSSResponse {
    /// Creates a new ServerInGSSResponse.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn new_unchecked(protocol: NegotiatedProtocol) -> Self {
        Self { protocol }
    }

    /// Creats its clone.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn clone_unchecked(&self) -> Self {
        Self {
            protocol: self.protocol.clone(),
        }
    }

    pub fn protocol(&self) -> &NegotiatedProtocol {
        &self.protocol
    }
}

/// A server in the GSSServerResponse state.
///
/// You need to write a GSSServerResponse to the client.
#[derive(Debug)]
pub struct ServerInGSSServerResponse {
    protocol: NegotiatedProtocol,
}

impl ServerInGSSServerResponse {
    /// Creates a new ServerInGSSServerResponse.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn new_unchecked(protocol: NegotiatedProtocol) -> Self {
        Self { protocol }
    }

    /// Creats its clone.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn clone_unchecked(&self) -> Self {
        Self {
            protocol: self.protocol.clone(),
        }
    }

    pub fn protocol(&self) -> &NegotiatedProtocol {
        &self.protocol
    }
}

/// A server in the SASLInitialResponse state.
///
/// You need to read a SASLInitialResponse from the client.
#[derive(Debug)]
pub struct ServerInSASLInitialResponse {
    protocol: NegotiatedProtocol,
}

impl ServerInSASLInitialResponse {
    /// Creates a new ServerInSASLInitialResponse.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn new_unchecked(protocol: NegotiatedProtocol) -> Self {
        Self { protocol }
    }

    /// Creats its clone.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn clone_unchecked(&self) -> Self {
        Self {
            protocol: self.protocol.clone(),
        }
    }

    pub fn protocol(&self) -> &NegotiatedProtocol {
        &self.protocol
    }
}

/// A server in the SASLServerResponse state.
///
/// You need to write a SASLServerResponse to the client.
#[derive(Debug)]
pub struct ServerInSASLServerResponse {
    protocol: NegotiatedProtocol,
}

impl ServerInSASLServerResponse {
    /// Creates a new ServerInSASLServerResponse.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn new_unchecked(protocol: NegotiatedProtocol) -> Self {
        Self { protocol }
    }

    /// Creats its clone.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn clone_unchecked(&self) -> Self {
        Self {
            protocol: self.protocol.clone(),
        }
    }

    pub fn protocol(&self) -> &NegotiatedProtocol {
        &self.protocol
    }
}

/// A server in the SASLResponse state.
///
/// You need to read a SASLResponse from the client.
#[derive(Debug)]
pub struct ServerInSASLResponse {
    protocol: NegotiatedProtocol,
}

impl ServerInSASLResponse {
    /// Creates a new ServerInSASLResponse.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn new_unchecked(protocol: NegotiatedProtocol) -> Self {
        Self { protocol }
    }

    /// Creats its clone.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn clone_unchecked(&self) -> Self {
        Self {
            protocol: self.protocol.clone(),
        }
    }

    pub fn protocol(&self) -> &NegotiatedProtocol {
        &self.protocol
    }
}

/// A server in the BackendStartupMessage state.
///
/// You need to write a BackendStartupMessage to the client.
#[derive(Debug)]
pub struct ServerInBackendStartupMessage {
    protocol: NegotiatedProtocol,
}

impl ServerInBackendStartupMessage {
    /// Creates a new ServerInBackendStartupMessage.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn new_unchecked(protocol: NegotiatedProtocol) -> Self {
        Self { protocol }
    }

    /// Creats its clone.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn clone_unchecked(&self) -> Self {
        Self {
            protocol: self.protocol.clone(),
        }
    }

    pub fn protocol(&self) -> &NegotiatedProtocol {
        &self.protocol
    }
}

/// A server in the QueryMessage state.
///
/// You need to read a QueryMessage from the client.
#[derive(Debug)]
pub struct ServerInQueryMessage {
    protocol: NegotiatedProtocol,
}

impl ServerInQueryMessage {
    /// Creates a new ServerInQueryMessage.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn new_unchecked(protocol: NegotiatedProtocol) -> Self {
        Self { protocol }
    }

    /// Creats its clone.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn clone_unchecked(&self) -> Self {
        Self {
            protocol: self.protocol.clone(),
        }
    }

    pub fn protocol(&self) -> &NegotiatedProtocol {
        &self.protocol
    }
}

/// A server in the QueryResponse state.
///
/// You need to write a QueryResponse to the client.
#[derive(Debug)]
pub struct ServerInQueryResponse {
    protocol: NegotiatedProtocol,
}

impl ServerInQueryResponse {
    /// Creates a new ServerInQueryResponse.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn new_unchecked(protocol: NegotiatedProtocol) -> Self {
        Self { protocol }
    }

    /// Creats its clone.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn clone_unchecked(&self) -> Self {
        Self {
            protocol: self.protocol.clone(),
        }
    }

    pub fn protocol(&self) -> &NegotiatedProtocol {
        &self.protocol
    }
}

/// A server in the CopyInMessage state.
///
/// You need to read a CopyInMessage from the client.
#[derive(Debug)]
pub struct ServerInCopyInMessage {
    protocol: NegotiatedProtocol,
}

impl ServerInCopyInMessage {
    /// Creates a new ServerInCopyInMessage.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn new_unchecked(protocol: NegotiatedProtocol) -> Self {
        Self { protocol }
    }

    /// Creats its clone.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn clone_unchecked(&self) -> Self {
        Self {
            protocol: self.protocol.clone(),
        }
    }

    pub fn protocol(&self) -> &NegotiatedProtocol {
        &self.protocol
    }
}

/// A server in the CopyOutMessage state.
///
/// You need to write a CopyOutMessage to the client.
#[derive(Debug)]
pub struct ServerInCopyOutMessage {
    protocol: NegotiatedProtocol,
}

impl ServerInCopyOutMessage {
    /// Creates a new ServerInCopyOutMessage.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn new_unchecked(protocol: NegotiatedProtocol) -> Self {
        Self { protocol }
    }

    /// Creats its clone.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn clone_unchecked(&self) -> Self {
        Self {
            protocol: self.protocol.clone(),
        }
    }

    pub fn protocol(&self) -> &NegotiatedProtocol {
        &self.protocol
    }
}

/// A server in the CopyBoth state.
///
/// You can either read a CopyInMessage or write a CopyOutMessage next.
#[derive(Debug)]
pub struct ServerInCopyBoth {
    protocol: NegotiatedProtocol,
}

impl ServerInCopyBoth {
    /// Creates a new ServerInCopyBoth.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn new_unchecked(protocol: NegotiatedProtocol) -> Self {
        Self { protocol }
    }

    /// Creats its clone.
    ///
    /// It may break protocol invariants. Use with caution.
    pub fn clone_unchecked(&self) -> Self {
        Self {
            protocol: self.protocol.clone(),
        }
    }
}

fn reporting_format_error<S, T, F>(stream: &mut S, f: F) -> IoResult<T>
where
    S: Write + ?Sized,
    F: FnOnce(&mut S) -> IoResult<T>,
{
    match f(stream) {
        Ok(value) => Ok(value),
        Err(err) => {
            if let Some(err) = WireFormatError::try_extract_ref(&err) {
                let msg = ErrorResponse {
                    error: DiagnosticMessage::from(err),
                };
                // Ignore nested errors while reporting the original error
                report_error(stream, msg).ok();
            }
            Err(err)
        }
    }
}

fn report_error<W>(writer: &mut W, msg: ErrorResponse) -> IoResult<()>
where
    W: Write + ?Sized,
{
    msg.write_to(writer)?;
    writer.flush()?;
    Ok(())
}
