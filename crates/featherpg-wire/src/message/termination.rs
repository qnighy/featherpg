use std::io::{Result as IoResult, Write};

/// Indicates that the client has implicitly terminated the connection,
/// without sending a Terminate message, where a message is expected.
///
/// This message-ish state conforms to the protocol in the following scenarios:
///
/// - When the client was not satisfied with the server's response
///   to SSLRequest or GSSENCRequest.
/// - When the client was not satisfied with the server's negotiated
///   protocol version or protocol options.
/// - When the client could not continue with the server's proposed
///   authentication method.
///
/// Additionally, some clients, such as service monitoring tools or
/// port scanners, may open a connection and then immediately close it
/// without sending any messages.
/// Although technically a protocol violation, it is a common enough
/// scenario that we handle more gracefully than other
/// kinds of protocol violations.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImplicitTerminate;

impl ImplicitTerminate {
    pub(in crate::message) fn write_to<W>(&self, _writer: &mut W) -> IoResult<()>
    where
        W: Write + ?Sized,
    {
        // ImplicitTerminate has no body to write.
        Ok(())
    }
}
