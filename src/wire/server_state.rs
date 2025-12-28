use std::{
    collections::VecDeque,
    sync::atomic::{self, AtomicU64},
};

use crate::wire::{
    io_util::ByteQueue,
    message::{WireMessage, WireState},
    message_common::{ByteQueueWriteExt, ProtocolVersion},
};

static NEXT_WIRE_SERVER_ID: AtomicU64 = AtomicU64::new(1);

/// Represents the wire protocol state on the server side.
#[derive(Debug)]
pub struct WireServer {
    state: WireState,
    read_queue: ByteQueue,
    /// Set to true if the end-of-stream has been reached on reading.
    read_closed: bool,
    /// Set to true if there is a chance the connection will be upgraded to SSL.
    pending_upgrade: bool,
    write_queue: ByteQueue,
    /// Set to true if the connection is to be closed after all pending writes are sent.
    close_write: bool,
    request_queue: VecDeque<ServerWireRequest>,
    /// Set to true if the server can no longer accept requests.
    request_closed: bool,
    /// The unique ID of this `WireServer` instance.
    id: u64,
    /// The next responder ID expected from the server implementation.
    next_pending_responder_id: u64,
    /// The next responder ID to assign to the next request.
    fresh_responder_id: u64,
}

impl WireServer {
    pub fn new() -> Self {
        Self {
            state: WireState::BackendStartup,
            read_queue: ByteQueue::new(),
            read_closed: false,
            pending_upgrade: false,
            write_queue: ByteQueue::new(),
            close_write: false,
            request_queue: VecDeque::new(),
            request_closed: false,
            id: NEXT_WIRE_SERVER_ID.fetch_add(1, atomic::Ordering::Relaxed),
            next_pending_responder_id: 1,
            fresh_responder_id: 1,
        }
    }

    pub fn append_read(&mut self, data: &[u8]) {
        assert!(
            !self.read_closed || data.is_empty(),
            "Non-empty read cannot happen after it is closed"
        );

        self.read_queue.extend_from_slice(data);

        self.process_incoming_messages();
    }

    pub fn mark_read_closed(&mut self) {
        self.read_closed = true;

        self.process_incoming_messages();
    }

    fn process_incoming_messages(&mut self) {
        while !self.pending_upgrade {
            if self.read_queue.is_empty() && self.read_closed {
                // No more data to read.
                break;
            } else if self.request_closed {
                todo!("Handle requests after request_closed");
            }

            // TODO: handle parse error
            let Some(msg) = WireMessage::read_from(&mut self.read_queue, self.state).unwrap()
            else {
                break;
            };
            self.state = WireState::Ordinary;

            self.process_message(msg);
        }
    }

    fn process_message(&mut self, msg: WireMessage) {
        match msg {
            WireMessage::StartupMessage {
                version,
                parameters,
            } => {
                let req = ServerWireRequest::StartupRequest(
                    ServerStartupRequest {
                        protocol_version: version,
                        parameters: parameters
                            .into_iter()
                            .map(|pair| (pair.name, pair.value))
                            .collect(),
                    },
                    ServerStartupResponder(self.next_untyped_responder()),
                );
                self.request_queue.push_back(req);
            }
            WireMessage::SSLRequest => {
                self.pending_upgrade = true;
                let req = ServerWireRequest::SSLRequest(
                    ServerSSLRequest,
                    ServerSSLResponder(self.next_untyped_responder()),
                );
                self.request_queue.push_back(req);
            }
            WireMessage::GSSENCRequest => {
                self.pending_upgrade = true;
                let req = ServerWireRequest::GSSENCRequest(
                    ServerGSSENCRequest,
                    ServerGSSENCResponder(self.next_untyped_responder()),
                );
                self.request_queue.push_back(req);
            }
            WireMessage::CancelRequest {
                process_id,
                secret_key,
            } => {
                let req = ServerWireRequest::CancelRequest(
                    ServerCancelRequest {
                        process_id,
                        secret_key,
                    },
                    ServerCancelResponder(self.next_untyped_responder()),
                );
                self.request_queue.push_back(req);
            }
            _ => todo!(),
        }
    }

    pub fn pop_request(&mut self) -> Option<ServerWireRequest> {
        self.request_queue.pop_front()
    }

    pub fn write_buffer(&mut self) -> &[u8] {
        &*self.write_queue
    }

    pub fn consume_write(&mut self, count: usize) {
        self.write_queue.consume(count);
    }

    pub fn should_close_write(&self) -> bool {
        self.close_write && self.write_queue.len() == 0
    }

    fn write_message(&mut self, msg: WireMessage) {
        assert!(
            !self.close_write,
            "Cannot write messages after close_write is set"
        );
        msg.write_to(&mut self.write_queue);
    }

    fn mark_write_closed(&mut self) {
        self.close_write = true;
    }

    fn consume_responder(&mut self, responder: UntypedResponder) {
        assert_eq!(
            responder.wire_server_id, self.id,
            "Responders must be used with the correct WireServer"
        );
        assert_eq!(
            responder.request_id, self.next_pending_responder_id,
            "Responders must be used in order"
        );
        self.next_pending_responder_id += 1;
    }

    fn next_untyped_responder(&mut self) -> UntypedResponder {
        let request_id = self.fresh_responder_id;
        self.fresh_responder_id += 1;
        UntypedResponder {
            wire_server_id: self.id,
            request_id,
        }
    }
}

#[derive(Debug)]
struct UntypedResponder {
    wire_server_id: u64,
    request_id: u64,
}

#[derive(Debug)]
pub enum ServerWireRequest {
    StartupRequest(ServerStartupRequest, ServerStartupResponder),
    SSLRequest(ServerSSLRequest, ServerSSLResponder),
    GSSENCRequest(ServerGSSENCRequest, ServerGSSENCResponder),
    CancelRequest(ServerCancelRequest, ServerCancelResponder),
}

#[derive(Debug, Clone)]
pub struct ServerStartupRequest {
    pub protocol_version: ProtocolVersion,
    pub parameters: Vec<(String, String)>,
}

#[derive(Debug)]
pub struct ServerStartupResponder(UntypedResponder);

impl ServerStartupResponder {
    pub fn respond_ok(self, server: &mut WireServer) {
        server.consume_responder(self.0);

        server.write_message(WireMessage::AuthenticationOk);
    }

    pub fn respond_cleartext_password(self, server: &mut WireServer) {
        server.consume_responder(self.0);

        server.write_message(WireMessage::AuthenticationCleartextPassword);
    }

    pub fn respond_md5_password(self, salt: [u8; 4], server: &mut WireServer) {
        server.consume_responder(self.0);

        server.write_message(WireMessage::AuthenticationMD5Password { salt });
    }

    // pub fn respond_kerberos_v5(self, server: &mut WireServer) {
    //     server.consume_responder(self.0);

    //     server.write_message(WireMessage::AuthenticationKerberosV5);
    // }

    pub fn respond_gss(self, server: &mut WireServer) {
        server.consume_responder(self.0);

        server.write_message(WireMessage::AuthenticationGSS);
    }
}

#[derive(Debug, Clone)]
pub struct ServerSSLRequest;

#[derive(Debug)]
pub struct ServerSSLResponder(UntypedResponder);

impl ServerSSLResponder {
    pub fn respond_ssl(self, mut server: WireServer) -> UpgradeConnection {
        server.consume_responder(self.0);

        server.write_queue.write_u8(b'S');

        UpgradeConnection {
            read_buffer: server.read_queue.into(),
            write_buffer: server.write_queue.into(),
        }
    }

    pub fn respond_no_ssl(self, server: &mut WireServer) {
        server.consume_responder(self.0);

        server.write_queue.write_u8(b'N');

        // Restart the protocol from the beginning.
        server.state = WireState::BackendStartup;
        server.pending_upgrade = false;
    }
}

#[derive(Debug, Clone)]
pub struct ServerGSSENCRequest;

#[derive(Debug)]
pub struct ServerGSSENCResponder(UntypedResponder);

impl ServerGSSENCResponder {
    pub fn respond_gssenc(self, mut server: WireServer) -> UpgradeConnection {
        server.consume_responder(self.0);

        server.write_queue.write_u8(b'G');

        UpgradeConnection {
            read_buffer: server.read_queue.into(),
            write_buffer: server.write_queue.into(),
        }
    }

    pub fn respond_no_gssenc(self, server: &mut WireServer) {
        server.consume_responder(self.0);

        server.write_queue.write_u8(b'N');

        // Restart the protocol from the beginning.
        server.state = WireState::BackendStartup;
        server.pending_upgrade = false;
    }
}

/// A structure representing an upgraded connection after protocol negotiation.
///
/// The caller is responsible for transferring the unconsumed data to the upgraded
/// connection, and completing the pending write operations.
#[derive(Debug)]
pub struct UpgradeConnection {
    /// The data read from the stream but haven't been consumed by the original protocol.
    pub read_buffer: Vec<u8>,
    /// The remaining data to be written to the stream from the original protocol.
    pub write_buffer: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ServerCancelRequest {
    pub process_id: i32,
    pub secret_key: Vec<u8>,
}

#[derive(Debug)]
pub struct ServerCancelResponder(UntypedResponder);

impl ServerCancelResponder {
    pub fn respond_cancelled(self, server: &mut WireServer) {
        server.consume_responder(self.0);

        server.mark_write_closed();
    }
}
