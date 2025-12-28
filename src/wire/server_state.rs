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
    /// Set to true if there is a chance the connection will be upgraded to SSL.
    pending_upgrade: bool,
    write_queue: ByteQueue,
    request_queue: VecDeque<ServerWireRequest>,
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
            pending_upgrade: false,
            write_queue: ByteQueue::new(),
            request_queue: VecDeque::new(),
            id: NEXT_WIRE_SERVER_ID.fetch_add(1, atomic::Ordering::Relaxed),
            next_pending_responder_id: 1,
            fresh_responder_id: 1,
        }
    }

    pub fn append_read(&mut self, data: &[u8]) {
        self.read_queue.extend_from_slice(data);

        self.process_incoming_messages();
    }

    fn process_incoming_messages(&mut self) {
        while !self.pending_upgrade {
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

    fn write_message(&mut self, msg: WireMessage) {
        msg.write_to(&mut self.write_queue);
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
