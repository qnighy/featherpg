use crate::wire::{
    io_util::ByteQueue,
    message::{WireMessage, WireState},
};

/// Represents the wire protocol state on the server side.
#[derive(Debug, Clone)]
pub struct WireServer {
    state: WireState,
    read_queue: ByteQueue,
    write_queue: ByteQueue,
}

impl WireServer {
    pub fn new() -> Self {
        Self {
            state: WireState::BackendStartup,
            read_queue: ByteQueue::new(),
            write_queue: ByteQueue::new(),
        }
    }

    pub fn append_read(&mut self, data: &[u8]) {
        self.read_queue.extend_from_slice(data);

        self.process_incoming_messages();
    }

    fn process_incoming_messages(&mut self) {
        loop {
            let len = WireMessage::bytes_required(&mut *self.read_queue, self.state);
            if self.read_queue.len() < len {
                break;
            }

            // TODO: handle parse error
            let (msg, consumed) =
                WireMessage::parse_prefix(&mut *self.read_queue, self.state).unwrap();

            self.read_queue.consume(consumed);

            self.process_message(msg);
        }
    }

    fn process_message(&mut self, msg: WireMessage) {
        match msg {
            WireMessage::StartupMessage { .. } => {
                self.state = WireState::Ordinary;
                todo!();
            }
            _ => todo!(),
        }
    }

    pub fn write_buffer(&mut self) -> &[u8] {
        &*self.write_queue
    }

    pub fn consume_write(&mut self, count: usize) {
        self.write_queue.consume(count);
    }
}
