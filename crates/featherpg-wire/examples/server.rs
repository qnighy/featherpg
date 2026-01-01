use std::io;
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};

use featherpg_wire::message::{CancelRequest, StartupMessage};
use featherpg_wire::server::{
    Authenticator, GSSENCResponse, InitializationNotifier, InitializeBackend, NegotiateEncryption,
    NoGSSENCUpgrade, NoTLSUpgrade, Session, TLSResponse, handle_session,
};

fn main() -> io::Result<()> {
    let port = 15432;
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))?;
    eprintln!(
        "PostgreSQL wire protocol server listening on 127.0.0.1:{}",
        port
    );

    let mut handles: Vec<JoinHandle<()>> = Vec::new();

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                handles.retain(|handle| !handle.is_finished());
                let handle = thread::spawn(move || {
                    let peer_addr = stream.peer_addr().ok();
                    if let Err(e) = handle_client(stream) {
                        eprintln!("Error handling client {:?}: {}", peer_addr, e);
                    }
                });
                handles.push(handle);
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }

    // Wait for all threads to complete
    eprintln!("Shutting down, waiting for {} threads...", handles.len());
    for handle in handles {
        let _ = handle.join();
    }
    eprintln!("All threads completed");

    Ok(())
}

struct ServerSession;

impl<S> NegotiateEncryption<S> for ServerSession {
    type UpgradeToTLS = NoTLSUpgrade;

    type UpgradeToGSSENC = NoGSSENCUpgrade;

    type InitializeBackend = Self;

    fn tls(&mut self) -> io::Result<TLSResponse<Self::UpgradeToTLS>> {
        eprintln!("No TLS");
        Ok(TLSResponse::NoTLS)
    }

    fn gssenc(&mut self) -> io::Result<GSSENCResponse<Self::UpgradeToGSSENC>> {
        eprintln!("No GSSENC");
        Ok(GSSENCResponse::NoGSSENC)
    }

    fn start(
        self,
        req: StartupMessage,
        _auth: &mut Authenticator<'_>,
    ) -> io::Result<Self::InitializeBackend> {
        eprintln!("Starting session with StartupMessage: {:?}", req);
        Ok(Self)
    }

    fn process_cancel(self, req: CancelRequest) -> io::Result<()> {
        eprintln!(
            "Processing CancelRequest: process_id={}, secret_key={:?}",
            req.process_id, req.secret_key
        );
        Ok(())
    }
}

impl InitializeBackend for ServerSession {
    type Session = Self;

    fn initialize_backend(
        self,
        _notifier: &mut InitializationNotifier<'_>,
    ) -> io::Result<Self::Session> {
        eprintln!("Backend initialized");
        Ok(self)
    }
}

impl Session for ServerSession {}

fn handle_client(stream: TcpStream) -> io::Result<()> {
    println!("Client connected from: {:?}", stream.peer_addr()?);

    handle_session(stream, ServerSession)?;

    Ok(())
}
