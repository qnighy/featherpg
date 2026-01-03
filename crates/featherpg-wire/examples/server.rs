use std::io;
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};

use featherpg_wire::message::{CancelRequest, StartupMessage};
use featherpg_wire::server::{
    ServerInStartupResponse, ServerStream, TypedCleartextPasswordClientResponse,
    TypedInitialRequest,
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

fn handle_client(stream: TcpStream) -> io::Result<()> {
    eprintln!("Client connected from: {:?}", stream.peer_addr()?);

    // handle_session(stream, ServerSession_)?;
    let (mut s, mut server) = ServerStream::new(stream);

    loop {
        match server.read_initial_request(&mut s)? {
            TypedInitialRequest::StartupMessage(msg, server) => {
                return handle_startup_message(s, server, msg);
            }
            TypedInitialRequest::SSLRequest(_, server2)
            | TypedInitialRequest::DirectTLS(_, server2) => {
                eprintln!("Refusing TLS upgrade");
                server = server2.no_tls(&mut s)?;
            }
            TypedInitialRequest::GSSENCRequest(_, server2) => {
                eprintln!("Refusing GSSENC upgrade");
                server = server2.no_gssenc(&mut s)?;
            }
            TypedInitialRequest::CancelRequest(msg) => {
                return handle_cancel_request(msg);
            }
            TypedInitialRequest::ImplicitTerminate(_) => {
                return Ok(());
            }
        }
    }
}

const REQUEST_PASSWORD: bool = false;

fn handle_startup_message(
    mut s: ServerStream<TcpStream>,
    server: ServerInStartupResponse,
    msg: StartupMessage,
) -> io::Result<()> {
    eprintln!("Processing StartupMessage: {:?}", msg);

    let _server = if REQUEST_PASSWORD {
        let server = server.request_cleartext_password(&mut s)?;
        let server = match server {
            TypedCleartextPasswordClientResponse::CleartextPasswordMessage(
                cleartext_password_message,
                server,
            ) => {
                eprintln!(
                    "Received cleartext password: {:?}",
                    cleartext_password_message.password
                );
                server
            }
            TypedCleartextPasswordClientResponse::ImplicitTerminate(_) => {
                return Ok(());
            }
        };
        server.authentication_ok(&mut s)?
    } else {
        server.authentication_ok(&mut s)?
    };

    Ok(())
}

fn handle_cancel_request(msg: CancelRequest) -> io::Result<()> {
    eprintln!(
        "Processing CancelRequest: process_id={}, secret_key={:?}",
        msg.process_id, msg.secret_key
    );
    Ok(())
}
