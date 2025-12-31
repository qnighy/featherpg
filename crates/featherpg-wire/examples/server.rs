use std::io;
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};

use featherpg_wire::server::{ConnectionKind, without_encryption};

fn main() -> io::Result<()> {
    let port = 15432;
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))?;
    println!(
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
    println!("Shutting down, waiting for {} threads...", handles.len());
    for handle in handles {
        let _ = handle.join();
    }
    println!("All threads completed");

    Ok(())
}

fn handle_client(stream: TcpStream) -> io::Result<()> {
    println!("Client connected from: {:?}", stream.peer_addr()?);

    let conn = match without_encryption(stream)? {
        ConnectionKind::Startup(conn) => conn,
        ConnectionKind::Cancel(req) => {
            println!(
                "Received CancelRequest: process_id={}, secret_key={:?}",
                req.process_id, req.secret_key
            );
            return Ok(());
        }
    };

    println!("Sending AuthenticationOk...");
    let conn = conn.authentication_ok()?;
    println!("Sending ReadyForQuery...");
    let conn = conn.ready()?;
    println!("Client is ready to process queries.");

    Ok(())
}
