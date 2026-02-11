pub mod unix_socket;
pub mod secure_channel;

use serde::{Serialize, Deserialize};
use std::path::PathBuf;
use tokio::net::{UnixListener, UnixStream};
#[cfg(target_os = "windows")]
use tokio::net::windows::named_pipe;
use anyhow::{anyhow, Result};
use std::sync::{Arc, Mutex};
use crate::jitter::SimpleJitterSample;

/// IPC Message Protocol for high-performance communication between Brain and Face.
#[derive(Debug, Serialize, Deserialize)]
pub enum IpcMessage {
    // Requests
    Handshake { version: String },
    StartWitnessing { file_path: PathBuf },
    StopWitnessing,
    
    // Events (Push from Brain to Face)
    Pulse(SimpleJitterSample),
    CheckpointCreated { id: i64, hash: [u8; 32] },
    SystemAlert { level: String, message: String },
    
    // Status
    Heartbeat,
}

pub struct IpcServer {
    #[cfg(not(target_os = "windows"))]
    listener: UnixListener,
    #[cfg(target_os = "windows")]
    pipe_name: String,
}

impl IpcServer {
    #[cfg(not(target_os = "windows"))]
    pub fn bind(path: PathBuf) -> Result<Self> {
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        let listener = UnixListener::bind(path)?;
        Ok(Self { listener })
    }

    #[cfg(target_os = "windows")]
    pub fn bind(pipe_name: String) -> Result<Self> {
        Ok(Self { pipe_name })
    }

    pub async fn run(&self) -> Result<()> {
        #[cfg(not(target_os = "windows"))]
        {
            loop {
                let (stream, _) = self.listener.accept().await?;
                tokio::spawn(handle_connection(stream));
            }
        }
        #[cfg(target_os = "windows")]
        {
            // Windows Named Pipe implementation using tokio
            loop {
                let server = named_pipe::ServerOptions::new()
                    .first_pipe_instance(true)
                    .create(&self.pipe_name)?;
                
                server.connect().await?;
                // handle_windows_connection(server)
            }
        }
    }
}

async fn handle_connection(mut stream: UnixStream) {
    // Binary protocol handling using bincode
    let mut buffer = vec![0u8; 1024];
    loop {
        match tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await {
            Ok(0) => break, // Connection closed
            Ok(n) => {
                if let Ok(msg) = bincode::deserialize::<IpcMessage>(&buffer[..n]) {
                    println!("Received IPC message: {:?}", msg);
                }
            }
            Err(_) => break,
        }
    }
}
