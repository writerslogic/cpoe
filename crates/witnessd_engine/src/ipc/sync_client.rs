// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::crypto::{decode_message, encode_message};
use super::messages::IpcMessage;
use anyhow::{anyhow, Result};
use std::path::PathBuf;
use std::time::Duration;

// ============================================================================
// IpcClient - Synchronous client for CLI commands
// ============================================================================

#[cfg(not(target_os = "windows"))]
use std::io::{Read, Write};
/// Synchronous IPC client for sending commands to the daemon.
/// Used by CLI commands like `track` and `untrack`.
#[cfg(not(target_os = "windows"))]
pub struct IpcClient {
    stream: std::os::unix::net::UnixStream,
}

#[cfg(not(target_os = "windows"))]
impl IpcClient {
    /// Connect to the daemon socket at the given path.
    pub fn connect(path: PathBuf) -> Result<Self> {
        let stream = std::os::unix::net::UnixStream::connect(&path).map_err(|e| {
            anyhow!(
                "Failed to connect to daemon socket at {}: {}",
                path.display(),
                e
            )
        })?;

        // Set read/write timeouts to prevent hanging
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;

        Ok(Self { stream })
    }

    /// Send a message to the daemon.
    pub fn send_message(&mut self, msg: &IpcMessage) -> Result<()> {
        let encoded = encode_message(msg)?;

        // Write length prefix (4 bytes, little-endian)
        let len = encoded.len() as u32;
        self.stream.write_all(&len.to_le_bytes())?;

        // Write message
        self.stream.write_all(&encoded)?;
        self.stream.flush()?;

        Ok(())
    }

    /// Receive a message from the daemon.
    pub fn recv_message(&mut self) -> Result<IpcMessage> {
        // Read length prefix
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf)?;
        let len = u32::from_le_bytes(len_buf) as usize;

        // Sanity check on message length
        if len > super::messages::MAX_MESSAGE_SIZE {
            return Err(anyhow!("Message too large: {} bytes", len));
        }

        // Read message
        let mut buffer = vec![0u8; len];
        self.stream.read_exact(&mut buffer)?;

        decode_message(&buffer)
    }

    /// Send a message and wait for a response.
    pub fn send_and_recv(&mut self, msg: &IpcMessage) -> Result<IpcMessage> {
        self.send_message(msg)?;
        self.recv_message()
    }
}

/// Windows IPC client using Named Pipes.
///
/// Connects to the witnessd daemon via a Windows Named Pipe. The pipe name is
/// derived from the provided path (e.g., a path ending in `witnessd_ipc` becomes
/// `\\.\pipe\witnessd-witnessd_ipc`). Uses the same length-prefixed bincode wire
/// protocol as the Unix client: [4-byte LE length][payload].
///
/// The Windows WinUI app uses its own C# IPC client for the GUI. This Rust client
/// is primarily used by `witnessd_cli` on Windows.
#[cfg(target_os = "windows")]
pub struct IpcClient {
    // std::fs::File can open Windows Named Pipes as regular file handles.
    // This avoids needing raw Win32 CreateFileW calls while supporting
    // synchronous Read/Write via the std::io traits.
    pipe: std::fs::File,
}

#[cfg(target_os = "windows")]
impl IpcClient {
    /// Connect to the daemon's named pipe.
    ///
    /// The `path` parameter is used to derive the pipe name, matching the server's
    /// naming convention: `\\.\pipe\witnessd-{filename}`.
    /// For example, if `path` is `/tmp/witnessd_ipc` or `C:\...\witnessd_ipc`,
    /// the pipe name will be `\\.\pipe\witnessd-witnessd_ipc`.
    pub fn connect(path: PathBuf) -> Result<Self> {
        let pipe_name = format!(
            r"\\.\pipe\witnessd-{}",
            path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "sentinel".to_string())
        );

        // Open the named pipe as a file. On Windows, named pipes are accessible
        // via their UNC path (\\.\pipe\...) using standard file I/O.
        let pipe = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&pipe_name)
            .map_err(|e| {
                anyhow!(
                    "Failed to connect to daemon named pipe at {}: {}. \
                     Is the witnessd daemon running?",
                    pipe_name,
                    e
                )
            })?;

        // Set read/write timeouts via the raw handle to prevent hanging.
        // Named pipes opened as files support timeouts through SetNamedPipeHandleState,
        // but the simplest cross-compatible approach is to rely on the pipe's default
        // timeout (set by the server). The server creates pipes with a 5-second default.

        Ok(Self { pipe })
    }

    /// Send a message to the daemon using the length-prefixed bincode wire protocol.
    pub fn send_message(&mut self, msg: &IpcMessage) -> Result<()> {
        use std::io::Write;

        let encoded = encode_message(msg)?;

        // Write length prefix (4 bytes, little-endian)
        let len = encoded.len() as u32;
        self.pipe.write_all(&len.to_le_bytes())?;

        // Write message payload
        self.pipe.write_all(&encoded)?;
        self.pipe.flush()?;

        Ok(())
    }

    /// Receive a message from the daemon using the length-prefixed bincode wire protocol.
    pub fn recv_message(&mut self) -> Result<IpcMessage> {
        use std::io::Read;

        // Read length prefix (4 bytes, little-endian)
        let mut len_buf = [0u8; 4];
        self.pipe.read_exact(&mut len_buf)?;
        let len = u32::from_le_bytes(len_buf) as usize;

        // Sanity check on message length
        if len > super::messages::MAX_MESSAGE_SIZE {
            return Err(anyhow!("Message too large: {} bytes", len));
        }

        // Read message payload
        let mut buffer = vec![0u8; len];
        self.pipe.read_exact(&mut buffer)?;

        decode_message(&buffer)
    }

    /// Send a message and wait for a response.
    pub fn send_and_recv(&mut self, msg: &IpcMessage) -> Result<IpcMessage> {
        self.send_message(msg)?;
        self.recv_message()
    }
}
