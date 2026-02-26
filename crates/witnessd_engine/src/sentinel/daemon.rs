// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::core::Sentinel;
use super::error::{Result, SentinelError};
use super::ipc_handler::SentinelIpcHandler;
use crate::config::SentinelConfig;
use crate::ipc::IpcServer;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// Persistent state of the sentinel daemon
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DaemonState {
    pub pid: i32,
    pub started_at: i64, // Unix timestamp
    pub version: String,
    pub identity: Option<String>,
}

/// Status information for display
#[derive(Debug, Clone)]
pub struct DaemonStatus {
    pub running: bool,
    pub pid: Option<i32>,
    pub started_at: Option<SystemTime>,
    pub uptime: Option<Duration>,
    pub version: Option<String>,
    pub identity: Option<String>,
}

/// Manages daemon lifecycle operations
pub struct DaemonManager {
    witnessd_dir: PathBuf,
    pid_file: PathBuf,
    state_file: PathBuf,
    socket_path: PathBuf,
}

impl DaemonManager {
    /// Create a new daemon manager
    pub fn new(witnessd_dir: impl AsRef<Path>) -> Self {
        let witnessd_dir = witnessd_dir.as_ref().to_path_buf();
        let sentinel_dir = witnessd_dir.join("sentinel");

        Self {
            witnessd_dir,
            pid_file: sentinel_dir.join("daemon.pid"),
            state_file: sentinel_dir.join("daemon.state"),
            socket_path: sentinel_dir.join("daemon.sock"),
        }
    }

    /// Check if the sentinel daemon is running
    pub fn is_running(&self) -> bool {
        if let Ok(pid) = self.read_pid() {
            is_process_running(pid)
        } else {
            false
        }
    }

    /// Read the daemon's PID from the PID file
    pub fn read_pid(&self) -> Result<i32> {
        let data = fs::read_to_string(&self.pid_file)?;
        data.trim().parse().map_err(|_| {
            SentinelError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid PID file",
            ))
        })
    }

    /// Write the current process PID to the PID file
    pub fn write_pid(&self) -> Result<()> {
        fs::create_dir_all(self.pid_file.parent().unwrap())?;
        fs::write(&self.pid_file, std::process::id().to_string())?;
        Ok(())
    }

    /// Remove the PID file
    pub fn remove_pid(&self) -> Result<()> {
        fs::remove_file(&self.pid_file)?;
        Ok(())
    }

    /// Write the daemon state
    pub fn write_state(&self, state: &DaemonState) -> Result<()> {
        let json = serde_json::to_string_pretty(state)
            .map_err(|e| SentinelError::Serialization(e.to_string()))?;
        fs::write(&self.state_file, json)?;
        Ok(())
    }

    /// Read the daemon state
    pub fn read_state(&self) -> Result<DaemonState> {
        let data = fs::read_to_string(&self.state_file)?;
        serde_json::from_str(&data).map_err(|e| SentinelError::Serialization(e.to_string()))
    }

    /// Signal the daemon to stop (SIGTERM)
    #[cfg(unix)]
    pub fn signal_stop(&self) -> Result<()> {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        let pid = self.read_pid()?;
        kill(Pid::from_raw(pid), Signal::SIGTERM)
            .map_err(|e| SentinelError::Io(std::io::Error::other(e.to_string())))?;
        Ok(())
    }

    #[cfg(not(unix))]
    pub fn signal_stop(&self) -> Result<()> {
        Err(SentinelError::NotAvailable(
            "Signal handling not available on this platform".to_string(),
        ))
    }

    /// Signal the daemon to reload (SIGHUP)
    #[cfg(unix)]
    pub fn signal_reload(&self) -> Result<()> {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        let pid = self.read_pid()?;
        kill(Pid::from_raw(pid), Signal::SIGHUP)
            .map_err(|e| SentinelError::Io(std::io::Error::other(e.to_string())))?;
        Ok(())
    }

    #[cfg(not(unix))]
    pub fn signal_reload(&self) -> Result<()> {
        Err(SentinelError::NotAvailable(
            "Signal handling not available on this platform".to_string(),
        ))
    }

    /// Wait for the daemon to stop
    pub fn wait_for_stop(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;

        while Instant::now() < deadline {
            if !self.is_running() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        Err(SentinelError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("daemon did not stop within {:?}", timeout),
        )))
    }

    /// Clean up PID and state files
    pub fn cleanup(&self) {
        let _ = fs::remove_file(&self.pid_file);
        let _ = fs::remove_file(&self.state_file);
        let _ = fs::remove_file(&self.socket_path);
    }

    /// Get the current daemon status
    pub fn status(&self) -> DaemonStatus {
        let mut status = DaemonStatus {
            running: false,
            pid: None,
            started_at: None,
            uptime: None,
            version: None,
            identity: None,
        };

        // Check if running
        if let Ok(pid) = self.read_pid() {
            if is_process_running(pid) {
                status.running = true;
                status.pid = Some(pid);
            }
        }

        // Read state if available
        if let Ok(state) = self.read_state() {
            let started_at = UNIX_EPOCH + Duration::from_secs(state.started_at as u64);
            status.started_at = Some(started_at);
            status.version = Some(state.version);
            status.identity = state.identity;

            if status.running {
                status.uptime = started_at.elapsed().ok();
            }
        }

        status
    }

    /// Get the sentinel directory path
    pub fn sentinel_dir(&self) -> PathBuf {
        self.witnessd_dir.join("sentinel")
    }

    /// Get the WAL directory path
    pub fn wal_dir(&self) -> PathBuf {
        self.witnessd_dir.join("sentinel").join("wal")
    }
}

/// Check if a process with the given PID is running
#[cfg(unix)]
fn is_process_running(pid: i32) -> bool {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    kill(Pid::from_raw(pid), Signal::SIGCONT).is_ok()
}

#[cfg(not(unix))]
fn is_process_running(_pid: i32) -> bool {
    false
}

// ============================================================================
// CLI Command Handlers
// ============================================================================

/// Start the sentinel daemon with IPC server.
///
/// This function:
/// 1. Creates and starts the Sentinel for document tracking
/// 2. Starts an IPC server to handle client requests
/// 3. Writes the PID and state files for daemon management
pub async fn cmd_start(witnessd_dir: &Path) -> Result<()> {
    let daemon_mgr = DaemonManager::new(witnessd_dir);

    if daemon_mgr.is_running() {
        let status = daemon_mgr.status();
        if let Some(pid) = status.pid {
            return Err(SentinelError::DaemonAlreadyRunning(pid));
        }
    }

    // Create config
    let config = SentinelConfig::default().with_witnessd_dir(witnessd_dir);

    // Create and start sentinel
    let sentinel = Arc::new(Sentinel::new(config)?);

    // Load signing key from secure storage if available
    if let Ok(Some(hmac_key)) = crate::identity::SecureStorage::load_hmac_key() {
        sentinel.set_hmac_key(hmac_key);
    }

    sentinel.start().await?;

    // Create IPC server
    let socket_path = witnessd_dir.join("sentinel.sock");
    let ipc_server = IpcServer::bind(socket_path.clone())
        .map_err(|e| SentinelError::Ipc(format!("Failed to bind IPC socket: {}", e)))?;

    // Create IPC handler
    let ipc_handler = Arc::new(SentinelIpcHandler::new(Arc::clone(&sentinel)));

    // Create shutdown channel for IPC server
    let (ipc_shutdown_tx, ipc_shutdown_rx) = mpsc::channel::<()>(1);

    // Start IPC server in background
    let ipc_handle = tokio::spawn(async move {
        if let Err(e) = ipc_server
            .run_with_shutdown(ipc_handler, ipc_shutdown_rx)
            .await
        {
            eprintln!("IPC server error: {}", e);
        }
    });

    // Write PID and state
    daemon_mgr.write_pid()?;
    daemon_mgr.write_state(&DaemonState {
        pid: std::process::id() as i32,
        started_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        version: env!("CARGO_PKG_VERSION").to_string(),
        identity: None,
    })?;

    // Store shutdown sender for later use (when stopping)
    // For now, we'll just drop it since the daemon will be stopped via signal
    // In a production setup, you'd want to store this in the DaemonManager
    // or use a different shutdown mechanism
    drop(ipc_shutdown_tx);
    drop(ipc_handle);

    Ok(())
}

/// Start the sentinel daemon and run until shutdown signal.
///
/// This is the main entry point for running the daemon as a foreground process.
/// It will block until a shutdown signal (SIGTERM, SIGINT) is received.
pub async fn cmd_start_foreground(witnessd_dir: &Path) -> Result<()> {
    let daemon_mgr = DaemonManager::new(witnessd_dir);

    if daemon_mgr.is_running() {
        let status = daemon_mgr.status();
        if let Some(pid) = status.pid {
            return Err(SentinelError::DaemonAlreadyRunning(pid));
        }
    }

    // Create config
    let config = SentinelConfig::default().with_witnessd_dir(witnessd_dir);

    // Create and start sentinel
    let sentinel = Arc::new(Sentinel::new(config)?);

    // Load signing key from secure storage if available
    if let Ok(Some(hmac_key)) = crate::identity::SecureStorage::load_hmac_key() {
        sentinel.set_hmac_key(hmac_key);
    }

    sentinel.start().await?;

    // Create IPC server
    let socket_path = witnessd_dir.join("sentinel.sock");
    let ipc_server = IpcServer::bind(socket_path.clone())
        .map_err(|e| SentinelError::Ipc(format!("Failed to bind IPC socket: {}", e)))?;

    // Create IPC handler
    let ipc_handler = Arc::new(SentinelIpcHandler::new(Arc::clone(&sentinel)));

    // Create shutdown channel for IPC server
    let (ipc_shutdown_tx, ipc_shutdown_rx) = mpsc::channel::<()>(1);

    // Write PID and state
    daemon_mgr.write_pid()?;
    daemon_mgr.write_state(&DaemonState {
        pid: std::process::id() as i32,
        started_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        version: env!("CARGO_PKG_VERSION").to_string(),
        identity: None,
    })?;

    // Start IPC server in background
    let sentinel_clone = Arc::clone(&sentinel);
    let ipc_handle = tokio::spawn(async move {
        if let Err(e) = ipc_server
            .run_with_shutdown(ipc_handler, ipc_shutdown_rx)
            .await
        {
            eprintln!("IPC server error: {}", e);
        }
    });

    // Wait for shutdown signal
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm =
            signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("Failed to install SIGINT handler");

        tokio::select! {
            _ = sigterm.recv() => {
                println!("Received SIGTERM, shutting down...");
            }
            _ = sigint.recv() => {
                println!("Received SIGINT, shutting down...");
            }
        }
    }

    #[cfg(not(unix))]
    {
        // On non-Unix platforms, just wait for Ctrl+C
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
        println!("Received shutdown signal, shutting down...");
    }

    // Shutdown sequence
    let _ = ipc_shutdown_tx.send(()).await;
    sentinel_clone.stop().await?;
    ipc_handle.abort();

    // Cleanup
    daemon_mgr.cleanup();

    Ok(())
}

/// Stop the sentinel daemon
pub fn cmd_stop(witnessd_dir: &Path) -> Result<()> {
    let daemon_mgr = DaemonManager::new(witnessd_dir);

    if !daemon_mgr.is_running() {
        return Err(SentinelError::DaemonNotRunning);
    }

    daemon_mgr.signal_stop()?;
    daemon_mgr.wait_for_stop(Duration::from_secs(10))?;
    daemon_mgr.cleanup();

    Ok(())
}

/// Get sentinel status
pub fn cmd_status(witnessd_dir: &Path) -> DaemonStatus {
    let daemon_mgr = DaemonManager::new(witnessd_dir);
    daemon_mgr.status()
}

/// Track a file via IPC to the running daemon.
///
/// Sends a StartWitnessing message to the daemon and waits for a response.
pub fn cmd_track(witnessd_dir: &Path, file_path: &Path) -> Result<()> {
    use crate::ipc::{IpcClient, IpcErrorCode, IpcMessage};

    let daemon_mgr = DaemonManager::new(witnessd_dir);

    if !daemon_mgr.is_running() {
        return Err(SentinelError::DaemonNotRunning);
    }

    // Canonicalize the file path to get absolute path
    let abs_path = file_path.canonicalize()?;

    // Connect to the daemon socket
    let socket_path = witnessd_dir.join("sentinel.sock");
    let mut client = IpcClient::connect(socket_path)
        .map_err(|e| SentinelError::Ipc(format!("Failed to connect to daemon: {}", e)))?;

    // Send StartWitnessing message
    let msg = IpcMessage::StartWitnessing {
        file_path: abs_path.clone(),
    };
    let response = client
        .send_and_recv(&msg)
        .map_err(|e| SentinelError::Ipc(format!("Failed to communicate with daemon: {}", e)))?;

    // Handle response
    match response {
        IpcMessage::Ok { message } => {
            if let Some(msg) = message {
                println!("{}", msg);
            } else {
                println!("Now tracking: {}", abs_path.display());
            }
            Ok(())
        }
        IpcMessage::Error { code, message } => {
            // Map IPC error codes to appropriate sentinel errors
            match code {
                IpcErrorCode::FileNotFound => Err(SentinelError::Ipc(format!(
                    "File not found: {}",
                    abs_path.display()
                ))),
                IpcErrorCode::AlreadyTracking => {
                    // Not necessarily an error - just inform user
                    println!("Already tracking: {}", abs_path.display());
                    Ok(())
                }
                IpcErrorCode::PermissionDenied => Err(SentinelError::Ipc(format!(
                    "Permission denied: {}",
                    abs_path.display()
                ))),
                _ => Err(SentinelError::Ipc(message)),
            }
        }
        _ => Err(SentinelError::Ipc(format!(
            "Unexpected response from daemon: {:?}",
            response
        ))),
    }
}

/// Untrack a file via IPC to the running daemon.
///
/// Sends a StopWitnessing message to the daemon and waits for a response.
pub fn cmd_untrack(witnessd_dir: &Path, file_path: &Path) -> Result<()> {
    use crate::ipc::{IpcClient, IpcErrorCode, IpcMessage};

    let daemon_mgr = DaemonManager::new(witnessd_dir);

    if !daemon_mgr.is_running() {
        return Err(SentinelError::DaemonNotRunning);
    }

    // Canonicalize the file path to get absolute path
    let abs_path = file_path.canonicalize()?;

    // Connect to the daemon socket
    let socket_path = witnessd_dir.join("sentinel.sock");
    let mut client = IpcClient::connect(socket_path)
        .map_err(|e| SentinelError::Ipc(format!("Failed to connect to daemon: {}", e)))?;

    // Send StopWitnessing message
    let msg = IpcMessage::StopWitnessing {
        file_path: Some(abs_path.clone()),
    };
    let response = client
        .send_and_recv(&msg)
        .map_err(|e| SentinelError::Ipc(format!("Failed to communicate with daemon: {}", e)))?;

    // Handle response
    match response {
        IpcMessage::Ok { message } => {
            if let Some(msg) = message {
                println!("{}", msg);
            } else {
                println!("Stopped tracking: {}", abs_path.display());
            }
            Ok(())
        }
        IpcMessage::Error { code, message } => {
            // Map IPC error codes to appropriate sentinel errors
            match code {
                IpcErrorCode::FileNotFound => Err(SentinelError::Ipc(format!(
                    "File not found: {}",
                    abs_path.display()
                ))),
                IpcErrorCode::NotTracking => {
                    // Not necessarily an error - just inform user
                    println!("Not currently tracking: {}", abs_path.display());
                    Ok(())
                }
                IpcErrorCode::PermissionDenied => Err(SentinelError::Ipc(format!(
                    "Permission denied: {}",
                    abs_path.display()
                ))),
                _ => Err(SentinelError::Ipc(message)),
            }
        }
        _ => Err(SentinelError::Ipc(format!(
            "Unexpected response from daemon: {:?}",
            response
        ))),
    }
}
