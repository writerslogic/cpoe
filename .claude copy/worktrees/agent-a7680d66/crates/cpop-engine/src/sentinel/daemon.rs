

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
use tokio::task::JoinHandle;

/
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DaemonState {
    /
    pub pid: i32,
    /
    pub started_at: i64,
    /
    pub version: String,
    /
    pub identity: Option<String>,
}

/
#[derive(Debug, Clone)]
pub struct DaemonStatus {
    /
    pub running: bool,
    /
    pub pid: Option<i32>,
    /
    pub started_at: Option<SystemTime>,
    /
    pub uptime: Option<Duration>,
    /
    pub version: Option<String>,
    /
    pub identity: Option<String>,
}

/
/
/
/
pub struct DaemonHandle {
    sentinel: Arc<Sentinel>,
    ipc_shutdown_tx: mpsc::Sender<()>,
    ipc_handle: JoinHandle<()>,
    daemon_mgr: DaemonManager,
}

impl DaemonHandle {
    /
    pub async fn shutdown(self) -> Result<()> {
        let _ = self.ipc_shutdown_tx.send(()).await;
        let stop_result = self.sentinel.stop().await;
        self.ipc_handle.abort();
        self.daemon_mgr.cleanup();
        stop_result
    }
}

/
pub struct DaemonManager {
    writerslogic_dir: PathBuf,
    pid_file: PathBuf,
    state_file: PathBuf,
    socket_path: PathBuf,
}

impl DaemonManager {
    /
    pub fn new(writerslogic_dir: impl AsRef<Path>) -> Self {
        let writerslogic_dir = writerslogic_dir.as_ref().to_path_buf();
        let sentinel_dir = writerslogic_dir.join("sentinel");

        Self {
            pid_file: sentinel_dir.join("daemon.pid"),
            state_file: sentinel_dir.join("daemon.state"),
            socket_path: writerslogic_dir.join("sentinel.sock"),
            writerslogic_dir,
        }
    }

    /
    pub fn is_running(&self) -> bool {
        if let Ok(pid) = self.read_pid() {
            is_process_running(pid)
        } else {
            false
        }
    }

    /
    pub fn read_pid(&self) -> Result<i32> {
        let data = fs::read_to_string(&self.pid_file)?;
        data.trim().parse().map_err(|_| {
            SentinelError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid PID file",
            ))
        })
    }

    /
    pub fn write_pid(&self) -> Result<()> {
        let parent = self.pid_file.parent().ok_or_else(|| {
            SentinelError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "PID file path has no parent directory: {}",
                    self.pid_file.display()
                ),
            ))
        })?;
        fs::create_dir_all(parent)?;
        fs::write(&self.pid_file, std::process::id().to_string())?;
        Ok(())
    }

    /
    pub fn write_pid_value(&self, pid: u32) -> Result<()> {
        let parent = self.pid_file.parent().ok_or_else(|| {
            SentinelError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "PID file path has no parent directory: {}",
                    self.pid_file.display()
                ),
            ))
        })?;
        fs::create_dir_all(parent)?;
        fs::write(&self.pid_file, pid.to_string())?;
        Ok(())
    }

    /
    /
    /
    /
    /
    /
    /
    pub fn acquire_pid_file(&self, pid: u32) -> Result<bool> {
        use std::fs::OpenOptions;
        use std::io::Write;

        let parent = self.pid_file.parent().ok_or_else(|| {
            SentinelError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "PID file path has no parent directory: {}",
                    self.pid_file.display()
                ),
            ))
        })?;
        fs::create_dir_all(parent)?;

        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.pid_file)
        {
            Ok(mut f) => {
                writeln!(f, "{}", pid)?;
                return Ok(true);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(SentinelError::Io(e)),
        }

        if let Ok(existing_pid) = self.read_pid() {
            if is_process_running(existing_pid) {
                return Ok(false);
            }
        }
        
        
        
        let _ = fs::remove_file(&self.pid_file);

        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.pid_file)
        {
            Ok(mut f) => {
                writeln!(f, "{}", pid)?;
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(SentinelError::Io(e)),
        }
    }

    /
    pub fn remove_pid(&self) -> Result<()> {
        fs::remove_file(&self.pid_file)?;
        Ok(())
    }

    /
    pub fn write_state(&self, state: &DaemonState) -> Result<()> {
        let json = serde_json::to_string_pretty(state)
            .map_err(|e| SentinelError::Serialization(e.to_string()))?;
        fs::write(&self.state_file, json)?;
        Ok(())
    }

    /
    pub fn read_state(&self) -> Result<DaemonState> {
        let data = fs::read_to_string(&self.state_file)?;
        serde_json::from_str(&data).map_err(|e| SentinelError::Serialization(e.to_string()))
    }

    /
    #[cfg(unix)]
    pub fn signal_stop(&self) -> Result<()> {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        let pid = self.read_pid()?;
        kill(Pid::from_raw(pid), Signal::SIGTERM)
            .map_err(|e| SentinelError::Io(std::io::Error::other(e.to_string())))?;
        Ok(())
    }

    #[cfg(windows)]
    pub fn signal_stop(&self) -> Result<()> {
        let pid = self.read_pid()?;
        let pid_str = pid.to_string();

        
        
        
        let graceful = std::process::Command::new("taskkill")
            .args(["/PID", &pid_str])
            .output()
            .map_err(SentinelError::Io)?;

        if graceful.status.success() {
            
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if !is_process_running(pid) {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }

        
        log::warn!("pid {pid} did not exit gracefully, sending /F");
        let output = std::process::Command::new("taskkill")
            .args(["/PID", &pid_str, "/F"])
            .output()
            .map_err(SentinelError::Io)?;
        if output.status.success() {
            Ok(())
        } else {
            Err(SentinelError::Io(std::io::Error::other(
                String::from_utf8_lossy(&output.stderr).to_string(),
            )))
        }
    }

    #[cfg(not(any(unix, windows)))]
    pub fn signal_stop(&self) -> Result<()> {
        Err(SentinelError::NotAvailable(
            "process signals not supported on this platform".to_string(),
        ))
    }

    /
    #[cfg(unix)]
    pub fn signal_reload(&self) -> Result<()> {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        let pid = self.read_pid()?;
        kill(Pid::from_raw(pid), Signal::SIGHUP)
            .map_err(|e| SentinelError::Io(std::io::Error::other(e.to_string())))?;
        Ok(())
    }

    /
    #[cfg(not(unix))]
    pub fn signal_reload(&self) -> Result<()> {
        Err(SentinelError::NotAvailable(
            "Signal handling not available on this platform".to_string(),
        ))
    }

    /
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

    /
    pub fn cleanup(&self) {
        for path in [&self.pid_file, &self.state_file, &self.socket_path] {
            if let Err(e) = fs::remove_file(path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    log::debug!("cleanup {}: {e}", path.display());
                }
            }
        }
    }

    /
    pub fn status(&self) -> DaemonStatus {
        let mut status = DaemonStatus {
            running: false,
            pid: None,
            started_at: None,
            uptime: None,
            version: None,
            identity: None,
        };

        if let Ok(pid) = self.read_pid() {
            if is_process_running(pid) {
                status.running = true;
                status.pid = Some(pid);
            }
        }

        if let Ok(state) = self.read_state() {
            
            let started_at =
                UNIX_EPOCH + Duration::from_secs(u64::try_from(state.started_at).unwrap_or(0));
            status.started_at = Some(started_at);
            status.version = Some(state.version);
            status.identity = state.identity;

            if status.running {
                status.uptime = started_at.elapsed().ok();
            }
        }

        status
    }

    /
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /
    pub fn sentinel_dir(&self) -> PathBuf {
        self.writerslogic_dir.join("sentinel")
    }

    /
    pub fn wal_dir(&self) -> PathBuf {
        self.writerslogic_dir.join("sentinel").join("wal")
    }
}

#[cfg(unix)]
fn is_process_running(pid: i32) -> bool {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;

    kill(Pid::from_raw(pid), None).is_ok()
}

#[cfg(windows)]
fn is_process_running(pid: i32) -> bool {
    use sysinfo::{Pid, ProcessesToUpdate, System};
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::Some(&[Pid::from(pid as usize)]), true);
    sys.process(Pid::from(pid as usize)).is_some()
}

#[cfg(not(any(unix, windows)))]
fn is_process_running(_pid: i32) -> bool {
    false
}

struct DaemonSetup {
    sentinel: Arc<Sentinel>,
    ipc_shutdown_tx: mpsc::Sender<()>,
    ipc_handle: tokio::task::JoinHandle<()>,
    daemon_mgr: DaemonManager,
}

async fn setup_daemon(writerslogic_dir: &Path) -> Result<DaemonSetup> {
    let daemon_mgr = DaemonManager::new(writerslogic_dir);

    if daemon_mgr.is_running() {
        let status = daemon_mgr.status();
        if let Some(pid) = status.pid {
            return Err(SentinelError::DaemonAlreadyRunning(pid));
        }
    }

    
    let pid = std::process::id();
    if !daemon_mgr.acquire_pid_file(pid)? {
        return Err(SentinelError::DaemonAlreadyRunning(pid as i32));
    }

    let config = SentinelConfig::default().with_writersproof_dir(writerslogic_dir);
    let sentinel = Arc::new(Sentinel::new(config)?);

    if let Ok(Some(hmac_key)) = crate::identity::SecureStorage::load_hmac_key() {
        sentinel.set_hmac_key(hmac_key.to_vec());
    }

    
    if let Err(e) = sentinel.start().await {
        daemon_mgr.cleanup();
        return Err(e);
    }

    let setup = async {
        let ipc_server = IpcServer::bind(daemon_mgr.socket_path().to_path_buf())
            .map_err(|e| SentinelError::Ipc(format!("Failed to bind IPC socket: {}", e)))?;

        let ipc_handler = Arc::new(SentinelIpcHandler::new(Arc::clone(&sentinel)));
        let (ipc_shutdown_tx, ipc_shutdown_rx) = mpsc::channel::<()>(1);

        let ipc_handle = tokio::spawn(async move {
            if let Err(e) = ipc_server
                .run_with_shutdown(ipc_handler, ipc_shutdown_rx)
                .await
            {
                log::error!("IPC server error: {}", e);
            }
        });

        daemon_mgr.write_state(&DaemonState {
            pid: pid as i32,
            started_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
                .unwrap_or(0),
            version: env!("CARGO_PKG_VERSION").to_string(),
            identity: None,
        })?;

        Ok((ipc_shutdown_tx, ipc_handle))
    }
    .await;

    let (ipc_shutdown_tx, ipc_handle) = match setup {
        Ok(val) => val,
        Err(e) => {
            if let Err(stop_err) = sentinel.stop().await {
                log::error!("Failed to stop sentinel after setup failure: {stop_err}");
            }
            daemon_mgr.cleanup();
            return Err(e);
        }
    };

    Ok(DaemonSetup {
        sentinel,
        ipc_shutdown_tx,
        ipc_handle,
        daemon_mgr,
    })
}

/
/
/
/
/
pub async fn cmd_start(writerslogic_dir: &Path) -> Result<DaemonHandle> {
    let setup = setup_daemon(writerslogic_dir).await?;

    Ok(DaemonHandle {
        sentinel: setup.sentinel,
        ipc_shutdown_tx: setup.ipc_shutdown_tx,
        ipc_handle: setup.ipc_handle,
        daemon_mgr: setup.daemon_mgr,
    })
}

/
pub async fn cmd_start_foreground(writerslogic_dir: &Path) -> Result<()> {
    let setup = setup_daemon(writerslogic_dir).await?;
    let sentinel = setup.sentinel;
    let ipc_shutdown_tx = setup.ipc_shutdown_tx;
    let ipc_handle = setup.ipc_handle;
    let daemon_mgr = setup.daemon_mgr;

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate())
            .map_err(|e| anyhow::anyhow!("Failed to install SIGTERM handler: {e}"))?;
        let mut sigint = signal(SignalKind::interrupt())
            .map_err(|e| anyhow::anyhow!("Failed to install SIGINT handler: {e}"))?;

        tokio::select! {
            _ = sigterm.recv() => {
                log::info!("Received SIGTERM, shutting down...");
            }
            _ = sigint.recv() => {
                log::info!("Received SIGINT, shutting down...");
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to install Ctrl+C handler: {e}"))?;
        log::info!("Received shutdown signal, shutting down...");
    }

    let _ = ipc_shutdown_tx.send(()).await;
    sentinel.stop().await?;
    ipc_handle.abort();

    daemon_mgr.cleanup();

    Ok(())
}

/
pub fn cmd_stop(writerslogic_dir: &Path) -> Result<()> {
    let daemon_mgr = DaemonManager::new(writerslogic_dir);

    if !daemon_mgr.is_running() {
        return Err(SentinelError::DaemonNotRunning);
    }

    daemon_mgr.signal_stop()?;
    daemon_mgr.wait_for_stop(Duration::from_secs(10))?;
    daemon_mgr.cleanup();

    Ok(())
}

/
pub fn cmd_status(writerslogic_dir: &Path) -> DaemonStatus {
    let daemon_mgr = DaemonManager::new(writerslogic_dir);
    daemon_mgr.status()
}

/
pub fn cmd_track(writerslogic_dir: &Path, file_path: &Path) -> Result<()> {
    use crate::ipc::{IpcClient, IpcErrorCode, IpcMessage};

    let daemon_mgr = DaemonManager::new(writerslogic_dir);

    if !daemon_mgr.is_running() {
        return Err(SentinelError::DaemonNotRunning);
    }

    let abs_path = file_path.canonicalize()?;

    let mut client = IpcClient::connect(daemon_mgr.socket_path().to_path_buf())
        .map_err(|e| SentinelError::Ipc(format!("Failed to connect to daemon: {}", e)))?;

    let msg = IpcMessage::StartWitnessing {
        file_path: abs_path.clone(),
    };
    let response = client
        .send_and_recv(&msg)
        .map_err(|e| SentinelError::Ipc(format!("Failed to communicate with daemon: {}", e)))?;

    match response {
        IpcMessage::Ok { message } => {
            if let Some(msg) = message {
                log::info!("{}", msg);
            } else {
                log::info!("Now tracking: {}", abs_path.display());
            }
            Ok(())
        }
        IpcMessage::Error { code, message } => match code {
            IpcErrorCode::FileNotFound => Err(SentinelError::Ipc(format!(
                "File not found: {}",
                abs_path.display()
            ))),
            IpcErrorCode::AlreadyTracking => {
                log::info!("Already tracking: {}", abs_path.display());
                Ok(())
            }
            IpcErrorCode::PermissionDenied => Err(SentinelError::Ipc(format!(
                "Permission denied: {}",
                abs_path.display()
            ))),
            _ => Err(SentinelError::Ipc(message)),
        },
        _ => Err(SentinelError::Ipc(format!(
            "Unexpected response from daemon: {:?}",
            response
        ))),
    }
}

/
pub fn cmd_untrack(writerslogic_dir: &Path, file_path: &Path) -> Result<()> {
    use crate::ipc::{IpcClient, IpcErrorCode, IpcMessage};

    let daemon_mgr = DaemonManager::new(writerslogic_dir);

    if !daemon_mgr.is_running() {
        return Err(SentinelError::DaemonNotRunning);
    }

    let abs_path = file_path.canonicalize()?;

    let mut client = IpcClient::connect(daemon_mgr.socket_path().to_path_buf())
        .map_err(|e| SentinelError::Ipc(format!("Failed to connect to daemon: {}", e)))?;

    let msg = IpcMessage::StopWitnessing {
        file_path: Some(abs_path.clone()),
    };
    let response = client
        .send_and_recv(&msg)
        .map_err(|e| SentinelError::Ipc(format!("Failed to communicate with daemon: {}", e)))?;

    match response {
        IpcMessage::Ok { message } => {
            if let Some(msg) = message {
                log::info!("{}", msg);
            } else {
                log::info!("Stopped tracking: {}", abs_path.display());
            }
            Ok(())
        }
        IpcMessage::Error { code, message } => match code {
            IpcErrorCode::FileNotFound => Err(SentinelError::Ipc(format!(
                "File not found: {}",
                abs_path.display()
            ))),
            IpcErrorCode::NotTracking => {
                log::info!("Not currently tracking: {}", abs_path.display());
                Ok(())
            }
            IpcErrorCode::PermissionDenied => Err(SentinelError::Ipc(format!(
                "Permission denied: {}",
                abs_path.display()
            ))),
            _ => Err(SentinelError::Ipc(message)),
        },
        _ => Err(SentinelError::Ipc(format!(
            "Unexpected response from daemon: {:?}",
            response
        ))),
    }
}
