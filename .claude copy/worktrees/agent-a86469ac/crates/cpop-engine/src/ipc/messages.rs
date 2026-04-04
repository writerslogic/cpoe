

use crate::jitter::SimpleJitterSample;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

/
/
/
pub(crate) const MAX_MESSAGE_SIZE: usize = 256 * 1024;

/
pub(crate) const MAX_CONCURRENT_CONNECTIONS: usize = 16;

/
/
/
fn validate_ipc_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!(
            "Relative path rejected (must be absolute): '{}'",
            path.display()
        ));
    }

    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(format!("Path traversal rejected: '{}'", path.display()));
        }
    }

    
    
    
    
    let canonical: std::borrow::Cow<'_, Path> = match std::fs::canonicalize(path) {
        Ok(p) => std::borrow::Cow::Owned(p),
        Err(_) => {
            let mut stack: Vec<Component<'_>> = Vec::new();
            for component in path.components() {
                match component {
                    Component::ParentDir => {
                        
                        match stack.last() {
                            Some(Component::Prefix(_) | Component::RootDir) | None => {}
                            _ => {
                                stack.pop();
                            }
                        }
                    }
                    Component::CurDir => {}
                    other => stack.push(other),
                }
            }
            let mut resolved = PathBuf::new();
            for part in stack {
                resolved.push(part);
            }
            std::borrow::Cow::Owned(resolved)
        }
    };

    
    
    if canonical.is_symlink() {
        return Err(format!(
            "Symlink rejected at IPC boundary: '{}'",
            canonical.display()
        ));
    }

    
    
    if is_blocked_system_path(&canonical)? {
        return Err("Access to system directory denied".to_string());
    }

    Ok(())
}

/
#[cfg(unix)]
pub(crate) const BLOCKED_UNIX_PREFIXES: &[&str] = &[
    "/etc/",
    "/var/root/",
    "/System/",
    "/Library/",
    "/proc/",
    "/dev/",
    "/sys/",
    "/root/",
    "/private/etc/",
    "/private/var/root/",
    "/boot/",
    "/sbin/",
    "/bin/",
    "/usr/",
];

/
#[cfg(target_os = "windows")]
pub(crate) const BLOCKED_WINDOWS_PREFIXES: &[&str] = &[
    r"c:\windows\",
    r"c:\program files\",
    r"c:\program files (x86)\",
    r"c:\programdata\",
];

/
/
/
/
pub(crate) fn is_blocked_system_path(path: &Path) -> Result<bool, String> {
    #[cfg(unix)]
    {
        let s = path.to_string_lossy();
        for prefix in BLOCKED_UNIX_PREFIXES {
            if s.starts_with(prefix) {
                return Ok(true);
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let s = path.to_string_lossy();
        let lower = s.to_lowercase();
        
        
        
        let normalized = lower
            .strip_prefix(r"\\?\unc\")
            .or_else(|| lower.strip_prefix(r"\\?\"))
            .or_else(|| lower.strip_prefix(r"\??\"))
            .or_else(|| lower.strip_prefix(r"\\.\"))
            .unwrap_or(&lower);
        for prefix in BLOCKED_WINDOWS_PREFIXES {
            if normalized.starts_with(prefix) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcMessage {
    /
    Handshake { version: String },
    /
    StartWitnessing { file_path: PathBuf },
    /
    StopWitnessing { file_path: Option<PathBuf> },
    /
    GetStatus,

    /
    GetAttestationNonce,
    /
    ExportWithNonce {
        file_path: PathBuf,
        title: String,
        verifier_nonce: [u8; 32],
    },
    /
    VerifyWithNonce {
        evidence_path: PathBuf,
        expected_nonce: Option<[u8; 32]>,
    },

    /
    Pulse(SimpleJitterSample),
    /
    CheckpointCreated { id: i64, hash: [u8; 32] },
    /
    SystemAlert { level: String, message: String },

    /
    Heartbeat,

    /
    Ok { message: Option<String> },
    /
    Error { code: IpcErrorCode, message: String },
    /
    HandshakeAck {
        version: String,
        server_version: String,
    },
    /
    HeartbeatAck { timestamp_ns: u64 },
    /
    StatusResponse {
        running: bool,
        tracked_files: Vec<String>,
        uptime_secs: u64,
    },
    /
    AttestationNonceResponse { nonce: [u8; 32] },
    /
    NonceExportResponse {
        success: bool,
        output_path: Option<String>,
        packet_hash: Option<String>,
        verifier_nonce: Option<String>,
        attestation_nonce: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        attestation_report: Option<String>,
        error: Option<String>,
    },
    /
    NonceVerifyResponse {
        valid: bool,
        nonce_valid: bool,
        checkpoint_count: u64,
        total_elapsed_time_secs: f64,
        verifier_nonce: Option<String>,
        attestation_nonce: Option<String>,
        errors: Vec<String>,
    },

    /
    VerifyFile { path: PathBuf },
    /
    VerifyFileResponse {
        success: bool,
        checkpoint_count: u32,
        signature_valid: bool,
        chain_integrity: bool,
        vdf_iterations_per_second: u64,
        error: Option<String>,
    },

    /
    ExportFile {
        path: PathBuf,
        tier: String,
        output: PathBuf,
    },
    /
    ExportFileResponse {
        success: bool,
        error: Option<String>,
    },

    /
    GetFileForensics { path: PathBuf },
    /
    ForensicsResponse {
        assessment_score: f64,
        risk_level: String,
        anomaly_count: u32,
        monotonic_append_ratio: f64,
        edit_entropy: f64,
        median_interval: f64,
        /
        biological_cadence_score: f64,
        error: Option<String>,
    },

    /
    ComputeProcessScore { path: PathBuf },
    /
    ProcessScoreResponse {
        residency: f64,
        sequence: f64,
        behavioral: f64,
        composite: f64,
        meets_threshold: bool,
        error: Option<String>,
    },

    /
    CreateFileCheckpoint { path: PathBuf, message: String },
    /
    CheckpointResponse {
        success: bool,
        hash: Option<String>,
        error: Option<String>,
    },
}

impl IpcMessage {
    /
    /
    /
    pub(crate) fn validate_paths(&self) -> Result<(), String> {
        /
        const MAX_JITTER_INTERVAL_NS: u64 = 60_000_000_000;
        /
        const MAX_TIMESTAMP_NS: i64 = 4_102_444_800_000_000_000;
        /
        const MAX_SHORT_STRING: usize = 64;
        /
        const MAX_ALERT_MESSAGE: usize = 4096;

        match self {
            IpcMessage::Handshake { version } => {
                if version.len() > MAX_SHORT_STRING {
                    return Err(format!(
                        "Handshake version too long: {} bytes (max {})",
                        version.len(),
                        MAX_SHORT_STRING
                    ));
                }
            }
            IpcMessage::SystemAlert { message, .. } => {
                if message.len() > MAX_ALERT_MESSAGE {
                    return Err(format!(
                        "SystemAlert message too long: {} bytes (max {})",
                        message.len(),
                        MAX_ALERT_MESSAGE
                    ));
                }
            }
            IpcMessage::StartWitnessing { file_path } => {
                validate_ipc_path(file_path)?;
            }
            IpcMessage::StopWitnessing { file_path: Some(p) } => {
                validate_ipc_path(p)?;
            }
            IpcMessage::ExportWithNonce { file_path, .. } => {
                validate_ipc_path(file_path)?;
            }
            IpcMessage::VerifyWithNonce { evidence_path, .. } => {
                validate_ipc_path(evidence_path)?;
            }
            IpcMessage::VerifyFile { path } => {
                validate_ipc_path(path)?;
            }
            IpcMessage::ExportFile {
                path, output, tier, ..
            } => {
                validate_ipc_path(path)?;
                validate_ipc_path(output)?;
                if tier.len() > MAX_SHORT_STRING {
                    return Err(format!(
                        "ExportFile tier too long: {} bytes (max {})",
                        tier.len(),
                        MAX_SHORT_STRING
                    ));
                }
            }
            IpcMessage::GetFileForensics { path } => {
                validate_ipc_path(path)?;
            }
            IpcMessage::ComputeProcessScore { path } => {
                validate_ipc_path(path)?;
            }
            IpcMessage::CreateFileCheckpoint { path, .. } => {
                validate_ipc_path(path)?;
            }
            IpcMessage::Pulse(sample) => {
                if sample.timestamp_ns < 0 || sample.timestamp_ns > MAX_TIMESTAMP_NS {
                    return Err(format!(
                        "Pulse timestamp_ns out of bounds: {}",
                        sample.timestamp_ns
                    ));
                }
                
                
                {
                    const FIVE_MINUTES_NS: i64 = 5 * 60 * 1_000_000_000;
                    let now_ns = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos() as i64)
                        .unwrap_or(0);
                    if (sample.timestamp_ns - now_ns).abs() > FIVE_MINUTES_NS {
                        return Err(format!(
                            "Pulse timestamp_ns too far from wall clock: {}",
                            sample.timestamp_ns
                        ));
                    }
                }
                if sample.duration_since_last_ns > MAX_JITTER_INTERVAL_NS {
                    return Err(format!(
                        "Pulse duration_since_last_ns out of bounds: {}",
                        sample.duration_since_last_ns
                    ));
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum IpcErrorCode {
    /
    Unknown = 0,
    /
    InvalidMessage = 1,
    /
    FileNotFound = 2,
    /
    AlreadyTracking = 3,
    /
    NotTracking = 4,
    /
    PermissionDenied = 5,
    /
    VersionMismatch = 6,
    /
    InternalError = 7,
    /
    NonceInvalid = 8,
    /
    NotInitialized = 9,
    /
    RateLimited = 10,
}

/
pub trait IpcMessageHandler: Send + Sync + 'static {
    /
    fn handle(&self, msg: IpcMessage) -> IpcMessage;
}
