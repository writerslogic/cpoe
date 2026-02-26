// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::jitter::SimpleJitterSample;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Maximum message size (1 MB)
pub(crate) const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// IPC Message Protocol for high-performance communication between Brain and Face.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcMessage {
    // Requests
    Handshake {
        version: String,
    },
    StartWitnessing {
        file_path: PathBuf,
    },
    StopWitnessing {
        file_path: Option<PathBuf>,
    },
    GetStatus,

    // Nonce Protocol Requests
    /// Request the current session's attestation nonce
    GetAttestationNonce,
    /// Export evidence with a verifier-provided nonce binding
    ExportWithNonce {
        file_path: PathBuf,
        title: String,
        verifier_nonce: [u8; 32],
    },
    /// Verify evidence with expected nonce validation
    VerifyWithNonce {
        evidence_path: PathBuf,
        expected_nonce: Option<[u8; 32]>,
    },

    // Events (Push from Brain to Face)
    Pulse(SimpleJitterSample),
    CheckpointCreated {
        id: i64,
        hash: [u8; 32],
    },
    SystemAlert {
        level: String,
        message: String,
    },

    // Status
    Heartbeat,

    // Responses
    Ok {
        message: Option<String>,
    },
    Error {
        code: IpcErrorCode,
        message: String,
    },
    HandshakeAck {
        version: String,
        server_version: String,
    },
    HeartbeatAck {
        timestamp_ns: u64,
    },
    StatusResponse {
        running: bool,
        tracked_files: Vec<String>,
        uptime_secs: u64,
    },
    /// Response containing the attestation nonce
    AttestationNonceResponse {
        nonce: [u8; 32],
    },
    /// Response for nonce-bound evidence export
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
    /// Response for nonce-validated verification
    NonceVerifyResponse {
        valid: bool,
        nonce_valid: bool,
        checkpoint_count: u64,
        total_elapsed_time_secs: f64,
        verifier_nonce: Option<String>,
        attestation_nonce: Option<String>,
        errors: Vec<String>,
    },

    // P2: Crypto Operation Requests (for Windows IPC, macOS uses FFI)
    /// Verify an evidence file
    VerifyFile {
        path: PathBuf,
    },
    /// Response for VerifyFile
    VerifyFileResponse {
        success: bool,
        checkpoint_count: u32,
        signature_valid: bool,
        chain_integrity: bool,
        vdf_iterations_per_second: u64,
        error: Option<String>,
    },

    /// Export evidence for a file
    ExportFile {
        path: PathBuf,
        tier: String,
        output: PathBuf,
    },
    /// Response for ExportFile
    ExportFileResponse {
        success: bool,
        error: Option<String>,
    },

    /// Get forensic analysis for a file
    GetFileForensics {
        path: PathBuf,
    },
    /// Response for GetFileForensics
    ForensicsResponse {
        assessment_score: f64,
        risk_level: String,
        anomaly_count: u32,
        monotonic_append_ratio: f64,
        edit_entropy: f64,
        median_interval: f64,
        error: Option<String>,
    },

    /// Compute the Process Score for a file
    ComputeProcessScore {
        path: PathBuf,
    },
    /// Response for ComputeProcessScore
    ProcessScoreResponse {
        residency: f64,
        sequence: f64,
        behavioral: f64,
        composite: f64,
        meets_threshold: bool,
        error: Option<String>,
    },

    /// Create a manual checkpoint for a file
    CreateFileCheckpoint {
        path: PathBuf,
        message: String,
    },
    /// Response for CreateFileCheckpoint
    CheckpointResponse {
        success: bool,
        hash: Option<String>,
        error: Option<String>,
    },
}

/// Error codes for IPC responses
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum IpcErrorCode {
    /// Unknown or generic error
    Unknown = 0,
    /// Invalid message format
    InvalidMessage = 1,
    /// File not found
    FileNotFound = 2,
    /// File already being tracked
    AlreadyTracking = 3,
    /// File not being tracked
    NotTracking = 4,
    /// Permission denied
    PermissionDenied = 5,
    /// Version mismatch
    VersionMismatch = 6,
    /// Internal server error
    InternalError = 7,
    /// Nonce validation failed
    NonceInvalid = 8,
    /// Identity not initialized
    NotInitialized = 9,
}

/// Trait for handling IPC messages
pub trait IpcMessageHandler: Send + Sync + 'static {
    /// Handle an incoming IPC message and return a response
    fn handle(&self, msg: IpcMessage) -> IpcMessage;
}
