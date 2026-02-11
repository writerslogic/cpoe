//! Flutter Rust Bridge - FFI exports for the Flutter GUI
//!
//! This module exposes all witnessd API functions via flutter_rust_bridge,
//! providing a clean interface between the Rust core and Flutter frontend.

use crate::api;
use crate::config::WitnessdConfig;
use crate::engine::{EngineStatus, ReportFile};
use anyhow::{anyhow, Result};
use flutter_rust_bridge::frb;
use std::path::PathBuf;

// =============================================================================
// Identity Management
// =============================================================================

/// Initialize witnessd with optional custom data directory and mnemonic.
///
/// Creates the necessary directory structure and identity.
/// Returns the identity fingerprint on success.
#[frb]
pub fn init_witnessd(data_dir: Option<String>, mnemonic: Option<String>) -> Result<String> {
    api::init_witnessd(data_dir, mnemonic)
}

/// Get the current identity fingerprint.
///
/// Returns None if witnessd is not initialized.
#[frb]
pub fn get_identity_fingerprint() -> Option<String> {
    api::get_identity_fingerprint()
}

/// Check if witnessd is properly initialized.
#[frb]
pub fn is_initialized() -> bool {
    api::is_initialized()
}

/// Setup identity with a specific mnemonic phrase.
#[frb]
pub fn setup_identity(phrase: String) -> Result<String> {
    api::setup_identity(phrase)
}

/// Generate a new mnemonic phrase for identity creation.
#[frb]
pub fn generate_mnemonic() -> String {
    api::generate_mnemonic()
}

// =============================================================================
// Document Operations
// =============================================================================

/// Create a checkpoint for a document.
///
/// Records the current state of the document with optional message.
/// Returns checkpoint information.
#[frb]
pub fn commit_document(path: String, message: Option<String>) -> Result<FrbCheckpointInfo> {
    let checkpoint = api::commit_document(path, message)?;
    Ok(FrbCheckpointInfo::from(checkpoint))
}

/// Get the checkpoint history for a document.
///
/// Returns array of checkpoint information.
#[frb]
pub fn get_document_log(path: String) -> Result<Vec<FrbCheckpointInfo>> {
    let log = api::get_document_log(path)?;
    Ok(log.into_iter().map(FrbCheckpointInfo::from).collect())
}

/// Verify the integrity of a document's checkpoint chain.
///
/// Returns verification result.
#[frb]
pub fn verify_document(path: String) -> Result<FrbVerificationResult> {
    let result = api::verify_document(path)?;
    Ok(FrbVerificationResult::from(result))
}

/// Export an evidence packet for a document.
///
/// Creates a comprehensive evidence packet.
/// Returns export result with output path.
#[frb]
pub fn export_evidence(path: String, title: String, tier: String) -> Result<FrbExportResult> {
    let result = api::export_evidence(path, title, tier)?;
    Ok(FrbExportResult::from(result))
}

// =============================================================================
// Keystroke Tracking
// =============================================================================

/// Start keystroke tracking for a document.
#[frb]
pub fn start_tracking(path: String) -> Result<()> {
    api::start_tracking(path)
}

/// Stop the current keystroke tracking session.
///
/// Returns tracking statistics.
#[frb]
pub fn stop_tracking() -> Result<FrbTrackingStatistics> {
    let stats = api::stop_tracking()?;
    Ok(FrbTrackingStatistics::from(stats))
}

/// Record a keystroke event.
///
/// Returns (jitter_micros, sample_created).
#[frb]
pub fn record_keystroke() -> Result<(u32, bool)> {
    api::record_keystroke()
}

/// Get the current tracking session status.
///
/// Returns tracking status.
#[frb]
pub fn get_tracking_status() -> FrbTrackingStatus {
    FrbTrackingStatus::from(api::get_tracking_status())
}

/// Get keystroke statistics from the current tracking session.
///
/// Returns statistics.
#[frb]
pub fn get_tracking_statistics() -> Result<FrbTrackingStatistics> {
    let stats = api::get_tracking_statistics()?;
    Ok(FrbTrackingStatistics::from(stats))
}

// =============================================================================
// Presence Verification
// =============================================================================

/// Start a presence verification session.
///
/// Returns the session ID.
#[frb]
pub fn start_presence_session() -> Result<String> {
    api::start_presence_session()
}

/// End the current presence verification session.
///
/// Returns presence status summary.
#[frb]
pub fn end_presence_session() -> Result<FrbPresenceStatus> {
    let status = api::end_presence_session()?;
    Ok(FrbPresenceStatus::from(status))
}

/// Get the current pending challenge, if any.
///
/// Returns challenge info, or None.
#[frb]
pub fn get_pending_challenge() -> Option<FrbChallengeInfo> {
    api::get_pending_challenge()
        .map(FrbChallengeInfo::from)
}

/// Submit a response to the current challenge.
///
/// Returns true if the response was correct.
#[frb]
pub fn submit_challenge_response(response: String) -> Result<bool> {
    api::submit_challenge_response(response)
}

/// Get the current presence verification status.
///
/// Returns presence status.
#[frb]
pub fn get_presence_status() -> FrbPresenceStatus {
    FrbPresenceStatus::from(api::get_presence_status())
}

// =============================================================================
// Forensics
// =============================================================================

/// Run forensic analysis on a document.
///
/// Returns forensic report.
#[frb]
pub fn analyze_document(path: String) -> Result<FrbForensicReport> {
    let report = api::analyze_document(path)?;
    Ok(FrbForensicReport::from(report))
}

/// Get the typing cadence score for a document.
///
/// Returns a score from 0.0 to 1.0 indicating consistency with original composition.
#[frb]
pub fn get_cadence_score(path: String) -> Result<f64> {
    api::get_cadence_score(path)
}

/// Get the forensic score for a file (legacy API).
#[frb]
pub fn get_forensic_score(file_path: String) -> f64 {
    api::get_forensic_score(file_path)
}

// =============================================================================
// Configuration
// =============================================================================

/// Get the current application configuration.
///
/// Returns configuration.
#[frb]
pub fn get_config() -> Result<FrbAppConfig> {
    let config = api::get_config()?;
    Ok(FrbAppConfig::from(config))
}

/// Update the application configuration.
///
/// Takes configuration.
#[frb]
pub fn set_config(config: FrbAppConfig) -> Result<()> {
    api::set_config(WitnessdConfig::from(config))
}

/// Get current VDF parameters.
///
/// Returns VDF parameters.
#[frb]
pub fn get_vdf_params() -> FrbVdfParams {
    FrbVdfParams::from(api::get_vdf_params())
}

/// Run VDF calibration and return optimized parameters.
///
/// Returns calibrated VDF parameters.
#[frb]
pub fn calibrate_vdf() -> Result<FrbVdfParams> {
    let params = api::calibrate_vdf()?;
    Ok(FrbVdfParams::from(params))
}

// =============================================================================
// Engine Control
// =============================================================================

/// Start the witnessing engine with default configuration.
///
/// Returns engine status.
#[frb]
pub fn start_engine() -> Result<FrbEngineStatus> {
    let status = api::start_engine_default()?;
    Ok(FrbEngineStatus::from(status))
}

/// Stop the witnessing engine.
#[frb]
pub fn stop_engine() -> Result<()> {
    api::stop_engine()
}

/// Get the current engine status.
///
/// Returns engine status, or None if engine is not running.
#[frb]
pub fn engine_status() -> Result<Option<FrbEngineStatus>> {
    let status = api::engine_status();
    if let Some(status) = status {
        return Ok(Some(FrbEngineStatus::from(status)));
    }
    Ok(None)
}

/// Get list of files being tracked by the engine.
///
/// Returns array of file reports.
#[frb]
pub fn report_files() -> Result<Vec<FrbReportFile>> {
    let reports = api::report_files()?;
    Ok(reports.into_iter().map(FrbReportFile::from).collect())
}

/// Get the engine configuration.
#[frb]
pub fn get_engine_config() -> Result<FrbEngineConfig> {
    let config = api::get_engine_config_struct()?;
    Ok(FrbEngineConfig::from(config))
}

/// Set the engine configuration.
#[frb]
pub fn set_engine_config(config: FrbEngineConfig) -> Result<()> {
    api::set_engine_config_struct(WitnessdConfig::from(config))
}

// =============================================================================
// Hardware & Security
// =============================================================================

/// Check hardware security capabilities.
///
/// Returns hardware status.
#[frb]
pub fn check_hardware_status() -> FrbHardwareStatus {
    FrbHardwareStatus::from(api::check_hardware_status())
}

/// Check if accessibility permissions are granted (macOS).
#[frb]
pub fn accessibility_trusted() -> bool {
    #[cfg(target_os = "macos")]
    {
        return crate::platform::macos::check_accessibility_permissions();
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Open accessibility settings (macOS).
#[frb]
pub fn open_accessibility_settings() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let status = std::process::Command::new("open")
            .arg("x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")
            .status()
            .map_err(|e| anyhow!("Failed to open System Settings: {e}"))?;
        if !status.success() {
            return Err(anyhow!("System Settings returned non-zero status"));
        }
        return Ok(());
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(anyhow!("Accessibility settings not available on this platform"))
    }
}

/// Request accessibility permissions (macOS).
#[frb]
pub fn request_accessibility_permissions() -> bool {
    #[cfg(target_os = "macos")]
    {
        return crate::platform::macos::request_accessibility_permissions();
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Check if input monitoring permissions are granted (macOS).
#[frb]
pub fn input_monitoring_trusted() -> bool {
    #[cfg(target_os = "macos")]
    {
        return crate::platform::macos::check_input_monitoring_permissions();
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Request input monitoring permissions (macOS).
#[frb]
pub fn request_input_monitoring_permissions() -> bool {
    #[cfg(target_os = "macos")]
    {
        return crate::platform::macos::request_input_monitoring_permissions();
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Open input monitoring settings (macOS).
#[frb]
pub fn open_input_monitoring_settings() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let status = std::process::Command::new("open")
            .arg("x-apple.systempreferences:com.apple.preference.security?Privacy_ListenEvent")
            .status()
            .map_err(|e| anyhow!("Failed to open System Settings: {e}"))?;
        if !status.success() {
            return Err(anyhow!("System Settings returned non-zero status"));
        }
        return Ok(());
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(anyhow!("Input monitoring settings not available on this platform"))
    }
}

// =============================================================================
// Synchronous Data Types (for direct FRB transfer)
// =============================================================================

/// Checkpoint info for direct FRB transfer without JSON.
#[frb]
#[derive(Debug, Clone)]
pub struct FrbCheckpointInfo {
    pub ordinal: u64,
    pub timestamp: String,
    pub content_hash: String,
    pub content_size: i64,
    pub message: Option<String>,
    pub has_vdf_proof: bool,
    pub elapsed_time_secs: Option<f64>,
}

impl From<api::CheckpointInfo> for FrbCheckpointInfo {
    fn from(info: api::CheckpointInfo) -> Self {
        Self {
            ordinal: info.ordinal,
            timestamp: info.timestamp,
            content_hash: info.content_hash,
            content_size: info.content_size,
            message: info.message,
            has_vdf_proof: info.has_vdf_proof,
            elapsed_time_secs: info.elapsed_time_secs,
        }
    }
}

/// Verification result for direct FRB transfer.
#[frb]
#[derive(Debug, Clone)]
pub struct FrbVerificationResult {
    pub valid: bool,
    pub checkpoint_count: u32,
    pub total_elapsed_time_secs: f64,
    pub first_commit: Option<String>,
    pub last_commit: Option<String>,
    pub errors: Vec<String>,
}

impl From<api::VerificationResult> for FrbVerificationResult {
    fn from(r: api::VerificationResult) -> Self {
        Self {
            valid: r.valid,
            checkpoint_count: r.checkpoint_count as u32,
            total_elapsed_time_secs: r.total_elapsed_time_secs,
            first_commit: r.first_commit,
            last_commit: r.last_commit,
            errors: r.errors,
        }
    }
}

/// Tracking status for direct FRB transfer.
#[frb]
#[derive(Debug, Clone)]
pub struct FrbTrackingStatus {
    pub active: bool,
    pub session_id: Option<String>,
    pub document_path: Option<String>,
    pub started_at: Option<String>,
    pub keystroke_count: u64,
    pub sample_count: u32,
    pub duration_secs: f64,
}

impl From<api::TrackingStatus> for FrbTrackingStatus {
    fn from(s: api::TrackingStatus) -> Self {
        Self {
            active: s.active,
            session_id: s.session_id,
            document_path: s.document_path,
            started_at: s.started_at,
            keystroke_count: s.keystroke_count,
            sample_count: s.sample_count as u32,
            duration_secs: s.duration_secs,
        }
    }
}

/// Presence status for direct FRB transfer.
#[frb]
#[derive(Debug, Clone)]
pub struct FrbPresenceStatus {
    pub session_active: bool,
    pub session_id: Option<String>,
    pub started_at: Option<String>,
    pub challenges_issued: i32,
    pub challenges_passed: i32,
    pub challenges_failed: i32,
    pub challenges_missed: i32,
    pub verification_rate: f64,
    pub has_pending_challenge: bool,
}

impl From<api::PresenceStatus> for FrbPresenceStatus {
    fn from(s: api::PresenceStatus) -> Self {
        Self {
            session_active: s.session_active,
            session_id: s.session_id,
            started_at: s.started_at,
            challenges_issued: s.challenges_issued,
            challenges_passed: s.challenges_passed,
            challenges_failed: s.challenges_failed,
            challenges_missed: s.challenges_missed,
            verification_rate: s.verification_rate,
            has_pending_challenge: s.has_pending_challenge,
        }
    }
}

/// Challenge info for direct FRB transfer.
#[frb]
#[derive(Debug, Clone)]
pub struct FrbChallengeInfo {
    pub id: String,
    pub challenge_type: String,
    pub prompt: String,
    pub issued_at: String,
    pub expires_at: String,
    pub window_secs: f64,
}

impl From<api::ChallengeInfo> for FrbChallengeInfo {
    fn from(c: api::ChallengeInfo) -> Self {
        Self {
            id: c.id,
            challenge_type: c.challenge_type,
            prompt: c.prompt,
            issued_at: c.issued_at,
            expires_at: c.expires_at,
            window_secs: c.window_secs,
        }
    }
}

/// Forensic report for direct FRB transfer.
#[frb]
#[derive(Debug, Clone)]
pub struct FrbForensicReport {
    pub confidence_score: f64,
    pub is_anomaly: bool,
    pub is_retyped_content: bool,
    pub signal_count: u32,
}

impl From<api::ForensicReportInfo> for FrbForensicReport {
    fn from(r: api::ForensicReportInfo) -> Self {
        Self {
            confidence_score: r.confidence_score,
            is_anomaly: r.is_anomaly,
            is_retyped_content: r.is_retyped_content,
            signal_count: r.signals.len() as u32,
        }
    }
}

/// VDF parameters for direct FRB transfer.
#[frb]
#[derive(Debug, Clone)]
pub struct FrbVdfParams {
    pub iterations_per_second: u64,
    pub min_iterations: u64,
    pub max_iterations: u64,
}

impl From<api::VdfParams> for FrbVdfParams {
    fn from(p: api::VdfParams) -> Self {
        Self {
            iterations_per_second: p.iterations_per_second,
            min_iterations: p.min_iterations,
            max_iterations: p.max_iterations,
        }
    }
}

/// Hardware status for direct FRB transfer.
#[frb]
#[derive(Debug, Clone)]
pub struct FrbHardwareStatus {
    pub enclave_active: bool,
    pub tpm_active: bool,
    pub silicon_id: String,
}

impl From<api::HardwareStatus> for FrbHardwareStatus {
    fn from(s: api::HardwareStatus) -> Self {
        Self {
            enclave_active: s.enclave_active,
            tpm_active: s.tpm_active,
            silicon_id: s.silicon_id,
        }
    }
}

/// Tracking statistics for direct FRB transfer.
#[frb]
#[derive(Debug, Clone)]
pub struct FrbTrackingStatistics {
    pub total_keystrokes: u64,
    pub total_samples: i32,
    pub duration_secs: f64,
    pub keystrokes_per_min: f64,
    pub unique_doc_hashes: i32,
    pub chain_valid: bool,
}

impl From<api::TrackingStatistics> for FrbTrackingStatistics {
    fn from(s: api::TrackingStatistics) -> Self {
        Self {
            total_keystrokes: s.total_keystrokes,
            total_samples: s.total_samples,
            duration_secs: s.duration_secs,
            keystrokes_per_min: s.keystrokes_per_min,
            unique_doc_hashes: s.unique_doc_hashes,
            chain_valid: s.chain_valid,
        }
    }
}

/// Export result for direct FRB transfer.
#[frb]
#[derive(Debug, Clone)]
pub struct FrbExportResult {
    pub success: bool,
    pub output_path: Option<String>,
    pub packet_hash: Option<String>,
    pub error: Option<String>,
}

impl From<api::ExportResult> for FrbExportResult {
    fn from(r: api::ExportResult) -> Self {
        Self {
            success: r.success,
            output_path: r.output_path,
            packet_hash: r.packet_hash,
            error: r.error,
        }
    }
}

/// App config for direct FRB transfer.
#[frb]
#[derive(Debug, Clone)]
pub struct FrbAppConfig {
    pub data_dir: String,
    pub watch_dirs: Vec<String>,
    pub retention_days: u32,
    pub presence_challenge_interval_secs: u64,
    pub presence_response_window_secs: u64,
    pub vdf_params: FrbVdfParams,
}

impl From<WitnessdConfig> for FrbAppConfig {
    fn from(c: WitnessdConfig) -> Self {
        Self {
            data_dir: c.data_dir.to_string_lossy().to_string(),
            watch_dirs: c
                .watch_dirs
                .iter()
                .map(|p: &PathBuf| p.to_string_lossy().to_string())
                .collect(),
            retention_days: c.retention_days,
            presence_challenge_interval_secs: c.presence.challenge_interval_secs,
            presence_response_window_secs: c.presence.response_window_secs,
            vdf_params: FrbVdfParams {
                iterations_per_second: c.vdf.iterations_per_second,
                min_iterations: c.vdf.min_iterations,
                max_iterations: c.vdf.max_iterations,
            },
        }
    }
}

impl From<FrbAppConfig> for WitnessdConfig {
    fn from(c: FrbAppConfig) -> Self {
        let mut cfg = WitnessdConfig::default_with_dir(&PathBuf::from(&c.data_dir));
        cfg.watch_dirs = c.watch_dirs.iter().map(PathBuf::from).collect();
        cfg.retention_days = c.retention_days;
        cfg.presence.challenge_interval_secs = c.presence_challenge_interval_secs;
        cfg.presence.response_window_secs = c.presence_response_window_secs;
        cfg.vdf.iterations_per_second = c.vdf_params.iterations_per_second;
        cfg.vdf.min_iterations = c.vdf_params.min_iterations;
        cfg.vdf.max_iterations = c.vdf_params.max_iterations;
        cfg
    }
}

/// Engine status for direct FRB transfer.
#[frb]
#[derive(Debug, Clone)]
pub struct FrbEngineStatus {
    pub running: bool,
    pub accessibility_trusted: bool,
    pub watch_dirs: Vec<String>,
    pub events_written: u64,
    pub jitter_samples: u64,
    pub last_event_timestamp_ns: Option<i64>,
}

impl From<EngineStatus> for FrbEngineStatus {
    fn from(s: EngineStatus) -> Self {
        Self {
            running: s.running,
            accessibility_trusted: s.accessibility_trusted,
            watch_dirs: s.watch_dirs.iter().map(|p| p.to_string_lossy().to_string()).collect(),
            events_written: s.events_written,
            jitter_samples: s.jitter_samples,
            last_event_timestamp_ns: s.last_event_timestamp_ns,
        }
    }
}

/// Report file for direct FRB transfer.
#[frb]
#[derive(Debug, Clone)]
pub struct FrbReportFile {
    pub file_path: String,
    pub last_event_timestamp_ns: i64,
    pub event_count: u64,
}

impl From<ReportFile> for FrbReportFile {
    fn from(r: ReportFile) -> Self {
        Self {
            file_path: r.file_path,
            last_event_timestamp_ns: r.last_event_timestamp_ns,
            event_count: r.event_count,
        }
    }
}

/// Engine config for direct FRB transfer.
#[frb]
#[derive(Debug, Clone)]
pub struct FrbEngineConfig {
    pub data_dir: String,
    pub watch_dirs: Vec<String>,
    pub retention_days: u32,
}

impl From<WitnessdConfig> for FrbEngineConfig {
    fn from(c: WitnessdConfig) -> Self {
        Self {
            data_dir: c.data_dir.to_string_lossy().to_string(),
            watch_dirs: c
                .watch_dirs
                .iter()
                .map(|p: &PathBuf| p.to_string_lossy().to_string())
                .collect(),
            retention_days: c.retention_days,
        }
    }
}

impl From<FrbEngineConfig> for WitnessdConfig {
    fn from(c: FrbEngineConfig) -> Self {
        let mut cfg = WitnessdConfig::default_with_dir(&PathBuf::from(&c.data_dir));
        cfg.watch_dirs = c.watch_dirs.iter().map(PathBuf::from).collect();
        cfg.retention_days = c.retention_days;
        cfg
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Get the application version.
#[frb]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Check if running on a supported platform.
#[frb]
pub fn is_supported_platform() -> bool {
    cfg!(any(
        target_os = "macos",
        target_os = "windows",
        target_os = "linux"
    ))
}

/// Get the current platform name.
#[frb]
pub fn get_platform() -> String {
    #[cfg(target_os = "macos")]
    return "macos".to_string();
    #[cfg(target_os = "windows")]
    return "windows".to_string();
    #[cfg(target_os = "linux")]
    return "linux".to_string();
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    return "unknown".to_string();
}
