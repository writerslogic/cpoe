// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Anonymous research data collection for jitter proof-of-process analysis.
//!
//! This module enables opt-in collection of anonymized jitter timing data
//! to help build datasets for security analysis of the proof-of-process primitive.
//!
//! ## What is collected:
//! - Jitter timing samples (inter-keystroke intervals in microseconds)
//! - Hardware class (CPU architecture, core count range)
//! - OS type (macOS, Linux, Windows)
//! - Sample timestamps (rounded to hour for privacy)
//! - Session statistics (sample count, duration buckets)
//!
//! ## What is NOT collected:
//! - Document content or paths
//! - Actual keystrokes or text
//! - User identity or device identifiers
//! - Exact hardware model or serial numbers
//! - Network information

use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::config::ResearchConfig;
use crate::jitter::{Evidence, Statistics};

pub const RESEARCH_UPLOAD_URL: &str =
    "https://aswcfxodrgcnjbwrcjrl.supabase.co/functions/v1/research-upload";

pub const MIN_SESSIONS_FOR_UPLOAD: usize = 5;

pub const DEFAULT_UPLOAD_INTERVAL_SECS: u64 = 4 * 60 * 60;

pub const WITNESSD_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Anonymized jitter sample -- timing data only, no document/user info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizedSample {
    pub relative_time_secs: f64,
    pub jitter_micros: u32,
    pub keystroke_ordinal: u64,
    pub document_changed: bool,
}

/// Anonymized session data for research contribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizedSession {
    pub research_id: String,
    pub collected_at: DateTime<Utc>,
    pub hardware_class: HardwareClass,
    pub os_type: OsType,
    pub samples: Vec<AnonymizedSample>,
    pub statistics: AnonymizedStatistics,
}

/// Coarse-grained hardware class (bucketed for privacy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareClass {
    pub arch: String,
    pub core_bucket: String,
    pub memory_bucket: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OsType {
    MacOS,
    Linux,
    Windows,
    Other,
}

/// Bucketed statistics for research (no raw identifiers).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizedStatistics {
    pub total_samples: usize,
    pub duration_bucket: String,
    pub typing_rate_bucket: String,
    pub mean_jitter_micros: f64,
    pub jitter_std_dev: f64,
    pub min_jitter_micros: u32,
    pub max_jitter_micros: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phys_ratio: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_source: Option<String>,
}

/// Serializable export envelope for research data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchDataExport {
    pub version: u32,
    pub exported_at: DateTime<Utc>,
    pub consent_confirmed: bool,
    pub sessions: Vec<AnonymizedSession>,
}

impl AnonymizedSession {
    /// Strip identifying info from `Evidence`, preserving only timing patterns.
    pub fn from_evidence(evidence: &Evidence) -> Self {
        let research_id = generate_research_id();
        let collected_at = round_timestamp_to_hour(Utc::now());
        let hardware_class = detect_hardware_class();
        let os_type = detect_os_type();

        let start_time = evidence.started_at;
        let mut prev_doc_hash: Option<[u8; 32]> = None;

        let samples: Vec<AnonymizedSample> = evidence
            .samples
            .iter()
            .map(|s| {
                let relative_time = s
                    .timestamp
                    .signed_duration_since(start_time)
                    .to_std()
                    .map(|d| d.as_secs_f64())
                    .unwrap_or(0.0);

                let doc_changed = prev_doc_hash
                    .map(|prev| prev != s.document_hash)
                    .unwrap_or(true);
                prev_doc_hash = Some(s.document_hash);

                AnonymizedSample {
                    relative_time_secs: relative_time,
                    jitter_micros: s.jitter_micros,
                    keystroke_ordinal: s.keystroke_count,
                    document_changed: doc_changed,
                }
            })
            .collect();

        let statistics = compute_anonymized_statistics(&evidence.statistics, &samples);

        Self {
            research_id,
            collected_at,
            hardware_class,
            os_type,
            samples,
            statistics,
        }
    }
}

fn generate_research_id() -> String {
    let random_bytes: [u8; 16] = rand::random();
    hex::encode(random_bytes)
}

fn round_timestamp_to_hour(ts: DateTime<Utc>) -> DateTime<Utc> {
    ts.with_minute(0)
        .and_then(|t| t.with_second(0))
        .and_then(|t| t.with_nanosecond(0))
        .unwrap_or(ts)
}

fn detect_hardware_class() -> HardwareClass {
    let arch = std::env::consts::ARCH.to_string();

    let core_count = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1);

    let core_bucket = match core_count {
        1..=2 => "1-2",
        3..=4 => "3-4",
        5..=8 => "5-8",
        9..=16 => "9-16",
        _ => "17+",
    }
    .to_string();

    let memory_bucket = detect_memory_bucket();

    HardwareClass {
        arch,
        core_bucket,
        memory_bucket,
    }
}

#[cfg(target_os = "macos")]
fn detect_memory_bucket() -> String {
    use std::process::Command;

    let output = Command::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u64>().ok());

    match output {
        Some(bytes) => {
            let gb = bytes / (1024 * 1024 * 1024);
            memory_gb_to_bucket(gb)
        }
        None => "unknown".to_string(),
    }
}

#[cfg(target_os = "linux")]
fn detect_memory_bucket() -> String {
    let meminfo = fs::read_to_string("/proc/meminfo").ok();

    let total_kb = meminfo.and_then(|content| {
        content
            .lines()
            .find(|l| l.starts_with("MemTotal:"))
            .and_then(|l| {
                l.split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse::<u64>().ok())
            })
    });

    match total_kb {
        Some(kb) => {
            let gb = kb / (1024 * 1024);
            memory_gb_to_bucket(gb)
        }
        None => "unknown".to_string(),
    }
}

#[cfg(target_os = "windows")]
fn detect_memory_bucket() -> String {
    // TODO: implement via GlobalMemoryStatusEx (requires unsafe)
    "unknown".to_string()
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn detect_memory_bucket() -> String {
    "unknown".to_string()
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn memory_gb_to_bucket(gb: u64) -> String {
    match gb {
        0..=4 => "<=4GB",
        5..=8 => "4-8GB",
        9..=16 => "8-16GB",
        17..=32 => "16-32GB",
        _ => "32GB+",
    }
    .to_string()
}

fn detect_os_type() -> OsType {
    match std::env::consts::OS {
        "macos" => OsType::MacOS,
        "linux" => OsType::Linux,
        "windows" => OsType::Windows,
        _ => OsType::Other,
    }
}

fn compute_anonymized_statistics(
    stats: &Statistics,
    samples: &[AnonymizedSample],
) -> AnonymizedStatistics {
    let duration_secs = stats.duration.as_secs();
    let duration_bucket = match duration_secs {
        0..=300 => "0-5min",
        301..=900 => "5-15min",
        901..=1800 => "15-30min",
        1801..=3600 => "30-60min",
        _ => "60min+",
    }
    .to_string();

    let typing_rate_bucket = match stats.keystrokes_per_min as u32 {
        0..=30 => "slow",
        31..=60 => "moderate",
        61..=120 => "fast",
        _ => "very_fast",
    }
    .to_string();

    let jitter_values: Vec<f64> = samples.iter().map(|s| s.jitter_micros as f64).collect();

    let (mean, std_dev) = if jitter_values.is_empty() {
        (0.0, 0.0)
    } else {
        let mean = jitter_values.iter().sum::<f64>() / jitter_values.len() as f64;
        let variance = jitter_values
            .iter()
            .map(|v| (v - mean).powi(2))
            .sum::<f64>()
            / jitter_values.len() as f64;
        (mean, variance.sqrt())
    };

    let min_jitter = samples.iter().map(|s| s.jitter_micros).min().unwrap_or(0);
    let max_jitter = samples.iter().map(|s| s.jitter_micros).max().unwrap_or(0);

    AnonymizedStatistics {
        total_samples: samples.len(),
        duration_bucket,
        typing_rate_bucket,
        mean_jitter_micros: mean,
        jitter_std_dev: std_dev,
        min_jitter_micros: min_jitter,
        max_jitter_micros: max_jitter,
        phys_ratio: None,
        entropy_source: None,
    }
}

/// Like `compute_anonymized_statistics` but includes hardware entropy metrics.
#[cfg(feature = "witnessd_jitter")]
pub fn compute_anonymized_statistics_hybrid(
    stats: &Statistics,
    samples: &[AnonymizedSample],
    phys_ratio: f64,
) -> AnonymizedStatistics {
    let mut base = compute_anonymized_statistics(stats, samples);
    base.phys_ratio = Some(phys_ratio);
    base.entropy_source = Some(describe_entropy_source(phys_ratio));
    base
}

#[cfg(feature = "witnessd_jitter")]
fn describe_entropy_source(phys_ratio: f64) -> String {
    if phys_ratio > 0.9 {
        "hardware (TSC-based)".to_string()
    } else if phys_ratio > 0.5 {
        "hybrid (hardware + HMAC)".to_string()
    } else if phys_ratio > 0.0 {
        "mostly HMAC (limited hardware)".to_string()
    } else {
        "pure HMAC (no hardware entropy)".to_string()
    }
}

/// Collects anonymized sessions and manages disk persistence / upload.
pub struct ResearchCollector {
    config: ResearchConfig,
    sessions: Vec<AnonymizedSession>,
}

impl ResearchCollector {
    pub fn new(config: ResearchConfig) -> Self {
        Self {
            config,
            sessions: Vec::new(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.contribute_to_research
    }

    /// Anonymize and enqueue a session (no-op if disabled or below min samples).
    pub fn add_session(&mut self, evidence: &Evidence) {
        if !self.is_enabled() {
            return;
        }

        if evidence.samples.len() < self.config.min_samples_per_session {
            return;
        }

        let anonymized = AnonymizedSession::from_evidence(evidence);
        self.sessions.push(anonymized);

        while self.sessions.len() > self.config.max_sessions {
            self.sessions.remove(0);
        }
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn export(&self) -> ResearchDataExport {
        ResearchDataExport {
            version: 1,
            exported_at: Utc::now(),
            consent_confirmed: self.config.contribute_to_research,
            sessions: self.sessions.clone(),
        }
    }

    pub fn export_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(&self.export()).map_err(|e| e.to_string())
    }

    pub fn save(&self) -> Result<(), String> {
        if self.sessions.is_empty() {
            return Ok(());
        }

        fs::create_dir_all(&self.config.research_data_dir).map_err(|e| e.to_string())?;

        let export = self.export();
        let filename = format!("research_{}.json", Utc::now().format("%Y%m%d_%H%M%S"));
        let path = self.config.research_data_dir.join(filename);

        let json = serde_json::to_string_pretty(&export).map_err(|e| e.to_string())?;
        fs::write(&path, json).map_err(|e| e.to_string())?;

        Ok(())
    }

    pub fn load(&mut self) -> Result<(), String> {
        if !self.config.research_data_dir.exists() {
            return Ok(());
        }

        let entries = fs::read_dir(&self.config.research_data_dir).map_err(|e| e.to_string())?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(export) = serde_json::from_str::<ResearchDataExport>(&content) {
                        for session in export.sessions {
                            self.sessions.push(session);
                        }
                    }
                }
            }
        }

        while self.sessions.len() > self.config.max_sessions {
            self.sessions.remove(0);
        }

        Ok(())
    }

    pub fn clear(&mut self) -> Result<(), String> {
        self.sessions.clear();

        if self.config.research_data_dir.exists() {
            fs::remove_dir_all(&self.config.research_data_dir).map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    pub async fn upload(&mut self) -> Result<UploadResult, String> {
        if !self.is_enabled() {
            return Err("Research contribution not enabled".to_string());
        }

        if self.sessions.is_empty() {
            return Ok(UploadResult {
                sessions_uploaded: 0,
                samples_uploaded: 0,
                message: "No sessions to upload".to_string(),
            });
        }

        if self.sessions.len() < MIN_SESSIONS_FOR_UPLOAD {
            return Ok(UploadResult {
                sessions_uploaded: 0,
                samples_uploaded: 0,
                message: format!(
                    "Waiting for more sessions ({}/{})",
                    self.sessions.len(),
                    MIN_SESSIONS_FOR_UPLOAD
                ),
            });
        }

        let export = self.export();
        let client = reqwest::Client::new();

        let response = client
            .post(RESEARCH_UPLOAD_URL)
            .header("Content-Type", "application/json")
            .header("X-Witnessd-Version", WITNESSD_VERSION)
            .json(&export)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| format!("Upload failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("Upload failed with status {}: {}", status, body));
        }

        let result: UploadResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        if result.uploaded > 0 {
            self.sessions.clear();
            if self.config.research_data_dir.exists() {
                let _ = fs::remove_dir_all(&self.config.research_data_dir);
            }
        }

        Ok(UploadResult {
            sessions_uploaded: result.uploaded,
            samples_uploaded: result.samples,
            message: result.message,
        })
    }

    pub fn should_upload(&self) -> bool {
        self.is_enabled() && self.sessions.len() >= MIN_SESSIONS_FOR_UPLOAD
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadResult {
    pub sessions_uploaded: usize,
    pub samples_uploaded: usize,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
struct UploadResponse {
    uploaded: usize,
    samples: usize,
    message: String,
}

pub struct ResearchUploader {
    collector: Arc<tokio::sync::Mutex<ResearchCollector>>,
    running: Arc<AtomicBool>,
    upload_interval: Duration,
}

impl ResearchUploader {
    pub fn new(collector: Arc<tokio::sync::Mutex<ResearchCollector>>) -> Self {
        Self {
            collector,
            running: Arc::new(AtomicBool::new(false)),
            upload_interval: Duration::from_secs(DEFAULT_UPLOAD_INTERVAL_SECS),
        }
    }

    pub fn with_interval(
        collector: Arc<tokio::sync::Mutex<ResearchCollector>>,
        interval: Duration,
    ) -> Self {
        Self {
            collector,
            running: Arc::new(AtomicBool::new(false)),
            upload_interval: interval,
        }
    }

    pub fn start(&self) -> tokio::task::JoinHandle<()> {
        let collector = Arc::clone(&self.collector);
        let running = Arc::clone(&self.running);
        let interval = self.upload_interval;

        running.store(true, Ordering::SeqCst);

        tokio::spawn(async move {
            while running.load(Ordering::SeqCst) {
                tokio::time::sleep(interval).await;

                if !running.load(Ordering::SeqCst) {
                    break;
                }

                let mut guard = collector.lock().await;
                if guard.should_upload() {
                    match guard.upload().await {
                        Ok(result) => {
                            if result.sessions_uploaded > 0 {
                                eprintln!(
                                    "[research] Uploaded {} sessions ({} samples)",
                                    result.sessions_uploaded, result.samples_uploaded
                                );
                            }
                        }
                        Err(e) => {
                            eprintln!("[research] Upload failed: {}", e);
                            let _ = guard.save();
                        }
                    }
                }
            }
        })
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub async fn upload_now(&self) -> Result<UploadResult, String> {
        let mut guard = self.collector.lock().await;
        guard.upload().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jitter::{default_parameters, Session};
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_hardware_class_detection() {
        let hw = detect_hardware_class();
        assert!(!hw.arch.is_empty());
        assert!(!hw.core_bucket.is_empty());
    }

    #[test]
    fn test_os_type_detection() {
        let os = detect_os_type();
        #[cfg(target_os = "macos")]
        assert_eq!(os, OsType::MacOS);
        #[cfg(target_os = "linux")]
        assert_eq!(os, OsType::Linux);
        #[cfg(target_os = "windows")]
        assert_eq!(os, OsType::Windows);
    }

    #[test]
    fn test_timestamp_rounding() {
        let ts = Utc::now();
        let rounded = round_timestamp_to_hour(ts);
        assert_eq!(rounded.minute(), 0);
        assert_eq!(rounded.second(), 0);
        assert_eq!(rounded.nanosecond(), 0);
    }

    #[test]
    fn test_anonymized_session_creation() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "test content").unwrap();
        temp_file.flush().unwrap();

        let params = default_parameters();
        let mut session = Session::new(temp_file.path(), params).unwrap();

        for _ in 0..100 {
            let _ = session.record_keystroke();
        }

        let evidence = session.export();
        let anonymized = AnonymizedSession::from_evidence(&evidence);

        assert!(!anonymized.research_id.is_empty());
        assert_eq!(anonymized.collected_at.minute(), 0);
        assert!(!anonymized.hardware_class.arch.is_empty());
    }

    #[test]
    fn test_research_collector_disabled() {
        let config = ResearchConfig {
            contribute_to_research: false,
            ..Default::default()
        };

        let mut collector = ResearchCollector::new(config);
        assert!(!collector.is_enabled());

        let evidence = Evidence {
            session_id: "test".to_string(),
            started_at: Utc::now(),
            ended_at: Utc::now(),
            document_path: "/test".to_string(),
            params: default_parameters(),
            samples: vec![],
            statistics: Statistics::default(),
        };

        collector.add_session(&evidence);
        assert_eq!(collector.session_count(), 0);
    }

    #[test]
    fn test_memory_bucket() {
        assert_eq!(memory_gb_to_bucket(2), "<=4GB");
        assert_eq!(memory_gb_to_bucket(6), "4-8GB");
        assert_eq!(memory_gb_to_bucket(12), "8-16GB");
        assert_eq!(memory_gb_to_bucket(24), "16-32GB");
        assert_eq!(memory_gb_to_bucket(64), "32GB+");
    }
}
