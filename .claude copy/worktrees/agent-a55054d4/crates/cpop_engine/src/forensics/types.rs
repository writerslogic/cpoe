

//! Core types, constants, and enums for forensic analysis.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::analysis::{
    BehavioralFingerprint, ForgeryAnalysis, IkiCompressionAnalysis, LabyrinthAnalysis,
    LyapunovAnalysis, SnrAnalysis,
};
use crate::forensics::cross_modal::CrossModalResult;
use crate::forensics::forgery_cost::ForgeryCostEstimate;
use cpop_protocol::forensics::{ForensicAnalysis as ProtocolForensicAnalysis, ForensicVerdict};

/
pub const DEFAULT_APPEND_THRESHOLD: f32 = 0.95;

/
pub const DEFAULT_HISTOGRAM_BINS: usize = 20;

/
pub const MIN_EVENTS_FOR_ANALYSIS: usize = 5;

/
pub const MIN_EVENTS_FOR_ASSESSMENT: usize = 10;

/
pub const DEFAULT_SESSION_GAP_SEC: f64 = 1800.0;

/
pub const THRESHOLD_MONOTONIC_APPEND: f64 = 0.85;

/
pub const THRESHOLD_TIMING_ENTROPY: f64 = 3.0;
/
pub const THRESHOLD_REVISION_ENTROPY: f64 = 3.0;
/
pub const THRESHOLD_PAUSE_ENTROPY: f64 = 2.0;
/
/
pub const THRESHOLD_LOW_ENTROPY: f64 = 2.0;

/
pub const THRESHOLD_HIGH_VELOCITY_BPS: f64 = 100.0;

/
pub const THRESHOLD_GAP_HOURS: f64 = 24.0;

/
pub const ALERT_THRESHOLD: usize = 2;

/
pub const ROBOTIC_CV_THRESHOLD: f64 = 0.15;

/
pub const DEFAULT_EDIT_RATIO: f64 = 0.15;

/
pub const SUSPICIOUS_RATIO_THRESHOLD: f64 = 0.3;

/
pub const INCONSISTENT_RATIO_THRESHOLD: f64 = 0.5;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventData {
    pub id: i64,
    pub timestamp_ns: i64,
    pub file_size: i64,
    pub size_delta: i32,
    pub file_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionData {
    /
    pub start_pct: f32,
    /
    pub end_pct: f32,
    /
    pub delta_sign: i8,
    pub byte_count: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrimaryMetrics {
    /
    pub monotonic_append_ratio: f64,
    /
    pub edit_entropy: f64,
    /
    pub median_interval: f64,
    /
    pub positive_negative_ratio: f64,
    /
    pub deletion_clustering: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CadenceMetrics {
    pub mean_iki_ns: f64,
    pub std_dev_iki_ns: f64,
    /
    pub coefficient_of_variation: f64,
    pub median_iki_ns: f64,
    pub burst_count: usize,
    /
    pub pause_count: usize,
    pub avg_burst_length: f64,
    pub avg_pause_duration_ns: f64,
    /
    pub is_robotic: bool,
    /
    pub percentiles: [f64; 5],
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ForensicMetrics {
    pub primary: PrimaryMetrics,
    pub cadence: CadenceMetrics,
    pub behavioral: Option<BehavioralFingerprint>,
    pub forgery_analysis: Option<ForgeryAnalysis>,
    pub velocity: VelocityMetrics,
    pub session_stats: SessionStats,
    /
    pub assessment_score: f64,
    /
    pub perplexity_score: f64,
    /
    pub steg_confidence: f64,
    pub anomaly_count: usize,
    pub risk_level: RiskLevel,
    /
    pub biological_cadence_score: f64,
    /
    pub cross_modal: Option<CrossModalResult>,
    /
    pub forgery_cost: Option<ForgeryCostEstimate>,
    /
    pub checkpoint_count: usize,
    /
    pub hurst_exponent: Option<f64>,
    pub snr: Option<SnrAnalysis>,
    pub lyapunov: Option<LyapunovAnalysis>,
    pub iki_compression: Option<IkiCompressionAnalysis>,
    pub labyrinth: Option<LabyrinthAnalysis>,
}

impl ForensicMetrics {
    /
    pub fn map_to_protocol_verdict(&self) -> ForensicVerdict {
        if let Some(forgery) = &self.forgery_analysis {
            if forgery.is_suspicious {
                
                
                return ForensicVerdict::V4LikelySynthetic;
            }
        }

        
        if let Some(cm) = &self.cross_modal {
            if cm.verdict == crate::forensics::cross_modal::CrossModalVerdict::Inconsistent {
                return ForensicVerdict::V4LikelySynthetic;
            }
        }

        match self.risk_level {
            RiskLevel::Low => {
                if self.assessment_score > 0.9 {
                    ForensicVerdict::V1VerifiedHuman
                } else {
                    ForensicVerdict::V2LikelyHuman
                }
            }
            RiskLevel::Medium => ForensicVerdict::V3Suspicious,
            RiskLevel::High => {
                if self.cadence.is_robotic {
                    ForensicVerdict::V4LikelySynthetic
                } else {
                    ForensicVerdict::V3Suspicious
                }
            }
            RiskLevel::Insufficient => ForensicVerdict::V2LikelyHuman,
        }
    }

    /
    pub fn to_protocol_analysis(&self) -> ProtocolForensicAnalysis {
        ProtocolForensicAnalysis {
            verdict: self.map_to_protocol_verdict(),
            coefficient_of_variation: self.cadence.coefficient_of_variation,
            linearity_score: Some(self.primary.monotonic_append_ratio),
            hurst_exponent: self.hurst_exponent,
            checkpoint_count: self.checkpoint_count,
            chain_duration_secs: self.session_stats.total_editing_time_sec as u64,
            explanation: format!("Internal Assessment Score: {:.2}", self.assessment_score),
        }
    }
}

/
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VelocityMetrics {
    pub mean_bps: f64,
    pub max_bps: f64,
    pub high_velocity_bursts: usize,
    /
    pub autocomplete_chars: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionStats {
    pub session_count: usize,
    pub avg_session_duration_sec: f64,
    pub total_editing_time_sec: f64,
    /
    pub time_span_sec: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RiskLevel {
    #[default]
    Low,
    Medium,
    High,
    Insufficient,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "LOW"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Insufficient => write!(f, "INSUFFICIENT DATA"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorshipProfile {
    pub file_path: String,
    pub event_count: usize,
    pub time_span: ChronoDuration,
    pub session_count: usize,
    pub first_event: DateTime<Utc>,
    pub last_event: DateTime<Utc>,
    pub metrics: PrimaryMetrics,
    pub anomalies: Vec<Anomaly>,
    pub assessment: Assessment,
}

impl Default for AuthorshipProfile {
    fn default() -> Self {
        Self {
            file_path: String::new(),
            event_count: 0,
            time_span: ChronoDuration::zero(),
            session_count: 0,
            first_event: Utc::now(),
            last_event: Utc::now(),
            metrics: PrimaryMetrics::default(),
            anomalies: Vec::new(),
            assessment: Assessment::Insufficient,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub timestamp: Option<DateTime<Utc>>,
    pub anomaly_type: AnomalyType,
    pub description: String,
    pub severity: Severity,
    pub context: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyType {
    Gap,
    HighVelocity,
    MonotonicAppend,
    LowEntropy,
    RoboticCadence,
    UndetectedPaste,
    ContentMismatch,
    ScatteredDeletions,
}

impl fmt::Display for AnomalyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnomalyType::Gap => write!(f, "gap"),
            AnomalyType::HighVelocity => write!(f, "high_velocity"),
            AnomalyType::MonotonicAppend => write!(f, "monotonic_append"),
            AnomalyType::LowEntropy => write!(f, "low_entropy"),
            AnomalyType::RoboticCadence => write!(f, "robotic_cadence"),
            AnomalyType::UndetectedPaste => write!(f, "undetected_paste"),
            AnomalyType::ContentMismatch => write!(f, "content_mismatch"),
            AnomalyType::ScatteredDeletions => write!(f, "scattered_deletions"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Alert,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Warning => write!(f, "warning"),
            Severity::Alert => write!(f, "alert"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointFlags {
    pub ordinal: u64,
    pub event_count: usize,
    pub timing_cv: f64,
    pub max_velocity_bps: f64,
    pub all_append: bool,
    pub flagged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerCheckpointResult {
    pub checkpoint_flags: Vec<CheckpointFlags>,
    pub pct_flagged: f64,
    pub suspicious: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Assessment {
    Consistent,
    Suspicious,
    #[default]
    Insufficient,
}

impl fmt::Display for Assessment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Assessment::Consistent => write!(f, "CONSISTENT WITH HUMAN AUTHORSHIP"),
            Assessment::Suspicious => write!(f, "SUSPICIOUS PATTERNS DETECTED"),
            Assessment::Insufficient => write!(f, "INSUFFICIENT DATA"),
        }
    }
}
