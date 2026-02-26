// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Core data types, enums, constants, and their implementations for forensic analysis.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::analysis::{BehavioralFingerprint, ForgeryAnalysis};
use witnessd_protocol::forensics::{ForensicAnalysis as ProtocolForensicAnalysis, ForensicVerdict};

// =============================================================================
// Constants
// =============================================================================

/// Default threshold for considering an edit as an "append" (at 95% of document).
pub const DEFAULT_APPEND_THRESHOLD: f32 = 0.95;

/// Default number of bins for edit entropy histogram.
pub const DEFAULT_HISTOGRAM_BINS: usize = 20;

/// Minimum events required for stable analysis.
pub const MIN_EVENTS_FOR_ANALYSIS: usize = 5;

/// Minimum events for assessment verdict.
pub const MIN_EVENTS_FOR_ASSESSMENT: usize = 10;

/// Default session gap threshold in seconds (30 minutes).
pub const DEFAULT_SESSION_GAP_SEC: f64 = 1800.0;

/// High monotonic append ratio threshold (suggests AI generation).
pub const THRESHOLD_MONOTONIC_APPEND: f64 = 0.85;

/// Low entropy threshold (suggests non-human editing).
pub const THRESHOLD_LOW_ENTROPY: f64 = 1.5;

/// High velocity threshold in bytes per second.
pub const THRESHOLD_HIGH_VELOCITY_BPS: f64 = 100.0;

/// Long gap threshold in hours.
pub const THRESHOLD_GAP_HOURS: f64 = 24.0;

/// Alert threshold for suspicious assessment.
pub const ALERT_THRESHOLD: usize = 2;

/// Coefficient of variation threshold for robotic typing detection.
pub const ROBOTIC_CV_THRESHOLD: f64 = 0.15;

/// Default edit ratio estimate (15% of keystrokes are deletions).
pub const DEFAULT_EDIT_RATIO: f64 = 0.15;

/// Suspicious discrepancy ratio threshold.
pub const SUSPICIOUS_RATIO_THRESHOLD: f64 = 0.3;

/// Inconsistent discrepancy ratio threshold.
pub const INCONSISTENT_RATIO_THRESHOLD: f64 = 0.5;

// =============================================================================
// Core Data Types
// =============================================================================

/// Minimal event data for forensic analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventData {
    pub id: i64,
    pub timestamp_ns: i64,
    pub file_size: i64,
    pub size_delta: i32,
    pub file_path: String,
}

/// Edit region data for topology analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionData {
    /// Start position as percentage of document (0.0 - 1.0).
    pub start_pct: f32,
    /// End position as percentage of document (0.0 - 1.0).
    pub end_pct: f32,
    /// Delta sign: +1 insertion, -1 deletion, 0 replacement.
    pub delta_sign: i8,
    /// Number of bytes affected.
    pub byte_count: i32,
}

/// Primary forensic metrics for authorship detection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrimaryMetrics {
    /// Fraction of edits at end of document (>0.95 position).
    pub monotonic_append_ratio: f64,
    /// Shannon entropy of edit position histogram (20 bins).
    pub edit_entropy: f64,
    /// Median inter-event interval in seconds.
    pub median_interval: f64,
    /// Insertions / (insertions + deletions).
    pub positive_negative_ratio: f64,
    /// Nearest-neighbor ratio for deletions.
    pub deletion_clustering: f64,
}

/// Keystroke cadence metrics for typing pattern analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CadenceMetrics {
    /// Mean inter-keystroke interval in nanoseconds.
    pub mean_iki_ns: f64,
    /// Standard deviation of IKI in nanoseconds.
    pub std_dev_iki_ns: f64,
    /// Coefficient of variation (std_dev / mean).
    pub coefficient_of_variation: f64,
    /// Median IKI in nanoseconds.
    pub median_iki_ns: f64,
    /// Number of detected typing bursts.
    pub burst_count: usize,
    /// Number of detected pauses (>2 seconds).
    pub pause_count: usize,
    /// Average burst length in keystrokes.
    pub avg_burst_length: f64,
    /// Average pause duration in nanoseconds.
    pub avg_pause_duration_ns: f64,
    /// Whether pattern suggests robotic/synthetic typing.
    pub is_robotic: bool,
    /// Percentile distribution of IKIs (10th, 25th, 50th, 75th, 90th).
    pub percentiles: [f64; 5],
}

/// Complete forensic metrics combining all analysis dimensions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ForensicMetrics {
    /// Primary edit topology metrics.
    pub primary: PrimaryMetrics,
    /// Keystroke cadence metrics.
    pub cadence: CadenceMetrics,
    /// Behavioral fingerprint analysis.
    pub behavioral: Option<BehavioralFingerprint>,
    /// Forgery detection results.
    pub forgery_analysis: Option<ForgeryAnalysis>,
    /// Edit velocity metrics.
    pub velocity: VelocityMetrics,
    /// Session-level statistics.
    pub session_stats: SessionStats,
    /// Overall assessment score (0.0 - 1.0, higher = more human-like).
    pub assessment_score: f64,
    /// Perplexity score (lower = more expected/human-like).
    pub perplexity_score: f64,
    /// Steganographic confidence (validity of timing modulation).
    pub steg_confidence: f64,
    /// Number of detected anomalies.
    pub anomaly_count: usize,
    /// Risk level classification.
    pub risk_level: RiskLevel,
}

impl ForensicMetrics {
    /// Maps internal metrics to the protocol-standard ForensicVerdict defined in pop-crate.
    pub fn map_to_protocol_verdict(&self) -> ForensicVerdict {
        if let Some(forgery) = &self.forgery_analysis {
            if forgery.is_suspicious {
                return ForensicVerdict::V5ConfirmedForgery;
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
            RiskLevel::Insufficient => ForensicVerdict::V2LikelyHuman, // Default to neutral-ish
        }
    }

    /// Converts internal metrics to a full ProtocolForensicAnalysis structure.
    pub fn to_protocol_analysis(&self) -> ProtocolForensicAnalysis {
        ProtocolForensicAnalysis {
            verdict: self.map_to_protocol_verdict(),
            coefficient_of_variation: self.cadence.coefficient_of_variation,
            linearity_score: Some(self.primary.monotonic_append_ratio),
            hurst_exponent: None, // Hurst analysis is only in pop-crate for now
            checkpoint_count: self.session_stats.session_count, // rough mapping
            chain_duration_secs: self.session_stats.total_editing_time_sec as u64,
            explanation: format!("Internal Assessment Score: {:.2}", self.assessment_score),
        }
    }
}

/// Edit velocity metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VelocityMetrics {
    /// Mean bytes per second.
    pub mean_bps: f64,
    /// Maximum bytes per second observed.
    pub max_bps: f64,
    /// Number of high-velocity bursts detected.
    pub high_velocity_bursts: usize,
    /// Estimated autocomplete characters.
    pub autocomplete_chars: i64,
}

/// Session-level statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionStats {
    /// Total number of editing sessions detected.
    pub session_count: usize,
    /// Average session duration in seconds.
    pub avg_session_duration_sec: f64,
    /// Total editing time in seconds.
    pub total_editing_time_sec: f64,
    /// Time between first and last event in seconds.
    pub time_span_sec: f64,
}

/// Risk level classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RiskLevel {
    /// Low risk - consistent with human authorship.
    #[default]
    Low,
    /// Medium risk - some suspicious patterns.
    Medium,
    /// High risk - likely AI-generated or suspicious activity.
    High,
    /// Insufficient data for assessment.
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

// =============================================================================
// Authorship Profile
// =============================================================================

/// Complete authorship analysis profile.
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

/// Detected anomaly in editing patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub timestamp: Option<DateTime<Utc>>,
    pub anomaly_type: AnomalyType,
    pub description: String,
    pub severity: Severity,
    pub context: Option<String>,
}

/// Types of anomalies that can be detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyType {
    /// Long gap between edits.
    Gap,
    /// High-velocity content addition.
    HighVelocity,
    /// High monotonic append pattern.
    MonotonicAppend,
    /// Low edit entropy.
    LowEntropy,
    /// Robotic keystroke cadence.
    RoboticCadence,
    /// Undetected paste operation.
    UndetectedPaste,
    /// Content-keystroke mismatch.
    ContentMismatch,
    /// Scattered deletion pattern.
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

/// Severity level for anomalies.
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

/// Overall assessment verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Assessment {
    /// Consistent with human authorship.
    Consistent,
    /// Suspicious patterns detected.
    Suspicious,
    /// Insufficient data for assessment.
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
