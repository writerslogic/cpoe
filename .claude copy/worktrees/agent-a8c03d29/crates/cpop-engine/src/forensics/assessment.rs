

//! Anomaly detection and assessment.

use chrono::DateTime;
use std::collections::HashMap;

use super::types::{
    Anomaly, AnomalyType, Assessment, CadenceMetrics, EventData, FocusMetrics, PrimaryMetrics,
    RegionData, RiskLevel, Severity, ALERT_THRESHOLD, MIN_EVENTS_FOR_ANALYSIS,
    MIN_EVENTS_FOR_ASSESSMENT, THRESHOLD_GAP_HOURS, THRESHOLD_HIGH_VELOCITY_BPS,
    THRESHOLD_LOW_ENTROPY, THRESHOLD_MONOTONIC_APPEND,
};

/
pub(crate) const ENTROPY_NORMALIZATION: f64 = 4.321928;
/
const LOW_ENTROPY_SCORE_THRESHOLD: f64 = 0.35;
/
const MONOTONIC_PENALTY_START: f64 = 0.85;
/
const CV_ROBOTIC_THRESHOLD: f64 = 0.2;
/
const ANOMALY_PENALTY: f64 = 0.05;

/
const DELETION_CLUSTERING_LOW: f64 = 0.9;
/
const DELETION_CLUSTERING_HIGH: f64 = 1.1;
/
const MONOTONIC_SUSPICIOUS: f64 = 0.90;
/
const POS_NEG_SUSPICIOUS: f64 = 0.95;
/
/
/
const INSUFFICIENT_DATA_SCORE: f64 = 0.0;
/
const MONOTONIC_PENALTY_WEIGHT: f64 = 0.2;
/
const LOW_ENTROPY_PENALTY: f64 = 0.15;
/
const POS_NEG_PENALTY: f64 = 0.1;
/
const ROBOTIC_CADENCE_PENALTY: f64 = 0.35;
/
const COV_PENALTY_WEIGHT: f64 = 0.15;
/
const BIOLOGICAL_CADENCE_THRESHOLD: f64 = 0.5;
/
const BIOLOGICAL_CADENCE_REWARD: f64 = 0.05;
/
const CADENCE_ROBOTIC_PENALTY: f64 = 0.5;
/
const CADENCE_COV_PENALTY: f64 = 0.2;
/
const RISK_LOW_THRESHOLD: f64 = 0.7;
/
const RISK_MEDIUM_THRESHOLD: f64 = 0.4;
/
const SUSPICIOUS_WARNING_COUNT: usize = 3;
/
const SUSPICIOUS_INDICATOR_COUNT: usize = 2;
/
const SUSPICIOUS_INDICATOR_CRITICAL: usize = 3;
/
const VELOCITY_WINDOW_SEC: f64 = 60.0;

/
const IKI_AUTOCORR_TRANSCRIPTIVE: f64 = 0.3;
/
const IKI_AUTOCORR_PENALTY: f64 = 0.15;
/
const CORRECTION_RATIO_LOW: f64 = 0.02;
/
const LOW_CORRECTION_PENALTY: f64 = 0.1;
/
const CORRECTION_MIN_EVENTS: usize = 50;
/
const POST_PAUSE_CV_REWARD_THRESHOLD: f64 = 0.25;
/
const POST_PAUSE_CV_REWARD: f64 = 0.05;
/
const DEEP_PAUSE_REWARD_THRESHOLD: f64 = 0.1;
/
const DEEP_PAUSE_REWARD: f64 = 0.05;
/
const CROSS_HAND_UNIFORM_THRESHOLD: f64 = 1.1;
/
const CROSS_HAND_PENALTY: f64 = 0.1;
/
const FOCUS_READING_PENALTY: f64 = 0.15;
/
const FOCUS_AI_SWITCH_THRESHOLD: usize = 3;
/
const FOCUS_AI_SWITCH_PENALTY: f64 = 0.1;
/
const FOCUS_OUT_OF_FOCUS_THRESHOLD: f64 = 0.5;
/
const FOCUS_OUT_OF_FOCUS_PENALTY: f64 = 0.1;

/
pub fn detect_anomalies(
    events: &[EventData],
    regions: &HashMap<i64, Vec<RegionData>>,
    metrics: &PrimaryMetrics,
) -> Vec<Anomaly> {
    let mut anomalies = Vec::new();

    if metrics.monotonic_append_ratio > THRESHOLD_MONOTONIC_APPEND {
        anomalies.push(Anomaly {
            timestamp: None,
            anomaly_type: AnomalyType::MonotonicAppend,
            description: "High monotonic append ratio suggests sequential content generation"
                .to_string(),
            severity: Severity::Warning,
            context: Some(format!(
                "Ratio: {:.2}%",
                metrics.monotonic_append_ratio * 100.0
            )),
        });
    }

    if metrics.edit_entropy < THRESHOLD_LOW_ENTROPY && metrics.edit_entropy > 0.0 {
        anomalies.push(Anomaly {
            timestamp: None,
            anomaly_type: AnomalyType::LowEntropy,
            description: "Low edit entropy indicates concentrated editing patterns".to_string(),
            severity: Severity::Warning,
            context: Some(format!("Entropy: {:.3}", metrics.edit_entropy)),
        });
    }

    if metrics.deletion_clustering > DELETION_CLUSTERING_LOW
        && metrics.deletion_clustering < DELETION_CLUSTERING_HIGH
    {
        anomalies.push(Anomaly {
            timestamp: None,
            anomaly_type: AnomalyType::ScatteredDeletions,
            description: "Scattered deletion pattern suggests artificial editing".to_string(),
            severity: Severity::Warning,
            context: Some(format!(
                "Clustering coef: {:.3}",
                metrics.deletion_clustering
            )),
        });
    }

    anomalies.extend(detect_temporal_anomalies(events, regions));

    anomalies
}

/
fn detect_temporal_anomalies(
    events: &[EventData],
    _regions: &HashMap<i64, Vec<RegionData>>,
) -> Vec<Anomaly> {
    let mut anomalies = Vec::new();

    if events.len() < 2 {
        return anomalies;
    }

    let mut sorted = events.to_vec();
    sorted.sort_by_key(|e| e.timestamp_ns);

    for window in sorted.windows(2) {
        let prev = &window[0];
        let curr = &window[1];

        let delta_ns = curr.timestamp_ns.saturating_sub(prev.timestamp_ns);
        let delta_sec = delta_ns as f64 / 1e9;
        let delta_hours = delta_sec / 3600.0;

        if delta_hours > THRESHOLD_GAP_HOURS {
            anomalies.push(Anomaly {
                timestamp: Some(DateTime::from_timestamp_nanos(curr.timestamp_ns)),
                anomaly_type: AnomalyType::Gap,
                description: "Long editing gap detected".to_string(),
                severity: Severity::Info,
                context: Some(format!("Gap: {:.1} hours", delta_hours)),
            });
        }

        if delta_sec > 0.0 && delta_sec < VELOCITY_WINDOW_SEC {
            let bytes_delta = curr.size_delta.unsigned_abs() as f64;
            let bytes_per_sec = bytes_delta / delta_sec;
            if bytes_per_sec > THRESHOLD_HIGH_VELOCITY_BPS {
                anomalies.push(Anomaly {
                    timestamp: Some(DateTime::from_timestamp_nanos(curr.timestamp_ns)),
                    anomaly_type: AnomalyType::HighVelocity,
                    description: "High-velocity content addition detected".to_string(),
                    severity: Severity::Warning,
                    context: Some(format!("Velocity: {:.1} bytes/sec", bytes_per_sec)),
                });
            }
        }
    }

    anomalies
}

/
pub fn determine_assessment(
    metrics: &PrimaryMetrics,
    anomalies: &[Anomaly],
    event_count: usize,
) -> Assessment {
    if event_count < MIN_EVENTS_FOR_ASSESSMENT {
        return Assessment::Insufficient;
    }

    let (alert_count, warning_count) =
        anomalies
            .iter()
            .fold((0, 0), |(a, w), anom| match anom.severity {
                Severity::Alert => (a + 1, w),
                Severity::Warning => (a, w + 1),
                _ => (a, w),
            });

    let mut suspicious_indicators = 0;

    if metrics.monotonic_append_ratio > MONOTONIC_SUSPICIOUS {
        suspicious_indicators += 1;
    }

    if metrics.edit_entropy < THRESHOLD_LOW_ENTROPY && metrics.edit_entropy > 0.0 {
        suspicious_indicators += 1;
    }

    if metrics.positive_negative_ratio > POS_NEG_SUSPICIOUS {
        suspicious_indicators += 1;
    }

    if metrics.deletion_clustering > DELETION_CLUSTERING_LOW
        && metrics.deletion_clustering < DELETION_CLUSTERING_HIGH
    {
        suspicious_indicators += 1;
    }

    if alert_count >= ALERT_THRESHOLD || suspicious_indicators >= SUSPICIOUS_INDICATOR_CRITICAL {
        return Assessment::Suspicious;
    }

    if warning_count >= SUSPICIOUS_WARNING_COUNT
        || suspicious_indicators >= SUSPICIOUS_INDICATOR_COUNT
    {
        return Assessment::Suspicious;
    }

    Assessment::Consistent
}

/
pub fn compute_assessment_score(
    primary: &PrimaryMetrics,
    cadence: &CadenceMetrics,
    anomaly_count: usize,
    event_count: usize,
    biological_cadence_score: f64,
) -> f64 {
    if event_count < MIN_EVENTS_FOR_ANALYSIS {
        return INSUFFICIENT_DATA_SCORE;
    }

    
    let bio_score = if biological_cadence_score.is_finite() {
        biological_cadence_score
    } else {
        0.0
    };

    let mut score = 1.0;

    let mar = if primary.monotonic_append_ratio.is_finite() {
        primary.monotonic_append_ratio
    } else {
        0.0
    };
    if mar > MONOTONIC_PENALTY_START {
        score -= MONOTONIC_PENALTY_WEIGHT * (mar - MONOTONIC_PENALTY_START)
            / (1.0 - MONOTONIC_PENALTY_START);
    }

    let edit_entropy = if primary.edit_entropy.is_finite() {
        primary.edit_entropy
    } else {
        ENTROPY_NORMALIZATION
    };
    let normalized_entropy = (edit_entropy / ENTROPY_NORMALIZATION).min(1.0);
    if normalized_entropy < LOW_ENTROPY_SCORE_THRESHOLD {
        score -= LOW_ENTROPY_PENALTY;
    }

    if primary.positive_negative_ratio > POS_NEG_SUSPICIOUS {
        score -= POS_NEG_PENALTY;
    }

    if primary.deletion_clustering > DELETION_CLUSTERING_LOW
        && primary.deletion_clustering < DELETION_CLUSTERING_HIGH
    {
        score -= POS_NEG_PENALTY;
    }

    if cadence.is_robotic {
        score -= ROBOTIC_CADENCE_PENALTY;
    }

    let cov = if cadence.coefficient_of_variation.is_finite() {
        cadence.coefficient_of_variation
    } else {
        CV_ROBOTIC_THRESHOLD
    };
    if cov < CV_ROBOTIC_THRESHOLD {
        score -= COV_PENALTY_WEIGHT * (CV_ROBOTIC_THRESHOLD - cov) / CV_ROBOTIC_THRESHOLD;
    }

    score -= ANOMALY_PENALTY * anomaly_count as f64;

    if bio_score > BIOLOGICAL_CADENCE_THRESHOLD {
        score += BIOLOGICAL_CADENCE_REWARD * (bio_score - BIOLOGICAL_CADENCE_THRESHOLD)
            / BIOLOGICAL_CADENCE_THRESHOLD;
    }

    
    let iki_ac = if cadence.iki_autocorrelation.is_finite() {
        cadence.iki_autocorrelation
    } else {
        0.0
    };
    if iki_ac > IKI_AUTOCORR_TRANSCRIPTIVE {
        score -= IKI_AUTOCORR_PENALTY * (iki_ac - IKI_AUTOCORR_TRANSCRIPTIVE)
            / (1.0 - IKI_AUTOCORR_TRANSCRIPTIVE);
    }

    
    if cadence.correction_ratio < CORRECTION_RATIO_LOW && event_count >= CORRECTION_MIN_EVENTS {
        score -= LOW_CORRECTION_PENALTY;
    }

    
    if cadence.post_pause_cv > POST_PAUSE_CV_REWARD_THRESHOLD {
        score += POST_PAUSE_CV_REWARD;
    }

    
    if cadence.pause_depth_distribution[2] > DEEP_PAUSE_REWARD_THRESHOLD {
        score += DEEP_PAUSE_REWARD;
    }

    
    if cadence.cross_hand_timing_ratio > 0.0
        && cadence.cross_hand_timing_ratio < CROSS_HAND_UNIFORM_THRESHOLD
    {
        score -= CROSS_HAND_PENALTY;
    }

    
    if cadence.burst_speed_cv > 0.0 && cadence.burst_speed_cv < 0.15 && cadence.burst_count >= 3 {
        score -= 0.10;
    }

    
    if cadence.zero_variance_windows > 3 {
        score -= 0.15;
    } else if cadence.zero_variance_windows > 0 {
        score -= 0.05;
    }

    score.clamp(0.0, 1.0)
}

/
pub fn compute_cadence_score(cadence: &CadenceMetrics) -> f64 {
    let mut score = 1.0;

    if cadence.is_robotic {
        score -= CADENCE_ROBOTIC_PENALTY;
    }

    let cov = if cadence.coefficient_of_variation.is_finite() {
        cadence.coefficient_of_variation
    } else {
        CV_ROBOTIC_THRESHOLD
    };
    if cov < CV_ROBOTIC_THRESHOLD {
        let penalty = (CV_ROBOTIC_THRESHOLD - cov) / CV_ROBOTIC_THRESHOLD;
        score -= CADENCE_COV_PENALTY * penalty;
    }

    if cadence.percentiles[4] == 0.0 {
        return INSUFFICIENT_DATA_SCORE;
    }

    
    if cadence.burst_speed_cv > 0.0 && cadence.burst_speed_cv < 0.15 && cadence.burst_count >= 3 {
        score -= 0.10;
    }
    if cadence.zero_variance_windows > 3 {
        score -= 0.15;
    }

    score.clamp(0.0, 1.0)
}

/
/
/
pub fn apply_focus_penalties(score: &mut f64, focus: &FocusMetrics) {
    if focus.reading_pattern_detected {
        *score -= FOCUS_READING_PENALTY;
    }
    if focus.ai_app_switch_count > FOCUS_AI_SWITCH_THRESHOLD {
        *score -= FOCUS_AI_SWITCH_PENALTY;
    }
    if focus.out_of_focus_ratio > FOCUS_OUT_OF_FOCUS_THRESHOLD {
        *score -= FOCUS_OUT_OF_FOCUS_PENALTY;
    }
    *score = score.clamp(0.0, 1.0);
}

/
pub fn determine_risk_level(score: f64, event_count: usize) -> RiskLevel {
    if event_count < MIN_EVENTS_FOR_ANALYSIS {
        return RiskLevel::Insufficient;
    }

    if score >= RISK_LOW_THRESHOLD {
        RiskLevel::Low
    } else if score >= RISK_MEDIUM_THRESHOLD {
        RiskLevel::Medium
    } else {
        RiskLevel::High
    }
}
