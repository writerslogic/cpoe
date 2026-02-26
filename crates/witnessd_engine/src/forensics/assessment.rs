// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Anomaly detection and assessment.

use chrono::DateTime;
use std::collections::HashMap;

use super::types::{
    Anomaly, AnomalyType, Assessment, CadenceMetrics, EventData, PrimaryMetrics, RegionData,
    RiskLevel, Severity, ALERT_THRESHOLD, MIN_EVENTS_FOR_ANALYSIS, MIN_EVENTS_FOR_ASSESSMENT,
    THRESHOLD_GAP_HOURS, THRESHOLD_HIGH_VELOCITY_BPS, THRESHOLD_LOW_ENTROPY,
    THRESHOLD_MONOTONIC_APPEND,
};

/// Detects anomalies in editing patterns.
pub fn detect_anomalies(
    events: &[EventData],
    regions: &HashMap<i64, Vec<RegionData>>,
    metrics: &PrimaryMetrics,
) -> Vec<Anomaly> {
    let mut anomalies = Vec::new();

    // Check for high monotonic append ratio
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

    // Check for low edit entropy
    if metrics.edit_entropy < THRESHOLD_LOW_ENTROPY && metrics.edit_entropy > 0.0 {
        anomalies.push(Anomaly {
            timestamp: None,
            anomaly_type: AnomalyType::LowEntropy,
            description: "Low edit entropy indicates concentrated editing patterns".to_string(),
            severity: Severity::Warning,
            context: Some(format!("Entropy: {:.3}", metrics.edit_entropy)),
        });
    }

    // Check for scattered deletions
    if metrics.deletion_clustering > 0.9 && metrics.deletion_clustering < 1.1 {
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

    // Detect temporal anomalies
    anomalies.extend(detect_temporal_anomalies(events, regions));

    anomalies
}

/// Detects gaps and high-velocity editing periods.
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

        let delta_ns = curr.timestamp_ns - prev.timestamp_ns;
        let delta_sec = delta_ns as f64 / 1e9;
        let delta_hours = delta_sec / 3600.0;

        // Check for long gaps
        if delta_hours > THRESHOLD_GAP_HOURS {
            anomalies.push(Anomaly {
                timestamp: Some(DateTime::from_timestamp_nanos(curr.timestamp_ns)),
                anomaly_type: AnomalyType::Gap,
                description: "Long editing gap detected".to_string(),
                severity: Severity::Info,
                context: Some(format!("Gap: {:.1} hours", delta_hours)),
            });
        }

        // Check for high-velocity editing
        if delta_sec > 0.0 && delta_sec < 60.0 {
            let bytes_delta = curr.size_delta.abs();
            let bytes_per_sec = bytes_delta as f64 / delta_sec;
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

/// Determines overall assessment verdict.
pub fn determine_assessment(
    metrics: &PrimaryMetrics,
    anomalies: &[Anomaly],
    event_count: usize,
) -> Assessment {
    if event_count < MIN_EVENTS_FOR_ASSESSMENT {
        return Assessment::Insufficient;
    }

    // Count alerts
    let alert_count = anomalies
        .iter()
        .filter(|a| a.severity == Severity::Alert)
        .count();
    let warning_count = anomalies
        .iter()
        .filter(|a| a.severity == Severity::Warning)
        .count();

    // Count suspicious indicators
    let mut suspicious_indicators = 0;

    // Very high monotonic append ratio
    if metrics.monotonic_append_ratio > 0.90 {
        suspicious_indicators += 1;
    }

    // Very low entropy
    if metrics.edit_entropy < 1.0 && metrics.edit_entropy > 0.0 {
        suspicious_indicators += 1;
    }

    // Extreme positive/negative ratio (almost all insertions)
    if metrics.positive_negative_ratio > 0.95 {
        suspicious_indicators += 1;
    }

    // No clustering in deletions
    if metrics.deletion_clustering > 0.9 && metrics.deletion_clustering < 1.1 {
        suspicious_indicators += 1;
    }

    // Determine verdict
    if alert_count >= ALERT_THRESHOLD || suspicious_indicators >= 3 {
        return Assessment::Suspicious;
    }

    if warning_count >= 3 || suspicious_indicators >= 2 {
        return Assessment::Suspicious;
    }

    Assessment::Consistent
}

/// Calculates an overall assessment score (0.0 - 1.0, higher = more human-like).
pub fn calculate_assessment_score(
    primary: &PrimaryMetrics,
    cadence: &CadenceMetrics,
    anomaly_count: usize,
    event_count: usize,
) -> f64 {
    if event_count < MIN_EVENTS_FOR_ANALYSIS {
        return 0.5; // Neutral for insufficient data
    }

    let mut score = 1.0;

    // Penalize high monotonic append ratio
    if primary.monotonic_append_ratio > 0.85 {
        score -= 0.2 * (primary.monotonic_append_ratio - 0.85) / 0.15;
    }

    // Penalize low entropy (max entropy for 20 bins is log2(20) ~ 4.32)
    let normalized_entropy = primary.edit_entropy / 4.32;
    if normalized_entropy < 0.35 {
        score -= 0.15;
    }

    // Penalize extreme positive/negative ratio
    if primary.positive_negative_ratio > 0.95 {
        score -= 0.1;
    }

    // Penalize scattered deletions
    if primary.deletion_clustering > 0.9 && primary.deletion_clustering < 1.1 {
        score -= 0.1;
    }

    // Penalize robotic cadence (Behavioral check)
    if cadence.is_robotic {
        score -= 0.35; // Increased penalty
    }

    // Penalize low coefficient of variation (too consistent)
    if cadence.coefficient_of_variation < 0.2 {
        score -= 0.15 * (0.2 - cadence.coefficient_of_variation) / 0.2;
    }

    // Penalize anomalies
    score -= 0.05 * anomaly_count as f64;

    score.clamp(0.0, 1.0)
}

/// Calculates a quick forensic score based solely on keystroke cadence.
/// Useful for real-time event scoring before full topology analysis is available.
pub fn calculate_cadence_score(cadence: &CadenceMetrics) -> f64 {
    let mut score = 1.0;

    // Penalize robotic cadence (most significant indicator)
    if cadence.is_robotic {
        score -= 0.5;
    }

    // Penalize low coefficient of variation (unnatural consistency)
    if cadence.coefficient_of_variation < 0.2 {
        let penalty = (0.2 - cadence.coefficient_of_variation) / 0.2;
        score -= 0.2 * penalty;
    }

    // Insufficient data penalty
    if cadence.percentiles[4] == 0.0 {
        // No samples or very few
        return 0.5;
    }

    score.clamp(0.0, 1.0)
}

/// Determines risk level from assessment score.
pub fn determine_risk_level(score: f64, event_count: usize) -> RiskLevel {
    if event_count < MIN_EVENTS_FOR_ANALYSIS {
        return RiskLevel::Insufficient;
    }

    if score >= 0.7 {
        RiskLevel::Low
    } else if score >= 0.4 {
        RiskLevel::Medium
    } else {
        RiskLevel::High
    }
}
