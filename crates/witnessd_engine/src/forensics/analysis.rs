// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Main orchestration functions for forensic analysis.

use chrono::DateTime;
use std::collections::HashMap;

use crate::analysis::BehavioralFingerprint;
use crate::jitter::SimpleJitterSample;

use super::assessment::{
    calculate_assessment_score, detect_anomalies, determine_assessment, determine_risk_level,
};
use super::cadence::analyze_cadence;
use super::topology::compute_primary_metrics;
use super::types::{
    Assessment, AuthorshipProfile, EventData, ForensicMetrics, RegionData, DEFAULT_SESSION_GAP_SEC,
    MIN_EVENTS_FOR_ANALYSIS,
};
use super::velocity::{compute_session_stats, detect_sessions};

/// Builds a complete authorship profile from events and regions.
pub fn build_profile(
    events: &[EventData],
    regions_by_event: &HashMap<i64, Vec<RegionData>>,
) -> AuthorshipProfile {
    if events.len() < MIN_EVENTS_FOR_ANALYSIS {
        return AuthorshipProfile {
            event_count: events.len(),
            assessment: Assessment::Insufficient,
            ..Default::default()
        };
    }

    let mut sorted = events.to_vec();
    sorted.sort_by_key(|e| e.timestamp_ns);

    let file_path = sorted
        .first()
        .map(|e| e.file_path.clone())
        .unwrap_or_default();
    let first_ts =
        DateTime::from_timestamp_nanos(sorted.first().map(|e| e.timestamp_ns).unwrap_or(0));
    let last_ts =
        DateTime::from_timestamp_nanos(sorted.last().map(|e| e.timestamp_ns).unwrap_or(0));
    let time_span = last_ts.signed_duration_since(first_ts);

    let sessions = detect_sessions(&sorted, DEFAULT_SESSION_GAP_SEC);

    let metrics = match compute_primary_metrics(&sorted, regions_by_event) {
        Ok(m) => m,
        Err(_) => {
            return AuthorshipProfile {
                file_path,
                event_count: events.len(),
                time_span,
                session_count: sessions.len(),
                first_event: first_ts,
                last_event: last_ts,
                assessment: Assessment::Insufficient,
                ..Default::default()
            };
        }
    };

    let anomalies = detect_anomalies(&sorted, regions_by_event, &metrics);
    let assessment = determine_assessment(&metrics, &anomalies, events.len());

    AuthorshipProfile {
        file_path,
        event_count: events.len(),
        time_span,
        session_count: sessions.len(),
        first_event: first_ts,
        last_event: last_ts,
        metrics,
        anomalies,
        assessment,
    }
}

/// Performs comprehensive forensic analysis.
pub fn analyze_forensics(
    events: &[EventData],
    regions: &HashMap<i64, Vec<RegionData>>,
    jitter_samples: Option<&[SimpleJitterSample]>,
    perplexity_model: Option<&crate::analysis::perplexity::PerplexityModel>,
    document_text: Option<&str>,
) -> ForensicMetrics {
    let mut metrics = ForensicMetrics::default();

    // Perplexity analysis
    if let (Some(model), Some(text)) = (perplexity_model, document_text) {
        metrics.perplexity_score = model.calculate_perplexity(text);
        if metrics.perplexity_score > 15.0 {
            // Heuristic threshold for "too surprising"
            metrics.anomaly_count += 1;
        }
    } else {
        metrics.perplexity_score = 1.0;
    }

    // Primary metrics
    if let Ok(primary) = compute_primary_metrics(events, regions) {
        metrics.primary = primary;
    }

    // Cadence and Behavioral metrics
    if let Some(samples) = jitter_samples {
        metrics.cadence = analyze_cadence(samples);

        // Compute behavioral fingerprint (the "How")
        let fingerprint = BehavioralFingerprint::from_samples(samples);
        metrics.behavioral = Some(fingerprint);

        // Run forgery detection
        let forgery = BehavioralFingerprint::detect_forgery(samples);
        metrics.forgery_analysis = Some(forgery.clone());

        // Compute Steganographic Confidence (the "What")
        // In a full implementation, this would verify the HMAC-jitter values.
        // For now, we correlate stability with steganographic presence.
        metrics.steg_confidence = if metrics.cadence.coefficient_of_variation > 0.3 {
            0.95 // High entropy suggests authentic human jitter
        } else {
            0.20 // Too stable suggests either replaying or missing steganography
        };

        // Fusion: If steg is "perfect" but behavioral is "suspicious", penalize score heavily.
        if forgery.is_suspicious && metrics.steg_confidence > 0.8 {
            // "Perfect Replay" detection
            metrics.anomaly_count += 1;
        }
    }

    // Velocity metrics
    metrics.velocity = super::velocity::analyze_velocity(events);

    // Session stats
    metrics.session_stats = compute_session_stats(events);

    // Anomaly count
    let anomalies = detect_anomalies(events, regions, &metrics.primary);
    metrics.anomaly_count += anomalies.len();

    // Assessment score
    metrics.assessment_score = calculate_assessment_score(
        &metrics.primary,
        &metrics.cadence,
        metrics.anomaly_count,
        events.len(),
    );

    // Risk level
    metrics.risk_level = determine_risk_level(metrics.assessment_score, events.len());

    metrics
}
