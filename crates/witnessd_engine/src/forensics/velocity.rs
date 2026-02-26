// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Velocity analysis and session detection.

use super::types::{
    EventData, SessionStats, VelocityMetrics, DEFAULT_SESSION_GAP_SEC, THRESHOLD_HIGH_VELOCITY_BPS,
};

/// Analyzes edit velocity patterns.
pub fn analyze_velocity(events: &[EventData]) -> VelocityMetrics {
    let mut metrics = VelocityMetrics::default();

    if events.len() < 2 {
        return metrics;
    }

    let mut sorted = events.to_vec();
    sorted.sort_by_key(|e| e.timestamp_ns);

    let mut velocities = Vec::new();
    let mut high_velocity_bursts = 0;
    let mut autocomplete_chars: i64 = 0;

    for window in sorted.windows(2) {
        let delta_ns = window[1].timestamp_ns - window[0].timestamp_ns;
        let delta_sec = delta_ns as f64 / 1e9;

        if delta_sec > 0.0 && delta_sec < 60.0 {
            let bytes_delta = window[1].size_delta.abs() as f64;
            let bps = bytes_delta / delta_sec;
            velocities.push(bps);

            if bps > THRESHOLD_HIGH_VELOCITY_BPS {
                high_velocity_bursts += 1;

                // Estimate autocomplete chars: excess over human typing speed (~50 chars/sec)
                let human_max_bps = 50.0;
                if bps > human_max_bps {
                    let excess = (bps - human_max_bps) * delta_sec;
                    autocomplete_chars += excess as i64;
                }
            }
        }
    }

    if !velocities.is_empty() {
        metrics.mean_bps = velocities.iter().sum::<f64>() / velocities.len() as f64;
        metrics.max_bps = velocities.iter().cloned().fold(0.0, f64::max);
    }

    metrics.high_velocity_bursts = high_velocity_bursts;
    metrics.autocomplete_chars = autocomplete_chars;

    metrics
}

/// Detects editing sessions based on gap threshold.
pub fn detect_sessions(events: &[EventData], gap_threshold_sec: f64) -> Vec<Vec<EventData>> {
    if events.is_empty() {
        return Vec::new();
    }

    let mut sorted = events.to_vec();
    sorted.sort_by_key(|e| e.timestamp_ns);

    let mut sessions = Vec::new();
    let mut current_session = vec![sorted[0].clone()];

    for window in sorted.windows(2) {
        let delta_ns = window[1].timestamp_ns - window[0].timestamp_ns;
        let delta_sec = delta_ns as f64 / 1e9;

        if delta_sec > gap_threshold_sec {
            sessions.push(std::mem::take(&mut current_session));
            current_session = vec![window[1].clone()];
        } else {
            current_session.push(window[1].clone());
        }
    }

    if !current_session.is_empty() {
        sessions.push(current_session);
    }

    sessions
}

/// Computes session statistics.
pub fn compute_session_stats(events: &[EventData]) -> SessionStats {
    let mut stats = SessionStats::default();

    if events.is_empty() {
        return stats;
    }

    let sessions = detect_sessions(events, DEFAULT_SESSION_GAP_SEC);
    stats.session_count = sessions.len();

    let mut total_duration = 0.0;
    for session in &sessions {
        if session.len() >= 2 {
            let first = session.iter().map(|e| e.timestamp_ns).min().unwrap_or(0);
            let last = session.iter().map(|e| e.timestamp_ns).max().unwrap_or(0);
            total_duration += (last - first) as f64 / 1e9;
        }
    }

    stats.total_editing_time_sec = total_duration;
    if stats.session_count > 0 {
        stats.avg_session_duration_sec = total_duration / stats.session_count as f64;
    }

    // Time span
    let first = events.iter().map(|e| e.timestamp_ns).min().unwrap_or(0);
    let last = events.iter().map(|e| e.timestamp_ns).max().unwrap_or(0);
    stats.time_span_sec = (last - first) as f64 / 1e9;

    stats
}
