// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! ForensicEngine for physical context analysis.

use statrs::distribution::{ContinuousCDF, Normal};

use crate::jitter::SimpleJitterSample;
use crate::PhysicalContext;

use super::cadence::is_retyped_content;

/// Result of a forensic physical analysis.
#[derive(Debug, Clone)]
pub struct ForensicReport {
    /// Confidence score (0.0 to 1.0).
    pub confidence_score: f64,
    /// Whether this is an anomaly.
    pub is_anomaly: bool,
    /// Whether retyped content was detected via robotic IKI cadence.
    pub is_retyped_content: bool,
    /// Detailed signal analyses.
    pub details: Vec<SignalAnalysis>,
}

/// Individual signal analysis result.
#[derive(Debug, Clone)]
pub struct SignalAnalysis {
    pub name: String,
    pub z_score: f64,
    pub probability: f64,
}

/// Forensic engine for physical context analysis.
pub struct ForensicEngine;

impl ForensicEngine {
    /// Evaluates authorship metrics including cognitive cadence.
    ///
    /// Human original composition has "Cognitive Bursts":
    /// Fast typing for familiar words, then long pauses for thought.
    /// Retyping AI content has high stability (consistent rhythm).
    pub fn evaluate_cadence(samples: &[SimpleJitterSample]) -> bool {
        is_retyped_content(samples)
    }

    /// Performs a full forensic authorship analysis on a sequence of events.
    pub fn evaluate_authorship(
        _file_path: &str,
        events: &[crate::store::SecureEvent],
    ) -> super::types::AuthorshipProfile {
        let event_data: Vec<super::types::EventData> = events
            .iter()
            .map(|e| super::types::EventData {
                id: e.id.unwrap_or(0),
                timestamp_ns: e.timestamp_ns,
                file_size: e.file_size,
                size_delta: e.size_delta,
                file_path: e.file_path.clone(),
            })
            .collect();

        // Note: Real RegionData would require file diffing.
        // For now, we use a heuristic based on size_delta.
        let mut regions = std::collections::HashMap::new();
        for e in events {
            if let Some(id) = e.id {
                let delta = e.size_delta;
                let sign = if delta > 0 {
                    1
                } else if delta < 0 {
                    -1
                } else {
                    0
                };
                regions.insert(
                    id,
                    vec![super::types::RegionData {
                        start_pct: 1.0, // Assume appends for simplicity in this fallback
                        end_pct: 1.0,
                        delta_sign: sign,
                        byte_count: delta.abs(),
                    }],
                );
            }
        }

        super::analysis::build_profile(&event_data, &regions)
    }

    /// Evaluates a PhysicalContext against known baselines.
    pub fn evaluate(
        ctx: &PhysicalContext,
        baselines: &[(String, f64, f64)], // (name, mean, std_dev)
    ) -> ForensicReport {
        let mut analyses = Vec::new();
        let mut total_prob = 0.0;
        let mut count = 0;

        for (name, mean, std_dev) in baselines {
            let val = match name.as_str() {
                "clock_skew" => ctx.clock_skew as f64,
                "thermal_proxy" => ctx.thermal_proxy as f64,
                "io_latency" => ctx.io_latency_ns as f64,
                _ => continue,
            };

            // Calculate Z-score
            let z_score = if *std_dev > 0.0 {
                (val - *mean).abs() / *std_dev
            } else {
                0.0
            };

            // Calculate probability using Gaussian CDF
            let prob = if *std_dev > 0.0 {
                if let Ok(n) = Normal::new(*mean, *std_dev) {
                    2.0 * (1.0 - n.cdf(mean + (val - mean).abs()))
                } else {
                    1.0
                }
            } else {
                1.0
            };

            analyses.push(SignalAnalysis {
                name: name.clone(),
                z_score,
                probability: prob,
            });

            total_prob += prob;
            count += 1;
        }

        let confidence = if count > 0 {
            total_prob / count as f64
        } else {
            1.0
        };

        ForensicReport {
            confidence_score: confidence,
            is_anomaly: confidence < 0.01,
            is_retyped_content: false,
            details: analyses,
        }
    }
}
