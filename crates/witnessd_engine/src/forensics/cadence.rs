// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Keystroke cadence analysis.

use statrs::statistics::{Data, OrderStatistics};

use crate::jitter::SimpleJitterSample;

use super::topology::compute_median;
use super::types::{CadenceMetrics, ROBOTIC_CV_THRESHOLD};

/// Analyzes keystroke cadence from jitter samples.
pub fn analyze_cadence(samples: &[SimpleJitterSample]) -> CadenceMetrics {
    let mut metrics = CadenceMetrics::default();

    if samples.len() < 2 {
        return metrics;
    }

    // Calculate inter-keystroke intervals
    let ikis: Vec<f64> = samples
        .windows(2)
        .map(|w| (w[1].timestamp_ns - w[0].timestamp_ns) as f64)
        .collect();

    if ikis.is_empty() {
        return metrics;
    }

    // Basic statistics
    let sum: f64 = ikis.iter().sum();
    metrics.mean_iki_ns = sum / ikis.len() as f64;

    let variance: f64 = ikis
        .iter()
        .map(|x| (x - metrics.mean_iki_ns).powi(2))
        .sum::<f64>()
        / ikis.len() as f64;
    metrics.std_dev_iki_ns = variance.sqrt();

    // Coefficient of variation
    if metrics.mean_iki_ns > 0.0 {
        metrics.coefficient_of_variation = metrics.std_dev_iki_ns / metrics.mean_iki_ns;
    }

    // Median
    metrics.median_iki_ns = compute_median(&ikis);

    // Percentiles using statrs
    let mut data = Data::new(ikis.clone());
    metrics.percentiles = [
        data.percentile(10),
        data.percentile(25),
        data.percentile(50),
        data.percentile(75),
        data.percentile(90),
    ];

    // Detect robotic patterns
    metrics.is_robotic = metrics.coefficient_of_variation < ROBOTIC_CV_THRESHOLD;

    // Burst and pause detection
    let (bursts, pauses) = detect_bursts_and_pauses(&ikis);
    metrics.burst_count = bursts.len();
    metrics.pause_count = pauses.len();

    if !bursts.is_empty() {
        metrics.avg_burst_length =
            bursts.iter().map(|b| b.length as f64).sum::<f64>() / bursts.len() as f64;
    }

    if !pauses.is_empty() {
        metrics.avg_pause_duration_ns = pauses.iter().sum::<f64>() / pauses.len() as f64;
    }

    metrics
}

/// Detected typing burst.
#[derive(Debug, Clone)]
pub struct TypingBurst {
    pub start_idx: usize,
    pub length: usize,
    pub avg_iki_ns: f64,
}

/// Detects typing bursts and pauses in IKI sequence.
///
/// A burst is a sequence of fast keystrokes (< 200ms between each).
/// A pause is an interval > 2 seconds.
fn detect_bursts_and_pauses(ikis: &[f64]) -> (Vec<TypingBurst>, Vec<f64>) {
    const BURST_THRESHOLD_NS: f64 = 200_000_000.0; // 200ms
    const PAUSE_THRESHOLD_NS: f64 = 2_000_000_000.0; // 2 seconds

    let mut bursts = Vec::new();
    let mut pauses = Vec::new();

    let mut burst_start: Option<usize> = None;
    let mut burst_sum = 0.0;

    for (i, &iki) in ikis.iter().enumerate() {
        if iki < BURST_THRESHOLD_NS {
            if burst_start.is_none() {
                burst_start = Some(i);
                burst_sum = 0.0;
            }
            burst_sum += iki;
        } else {
            // End current burst if any
            if let Some(start) = burst_start {
                let length = i - start;
                if length >= 3 {
                    // Minimum burst length
                    bursts.push(TypingBurst {
                        start_idx: start,
                        length,
                        avg_iki_ns: burst_sum / length as f64,
                    });
                }
                burst_start = None;
            }

            // Check for pause
            if iki > PAUSE_THRESHOLD_NS {
                pauses.push(iki);
            }
        }
    }

    // Close final burst if any
    if let Some(start) = burst_start {
        let length = ikis.len() - start;
        if length >= 3 {
            bursts.push(TypingBurst {
                start_idx: start,
                length,
                avg_iki_ns: burst_sum / length as f64,
            });
        }
    }

    (bursts, pauses)
}

/// Evaluates whether keystrokes suggest retyped/transcribed content.
///
/// Returns true if the cadence pattern is too rhythmic to be original composition.
pub fn is_retyped_content(samples: &[SimpleJitterSample]) -> bool {
    if samples.len() < 20 {
        return false;
    }

    let ikis: Vec<f64> = samples
        .windows(2)
        .map(|w| (w[1].timestamp_ns - w[0].timestamp_ns) as f64)
        .collect();

    let mean = ikis.iter().sum::<f64>() / ikis.len() as f64;
    let variance = ikis.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / ikis.len() as f64;
    let std_dev = variance.sqrt();

    if mean <= 0.0 {
        return false;
    }

    let cv = std_dev / mean;
    cv < ROBOTIC_CV_THRESHOLD
}
