// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Edit topology analysis functions.

use std::collections::HashMap;

use super::error::ForensicsError;
use super::types::{
    EventData, PrimaryMetrics, RegionData, DEFAULT_APPEND_THRESHOLD, DEFAULT_HISTOGRAM_BINS,
    MIN_EVENTS_FOR_ANALYSIS,
};

/// Computes all primary metrics from events and regions.
pub fn compute_primary_metrics(
    events: &[EventData],
    regions: &HashMap<i64, Vec<RegionData>>,
) -> Result<PrimaryMetrics, ForensicsError> {
    if events.len() < MIN_EVENTS_FOR_ANALYSIS {
        return Err(ForensicsError::InsufficientData);
    }

    let all_regions = flatten_regions(regions);
    if all_regions.is_empty() {
        return Err(ForensicsError::InsufficientData);
    }

    Ok(PrimaryMetrics {
        monotonic_append_ratio: monotonic_append_ratio(&all_regions, DEFAULT_APPEND_THRESHOLD),
        edit_entropy: edit_entropy(&all_regions, DEFAULT_HISTOGRAM_BINS),
        median_interval: median_interval(events),
        positive_negative_ratio: positive_negative_ratio(&all_regions),
        deletion_clustering: deletion_clustering_coef(&all_regions),
    })
}

/// Calculates the fraction of edits at document end.
///
/// Formula: |{r : r.start_pct >= threshold}| / |R|
pub fn monotonic_append_ratio(regions: &[RegionData], threshold: f32) -> f64 {
    if regions.is_empty() {
        return 0.0;
    }

    let append_count = regions.iter().filter(|r| r.start_pct >= threshold).count();
    append_count as f64 / regions.len() as f64
}

/// Calculates Shannon entropy of edit position histogram.
///
/// Formula: H = -sum (c_j/n) * log2(c_j/n) for non-zero bins
pub fn edit_entropy(regions: &[RegionData], bins: usize) -> f64 {
    if regions.is_empty() || bins == 0 {
        return 0.0;
    }

    // Build histogram of edit positions
    let mut histogram = vec![0usize; bins];
    for r in regions {
        let mut pos = r.start_pct;
        if pos < 0.0 {
            pos = 0.0;
        }
        if pos >= 1.0 {
            pos = 0.9999;
        }
        let bin_idx = (pos * bins as f32) as usize;
        let bin_idx = bin_idx.min(bins - 1);
        histogram[bin_idx] += 1;
    }

    shannon_entropy(&histogram)
}

/// Calculates Shannon entropy from a histogram.
fn shannon_entropy(histogram: &[usize]) -> f64 {
    let n: usize = histogram.iter().sum();
    if n == 0 {
        return 0.0;
    }

    let n_float = n as f64;
    let mut entropy = 0.0;
    for &count in histogram {
        if count > 0 {
            let p = count as f64 / n_float;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Calculates the median inter-event interval in seconds.
pub fn median_interval(events: &[EventData]) -> f64 {
    if events.len() < 2 {
        return 0.0;
    }

    // Sort events by timestamp
    let mut sorted: Vec<_> = events.to_vec();
    sorted.sort_by_key(|e| e.timestamp_ns);

    // Calculate intervals
    let intervals: Vec<f64> = sorted
        .windows(2)
        .map(|w| (w[1].timestamp_ns - w[0].timestamp_ns) as f64 / 1e9)
        .collect();

    compute_median(&intervals)
}

/// Computes the median of a slice of values.
pub(crate) fn compute_median(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    let mut buf = values.to_vec();
    let n = buf.len();
    let cmp = |a: &f64, b: &f64| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal);
    if n % 2 == 0 {
        buf.select_nth_unstable_by(n / 2, cmp);
        let upper = buf[n / 2];
        buf.select_nth_unstable_by(n / 2 - 1, cmp);
        (buf[n / 2 - 1] + upper) / 2.0
    } else {
        buf.select_nth_unstable_by(n / 2, cmp);
        buf[n / 2]
    }
}

/// Calculates insertions / (insertions + deletions).
///
/// Formula: |{r : r.delta_sign > 0}| / |{r : r.delta_sign != 0}|
pub fn positive_negative_ratio(regions: &[RegionData]) -> f64 {
    let mut insertions = 0;
    let mut total = 0;

    for r in regions {
        if r.delta_sign > 0 {
            insertions += 1;
            total += 1;
        } else if r.delta_sign < 0 {
            total += 1;
        }
        // delta_sign == 0 are replacements without size change, excluded
    }

    if total == 0 {
        return 0.5; // Neutral when no insertions or deletions
    }

    insertions as f64 / total as f64
}

/// Calculates the nearest-neighbor ratio for deletions.
///
/// Clustered deletions (revision pass) produce < 1.
/// Scattered deletions (fake) produce ~ 1.
/// No deletions produces 0.
pub fn deletion_clustering_coef(regions: &[RegionData]) -> f64 {
    // Extract deletion positions
    let mut deletion_positions: Vec<f64> = regions
        .iter()
        .filter(|r| r.delta_sign < 0)
        .map(|r| r.start_pct as f64)
        .collect();

    let n = deletion_positions.len();
    if n < 2 {
        return 0.0;
    }

    // Sort positions
    deletion_positions.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    // Calculate nearest-neighbor distances
    let mut total_dist = 0.0;
    for i in 0..n {
        let mut min_dist = f64::MAX;

        // Check left neighbor
        if i > 0 {
            let dist = deletion_positions[i] - deletion_positions[i - 1];
            if dist < min_dist {
                min_dist = dist;
            }
        }

        // Check right neighbor
        if i < n - 1 {
            let dist = deletion_positions[i + 1] - deletion_positions[i];
            if dist < min_dist {
                min_dist = dist;
            }
        }

        total_dist += min_dist;
    }

    let mean_dist = total_dist / n as f64;

    // Expected uniform distance for n points in [0,1]
    let expected_uniform_dist = 1.0 / (n + 1) as f64;

    if expected_uniform_dist == 0.0 {
        return 0.0;
    }

    mean_dist / expected_uniform_dist
}

/// Flattens regions from a map into a single slice.
fn flatten_regions(regions: &HashMap<i64, Vec<RegionData>>) -> Vec<RegionData> {
    regions.values().flat_map(|rs| rs.iter().cloned()).collect()
}
