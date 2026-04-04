

//! Profile comparison and similarity analysis.

use serde::{Deserialize, Serialize};

use super::types::AuthorshipProfile;

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileComparison {
    /
    pub similarity_score: f64,
    /
    pub is_consistent: bool,
    /
    pub dimension_scores: DimensionScores,
    /
    pub explanation: String,
}

/
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DimensionScores {
    pub monotonic_append_similarity: f64,
    pub entropy_similarity: f64,
    pub interval_similarity: f64,
    pub pos_neg_ratio_similarity: f64,
    pub deletion_clustering_similarity: f64,
}

/
pub fn compare_profiles(
    profile_a: &AuthorshipProfile,
    profile_b: &AuthorshipProfile,
) -> ProfileComparison {
    let scores = DimensionScores {
        monotonic_append_similarity: gaussian_similarity(
            profile_a.metrics.monotonic_append_ratio,
            profile_b.metrics.monotonic_append_ratio,
            0.15,
        ),
        entropy_similarity: gaussian_similarity(
            profile_a.metrics.edit_entropy,
            profile_b.metrics.edit_entropy,
            0.5,
        ),
        
        interval_similarity: gaussian_similarity(
            safe_ln(profile_a.metrics.median_interval),
            safe_ln(profile_b.metrics.median_interval),
            0.5,
        ),
        pos_neg_ratio_similarity: gaussian_similarity(
            profile_a.metrics.positive_negative_ratio,
            profile_b.metrics.positive_negative_ratio,
            0.1,
        ),
        deletion_clustering_similarity: gaussian_similarity(
            profile_a.metrics.deletion_clustering,
            profile_b.metrics.deletion_clustering,
            0.2,
        ),
    };

    let similarity_score = 0.25 * scores.monotonic_append_similarity
        + 0.20 * scores.entropy_similarity
        + 0.15 * scores.interval_similarity
        + 0.20 * scores.pos_neg_ratio_similarity
        + 0.20 * scores.deletion_clustering_similarity;

    let is_consistent = similarity_score >= 0.6;

    let explanation = if is_consistent {
        format!(
            "Profiles are consistent with same author (similarity: {:.1}%)",
            similarity_score * 100.0
        )
    } else {
        format!(
            "Profiles show significant differences (similarity: {:.1}%)",
            similarity_score * 100.0
        )
    };

    ProfileComparison {
        similarity_score,
        is_consistent,
        dimension_scores: scores,
        explanation,
    }
}

/
fn gaussian_similarity(a: f64, b: f64, sigma: f64) -> f64 {
    let diff = a - b;
    (-diff * diff / (2.0 * sigma * sigma)).exp()
}

/
fn safe_ln(v: f64) -> f64 {
    if v > 0.0 {
        v.ln().max(0.0)
    } else {
        0.0
    }
}
