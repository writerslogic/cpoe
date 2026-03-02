// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Quantified trust policies per the witnessd RFC.
//!
//! Relying Parties configure an [`AppraisalPolicy`] with weighted
//! [`TrustFactor`]s and [`TrustThreshold`]s. Supported computation models:
//!
//! - **Weighted average** -- `sum(factor * weight)`, normalized
//! - **Minimum of factors** -- score limited by weakest factor
//! - **Geometric mean** -- balanced penalty for outliers

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustComputation {
    WeightedAverage,
    MinimumOfFactors,
    GeometricMean,
    /// Delegated to external implementation identified by `policy_uri`
    CustomFormula,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactorType {
    // Chain-verifiable (1-9)
    VdfDuration,
    CheckpointCount,
    JitterEntropy,
    ChainIntegrity,
    RevisionDepth,

    // Presence (10-19)
    PresenceRate,
    PresenceResponseTime,

    // Hardware (20-29)
    HardwareAttestation,
    CalibrationAttestation,

    // Behavioral (30-39)
    EditEntropy,
    MonotonicRatio,
    TypingRateConsistency,

    // External (40-49)
    AnchorConfirmation,
    AnchorCount,

    // Collaboration (50-59)
    CollaboratorAttestations,
    ContributionConsistency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdType {
    /// Overall score >= value
    MinimumScore,
    /// Named factor >= value
    MinimumFactor,
    /// Named factor must be present (score > 0)
    RequiredFactor,
    /// Caveat count <= value
    MaximumCaveats,
}

/// Supporting evidence for a single factor score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactorEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_value: Option<f32>,

    /// Normalization reference
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_value: Option<f32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computation_notes: Option<String>,

    /// (start, end) checkpoint indices this factor covers
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_range: Option<(u32, u32)>,
}

/// Single scored factor in a trust computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustFactor {
    pub factor_name: String,
    pub factor_type: FactorType,
    /// 0.0..1.0
    pub weight: f32,
    pub observed_value: f32,
    /// 0.0..1.0
    pub normalized_score: f32,
    /// `weight * normalized_score`
    pub contribution: f32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<FactorEvidence>,
}

/// Pass/fail threshold requirement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustThreshold {
    pub threshold_name: String,
    pub threshold_type: ThresholdType,
    pub required_value: f32,
    pub met: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_authority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_effective_date: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applicable_domains: Vec<String>,
}

/// Complete appraisal policy: factors, thresholds, and computation model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppraisalPolicy {
    pub policy_uri: String,
    pub policy_version: String,
    pub computation_model: TrustComputation,
    pub factors: Vec<TrustFactor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub thresholds: Vec<TrustThreshold>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<PolicyMetadata>,
}

impl AppraisalPolicy {
    pub fn new(uri: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            policy_uri: uri.into(),
            policy_version: version.into(),
            computation_model: TrustComputation::WeightedAverage,
            factors: Vec::new(),
            thresholds: Vec::new(),
            metadata: None,
        }
    }

    pub fn with_computation(mut self, model: TrustComputation) -> Self {
        self.computation_model = model;
        self
    }

    pub fn add_factor(mut self, factor: TrustFactor) -> Self {
        self.factors.push(factor);
        self
    }

    pub fn add_threshold(mut self, threshold: TrustThreshold) -> Self {
        self.thresholds.push(threshold);
        self
    }

    pub fn with_metadata(mut self, metadata: PolicyMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Compute the aggregate trust score from all factors.
    pub fn compute_score(&self) -> f32 {
        if self.factors.is_empty() {
            return 0.0;
        }

        match self.computation_model {
            TrustComputation::WeightedAverage => {
                let total_weight: f32 = self.factors.iter().map(|f| f.weight).sum();
                if total_weight == 0.0 {
                    return 0.0;
                }
                let weighted_sum: f32 = self.factors.iter().map(|f| f.contribution).sum();
                weighted_sum / total_weight
            }
            TrustComputation::MinimumOfFactors => self
                .factors
                .iter()
                .map(|f| f.normalized_score)
                .fold(f32::INFINITY, f32::min),
            TrustComputation::GeometricMean => {
                let product: f32 = self.factors.iter().map(|f| f.normalized_score).product();
                product.powf(1.0 / self.factors.len() as f32)
            }
            TrustComputation::CustomFormula => {
                // Fallback to weighted average; real custom formulas are external
                let total_weight: f32 = self.factors.iter().map(|f| f.weight).sum();
                if total_weight == 0.0 {
                    return 0.0;
                }
                self.factors.iter().map(|f| f.contribution).sum::<f32>() / total_weight
            }
        }
    }

    /// Return `true` if all thresholds are met.
    pub fn check_thresholds(&self) -> bool {
        self.thresholds.iter().all(|t| t.met)
    }

    pub fn failed_thresholds(&self) -> Vec<&TrustThreshold> {
        self.thresholds.iter().filter(|t| !t.met).collect()
    }
}

impl TrustFactor {
    pub fn new(
        name: impl Into<String>,
        factor_type: FactorType,
        weight: f32,
        observed: f32,
        normalized: f32,
    ) -> Self {
        Self {
            factor_name: name.into(),
            factor_type,
            weight,
            observed_value: observed,
            normalized_score: normalized,
            contribution: weight * normalized,
            evidence: None,
        }
    }

    pub fn with_evidence(mut self, evidence: FactorEvidence) -> Self {
        self.evidence = Some(evidence);
        self
    }
}

impl TrustThreshold {
    pub fn new(
        name: impl Into<String>,
        threshold_type: ThresholdType,
        required: f32,
        met: bool,
    ) -> Self {
        Self {
            threshold_name: name.into(),
            threshold_type,
            required_value: required,
            met,
            failure_reason: None,
        }
    }

    pub fn with_failure_reason(mut self, reason: impl Into<String>) -> Self {
        self.failure_reason = Some(reason.into());
        self
    }
}

/// Metrics extracted from evidence for trust evaluation.
#[derive(Debug, Clone, Default)]
pub struct EvidenceMetrics {
    /// Checkpoint interval CoV (std/mean); higher = more natural timing
    pub checkpoint_interval_cov: f32,
    /// Fraction of checkpoints with monotonic character-count growth (0.0..1.0)
    pub monotonic_growth_ratio: f32,
    /// Typing-pattern entropy (0.0..1.0)
    pub behavioral_entropy: f32,
    /// 1=SoftwareOnly, 2=AttestedSoftware, 3=HardwareBound, 4=HardwareHardened
    pub attestation_tier_level: u32,
    pub chain_verified: bool,
    pub checkpoint_count: u32,
}

impl AppraisalPolicy {
    /// Score all factors against `metrics` and evaluate thresholds.
    /// Returns a new policy instance with populated scores.
    pub fn evaluate(&self, metrics: &EvidenceMetrics) -> Self {
        let mut policy = self.clone();

        for factor in &mut policy.factors {
            let (observed, normalized) = match factor.factor_type {
                FactorType::ChainIntegrity => {
                    let score = if metrics.chain_verified { 1.0 } else { 0.0 };
                    (score, score)
                }
                FactorType::TypingRateConsistency => {
                    // CoV 0.3-0.6 is typical human; <0.1 is suspiciously regular
                    let cov = metrics.checkpoint_interval_cov;
                    let score = if cov <= 0.0 {
                        0.0
                    } else if cov < 0.1 {
                        cov / 0.1 * 0.3
                    } else if cov <= 0.6 {
                        0.3 + (cov - 0.1) / 0.5 * 0.7
                    } else {
                        (1.0 - (cov - 0.6).min(0.4) / 0.4 * 0.2).max(0.0)
                    };
                    (cov, score)
                }
                FactorType::MonotonicRatio => (
                    metrics.monotonic_growth_ratio,
                    metrics.monotonic_growth_ratio,
                ),
                FactorType::EditEntropy => (metrics.behavioral_entropy, metrics.behavioral_entropy),
                FactorType::HardwareAttestation => {
                    let score = match metrics.attestation_tier_level {
                        4 => 1.0,
                        3 => 0.85,
                        2 => 0.5,
                        1 => 0.2,
                        _ => 0.0,
                    };
                    (metrics.attestation_tier_level as f32, score)
                }
                FactorType::CheckpointCount => {
                    let count = metrics.checkpoint_count as f32;
                    // Linear up to 20, then saturates
                    let score = (count / 20.0).min(1.0);
                    (count, score)
                }
                _ => (factor.observed_value, factor.normalized_score),
            };

            factor.observed_value = observed;
            factor.normalized_score = normalized.clamp(0.0, 1.0);
            factor.contribution = factor.weight * factor.normalized_score;
        }

        let overall_score = policy.compute_score();

        for threshold in &mut policy.thresholds {
            match threshold.threshold_type {
                ThresholdType::MinimumScore => {
                    threshold.met = overall_score >= threshold.required_value;
                    if !threshold.met {
                        threshold.failure_reason = Some(format!(
                            "Overall score {:.2} < required {:.2}",
                            overall_score, threshold.required_value
                        ));
                    }
                }
                ThresholdType::MinimumFactor => {
                    let met = policy
                        .factors
                        .iter()
                        .any(|f| f.normalized_score >= threshold.required_value);
                    threshold.met = met;
                    if !met {
                        threshold.failure_reason = Some(format!(
                            "No factor meets minimum score of {:.2}",
                            threshold.required_value
                        ));
                    }
                }
                ThresholdType::RequiredFactor => {
                    let met = policy.factors.iter().any(|f| {
                        f.factor_name == threshold.threshold_name && f.normalized_score > 0.0
                    });
                    threshold.met = met;
                    if !met {
                        threshold.failure_reason = Some(format!(
                            "Required factor '{}' not present or scored zero",
                            threshold.threshold_name
                        ));
                    }
                }
                ThresholdType::MaximumCaveats => {
                    // Factors scoring <0.5 count as caveats
                    let caveat_count = policy
                        .factors
                        .iter()
                        .filter(|f| f.normalized_score < 0.5)
                        .count() as f32;
                    threshold.met = caveat_count <= threshold.required_value;
                    if !threshold.met {
                        threshold.failure_reason = Some(format!(
                            "{} caveats exceed maximum of {}",
                            caveat_count, threshold.required_value
                        ));
                    }
                }
            }
        }

        policy
    }
}

pub mod profiles {
    use super::*;

    /// Chain integrity + timing + content + hardware attestation.
    pub fn basic() -> AppraisalPolicy {
        AppraisalPolicy::new("urn:ietf:params:pop:policy:basic", "1.0")
            .with_computation(TrustComputation::WeightedAverage)
            .add_factor(TrustFactor::new(
                "chain-integrity",
                FactorType::ChainIntegrity,
                0.4,
                0.0,
                0.0,
            ))
            .add_factor(TrustFactor::new(
                "timing-regularity",
                FactorType::TypingRateConsistency,
                0.2,
                0.0,
                0.0,
            ))
            .add_factor(TrustFactor::new(
                "content-progression",
                FactorType::MonotonicRatio,
                0.2,
                0.0,
                0.0,
            ))
            .add_factor(TrustFactor::new(
                "hardware-attestation",
                FactorType::HardwareAttestation,
                0.2,
                0.0,
                0.0,
            ))
            .with_metadata(PolicyMetadata {
                policy_name: Some("Basic Verification".to_string()),
                policy_description: Some(
                    "Chain integrity with timing and content analysis".to_string(),
                ),
                policy_authority: None,
                policy_effective_date: None,
                applicable_domains: vec!["general".to_string()],
            })
    }

    /// Weighted average, min score 0.70, presence required.
    pub fn academic() -> AppraisalPolicy {
        AppraisalPolicy::new("urn:ietf:params:pop:policy:academic", "1.0")
            .with_computation(TrustComputation::WeightedAverage)
            .add_threshold(TrustThreshold::new(
                "minimum-overall",
                ThresholdType::MinimumScore,
                0.70,
                false,
            ))
            .add_threshold(TrustThreshold::new(
                "presence-required",
                ThresholdType::RequiredFactor,
                0.0,
                false,
            ))
            .with_metadata(PolicyMetadata {
                policy_name: Some("Academic Submission".to_string()),
                policy_description: Some(
                    "Policy for academic paper and thesis submissions".to_string(),
                ),
                policy_authority: None,
                policy_effective_date: None,
                applicable_domains: vec!["academic".to_string(), "education".to_string()],
            })
    }

    /// Minimum-of-factors model, hardware attestation required.
    pub fn legal() -> AppraisalPolicy {
        AppraisalPolicy::new("urn:ietf:params:pop:policy:legal", "1.0")
            .with_computation(TrustComputation::MinimumOfFactors)
            .add_threshold(TrustThreshold::new(
                "hardware-required",
                ThresholdType::RequiredFactor,
                0.0,
                false,
            ))
            .with_metadata(PolicyMetadata {
                policy_name: Some("Legal Proceedings".to_string()),
                policy_description: Some(
                    "High-assurance policy for legal and forensic use".to_string(),
                ),
                policy_authority: None,
                policy_effective_date: None,
                applicable_domains: vec!["legal".to_string(), "forensic".to_string()],
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weighted_average() {
        let policy = AppraisalPolicy::new("test", "1.0")
            .with_computation(TrustComputation::WeightedAverage)
            .add_factor(TrustFactor::new(
                "f1",
                FactorType::VdfDuration,
                0.5,
                1.0,
                1.0,
            ))
            .add_factor(TrustFactor::new(
                "f2",
                FactorType::JitterEntropy,
                0.5,
                0.5,
                0.5,
            ));

        let score = policy.compute_score();
        // (0.5 * 1.0 + 0.5 * 0.5) / 1.0 = 0.75
        assert!((score - 0.75).abs() < 0.001);
    }

    #[test]
    fn test_minimum_of_factors() {
        let policy = AppraisalPolicy::new("test", "1.0")
            .with_computation(TrustComputation::MinimumOfFactors)
            .add_factor(TrustFactor::new(
                "f1",
                FactorType::VdfDuration,
                0.5,
                1.0,
                0.9,
            ))
            .add_factor(TrustFactor::new(
                "f2",
                FactorType::JitterEntropy,
                0.5,
                0.5,
                0.3,
            ));

        let score = policy.compute_score();
        assert!((score - 0.3).abs() < 0.001);
    }

    #[test]
    fn test_geometric_mean() {
        let policy = AppraisalPolicy::new("test", "1.0")
            .with_computation(TrustComputation::GeometricMean)
            .add_factor(TrustFactor::new(
                "f1",
                FactorType::VdfDuration,
                0.5,
                1.0,
                1.0,
            ))
            .add_factor(TrustFactor::new(
                "f2",
                FactorType::JitterEntropy,
                0.5,
                0.5,
                0.5,
            ));

        let score = policy.compute_score();
        // sqrt(1.0 * 0.5) = 0.707
        assert!((score - 0.707).abs() < 0.01);
    }

    #[test]
    fn test_threshold_checking() {
        let policy = AppraisalPolicy::new("test", "1.0")
            .add_threshold(TrustThreshold::new(
                "t1",
                ThresholdType::MinimumScore,
                0.5,
                true,
            ))
            .add_threshold(TrustThreshold::new(
                "t2",
                ThresholdType::MinimumScore,
                0.9,
                false,
            ));

        assert!(!policy.check_thresholds());
        assert_eq!(policy.failed_thresholds().len(), 1);
    }

    #[test]
    fn test_predefined_profiles() {
        let basic = profiles::basic();
        assert_eq!(basic.policy_uri, "urn:ietf:params:pop:policy:basic");

        let academic = profiles::academic();
        assert_eq!(
            academic.computation_model,
            TrustComputation::WeightedAverage
        );

        let legal = profiles::legal();
        assert_eq!(legal.computation_model, TrustComputation::MinimumOfFactors);
    }

    #[test]
    fn test_serialization() {
        let policy = AppraisalPolicy::new("urn:test:policy", "1.0.0").add_factor(TrustFactor::new(
            "test",
            FactorType::ChainIntegrity,
            1.0,
            1.0,
            1.0,
        ));

        let json = serde_json::to_string(&policy).unwrap();
        let parsed: AppraisalPolicy = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.policy_uri, "urn:test:policy");
    }

    #[test]
    fn test_evaluate_basic_policy() {
        let policy = profiles::basic();
        let metrics = EvidenceMetrics {
            checkpoint_interval_cov: 0.4,
            monotonic_growth_ratio: 0.95,
            behavioral_entropy: 0.7,
            attestation_tier_level: 3, // HardwareBound
            chain_verified: true,
            checkpoint_count: 10,
        };

        let evaluated = policy.evaluate(&metrics);
        let score = evaluated.compute_score();
        assert!(score > 0.5, "Expected score > 0.5, got {}", score);

        let chain = evaluated
            .factors
            .iter()
            .find(|f| f.factor_type == FactorType::ChainIntegrity)
            .unwrap();
        assert!((chain.normalized_score - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_evaluate_broken_chain() {
        let policy = profiles::basic();
        let metrics = EvidenceMetrics {
            chain_verified: false,
            ..Default::default()
        };

        let evaluated = policy.evaluate(&metrics);
        let chain = evaluated
            .factors
            .iter()
            .find(|f| f.factor_type == FactorType::ChainIntegrity)
            .unwrap();
        assert!((chain.normalized_score - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_evaluate_threshold_checking() {
        let policy = AppraisalPolicy::new("test", "1.0")
            .with_computation(TrustComputation::WeightedAverage)
            .add_factor(TrustFactor::new(
                "chain-integrity",
                FactorType::ChainIntegrity,
                1.0,
                0.0,
                0.0,
            ))
            .add_threshold(TrustThreshold::new(
                "minimum-overall",
                ThresholdType::MinimumScore,
                0.5,
                false,
            ));

        let metrics = EvidenceMetrics {
            chain_verified: true,
            ..Default::default()
        };

        let evaluated = policy.evaluate(&metrics);
        assert!(evaluated.check_thresholds()); // 1.0 >= 0.5

        let metrics_bad = EvidenceMetrics {
            chain_verified: false,
            ..Default::default()
        };
        let evaluated_bad = policy.evaluate(&metrics_bad);
        assert!(!evaluated_bad.check_thresholds()); // 0.0 < 0.5
    }
}
