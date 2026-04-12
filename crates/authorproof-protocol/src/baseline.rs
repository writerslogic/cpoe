// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

/// Progressive confidence tier based on session count:
/// - PopulationReference (0-4): Human vs machine only
/// - Emerging (5-9): Meaningful author consistency
/// - Established (10-19): Author identity distinguishable
/// - Mature (20+): Full authorship attribution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u64)]
pub enum ConfidenceTier {
    PopulationReference = 1,
    Emerging = 2,
    Established = 3,
    Mature = 4,
}

impl ConfidenceTier {
    pub fn from_session_count(count: u64) -> Self {
        match count {
            0..=4 => Self::PopulationReference,
            5..=9 => Self::Emerging,
            10..=19 => Self::Established,
            _ => Self::Mature,
        }
    }
}

/// Welford's algorithm for streaming metrics.
///
/// Note: this baseline-specific copy uses `f64` to match the wire-format
/// `streaming-stats` definition in `rfc::wire_types::components::StreamingStats`.
/// Both use CBOR float64 on the wire per the CDDL schema (`float64`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StreamingStats {
    #[serde(rename = "1")]
    pub count: u64,
    #[serde(rename = "2")]
    pub mean: f64,
    #[serde(rename = "3")]
    pub m2: f64,
    #[serde(rename = "4")]
    pub min: f64,
    #[serde(rename = "5")]
    pub max: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionBehavioralSummary {
    /// 9-bin IKI histogram (edges: 0, 50, 100, 150, 200, 300, 500, 1000, 2000ms)
    #[serde(rename = "1")]
    pub iki_histogram: [f64; 9],
    #[serde(rename = "2")]
    pub iki_cv: f64,
    /// Long-range dependency exponent
    #[serde(rename = "3")]
    pub hurst: f64,
    #[serde(rename = "4")]
    pub pause_frequency: f64,
    #[serde(rename = "5")]
    pub duration_secs: u64,
    #[serde(rename = "6")]
    pub keystroke_count: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaselineDigest {
    #[serde(rename = "1")]
    pub version: u32,
    #[serde(rename = "2")]
    pub session_count: u64,
    #[serde(rename = "3")]
    pub total_keystrokes: u64,
    #[serde(rename = "4")]
    pub iki_stats: StreamingStats,
    #[serde(rename = "5")]
    pub cv_stats: StreamingStats,
    #[serde(rename = "6")]
    pub hurst_stats: StreamingStats,
    #[serde(rename = "7")]
    pub aggregate_iki_histogram: [f64; 9],
    #[serde(rename = "8")]
    pub pause_stats: StreamingStats,
    /// MMR root over previous session evidence hashes
    #[serde(rename = "9", with = "serde_bytes")]
    pub session_merkle_root: Vec<u8>,
    #[serde(rename = "10")]
    pub confidence_tier: ConfidenceTier,
    #[serde(rename = "11")]
    pub computed_at: u64,
    /// SHA-256(Ed25519 public key)
    #[serde(rename = "12", with = "serde_bytes")]
    pub identity_fingerprint: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaselineVerification {
    /// None during enrollment phase.
    #[serde(rename = "1", default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<BaselineDigest>,
    #[serde(rename = "2")]
    pub session_summary: SessionBehavioralSummary,
    /// COSE_Sign1 over the CBOR-encoded digest.
    #[serde(
        rename = "3",
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::rfc::wire_types::serde_helpers::serde_bytes_opt"
    )]
    pub digest_signature: Option<Vec<u8>>,
}

/// Neutral Hurst exponent (random walk, no long-range dependence).
const HURST_NEUTRAL: f64 = 0.5;

impl StreamingStats {
    pub fn validate(&self) -> Result<(), String> {
        if !self.mean.is_finite() {
            return Err(format!("mean invalid: {}", self.mean));
        }
        if !self.m2.is_finite() || self.m2 < 0.0 {
            return Err(format!("m2 invalid: {}", self.m2));
        }
        if !self.min.is_finite() {
            return Err(format!("min invalid: {}", self.min));
        }
        if !self.max.is_finite() {
            return Err(format!("max invalid: {}", self.max));
        }
        if self.count > 0 && self.min > self.max {
            return Err(format!("min {} > max {}", self.min, self.max));
        }
        Ok(())
    }
}

impl BaselineDigest {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 {
            return Err(format!("unsupported baseline version: {}", self.version));
        }
        self.iki_stats
            .validate()
            .map_err(|e| format!("iki_stats: {e}"))?;
        self.cv_stats
            .validate()
            .map_err(|e| format!("cv_stats: {e}"))?;
        self.hurst_stats
            .validate()
            .map_err(|e| format!("hurst_stats: {e}"))?;
        self.pause_stats
            .validate()
            .map_err(|e| format!("pause_stats: {e}"))?;
        for (i, &v) in self.aggregate_iki_histogram.iter().enumerate() {
            if !v.is_finite() || v < 0.0 {
                return Err(format!("aggregate_iki_histogram[{i}] invalid: {v}"));
            }
        }
        if self.session_merkle_root.len() != 32 {
            return Err(format!(
                "session_merkle_root length {}, expected 32",
                self.session_merkle_root.len()
            ));
        }
        if self.identity_fingerprint.len() != 32 {
            return Err(format!(
                "identity_fingerprint length {}, expected 32",
                self.identity_fingerprint.len()
            ));
        }
        Ok(())
    }
}

impl SessionBehavioralSummary {
    /// Validate that all fields contain sensible values.
    pub fn validate(&self) -> Result<(), String> {
        for (i, &v) in self.iki_histogram.iter().enumerate() {
            if !v.is_finite() || v < 0.0 {
                return Err(format!("iki_histogram[{i}] invalid: {v}"));
            }
        }
        if !self.iki_cv.is_finite() || self.iki_cv < 0.0 {
            return Err(format!("iki_cv invalid: {}", self.iki_cv));
        }
        if !self.hurst.is_finite() {
            return Err("hurst is NaN or infinite".to_string());
        }
        if !(0.0..=1.0).contains(&self.hurst) {
            return Err(format!("hurst {} outside valid range [0, 1]", self.hurst));
        }
        if !self.pause_frequency.is_finite() || self.pause_frequency < 0.0 {
            return Err(format!("pause_frequency invalid: {}", self.pause_frequency));
        }
        Ok(())
    }
}

impl Default for SessionBehavioralSummary {
    fn default() -> Self {
        Self {
            iki_histogram: [0.0; 9],
            iki_cv: 0.0,
            hurst: HURST_NEUTRAL,
            pause_frequency: 0.0,
            duration_secs: 0,
            keystroke_count: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidence_tier_from_session_count() {
        assert_eq!(
            ConfidenceTier::from_session_count(0),
            ConfidenceTier::PopulationReference
        );
        assert_eq!(
            ConfidenceTier::from_session_count(4),
            ConfidenceTier::PopulationReference
        );
        assert_eq!(
            ConfidenceTier::from_session_count(5),
            ConfidenceTier::Emerging
        );
        assert_eq!(
            ConfidenceTier::from_session_count(10),
            ConfidenceTier::Established
        );
        assert_eq!(
            ConfidenceTier::from_session_count(20),
            ConfidenceTier::Mature
        );
        assert_eq!(
            ConfidenceTier::from_session_count(100),
            ConfidenceTier::Mature
        );
    }

    #[test]
    fn test_baseline_verification_cbor_roundtrip_enrollment() {
        let summary = SessionBehavioralSummary {
            iki_histogram: [0.1, 0.2, 0.15, 0.1, 0.1, 0.15, 0.1, 0.05, 0.05],
            iki_cv: 0.45,
            hurst: 0.72,
            pause_frequency: 3.5,
            duration_secs: 1800,
            keystroke_count: 5000,
        };

        let bv = BaselineVerification {
            digest: None,
            session_summary: summary,
            digest_signature: None,
        };

        let mut buf = Vec::new();
        ciborium::into_writer(&bv, &mut buf).expect("CBOR encode");
        let decoded: BaselineVerification = ciborium::from_reader(&buf[..]).expect("CBOR decode");

        assert!(decoded.digest.is_none());
        assert!((decoded.session_summary.iki_cv - 0.45).abs() < 1e-10);
        assert_eq!(decoded.session_summary.keystroke_count, 5000);
        assert!(
            buf.len() < 200,
            "Enrollment wire overhead: {} bytes",
            buf.len()
        );
    }

    #[test]
    fn test_baseline_verification_cbor_roundtrip_with_digest() {
        let digest = BaselineDigest {
            version: 1,
            session_count: 10,
            total_keystrokes: 50000,
            iki_stats: StreamingStats {
                count: 10,
                mean: 150.0,
                m2: 500.0,
                min: 80.0,
                max: 300.0,
            },
            cv_stats: StreamingStats {
                count: 10,
                mean: 0.45,
                m2: 0.02,
                min: 0.3,
                max: 0.6,
            },
            hurst_stats: StreamingStats {
                count: 10,
                mean: 0.72,
                m2: 0.01,
                min: 0.65,
                max: 0.8,
            },
            aggregate_iki_histogram: [0.1, 0.2, 0.15, 0.1, 0.1, 0.15, 0.1, 0.05, 0.05],
            pause_stats: StreamingStats {
                count: 10,
                mean: 3.5,
                m2: 2.0,
                min: 1.0,
                max: 7.0,
            },
            session_merkle_root: vec![0xAA; 32],
            confidence_tier: ConfidenceTier::Established,
            computed_at: 1708790400,
            identity_fingerprint: vec![0xBB; 32],
        };

        let bv = BaselineVerification {
            digest: Some(digest),
            session_summary: SessionBehavioralSummary::default(),
            digest_signature: Some(vec![0xCC; 64]),
        };

        let mut buf = Vec::new();
        ciborium::into_writer(&bv, &mut buf).expect("CBOR encode");
        let decoded: BaselineVerification = ciborium::from_reader(&buf[..]).expect("CBOR decode");

        let d = decoded.digest.as_ref().unwrap();
        assert_eq!(d.session_count, 10);
        assert_eq!(d.confidence_tier, ConfidenceTier::Established);
        assert_eq!(d.identity_fingerprint, vec![0xBB; 32]);
        assert_eq!(decoded.digest_signature.as_ref().unwrap().len(), 64);
        assert!(buf.len() < 600, "Full wire overhead: {} bytes", buf.len());
    }

    // -- StreamingStats validation tests --

    fn valid_stats() -> StreamingStats {
        StreamingStats {
            count: 10,
            mean: 150.0,
            m2: 500.0,
            min: 80.0,
            max: 300.0,
        }
    }

    #[test]
    fn test_streaming_stats_valid() {
        assert!(valid_stats().validate().is_ok());
    }

    #[test]
    fn test_streaming_stats_nan_mean() {
        let mut s = valid_stats();
        s.mean = f64::NAN;
        assert!(s.validate().unwrap_err().contains("mean"));
    }

    #[test]
    fn test_streaming_stats_negative_m2() {
        let mut s = valid_stats();
        s.m2 = -1.0;
        assert!(s.validate().unwrap_err().contains("m2"));
    }

    #[test]
    fn test_streaming_stats_infinity_max() {
        let mut s = valid_stats();
        s.max = f64::INFINITY;
        assert!(s.validate().unwrap_err().contains("max"));
    }

    #[test]
    fn test_streaming_stats_min_gt_max() {
        let s = StreamingStats {
            count: 5,
            mean: 0.0,
            m2: 0.0,
            min: 10.0,
            max: 1.0,
        };
        assert!(s.validate().unwrap_err().contains("min"));
    }

    #[test]
    fn test_streaming_stats_min_gt_max_zero_count() {
        let s = StreamingStats {
            count: 0,
            mean: 0.0,
            m2: 0.0,
            min: 10.0,
            max: 1.0,
        };
        assert!(s.validate().is_ok(), "min > max allowed when count == 0");
    }

    // -- BaselineDigest validation tests --

    fn valid_digest() -> BaselineDigest {
        BaselineDigest {
            version: 1,
            session_count: 10,
            total_keystrokes: 50000,
            iki_stats: valid_stats(),
            cv_stats: valid_stats(),
            hurst_stats: valid_stats(),
            aggregate_iki_histogram: [0.1, 0.2, 0.15, 0.1, 0.1, 0.15, 0.1, 0.05, 0.05],
            pause_stats: valid_stats(),
            session_merkle_root: vec![0xAA; 32],
            confidence_tier: ConfidenceTier::Established,
            computed_at: 1708790400,
            identity_fingerprint: vec![0xBB; 32],
        }
    }

    #[test]
    fn test_baseline_digest_valid() {
        assert!(valid_digest().validate().is_ok());
    }

    #[test]
    fn test_baseline_digest_bad_version() {
        let mut d = valid_digest();
        d.version = 2;
        assert!(d.validate().unwrap_err().contains("version"));
    }

    #[test]
    fn test_baseline_digest_short_merkle_root() {
        let mut d = valid_digest();
        d.session_merkle_root = vec![0; 16];
        assert!(d.validate().unwrap_err().contains("session_merkle_root"));
    }

    #[test]
    fn test_baseline_digest_short_fingerprint() {
        let mut d = valid_digest();
        d.identity_fingerprint = vec![0; 31];
        assert!(d.validate().unwrap_err().contains("identity_fingerprint"));
    }

    #[test]
    fn test_baseline_digest_nan_in_stats() {
        let mut d = valid_digest();
        d.iki_stats.mean = f64::NAN;
        assert!(d.validate().unwrap_err().contains("iki_stats"));
    }

    #[test]
    fn test_baseline_digest_nan_aggregate_histogram() {
        let mut d = valid_digest();
        d.aggregate_iki_histogram[3] = f64::NAN;
        assert!(d
            .validate()
            .unwrap_err()
            .contains("aggregate_iki_histogram"));
    }

    // -- SessionBehavioralSummary validation tests --

    #[test]
    fn test_summary_valid() {
        let s = SessionBehavioralSummary {
            iki_histogram: [0.1, 0.2, 0.15, 0.1, 0.1, 0.15, 0.1, 0.05, 0.05],
            iki_cv: 0.45,
            hurst: 0.72,
            pause_frequency: 3.5,
            duration_secs: 1800,
            keystroke_count: 5000,
        };
        assert!(s.validate().is_ok());
    }

    #[test]
    fn test_summary_default_valid() {
        assert!(SessionBehavioralSummary::default().validate().is_ok());
    }

    #[test]
    fn test_summary_nan_histogram() {
        let mut s = SessionBehavioralSummary::default();
        s.iki_histogram[4] = f64::NAN;
        assert!(s.validate().unwrap_err().contains("iki_histogram"));
    }

    #[test]
    fn test_summary_negative_iki_cv() {
        let mut s = SessionBehavioralSummary::default();
        s.iki_cv = -0.1;
        assert!(s.validate().unwrap_err().contains("iki_cv"));
    }

    #[test]
    fn test_summary_nan_iki_cv() {
        let mut s = SessionBehavioralSummary::default();
        s.iki_cv = f64::NAN;
        assert!(s.validate().unwrap_err().contains("iki_cv"));
    }

    #[test]
    fn test_summary_hurst_out_of_range() {
        let mut s = SessionBehavioralSummary::default();
        s.hurst = 1.5;
        assert!(s.validate().unwrap_err().contains("hurst"));
    }

    #[test]
    fn test_summary_negative_pause_frequency() {
        let mut s = SessionBehavioralSummary::default();
        s.pause_frequency = -1.0;
        assert!(s.validate().unwrap_err().contains("pause_frequency"));
    }

    #[test]
    fn test_summary_infinity_pause_frequency() {
        let mut s = SessionBehavioralSummary::default();
        s.pause_frequency = f64::INFINITY;
        assert!(s.validate().unwrap_err().contains("pause_frequency"));
    }
}
