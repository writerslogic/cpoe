

//! RFC-compliant biology-invariant-claim structure.
//!
//! Implements the biology-invariant-claim CDDL structure from draft-condrey-rats-pop-01
//! for behavioral biometric validation with millibits scoring.

use serde::{Deserialize, Serialize};

/
/
/
/
/
/
/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[derive(Default)]
pub enum ValidationStatus {
    /
    #[serde(rename = "empirical")]
    Empirical = 1,

    /
    #[serde(rename = "theoretical")]
    Theoretical = 2,

    /
    #[serde(rename = "unsupported")]
    #[default]
    Unsupported = 3,
}

impl ValidationStatus {
    /
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Empirical => "empirical",
            Self::Theoretical => "theoretical",
            Self::Unsupported => "unsupported",
        }
    }
}

/
/
/
/
/
/
/
/
/
/
/
/
/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiologyInvariantClaim {
    #[serde(rename = "1")]
    pub validation_status: ValidationStatus,

    /
    #[serde(rename = "2")]
    pub millibits: u16,

    #[serde(rename = "3")]
    pub parameter_version: String,

    #[serde(rename = "4")]
    pub parameters: BiologyScoringParameters,

    #[serde(rename = "5")]
    pub measurements: BiologyMeasurements,

    /
    #[serde(rename = "6", default, skip_serializing_if = "Option::is_none")]
    pub hurst_exponent: Option<f64>,

    #[serde(rename = "7", default, skip_serializing_if = "Option::is_none")]
    pub pink_noise: Option<PinkNoiseAnalysis>,

    #[serde(rename = "8", default, skip_serializing_if = "Option::is_none")]
    pub error_topology: Option<ErrorTopology>,

    #[serde(rename = "9", default, skip_serializing_if = "Option::is_none")]
    pub anomaly_flags: Option<Vec<AnomalyFlag>>,
}

/
/
/
/
/
/
/
/
/
/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiologyScoringParameters {
    #[serde(rename = "1")]
    pub hurst_weight: f64,

    #[serde(rename = "2")]
    pub pink_noise_weight: f64,

    #[serde(rename = "3")]
    pub error_topology_weight: f64,

    #[serde(rename = "4")]
    pub cadence_weight: f64,

    #[serde(rename = "5")]
    pub human_threshold: f64,

    #[serde(rename = "6")]
    pub min_samples: u32,
}

impl Default for BiologyScoringParameters {
    fn default() -> Self {
        Self {
            hurst_weight: 0.25,
            pink_noise_weight: 0.25,
            error_topology_weight: 0.25,
            cadence_weight: 0.25,
            human_threshold: 0.75,
            min_samples: 100,
        }
    }
}

/
/
/
/
/
/
/
/
/
/
/
/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiologyMeasurements {
    #[serde(rename = "1")]
    pub sample_count: u64,

    /
    #[serde(rename = "2")]
    pub mean_iki_us: f64,

    /
    #[serde(rename = "3")]
    pub std_dev_us: f64,

    #[serde(rename = "4")]
    pub coefficient_of_variation: f64,

    /
    #[serde(rename = "5")]
    pub percentiles: [f64; 5],

    #[serde(rename = "6")]
    pub burst_count: u32,

    /
    #[serde(rename = "7")]
    pub pause_count: u32,

    /
    #[serde(rename = "8")]
    pub typing_rate: f64,
}

/
/
/
/
/
/
/
/
/
/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinkNoiseAnalysis {
    /
    #[serde(rename = "1")]
    pub spectral_slope: f64,

    #[serde(rename = "2")]
    pub r_squared: f64,

    #[serde(rename = "3")]
    pub low_freq_power: f64,

    #[serde(rename = "4")]
    pub high_freq_power: f64,

    #[serde(rename = "5")]
    pub within_human_range: bool,
}

impl PinkNoiseAnalysis {
    /
    pub fn is_human_like(&self) -> bool {
        self.spectral_slope >= 0.8 && self.spectral_slope <= 1.2 && self.r_squared > 0.7
    }
}

/
/
/
/
/
/
/
/
/
/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorTopology {
    #[serde(rename = "1")]
    pub gap_ratio: f64,

    #[serde(rename = "2")]
    pub error_clustering: f64,

    #[serde(rename = "3")]
    pub adjacent_key_score: f64,

    /
    #[serde(rename = "4")]
    pub score: f64,

    /
    #[serde(rename = "5")]
    pub passed: bool,
}

impl ErrorTopology {
    /
    pub fn compute_score(gap_ratio: f64, error_clustering: f64, adjacent_key_score: f64) -> f64 {
        0.4 * gap_ratio + 0.4 * error_clustering + 0.2 * adjacent_key_score
    }

    /
    pub fn new(gap_ratio: f64, error_clustering: f64, adjacent_key_score: f64) -> Self {
        let score = Self::compute_score(gap_ratio, error_clustering, adjacent_key_score);
        Self {
            gap_ratio,
            error_clustering,
            adjacent_key_score,
            score,
            passed: score >= 0.75,
        }
    }
}

/
/
/
/
/
/
/
/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyFlag {
    #[serde(rename = "1")]
    pub anomaly_type: AnomalyType,

    #[serde(rename = "2")]
    pub description: String,

    /
    #[serde(rename = "3")]
    pub severity: u8,

    /
    #[serde(rename = "4", default, skip_serializing_if = "Option::is_none")]
    pub timestamp_ms: Option<u64>,
}

impl AnomalyFlag {
    /
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=3).contains(&self.severity) {
            return Err(format!(
                "anomaly severity {} out of CDDL range 1..=3",
                self.severity
            ));
        }
        Ok(())
    }
}

/
/
/
/
/
/
/
/
/
/
/
/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AnomalyType {
    /
    #[serde(rename = "white_noise_hurst")]
    WhiteNoiseHurst = 1,
    /
    #[serde(rename = "predictable_hurst")]
    PredictableHurst = 2,
    /
    #[serde(rename = "robotic_cadence")]
    RoboticCadence = 3,
    /
    #[serde(rename = "spectral_anomaly")]
    SpectralAnomaly = 4,
    /
    #[serde(rename = "error_topology_fail")]
    ErrorTopologyFail = 5,
    /
    #[serde(rename = "insufficient_data")]
    InsufficientData = 6,
    /
    #[serde(rename = "temporal_discontinuity")]
    TemporalDiscontinuity = 7,
    /
    #[serde(rename = "velocity_anomaly")]
    VelocityAnomaly = 8,
}

impl BiologyInvariantClaim {
    /
    pub fn new(measurements: BiologyMeasurements, parameters: BiologyScoringParameters) -> Self {
        Self {
            validation_status: ValidationStatus::Unsupported,
            millibits: 0,
            parameter_version: "1.0.0".to_string(),
            parameters,
            measurements,
            hurst_exponent: None,
            pink_noise: None,
            error_topology: None,
            anomaly_flags: None,
        }
    }

    /
    pub fn with_hurst(mut self, h: f64) -> Self {
        self.hurst_exponent = Some(h);
        self
    }

    /
    pub fn with_pink_noise(mut self, analysis: PinkNoiseAnalysis) -> Self {
        self.pink_noise = Some(analysis);
        self
    }

    /
    pub fn with_error_topology(mut self, topology: ErrorTopology) -> Self {
        self.error_topology = Some(topology);
        self
    }

    /
    pub fn add_anomaly(&mut self, flag: AnomalyFlag) {
        self.anomaly_flags.get_or_insert_with(Vec::new).push(flag);
    }

    /
    fn active_weight(&self) -> f64 {
        let mut w = self.parameters.cadence_weight; 
        if self.hurst_exponent.is_some() {
            w += self.parameters.hurst_weight;
        }
        if self.pink_noise.is_some() {
            w += self.parameters.pink_noise_weight;
        }
        if self.error_topology.is_some() {
            w += self.parameters.error_topology_weight;
        }
        w
    }

    /
    /
    /
    /
    /
    /
    pub fn compute_score(&mut self) {
        let mut score = 0.0;
        let mut components = 0;

        if let Some(h) = self.hurst_exponent {
            if h.is_finite() {
                
                let h_score = if (0.55..=0.85).contains(&h) {
                    (1.0 - ((h - 0.7).abs() / 0.15)).clamp(0.0, 1.0)
                } else {
                    0.0
                };
                score += h_score * self.parameters.hurst_weight;
                components += 1;
            }
        }

        if let Some(ref pn) = self.pink_noise {
            let pn_score = if pn.is_human_like() {
                pn.r_squared
            } else {
                0.0
            };
            if pn_score.is_finite() {
                score += pn_score * self.parameters.pink_noise_weight;
                components += 1;
            }
        }

        if let Some(ref et) = self.error_topology {
            if et.score.is_finite() {
                score += et.score.clamp(0.0, 1.0) * self.parameters.error_topology_weight;
                components += 1;
            }
        }

        let cv = self.measurements.coefficient_of_variation;
        let cv_score = if cv.is_finite() && (0.15..=0.6).contains(&cv) {
            1.0 - ((cv - 0.35).abs() / 0.25).min(1.0)
        } else {
            0.0
        };
        score += cv_score * self.parameters.cadence_weight;
        components += 1;

        if components > 0 {
            let total_weight = self.active_weight();
            
            
            if total_weight > 0.0 {
                score /= total_weight;
            }
        }

        
        
        let clamped = if score.is_finite() {
            (score * 10000.0).round().clamp(0.0, 10000.0)
        } else {
            0.0
        };
        self.millibits = clamped as u16;

        self.validation_status = if self.hurst_exponent.is_some()
            && self.pink_noise.is_some()
            && self.error_topology.is_some()
        {
            ValidationStatus::Empirical
        } else if components >= 2 {
            ValidationStatus::Theoretical
        } else {
            ValidationStatus::Unsupported
        };
    }

    /
    pub fn is_human_like(&self) -> bool {
        (self.millibits as f64 / 10000.0) >= self.parameters.human_threshold
    }

    /
    pub fn anomaly_count(&self) -> usize {
        self.anomaly_flags.as_ref().map_or(0, |v| v.len())
    }

    /
    pub fn has_alerts(&self) -> bool {
        self.anomaly_flags
            .as_ref()
            .is_some_and(|flags| flags.iter().any(|f| f.severity >= 3))
    }

    /
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if self.millibits > 10000 {
            errors.push(format!("millibits {} exceeds max 10000", self.millibits));
        }

        if self.parameter_version.is_empty() {
            errors.push("parameter version is empty".into());
        }

        let params = &self.parameters;
        let weights = [
            params.hurst_weight,
            params.pink_noise_weight,
            params.error_topology_weight,
            params.cadence_weight,
        ];
        for (i, &w) in weights.iter().enumerate() {
            if !w.is_finite() {
                errors.push(format!("parameter weight[{}] is NaN or infinite", i));
            }
        }
        if !params.human_threshold.is_finite() {
            errors.push("human_threshold is NaN or infinite".into());
        }
        let total_weight = params.hurst_weight
            + params.pink_noise_weight
            + params.error_topology_weight
            + params.cadence_weight;
        const WEIGHT_SUM_TOLERANCE: f64 = 0.01;
        if (total_weight - 1.0).abs() > WEIGHT_SUM_TOLERANCE && total_weight > 0.0 {
            
            errors.push(format!(
                "parameter weights sum to {} (expected 1.0)",
                total_weight
            ));
        }
        if params.human_threshold < 0.0 || params.human_threshold > 1.0 {
            errors.push(format!(
                "human threshold {} out of range [0, 1]",
                params.human_threshold
            ));
        }

        let m = &self.measurements;
        if m.sample_count == 0 {
            errors.push("sample count is zero".into());
        }
        if !m.mean_iki_us.is_finite() || m.mean_iki_us <= 0.0 {
            errors.push("mean inter-key interval is non-positive or non-finite".into());
        }
        if m.std_dev_us < 0.0 {
            errors.push("standard deviation is negative".into());
        }
        if m.coefficient_of_variation < 0.0 {
            errors.push("coefficient of variation is negative".into());
        }
        if m.typing_rate < 0.0 {
            errors.push("typing rate is negative".into());
        }
        for i in 1..5 {
            if m.percentiles[i] < m.percentiles[i - 1] {
                errors.push(format!("percentiles not monotonic at index {}", i));
                break;
            }
        }

        if let Some(h) = self.hurst_exponent {
            if !(0.0..=1.0).contains(&h) {
                errors.push(format!("Hurst exponent {} out of range [0, 1]", h));
            }
        }

        if let Some(pn) = &self.pink_noise {
            if pn.r_squared < 0.0 || pn.r_squared > 1.0 {
                errors.push(format!(
                    "pink noise R² {} out of range [0, 1]",
                    pn.r_squared
                ));
            }
        }

        if let Some(et) = &self.error_topology {
            if et.score < 0.0 || et.score > 1.0 {
                errors.push(format!(
                    "error topology score {} out of range [0, 1]",
                    et.score
                ));
            }
        }

        errors
    }

    /
    pub fn is_valid(&self) -> bool {
        self.validate().is_empty()
    }
}
