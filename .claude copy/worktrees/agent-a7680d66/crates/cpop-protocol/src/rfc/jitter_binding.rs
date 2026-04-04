

//! RFC-compliant jitter-binding structure.
//!
//! Implements the 7-key CDDL structure from draft-condrey-rats-pop-01:
//! - entropy-commitment: Hash commitment to entropy sources
//! - sources: Entropy source descriptors
//! - summary: Statistical summary of jitter data
//! - binding-mac: HMAC binding to document state
//! - raw-intervals: Optional raw interval data (Enhanced/Maximum tiers)
//! - active-probes: Active behavioral probes (Galton Invariant, Reflex Gate)
//! - labyrinth-structure: Topological phase space analysis

use serde::{Deserialize, Serialize};
use std::fmt;

/
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationSeverity {
    /
    Error,
    /
    Warning,
}

/
#[derive(Debug, Clone)]
pub struct ValidationFinding {
    pub severity: ValidationSeverity,
    pub field: &'static str,
    pub message: String,
}

impl fmt::Display for ValidationFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tag = match self.severity {
            ValidationSeverity::Error => "error",
            ValidationSeverity::Warning => "warning",
        };
        write!(f, "[{}] {}: {}", tag, self.field, self.message)
    }
}

impl ValidationFinding {
    fn error(field: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: ValidationSeverity::Error,
            field,
            message: message.into(),
        }
    }

    fn warning(field: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: ValidationSeverity::Warning,
            field,
            message: message.into(),
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitterBinding {
    #[serde(rename = "1")]
    pub entropy_commitment: EntropyCommitment,

    #[serde(rename = "2")]
    pub sources: Vec<SourceDescriptor>,

    #[serde(rename = "3")]
    pub summary: JitterSummary,

    #[serde(rename = "4")]
    pub binding_mac: BindingMac,

    /
    #[serde(rename = "5", default, skip_serializing_if = "Option::is_none")]
    pub raw_intervals: Option<RawIntervals>,

    /
    #[serde(rename = "6", default, skip_serializing_if = "Option::is_none")]
    pub active_probes: Option<ActiveProbes>,

    /
    #[serde(rename = "7", default, skip_serializing_if = "Option::is_none")]
    pub labyrinth_structure: Option<LabyrinthStructure>,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyCommitment {
    #[serde(rename = "1", with = "super::serde_helpers::hex_bytes")]
    pub hash: [u8; 32],

    #[serde(rename = "2")]
    pub timestamp_ms: u64,

    /
    #[serde(rename = "3", with = "super::serde_helpers::hex_bytes")]
    pub previous_hash: [u8; 32],
}

/
/
/
/
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SourceType {
    Keyboard,
    Mouse,
    Touchscreen,
    Stylus,
    Accelerometer,
    CpopJitter,
    /
    Other(String),
}

impl SourceType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Keyboard => "keyboard",
            Self::Mouse => "mouse",
            Self::Touchscreen => "touchscreen",
            Self::Stylus => "stylus",
            Self::Accelerometer => "accelerometer",
            Self::CpopJitter => "cpop_jitter",
            Self::Other(s) => s,
        }
    }
}

impl fmt::Display for SourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for SourceType {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "keyboard" | "keyboard.usb" | "keyboard_usb" => Self::Keyboard,
            "mouse" | "mouse.usb" => Self::Mouse,
            "touchscreen" | "touch" => Self::Touchscreen,
            "stylus" | "pen" => Self::Stylus,
            "accelerometer" | "accel" | "imu" => Self::Accelerometer,
            "cpop_jitter" | "cpop-jitter" => Self::CpopJitter,
            _ => Self::Other(s.to_string()),
        }
    }
}

impl Serialize for SourceType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SourceType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(SourceType::from(s.as_str()))
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
pub struct SourceDescriptor {
    /
    #[serde(rename = "1")]
    pub source_type: SourceType,

    /
    #[serde(rename = "2")]
    pub weight: u16,

    #[serde(rename = "3", default, skip_serializing_if = "Option::is_none")]
    pub device_fingerprint: Option<String>,

    #[serde(rename = "4", default, skip_serializing_if = "Option::is_none")]
    pub transport_calibration: Option<TransportCalibration>,
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
pub struct TransportCalibration {
    #[serde(rename = "1")]
    pub transport: String,

    #[serde(rename = "2")]
    pub baseline_latency_us: u64,

    #[serde(rename = "3")]
    pub latency_variance_us: u64,

    #[serde(rename = "4")]
    pub calibrated_at_ms: u64,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitterSummary {
    #[serde(rename = "1")]
    pub sample_count: u64,

    #[serde(rename = "2")]
    pub mean_interval_us: f64,

    #[serde(rename = "3")]
    pub std_dev: f64,

    /
    #[serde(rename = "4")]
    pub coefficient_of_variation: f64,

    #[serde(rename = "5")]
    pub percentiles: [f64; 5],

    /
    #[serde(rename = "6")]
    pub entropy_bits: f64,

    /
    #[serde(rename = "7", default, skip_serializing_if = "Option::is_none")]
    pub hurst_exponent: Option<f64>,
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
pub struct BindingMac {
    #[serde(rename = "1", with = "super::serde_helpers::hex_bytes")]
    pub mac: [u8; 32],

    #[serde(rename = "2", with = "super::serde_helpers::hex_bytes")]
    pub document_hash: [u8; 32],

    /
    #[serde(rename = "3")]
    pub keystroke_count: u64,

    #[serde(rename = "4")]
    pub timestamp_ms: u64,
}

impl BindingMac {
    /
    pub fn compute(
        key: &[u8],
        document_hash: [u8; 32],
        keystroke_count: u64,
        timestamp_ms: u64,
        entropy_hash: &[u8; 32],
    ) -> Self {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        
        let mut mac =
            Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts any key size");
        mac.update(&document_hash);
        mac.update(&keystroke_count.to_be_bytes());
        mac.update(&timestamp_ms.to_be_bytes());
        mac.update(entropy_hash);
        Self {
            mac: mac.finalize().into_bytes().into(),
            document_hash,
            keystroke_count,
            timestamp_ms,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawIntervals {
    #[serde(rename = "1")]
    pub intervals: Vec<u32>,

    #[serde(rename = "2")]
    pub compression_method: u8,

    #[serde(rename = "3", default, skip_serializing_if = "Option::is_none")]
    pub compressed_data: Option<Vec<u8>>,
}

/
/
/
/
/
/
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActiveProbes {
    #[serde(rename = "1", default, skip_serializing_if = "Option::is_none")]
    pub galton_invariant: Option<GaltonInvariant>,

    #[serde(rename = "2", default, skip_serializing_if = "Option::is_none")]
    pub reflex_gate: Option<ReflexGate>,
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
pub struct GaltonInvariant {
    #[serde(rename = "1")]
    pub absorption_coefficient: f64,

    #[serde(rename = "2")]
    pub stimulus_count: u32,

    #[serde(rename = "3")]
    pub expected_absorption: f64,

    #[serde(rename = "4")]
    pub z_score: f64,

    #[serde(rename = "5")]
    pub passed: bool,
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
pub struct ReflexGate {
    #[serde(rename = "1")]
    pub mean_latency_ms: f64,

    #[serde(rename = "2")]
    pub std_dev_ms: f64,

    #[serde(rename = "3")]
    pub event_count: u32,

    #[serde(rename = "4")]
    pub percentiles: [f64; 5],

    /
    #[serde(rename = "5")]
    pub passed: bool,
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
pub struct LabyrinthStructure {
    #[serde(rename = "1")]
    pub embedding_dimension: u8,

    #[serde(rename = "2")]
    pub time_delay: u16,

    /
    #[serde(rename = "3")]
    pub attractor_points: Vec<Vec<f64>>,

    /
    #[serde(rename = "4")]
    pub betti_numbers: Vec<u32>,

    /
    /
    #[serde(rename = "5")]
    pub lyapunov_exponent: Option<f64>,

    /
    #[serde(rename = "6")]
    pub correlation_dimension: f64,
}

impl JitterBinding {
    /
    pub fn new(
        entropy_commitment: EntropyCommitment,
        sources: Vec<SourceDescriptor>,
        summary: JitterSummary,
        binding_mac: BindingMac,
    ) -> Self {
        Self {
            entropy_commitment,
            sources,
            summary,
            binding_mac,
            raw_intervals: None,
            active_probes: None,
            labyrinth_structure: None,
        }
    }

    /
    pub fn with_raw_intervals(mut self, intervals: RawIntervals) -> Self {
        self.raw_intervals = Some(intervals);
        self
    }

    /
    pub fn with_active_probes(mut self, probes: ActiveProbes) -> Self {
        self.active_probes = Some(probes);
        self
    }

    /
    pub fn with_labyrinth(mut self, labyrinth: LabyrinthStructure) -> Self {
        self.labyrinth_structure = Some(labyrinth);
        self
    }

    /
    pub fn verify_binding(&self, seed: &[u8]) -> bool {
        let expected = BindingMac::compute(
            seed,
            self.binding_mac.document_hash,
            self.binding_mac.keystroke_count,
            self.binding_mac.timestamp_ms,
            &self.entropy_commitment.hash,
        );
        subtle::ConstantTimeEq::ct_eq(&self.binding_mac.mac[..], &expected.mac[..]).unwrap_u8() == 1
    }

    /
    pub fn is_hurst_valid(&self) -> bool {
        if let Some(h) = self.summary.hurst_exponent {
            
            h > 0.55 && h < 0.85
        } else {
            true
        }
    }

    /
    pub fn probes_passed(&self) -> bool {
        if let Some(probes) = &self.active_probes {
            let galton_ok = probes
                .galton_invariant
                .as_ref()
                .map(|g| g.passed)
                .unwrap_or(true);
            let reflex_ok = probes
                .reflex_gate
                .as_ref()
                .map(|r| r.passed)
                .unwrap_or(true);
            galton_ok && reflex_ok
        } else {
            true
        }
    }

    /
    pub fn validate(&self) -> Vec<ValidationFinding> {
        let mut findings = Vec::new();

        
        if self.entropy_commitment.hash == [0u8; 32] {
            findings.push(ValidationFinding::error(
                "entropy_commitment.hash",
                "is zero",
            ));
        }
        if self.entropy_commitment.timestamp_ms == 0 {
            findings.push(ValidationFinding::error(
                "entropy_commitment.timestamp_ms",
                "is zero",
            ));
        }

        
        if self.sources.is_empty() {
            findings.push(ValidationFinding::error(
                "sources",
                "no entropy sources declared",
            ));
        }
        let mut total_weight: u32 = 0;
        let mut weight_overflow = false;
        for s in &self.sources {
            match total_weight.checked_add(s.weight as u32) {
                Some(sum) => total_weight = sum,
                None => {
                    weight_overflow = true;
                    break;
                }
            }
        }
        if weight_overflow {
            findings.push(ValidationFinding::error(
                "sources.weight",
                "total weight overflows u32",
            ));
        } else if total_weight == 0 {
            findings.push(ValidationFinding::error(
                "sources.weight",
                "total weight is zero",
            ));
        } else if total_weight > 1000 {
            findings.push(ValidationFinding::error(
                "sources.weight",
                format!("total weight {} exceeds 1000", total_weight),
            ));
        }
        for (i, source) in self.sources.iter().enumerate() {
            if source.source_type.as_str().is_empty() {
                findings.push(ValidationFinding::error("sources.source_type", "is empty"));
            }
            if source.weight > 1000 {
                findings.push(ValidationFinding::error(
                    "sources.weight",
                    format!(
                        "source[{}] weight {} exceeds CDDL maximum 1000",
                        i, source.weight
                    ),
                ));
            }
        }

        
        if !self.summary.mean_interval_us.is_finite() {
            findings.push(ValidationFinding::error(
                "summary.mean_interval_us",
                "is NaN or infinite",
            ));
        }
        if !self.summary.std_dev.is_finite() {
            findings.push(ValidationFinding::error(
                "summary.std_dev",
                "is NaN or infinite",
            ));
        }
        if !self.summary.coefficient_of_variation.is_finite() {
            findings.push(ValidationFinding::error(
                "summary.coefficient_of_variation",
                "is NaN or infinite",
            ));
        }
        if !self.summary.entropy_bits.is_finite() {
            findings.push(ValidationFinding::error(
                "summary.entropy_bits",
                "is NaN or infinite",
            ));
        }
        for (i, &p) in self.summary.percentiles.iter().enumerate() {
            if !p.is_finite() {
                findings.push(ValidationFinding::error(
                    "summary.percentiles",
                    format!("index {} is NaN or infinite", i),
                ));
            }
        }

        
        if self.summary.sample_count == 0 {
            findings.push(ValidationFinding::error("summary.sample_count", "is zero"));
        }
        if self.summary.mean_interval_us <= 0.0 {
            findings.push(ValidationFinding::error(
                "summary.mean_interval_us",
                "is non-positive",
            ));
        }
        if self.summary.std_dev < 0.0 {
            findings.push(ValidationFinding::error("summary.std_dev", "is negative"));
        }
        if self.summary.coefficient_of_variation < 0.0 {
            findings.push(ValidationFinding::warning(
                "summary.coefficient_of_variation",
                "is negative",
            ));
        }
        if self.summary.entropy_bits < 0.0 {
            findings.push(ValidationFinding::warning(
                "summary.entropy_bits",
                "is negative",
            ));
        }

        for i in 1..self.summary.percentiles.len() {
            if self.summary.percentiles[i] < self.summary.percentiles[i - 1] {
                findings.push(ValidationFinding::error(
                    "summary.percentiles",
                    format!(
                        "not monotonic: index {} ({}) < index {} ({})",
                        i,
                        self.summary.percentiles[i],
                        i - 1,
                        self.summary.percentiles[i - 1]
                    ),
                ));
                break;
            }
        }

        if let Some(h) = self.summary.hurst_exponent {
            if !(0.0..=1.0).contains(&h) {
                findings.push(ValidationFinding::warning(
                    "summary.hurst_exponent",
                    format!("{} out of range [0, 1]", h),
                ));
            }
        }

        
        if self.binding_mac.mac == [0u8; 32] {
            findings.push(ValidationFinding::error("binding_mac.mac", "is zero"));
        }
        if self.binding_mac.document_hash == [0u8; 32] {
            findings.push(ValidationFinding::error(
                "binding_mac.document_hash",
                "is zero",
            ));
        }
        if self.binding_mac.timestamp_ms == 0 {
            findings.push(ValidationFinding::error(
                "binding_mac.timestamp_ms",
                "is zero",
            ));
        }

        
        if let Some(probes) = &self.active_probes {
            if let Some(galton) = &probes.galton_invariant {
                if galton.absorption_coefficient < 0.0 || galton.absorption_coefficient > 1.0 {
                    findings.push(ValidationFinding::error(
                        "active_probes.galton.absorption_coefficient",
                        format!("{} out of range [0, 1]", galton.absorption_coefficient),
                    ));
                }
                if galton.stimulus_count == 0 {
                    findings.push(ValidationFinding::error(
                        "active_probes.galton.stimulus_count",
                        "is zero",
                    ));
                }
            }
            if let Some(reflex) = &probes.reflex_gate {
                if reflex.mean_latency_ms < 0.0 {
                    findings.push(ValidationFinding::error(
                        "active_probes.reflex.mean_latency_ms",
                        "is negative",
                    ));
                }
                if reflex.std_dev_ms < 0.0 {
                    findings.push(ValidationFinding::error(
                        "active_probes.reflex.std_dev_ms",
                        "is negative",
                    ));
                }
            }
        }

        
        if let Some(labyrinth) = &self.labyrinth_structure {
            if labyrinth.embedding_dimension < 2 {
                findings.push(ValidationFinding::error(
                    "labyrinth.embedding_dimension",
                    "less than 2",
                ));
            }
            if labyrinth.time_delay == 0 {
                findings.push(ValidationFinding::error("labyrinth.time_delay", "is zero"));
            }
            if labyrinth.betti_numbers.is_empty() {
                findings.push(ValidationFinding::error(
                    "labyrinth.betti_numbers",
                    "is empty",
                ));
            }
            if labyrinth.correlation_dimension < 0.0 {
                findings.push(ValidationFinding::warning(
                    "labyrinth.correlation_dimension",
                    "is negative",
                ));
            }
        }

        findings
    }

    /
    pub fn validate_strings(&self) -> Vec<String> {
        self.validate().iter().map(|f| f.to_string()).collect()
    }

    /
    pub fn is_valid(&self) -> bool {
        !self
            .validate()
            .iter()
            .any(|f| f.severity == ValidationSeverity::Error)
    }

    /
    pub fn has_no_findings(&self) -> bool {
        self.validate().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_binding() -> JitterBinding {
        let commitment = EntropyCommitment {
            hash: [1u8; 32],
            timestamp_ms: 1700000000000,
            previous_hash: [0u8; 32],
        };

        let sources = vec![
            SourceDescriptor {
                source_type: SourceType::Keyboard,
                weight: 700,
                device_fingerprint: Some("usb:1234:5678".to_string()),
                transport_calibration: None,
            },
            SourceDescriptor {
                source_type: SourceType::Mouse,
                weight: 300,
                device_fingerprint: None,
                transport_calibration: None,
            },
        ];

        let summary = JitterSummary {
            sample_count: 1000,
            mean_interval_us: 150000.0,
            std_dev: 50000.0,
            coefficient_of_variation: 0.33,
            percentiles: [50000.0, 80000.0, 140000.0, 200000.0, 300000.0],
            entropy_bits: 8.5,
            hurst_exponent: Some(0.72),
        };

        let binding_mac = BindingMac {
            mac: [2u8; 32],
            document_hash: [3u8; 32],
            keystroke_count: 5000,
            timestamp_ms: 1700000000000,
        };

        JitterBinding::new(commitment, sources, summary, binding_mac)
    }

    #[test]
    fn test_jitter_binding_serialization() {
        let binding = create_test_binding();

        let json = serde_json::to_string_pretty(&binding).unwrap();
        let decoded: JitterBinding = serde_json::from_str(&json).unwrap();

        assert_eq!(binding.summary.sample_count, decoded.summary.sample_count);
        assert_eq!(binding.sources.len(), decoded.sources.len());
    }

    #[test]
    fn test_hurst_validation() {
        let mut binding = create_test_binding();

        binding.summary.hurst_exponent = Some(0.72);
        assert!(binding.is_hurst_valid());

        binding.summary.hurst_exponent = Some(0.5);
        assert!(!binding.is_hurst_valid());

        binding.summary.hurst_exponent = Some(1.0);
        assert!(!binding.is_hurst_valid());

        binding.summary.hurst_exponent = None;
        assert!(binding.is_hurst_valid());
    }

    #[test]
    fn test_active_probes() {
        let mut binding = create_test_binding();

        let probes = ActiveProbes {
            galton_invariant: Some(GaltonInvariant {
                absorption_coefficient: 0.65,
                stimulus_count: 100,
                expected_absorption: 0.63,
                z_score: 0.5,
                passed: true,
            }),
            reflex_gate: Some(ReflexGate {
                mean_latency_ms: 250.0,
                std_dev_ms: 50.0,
                event_count: 50,
                percentiles: [180.0, 210.0, 245.0, 285.0, 340.0],
                passed: true,
            }),
        };

        binding.active_probes = Some(probes);
        assert!(binding.probes_passed());

        binding
            .active_probes
            .as_mut()
            .unwrap()
            .galton_invariant
            .as_mut()
            .unwrap()
            .passed = false;
        assert!(!binding.probes_passed());
    }

    #[test]
    fn test_jitter_binding_validation_valid() {
        let binding = create_test_binding();
        let findings = binding.validate();
        assert!(
            findings.is_empty(),
            "expected no findings, got: {:?}",
            findings
        );
        assert!(binding.is_valid());
    }

    #[test]
    fn test_jitter_binding_validation_zero_hash() {
        let mut binding = create_test_binding();
        binding.entropy_commitment.hash = [0u8; 32];
        let findings = binding.validate();
        assert!(findings.iter().any(
            |f| f.field == "entropy_commitment.hash" && f.severity == ValidationSeverity::Error
        ));
        assert!(!binding.is_valid());
    }

    #[test]
    fn test_jitter_binding_validation_empty_sources() {
        let mut binding = create_test_binding();
        binding.sources.clear();
        let findings = binding.validate();
        assert!(findings
            .iter()
            .any(|f| f.field == "sources" && f.message.contains("no entropy sources")));
    }

    #[test]
    fn test_jitter_binding_validation_excessive_weight() {
        let mut binding = create_test_binding();
        binding.sources[0].weight = 800;
        binding.sources[1].weight = 500;
        let findings = binding.validate();
        assert!(findings
            .iter()
            .any(|f| f.field == "sources.weight" && f.message.contains("exceeds 1000")));
    }

    #[test]
    fn test_jitter_binding_validation_invalid_hurst() {
        let mut binding = create_test_binding();
        binding.summary.hurst_exponent = Some(1.5);
        let findings = binding.validate();
        assert!(findings
            .iter()
            .any(|f| f.field == "summary.hurst_exponent"
                && f.severity == ValidationSeverity::Warning));
    }

    #[test]
    fn test_jitter_binding_validation_non_monotonic_percentiles() {
        let mut binding = create_test_binding();
        binding.summary.percentiles = [100.0, 50.0, 75.0, 80.0, 90.0];
        let findings = binding.validate();
        assert!(findings
            .iter()
            .any(|f| f.field == "summary.percentiles" && f.message.contains("not monotonic")));
    }

    #[test]
    fn test_validation_severity_distinction() {
        let mut binding = create_test_binding();
        binding.summary.entropy_bits = -1.0;
        binding.summary.hurst_exponent = Some(1.5);
        let findings = binding.validate();
        let warnings: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == ValidationSeverity::Warning)
            .collect();
        assert!(
            warnings.len() >= 2,
            "expected warnings for entropy_bits and hurst"
        );
        assert!(
            binding.is_valid(),
            "warnings alone should not fail is_valid()"
        );
    }
}
