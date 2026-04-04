

//! IKI compression ratio analysis.
//!
//! Quantizes IKI intervals to milliseconds and measures information density
//! via byte-level entropy estimation. Highly compressible (low entropy) data
//! suggests LLM-like replay; incompressible (high entropy) suggests random noise.

use serde::{Deserialize, Serialize};

/
const LOW_RATIO_THRESHOLD: f64 = 0.2;

/
const HIGH_RATIO_THRESHOLD: f64 = 0.95;

/
const MIN_SAMPLES: usize = 50;

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IkiCompressionAnalysis {
    /
    pub ratio: f64,
    /
    pub flagged: bool,
}

/
/
/
/
/
pub fn analyze_iki_compression(iki_intervals_ns: &[f64]) -> Option<IkiCompressionAnalysis> {
    debug_assert!(
        !iki_intervals_ns.iter().any(|&v| v > 1_000_000_000_000.0),
        "IKI values exceed 10^12 ns (>1000s); likely invalid input"
    );
    if iki_intervals_ns.len() < MIN_SAMPLES {
        return None;
    }
    if iki_intervals_ns.iter().any(|x| !x.is_finite()) {
        return None;
    }

    
    let mut bytes = Vec::with_capacity(iki_intervals_ns.len() * 2);
    let mut negative_count = 0usize;
    for &iki_ns in iki_intervals_ns {
        let ms_f = (iki_ns / 1_000_000.0).round();
        if ms_f < 0.0 {
            negative_count += 1;
            continue;
        }
        let clamped = (ms_f as u64).min(u16::MAX as u64) as u16;
        bytes.extend_from_slice(&clamped.to_le_bytes());
    }
    if negative_count > 0 {
        log::warn!("IKI compression: skipped {negative_count} negative IKI value(s)");
    }

    if bytes.is_empty() {
        return None;
    }

    
    let mut freq = [0u64; 256];
    for &b in &bytes {
        freq[b as usize] += 1;
    }

    let total = bytes.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }

    
    let ratio = entropy / 8.0;

    let flagged = !(LOW_RATIO_THRESHOLD..=HIGH_RATIO_THRESHOLD).contains(&ratio);

    Some(IkiCompressionAnalysis { ratio, flagged })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_insufficient_data() {
        let data: Vec<f64> = (0..20).map(|i| i as f64 * 1_000_000.0).collect();
        assert!(analyze_iki_compression(&data).is_none());
    }

    #[test]
    fn test_compression_constant_data() {
        
        let data = vec![150_000_000.0; 100];
        let result = analyze_iki_compression(&data).unwrap();
        assert!(
            result.ratio < LOW_RATIO_THRESHOLD,
            "Constant data ratio={:.3} should be below {}",
            result.ratio,
            LOW_RATIO_THRESHOLD
        );
        assert!(result.flagged);
    }

    #[test]
    fn test_compression_varied_data() {
        
        let data: Vec<f64> = (0..200)
            .map(|i| {
                let base = 150_000_000.0;
                let variation = ((i as f64 * 0.3).sin() * 80_000_000.0)
                    + ((i as f64 * 1.7).cos() * 40_000_000.0)
                    + (i as f64 * 7.0 % 30.0) * 1_000_000.0;
                base + variation
            })
            .collect();
        let result = analyze_iki_compression(&data).unwrap();
        
        assert!(
            result.ratio >= LOW_RATIO_THRESHOLD && result.ratio <= HIGH_RATIO_THRESHOLD,
            "Varied data ratio={:.3} should be in range [{}, {}]",
            result.ratio,
            LOW_RATIO_THRESHOLD,
            HIGH_RATIO_THRESHOLD
        );
    }
}
