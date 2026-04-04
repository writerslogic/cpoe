

//! Signal-to-noise ratio analysis on inter-keystroke interval (IKI) data.
//!
//! Human typing produces a mix of low-frequency cadence patterns (signal)
//! and high-frequency jitter (noise). Synthetic input that is "too clean"
//! will have an abnormally high SNR across all windows.

use serde::{Deserialize, Serialize};

/
const SNR_SYNTHETIC_THRESHOLD_DB: f64 = 20.0;

/
const MAX_SNR_DB: f64 = 100.0;

/
const WINDOW_SIZE: usize = 32;

/
const MIN_SAMPLES: usize = 64;

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnrAnalysis {
    /
    pub snr_db: f64,
    /
    pub windowed_snr: Vec<f64>,
    /
    pub flagged: bool,
}

/
/
/
/
pub fn analyze_snr(iki_intervals_ns: &[f64]) -> Option<SnrAnalysis> {
    if iki_intervals_ns.len() < MIN_SAMPLES {
        return None;
    }
    if iki_intervals_ns.iter().any(|x| !x.is_finite()) {
        return None;
    }

    let windows: Vec<&[f64]> = iki_intervals_ns
        .windows(WINDOW_SIZE)
        .step_by(WINDOW_SIZE / 2)
        .collect();
    if windows.len() < 2 {
        return None;
    }

    let window_means: Vec<f64> = windows
        .iter()
        .map(|w| w.iter().sum::<f64>() / w.len() as f64)
        .collect();

    let window_variances: Vec<f64> = windows
        .iter()
        .zip(window_means.iter())
        .map(|(w, &mean)| w.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / w.len() as f64)
        .collect();

    
    let grand_mean = window_means.iter().sum::<f64>() / window_means.len() as f64;
    let signal_power = window_means
        .iter()
        .map(|&m| (m - grand_mean).powi(2))
        .sum::<f64>()
        / window_means.len() as f64;

    
    let noise_power = window_variances.iter().sum::<f64>() / window_variances.len() as f64;

    let snr_db = if noise_power > 0.0 {
        (10.0 * (signal_power / noise_power).log10()).clamp(-MAX_SNR_DB, MAX_SNR_DB)
    } else {
        MAX_SNR_DB
    };

    
    let windowed_snr: Vec<f64> = window_variances
        .iter()
        .map(|&var| {
            if var > 0.0 {
                (10.0 * (signal_power / var).log10()).clamp(-MAX_SNR_DB, MAX_SNR_DB)
            } else {
                MAX_SNR_DB
            }
        })
        .collect();

    let all_high = windowed_snr.iter().all(|&s| s > SNR_SYNTHETIC_THRESHOLD_DB);
    let flagged = all_high && snr_db > SNR_SYNTHETIC_THRESHOLD_DB;

    Some(SnrAnalysis {
        snr_db,
        windowed_snr,
        flagged,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snr_human_like_data() {
        
        let mut data = Vec::new();
        for i in 0..200 {
            let base = 150_000_000.0; 
            let jitter =
                ((i as f64 * 0.7).sin() * 50_000_000.0) + ((i as f64 * 2.3).cos() * 30_000_000.0);
            data.push(base + jitter);
        }
        let result = analyze_snr(&data).unwrap();
        
        assert!(
            !result.flagged,
            "Human-like data should not be flagged, SNR={:.1}",
            result.snr_db
        );
    }

    #[test]
    fn test_snr_too_few_samples() {
        let data: Vec<f64> = (0..30).map(|i| i as f64 * 1000.0).collect();
        assert!(analyze_snr(&data).is_none());
    }

    #[test]
    fn test_snr_robotic_constant() {
        
        let data: Vec<f64> = vec![100_000_000.0; 200];
        let result = analyze_snr(&data).unwrap();
        assert!(result.flagged, "Constant intervals should be flagged");
    }
}
