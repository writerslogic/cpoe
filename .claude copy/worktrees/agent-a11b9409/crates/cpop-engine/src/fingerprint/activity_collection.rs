

//! Ring-buffer accumulator for building fingerprints from streaming keystroke samples.

use super::activity::ActivityFingerprint;
use crate::jitter::SimpleJitterSample;
use crate::MutexRecover;
use cpop_protocol::baseline::SessionBehavioralSummary;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/
pub struct ActivityFingerprintAccumulator {
    samples: VecDeque<SimpleJitterSample>,
    max_samples: usize,
    cached_fingerprint: Mutex<ActivityFingerprint>,
    dirty: AtomicBool,
}

impl ActivityFingerprintAccumulator {
    /
    pub fn new() -> Self {
        Self::with_capacity(10000)
    }

    /
    pub fn to_session_summary(&self) -> SessionBehavioralSummary {
        let fp = self.current_fingerprint();

        
        let mut sum_hist = [0.0f64; 9];
        let h = &fp.iki_distribution.histogram;
        sum_hist[0] = h[0];
        sum_hist[1] = h[1];
        sum_hist[2] = h[2];
        sum_hist[3] = h[3];
        sum_hist[4] = h[4] + h[5];
        sum_hist[5] = h[6] + h[7] + h[8] + h[9];
        sum_hist[6] = h[10..20].iter().sum::<f64>();
        sum_hist[7] = h[20..40].iter().sum::<f64>();
        sum_hist[8] = h[40..50].iter().sum::<f64>();

        let duration_secs =
            if let (Some(first), Some(last)) = (self.samples.front(), self.samples.back()) {
                last.timestamp_ns.saturating_sub(first.timestamp_ns).max(0) as u64 / 1_000_000_000
            } else {
                0
            };

        SessionBehavioralSummary {
            iki_histogram: sum_hist,
            iki_cv: if fp.iki_distribution.mean > 0.0 {
                fp.iki_distribution.std_dev / fp.iki_distribution.mean
            } else {
                0.0
            },
            hurst: {
                let intervals: Vec<f64> = self
                    .samples
                    .iter()
                    .zip(self.samples.iter().skip(1))
                    .filter_map(|(a, b)| {
                        b.timestamp_ns
                            .checked_sub(a.timestamp_ns)
                            .map(|d| d as f64 / 1_000_000.0)
                    })
                    .filter(|&i| i > 0.0 && i < 5000.0)
                    .collect();
                if intervals.len() >= 20 {
                    crate::analysis::hurst::compute_hurst_rs(&intervals)
                        .map(|h| h.exponent)
                        .unwrap_or(0.5)
                } else {
                    0.5
                }
            },
            pause_frequency: fp.pause_signature.sentence_pause_frequency
                + fp.pause_signature.paragraph_pause_frequency
                + fp.pause_signature.thinking_pause_frequency,
            duration_secs,
            keystroke_count: self.samples.len() as u64,
        }
    }

    /
    pub fn with_capacity(max_samples: usize) -> Self {
        Self {
            samples: VecDeque::with_capacity(max_samples),
            max_samples,
            cached_fingerprint: Mutex::new(ActivityFingerprint::default()),
            dirty: AtomicBool::new(false),
        }
    }

    /
    pub fn add_sample(&mut self, sample: &SimpleJitterSample) {
        if self.samples.len() >= self.max_samples {
            self.samples.pop_front();
        }
        self.samples.push_back(sample.clone());
        self.dirty.store(true, Ordering::Relaxed);
    }

    /
    pub fn current_fingerprint(&self) -> ActivityFingerprint {
        let mut cached = self.cached_fingerprint.lock_recover();
        if self.dirty.load(Ordering::Relaxed) || cached.sample_count == 0 {
            let samples: Vec<_> = self.samples.iter().cloned().collect();
            *cached = ActivityFingerprint::from_samples(&samples);
            self.dirty.store(false, Ordering::Relaxed);
        }
        cached.clone()
    }

    /
    pub fn samples(&self) -> Vec<SimpleJitterSample> {
        self.samples.iter().cloned().collect()
    }

    /
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    /
    pub fn reset(&mut self) {
        self.samples.clear();
        *self.cached_fingerprint.lock_recover() = ActivityFingerprint::default();
        self.dirty.store(false, Ordering::Relaxed);
    }
}

impl Default for ActivityFingerprintAccumulator {
    fn default() -> Self {
        Self::new()
    }
}
