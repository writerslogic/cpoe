// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Content-keystroke correlation analysis.

use serde::{Deserialize, Serialize};
use std::fmt;

use super::types::{DEFAULT_EDIT_RATIO, INCONSISTENT_RATIO_THRESHOLD, SUSPICIOUS_RATIO_THRESHOLD};

/// Input for content-keystroke correlation analysis.
#[derive(Debug, Clone, Default)]
pub struct CorrelationInput {
    /// Final document size in bytes.
    pub document_length: i64,
    /// Total keystroke count.
    pub total_keystrokes: i64,
    /// Characters from detected pastes.
    pub detected_paste_chars: i64,
    /// Number of paste operations.
    pub detected_paste_count: i64,
    /// Characters from velocity-detected autocomplete.
    pub autocomplete_chars: i64,
    /// Number of suspicious velocity bursts.
    pub suspicious_bursts: usize,
    /// Actual edit ratio if known.
    pub actual_edit_ratio: Option<f64>,
}

/// Result of content-keystroke correlation analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    pub document_length: i64,
    pub total_keystrokes: i64,
    pub detected_paste_chars: i64,
    pub detected_paste_count: i64,
    pub effective_keystrokes: i64,
    pub expected_content: i64,
    pub discrepancy: i64,
    pub discrepancy_ratio: f64,
    pub autocomplete_chars: i64,
    pub suspicious_bursts: usize,
    pub status: CorrelationStatus,
    pub explanation: String,
    pub flags: Vec<CorrelationFlag>,
}

/// Correlation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CorrelationStatus {
    Consistent,
    Suspicious,
    Inconsistent,
    Insufficient,
}

impl fmt::Display for CorrelationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CorrelationStatus::Consistent => write!(f, "consistent"),
            CorrelationStatus::Suspicious => write!(f, "suspicious"),
            CorrelationStatus::Inconsistent => write!(f, "inconsistent"),
            CorrelationStatus::Insufficient => write!(f, "insufficient"),
        }
    }
}

/// Correlation flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CorrelationFlag {
    ExcessContent,
    UndetectedPaste,
    Autocomplete,
    NoKeystrokes,
    HighEditRatio,
    ExternalGenerated,
}

impl fmt::Display for CorrelationFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CorrelationFlag::ExcessContent => write!(f, "excess_content"),
            CorrelationFlag::UndetectedPaste => write!(f, "undetected_paste"),
            CorrelationFlag::Autocomplete => write!(f, "autocomplete"),
            CorrelationFlag::NoKeystrokes => write!(f, "no_keystrokes"),
            CorrelationFlag::HighEditRatio => write!(f, "high_edit_ratio"),
            CorrelationFlag::ExternalGenerated => write!(f, "external_generated"),
        }
    }
}

/// Content-keystroke correlator.
#[derive(Debug, Clone)]
pub struct ContentKeystrokeCorrelator {
    suspicious_ratio_threshold: f64,
    inconsistent_ratio_threshold: f64,
    estimated_edit_ratio: f64,
    min_keystrokes: i64,
    min_document_length: i64,
}

impl Default for ContentKeystrokeCorrelator {
    fn default() -> Self {
        Self {
            suspicious_ratio_threshold: SUSPICIOUS_RATIO_THRESHOLD,
            inconsistent_ratio_threshold: INCONSISTENT_RATIO_THRESHOLD,
            estimated_edit_ratio: DEFAULT_EDIT_RATIO,
            min_keystrokes: 10,
            min_document_length: 50,
        }
    }
}

impl ContentKeystrokeCorrelator {
    /// Creates a new correlator with default config.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a correlator with custom thresholds.
    pub fn with_thresholds(
        suspicious_threshold: f64,
        inconsistent_threshold: f64,
        edit_ratio: f64,
    ) -> Self {
        Self {
            suspicious_ratio_threshold: suspicious_threshold,
            inconsistent_ratio_threshold: inconsistent_threshold,
            estimated_edit_ratio: edit_ratio,
            ..Default::default()
        }
    }

    /// Performs correlation analysis.
    pub fn analyze(&self, input: &CorrelationInput) -> CorrelationResult {
        let mut result = CorrelationResult {
            document_length: input.document_length,
            total_keystrokes: input.total_keystrokes,
            detected_paste_chars: input.detected_paste_chars,
            detected_paste_count: input.detected_paste_count,
            effective_keystrokes: 0,
            expected_content: 0,
            discrepancy: 0,
            discrepancy_ratio: 0.0,
            autocomplete_chars: input.autocomplete_chars,
            suspicious_bursts: input.suspicious_bursts,
            status: CorrelationStatus::Insufficient,
            explanation: String::new(),
            flags: Vec::new(),
        };

        // Insufficient data check
        if input.total_keystrokes < self.min_keystrokes
            && input.document_length < self.min_document_length
        {
            result.explanation =
                "Insufficient data for meaningful correlation analysis".to_string();
            return result;
        }

        // Calculate effective keystrokes
        let edit_ratio = input.actual_edit_ratio.unwrap_or(self.estimated_edit_ratio);
        result.effective_keystrokes = (input.total_keystrokes as f64 * (1.0 - edit_ratio)) as i64;

        // Expected content
        result.expected_content =
            result.effective_keystrokes + input.detected_paste_chars + input.autocomplete_chars;

        // Handle edge case: no expected content
        if result.expected_content <= 0 {
            if input.document_length > 0 {
                result.status = CorrelationStatus::Inconsistent;
                result.explanation =
                    "Document has content but no keystroke/paste activity detected".to_string();
                result.flags.push(CorrelationFlag::NoKeystrokes);
                result.flags.push(CorrelationFlag::ExternalGenerated);
            } else {
                result.status = CorrelationStatus::Consistent;
                result.explanation = "Empty document with no activity".to_string();
            }
            return result;
        }

        // Calculate discrepancy
        result.discrepancy = input.document_length - result.expected_content;
        result.discrepancy_ratio = result.discrepancy as f64 / result.expected_content as f64;

        // Assess discrepancy
        self.assess_discrepancy(&mut result, input);

        result
    }

    fn assess_discrepancy(&self, result: &mut CorrelationResult, input: &CorrelationInput) {
        let abs_ratio = result.discrepancy_ratio.abs();

        // Check for suspicious velocity patterns
        if input.suspicious_bursts > 0 {
            result.flags.push(CorrelationFlag::Autocomplete);
        }

        // Positive discrepancy: more content than explained
        if result.discrepancy > 0 {
            if abs_ratio >= self.inconsistent_ratio_threshold {
                result.status = CorrelationStatus::Inconsistent;
                result.flags.push(CorrelationFlag::ExcessContent);

                let unexplained = result.discrepancy;
                if unexplained > 100 && input.detected_paste_count == 0 {
                    result.flags.push(CorrelationFlag::UndetectedPaste);
                    result.explanation = format!(
                        "Content exceeds expected by {} bytes ({:.0}%); likely undetected paste or external generation",
                        result.discrepancy, abs_ratio * 100.0
                    );
                } else if input.suspicious_bursts > 3 {
                    result.flags.push(CorrelationFlag::ExternalGenerated);
                    result.explanation = format!(
                        "Content exceeds expected by {} bytes ({:.0}%) with {} suspicious velocity bursts",
                        result.discrepancy, abs_ratio * 100.0, input.suspicious_bursts
                    );
                } else {
                    result.explanation = format!(
                        "Content exceeds expected by {} bytes ({:.0}%)",
                        result.discrepancy,
                        abs_ratio * 100.0
                    );
                }
            } else if abs_ratio >= self.suspicious_ratio_threshold {
                result.status = CorrelationStatus::Suspicious;
                result.explanation = format!(
                    "Minor discrepancy: content exceeds expected by {} bytes ({:.0}%)",
                    result.discrepancy,
                    abs_ratio * 100.0
                );
            } else {
                result.status = CorrelationStatus::Consistent;
                result.explanation =
                    "Content length is consistent with keystroke activity".to_string();
            }
            return;
        }

        // Negative discrepancy: less content than expected (heavy editing)
        if result.discrepancy < 0 {
            if abs_ratio >= self.suspicious_ratio_threshold {
                result.status = CorrelationStatus::Suspicious;
                result.flags.push(CorrelationFlag::HighEditRatio);
                result.explanation = format!(
                    "Document is {} bytes shorter than expected; indicates heavy editing ({:.0}% edit ratio)",
                    -result.discrepancy, abs_ratio * 100.0
                );
            } else {
                result.status = CorrelationStatus::Consistent;
                result.explanation =
                    "Content length is consistent with keystroke activity (normal editing)"
                        .to_string();
            }
            return;
        }

        // Perfect match
        result.status = CorrelationStatus::Consistent;
        result.explanation =
            "Content length exactly matches expected keystroke activity".to_string();
    }
}

/// Quick correlation check.
///
/// Returns true if content is suspicious (likely not human-typed).
pub fn quick_correlate(document_length: i64, keystrokes: i64, paste_chars: i64) -> bool {
    if keystrokes == 0 && document_length > 50 {
        return true;
    }

    let effective_keystrokes = (keystrokes as f64 * 0.85) as i64;
    let expected = effective_keystrokes + paste_chars;

    if expected <= 0 {
        return document_length > 50;
    }

    let discrepancy_ratio = (document_length - expected) as f64 / expected as f64;
    discrepancy_ratio > 0.5
}
