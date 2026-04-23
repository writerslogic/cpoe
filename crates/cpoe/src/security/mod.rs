// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Security hardening for evidence integrity: entropy validation and tampering detection.

pub mod entropy_validator;
pub mod tampering_detection;

pub use entropy_validator::{
    EntropyAssessment, EntropyValidator, KeystrokeSample, MIN_ENTROPY_BITS_DEFAULT,
};
pub use tampering_detection::{KeystrokeEvent, TamperingDetector, TamperingFlags};

#[cfg(test)]
mod tests;
