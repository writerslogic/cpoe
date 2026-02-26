// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Forensic authorship analysis module.
//!
//! Provides comprehensive analysis capabilities for detecting AI-generated content
//! and verifying human authorship through edit topology analysis, keystroke cadence
//! analysis, and profile correlation.

mod analysis;
mod assessment;
mod cadence;
mod comparison;
mod correlation;
mod engine;
pub mod error;
mod report;
mod topology;
pub mod types;
mod velocity;

// Re-export all public items to maintain API compatibility
pub use analysis::*;
pub use assessment::*;
pub use cadence::*;
pub use comparison::*;
pub use correlation::*;
pub use engine::*;
pub use error::*;
pub use report::*;
pub use topology::*;
pub use types::*;
pub use velocity::*;

#[cfg(test)]
mod tests;
