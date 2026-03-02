// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Forensic authorship analysis: edit topology, keystroke cadence, and profile correlation.

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

// Re-export public items
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
