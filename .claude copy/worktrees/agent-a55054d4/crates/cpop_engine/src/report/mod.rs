

//! CPOP Authorship Report (WAR) generation.
//!
//! Produces self-contained HTML reports from evidence packets and forensic
//! analysis. Reports follow the WAR-v1.4 schema and ENFSI verbal equivalence
//! scale for likelihood ratios.

mod html;
mod types;

pub use html::render_html;
pub use types::*;
