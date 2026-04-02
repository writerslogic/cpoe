// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

mod css;
mod helpers;
mod sections;

use super::types::*;
use std::fmt::Write;

/// Render a self-contained HTML report from a `WarReport`.
pub fn render_html(r: &WarReport) -> String {
    let mut html = String::with_capacity(40_000);
    let _ = render_html_inner(&mut html, r);
    html
}

fn render_html_inner(html: &mut String, r: &WarReport) -> std::fmt::Result {
    css::write_head(html, r)?;

    // 1. Document identification
    sections::write_header(html, r)?;

    // 2. Declaration of findings (verdict + ENFSI scale)
    sections::write_verdict(html, r)?;
    sections::write_enfsi_scale(html, r)?;

    // 3. Methodology
    sections::write_methodology(html, r)?;

    // 4. Chain of evidence
    sections::write_chain_of_custody(html, r)?;

    // 5. Category scores + writing flow visualization
    sections::write_category_scores(html, r)?;

    // 6. Findings: process evidence (exhibits A-F)
    sections::write_process_evidence(html, r)?;

    // 7. Session timeline
    sections::write_session_timeline(html, r)?;

    // 8. Detailed dimension analysis
    sections::write_dimension_analysis(html, r)?;

    // 9. Statistical analysis: per-dimension LR table
    sections::write_dimension_lr_table(html, r)?;

    // 10. Checkpoint chain integrity
    sections::write_checkpoint_chain(html, r)?;

    // 11. Forgery resistance assessment
    sections::write_forgery_resistance(html, r)?;

    // 12. Analysis flags
    sections::write_flags(html, r)?;

    // 13. Scope, limitations, and admissibility
    sections::write_scope(html, r)?;

    // 14. Analyzed text (if included)
    sections::write_analyzed_text(html, r)?;

    // 15. Independent verification instructions
    sections::write_verification_instructions(html)?;

    // 16. Certification
    sections::write_footer(html, r)?;

    write!(html, "</div></body></html>")
}
