// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::helpers::*;
use crate::report::types::*;
use std::fmt::{self, Write};

/// Validate a CSS color value to prevent XSS injection via style attributes.
fn sanitize_css_color(color: &str) -> &str {
    let bytes = color.as_bytes();
    let valid = bytes.first() == Some(&b'#')
        && matches!(bytes.len(), 4 | 5 | 7 | 9)
        && bytes[1..].iter().all(|b| b.is_ascii_hexdigit());
    if valid {
        color
    } else {
        "#4a4a4a"
    }
}

// ---------------------------------------------------------------------------
// Document Header
// ---------------------------------------------------------------------------

pub(super) fn write_header(html: &mut String, r: &WarReport) -> fmt::Result {
    let sample = if r.is_sample {
        r#"<span class="sample-badge">SAMPLE</span>"#
    } else {
        ""
    };
    write!(
        html,
        r#"<h1>Forensic Authorship Examination Report{sample}</h1>
<p class="subtitle">
  Report {id} &ensp;|&ensp; Algorithm {alg} &ensp;|&ensp;
  Issued {ts} &ensp;|&ensp; Schema {schema}
</p>
"#,
        id = html_escape(&r.report_id),
        alg = html_escape(&r.algorithm_version),
        ts = r.generated_at.format("%B %-d, %Y at %H:%M:%S UTC"),
        schema = html_escape(&r.schema_version),
    )
}

// ---------------------------------------------------------------------------
// Examination Metadata
// ---------------------------------------------------------------------------

pub(super) fn write_examination_metadata(html: &mut String, r: &WarReport) -> fmt::Result {
    let doc_hash_short = if r.document_hash.len() > 16 {
        format!(
            "{}...{}",
            &r.document_hash[..8],
            &r.document_hash[r.document_hash.len().saturating_sub(8)..],
        )
    } else {
        r.document_hash.clone()
    };
    write!(
        html,
        r#"<div class="exam-meta">
<div><span class="meta-label">Report Reference</span><span class="meta-value">{id}</span></div>
<div><span class="meta-label">Date of Report</span><span class="meta-value">{date}</span></div>
<div><span class="meta-label">Examination System</span><span class="meta-value">CPOP Forensic Engine {alg}</span></div>
<div><span class="meta-label">Document Fingerprint</span><span class="meta-value"><code>{hash}</code></span></div>
<div><span class="meta-label">Evidence Sessions</span><span class="meta-value">{sessions} session{s_plural}, {dur:.0} min total</span></div>
<div><span class="meta-label">Reporting Standard</span><span class="meta-value">ENFSI Guideline for Evaluative Reporting (2015)</span></div>
</div>
"#,
        id = html_escape(&r.report_id),
        date = r.generated_at.format("%B %-d, %Y"),
        alg = html_escape(&r.algorithm_version),
        hash = html_escape(&doc_hash_short),
        sessions = r.session_count,
        s_plural = if r.session_count == 1 { "" } else { "s" },
        dur = r.total_duration_min,
    )
}

// ---------------------------------------------------------------------------
// Executive Summary
// ---------------------------------------------------------------------------

pub(super) fn write_executive_summary(html: &mut String, r: &WarReport) -> fmt::Result {
    let strength = match r.enfsi_tier {
        EnfsiTier::VeryStrong => "very strongly supports",
        EnfsiTier::Strong => "strongly supports",
        EnfsiTier::ModeratelyStrong => "moderately supports",
        EnfsiTier::Moderate => "provides moderate support for",
        EnfsiTier::Weak => "provides limited support for",
        EnfsiTier::Against => "does not support",
        EnfsiTier::Inconclusive => "is inconclusive regarding",
    };

    let human_flags = r
        .flags
        .iter()
        .filter(|f| f.signal == FlagSignal::Human)
        .count();
    let synthetic_flags = r
        .flags
        .iter()
        .filter(|f| f.signal == FlagSignal::Synthetic)
        .count();

    let duration_desc = if r.total_duration_min < 1.0 {
        "less than one minute".to_string()
    } else if r.total_duration_min < 60.0 {
        format!("approximately {:.0} minutes", r.total_duration_min)
    } else {
        let hours = r.total_duration_min / 60.0;
        format!("approximately {:.1} hours", hours)
    };

    let keystrokes_desc = r
        .process
        .total_keystrokes
        .map(|k| format!(", with {} keystrokes captured", format_number(k)))
        .unwrap_or_default();

    let checkpoint_desc = if r.checkpoints.is_empty() {
        String::new()
    } else {
        format!(
            " {} cryptographic checkpoints were recorded and verified.",
            r.checkpoints.len()
        )
    };

    let flag_desc = if synthetic_flags > 0 {
        format!(
            " The analysis identified {} behavioral indicator{} consistent with human authorship \
             and {} indicator{} of potential synthetic generation.",
            human_flags,
            if human_flags == 1 { "" } else { "s" },
            synthetic_flags,
            if synthetic_flags == 1 { "" } else { "s" },
        )
    } else if human_flags > 0 {
        format!(
            " The analysis identified {} behavioral indicator{} consistent with human authorship \
             and no indicators of synthetic generation.",
            human_flags,
            if human_flags == 1 { "" } else { "s" },
        )
    } else {
        String::new()
    };

    write!(
        html,
        r#"<div class="executive-summary">
<p>Based on forensic examination of the submitted document, the evidence {strength} the proposition that the text was composed through a human writing process. The document was produced across {sessions} writing session{s_plural} spanning {duration}{keystrokes}.{checkpoints}{flags}</p>
</div>
"#,
        sessions = r.session_count,
        s_plural = if r.session_count == 1 { "" } else { "s" },
        duration = duration_desc,
        keystrokes = keystrokes_desc,
        checkpoints = checkpoint_desc,
        flags = flag_desc,
    )
}

// ---------------------------------------------------------------------------
// Declaration of Findings
// ---------------------------------------------------------------------------

pub(super) fn write_verdict(html: &mut String, r: &WarReport) -> fmt::Result {
    let color = sanitize_css_color(r.verdict.css_color());
    let lr_display = format_lr(r.likelihood_ratio);
    write!(
        html,
        r#"<h2><span class="section-number">1.</span> Declaration of Findings</h2>
<div class="declaration" style="border-color:{color}">
  <div class="declaration-header">Examiner's Determination</div>
  <div class="declaration-body">
    <div class="declaration-score" style="color:{color}">{score}<small>of 100</small></div>
    <div class="declaration-text">
      <div class="verdict-label" style="color:{color}">{label}</div>
      <p>{desc}</p>
    </div>
    <div class="declaration-lr">
      <div class="lr-value">{lr}</div>
      <div class="lr-label">Likelihood Ratio</div>
      <div class="lr-tier">{tier}</div>
    </div>
  </div>
</div>
"#,
        score = r.score,
        label = r.verdict.label(),
        desc = html_escape(&r.verdict_description),
        lr = lr_display,
        tier = r.enfsi_tier.label(),
    )
}

pub(super) fn write_enfsi_scale(html: &mut String, r: &WarReport) -> fmt::Result {
    let tiers = [
        ("enfsi-against", "&lt;1 Against", EnfsiTier::Against),
        ("enfsi-weak", "1\u{2013}10 Weak", EnfsiTier::Weak),
        (
            "enfsi-moderate",
            "10\u{2013}100 Moderate",
            EnfsiTier::Moderate,
        ),
        (
            "enfsi-modstrong",
            "10\u{00b2}\u{2013}10\u{00b3} Mod. Strong",
            EnfsiTier::ModeratelyStrong,
        ),
        (
            "enfsi-strong",
            "10\u{00b3}\u{2013}10\u{2074} Strong",
            EnfsiTier::Strong,
        ),
        (
            "enfsi-vstrong",
            "\u{2265}10\u{2074} Very Strong",
            EnfsiTier::VeryStrong,
        ),
    ];
    write!(
        html,
        r#"<p class="enfsi-label">ENFSI Verbal Equivalence Scale (per ENFSI Guideline for Evaluative Reporting, 2015):</p>
<div class="enfsi-scale">"#
    )?;
    for (class, label, tier) in &tiers {
        let active = if *tier == r.enfsi_tier {
            " enfsi-active"
        } else {
            ""
        };
        write!(html, r#"<span class="{class}{active}">{label}</span>"#)?;
    }
    writeln!(html, "</div>")
}

pub(super) fn write_lr_interpretation(html: &mut String, r: &WarReport) -> fmt::Result {
    let lr = r.likelihood_ratio;
    if !lr.is_finite() || lr <= 0.0 {
        return Ok(());
    }

    let interpretation = if lr >= 1.0 {
        format!(
            "The observed behavioral evidence is approximately <strong>{}</strong> times more \
             probable under the hypothesis that the document was composed through a human writing \
             process (H\u{2081}) than under the hypothesis that it was generated or substantially \
             produced by automated means (H\u{2082}). On the ENFSI verbal equivalence scale, \
             this constitutes <strong>{}</strong> the proposition of human authorship.",
            format_lr(lr),
            r.enfsi_tier.label().to_lowercase(),
        )
    } else {
        format!(
            "The observed behavioral evidence is approximately <strong>{:.2}</strong> times as \
             probable under the hypothesis of human authorship (H\u{2081}) as under the \
             alternative (H\u{2082}). An LR below 1.0 means the evidence favors the alternative \
             hypothesis. On the ENFSI scale, this constitutes evidence <strong>against</strong> \
             the proposition of human authorship.",
            lr,
        )
    };

    write!(
        html,
        r#"<div class="lr-interpretation"><strong>Interpretation:</strong> {interpretation}</div>"#,
    )
}

pub(super) fn write_key_findings(html: &mut String, r: &WarReport) -> fmt::Result {
    write!(html, r#"<ol class="key-findings">"#)?;

    // Duration and session count
    write!(
        html,
        "<li><strong>Writing duration:</strong> {} session{}, {:.0} minutes of active composition, \
         {} revision events recorded.</li>",
        r.session_count,
        if r.session_count == 1 { "" } else { "s" },
        r.total_duration_min,
        format_number(r.revision_events),
    )?;

    // Keystroke capture
    if let Some(ks) = r.process.total_keystrokes {
        write!(
            html,
            "<li><strong>Keystroke capture:</strong> {} keystrokes recorded with timing data.",
            format_number(ks),
        )?;
        if let Some(cv) = r.process.iki_cv {
            write!(
                html,
                " Inter-keystroke interval CV of {:.2} {}.",
                cv,
                if cv > 0.3 {
                    "indicates variable, human-like typing rhythm"
                } else if cv > 0.15 {
                    "is within normal range for focused typing"
                } else {
                    "is unusually uniform and may warrant further review"
                },
            )?;
        }
        write!(html, "</li>")?;
    }

    // Checkpoints
    if !r.checkpoints.is_empty() {
        let verified = if r.process.swf_chain_verified {
            "integrity verified"
        } else {
            "integrity unverified"
        };
        write!(
            html,
            "<li><strong>Cryptographic checkpoints:</strong> {} checkpoints in tamper-evident chain, {}.",
            r.checkpoints.len(),
            verified,
        )?;
        if let Some(hrs) = r.process.swf_backdating_hours {
            write!(
                html,
                " Backdating cost: ~{:.0} hours sequential computation.",
                hrs,
            )?;
        }
        write!(html, "</li>")?;
    }

    // Paste ratio
    if let Some(pr) = r.process.paste_ratio_pct {
        let assessment = if pr < 5.0 {
            "minimal paste activity, consistent with original composition"
        } else if pr < 20.0 {
            "moderate paste activity, within normal editing range"
        } else if pr < 50.0 {
            "elevated paste activity; may include quoted material or self-editing"
        } else {
            "high paste ratio; document may contain substantial externally-sourced content"
        };
        write!(
            html,
            "<li><strong>Paste analysis:</strong> {:.1}% of text entered via paste ({}).</li>",
            pr, assessment,
        )?;
    }

    // Dimension concordance
    if !r.dimensions.is_empty() {
        let below = r.dimensions.iter().filter(|d| d.score < 40).count();
        if below == 0 {
            write!(
                html,
                "<li><strong>Dimension concordance:</strong> All {} analytical dimensions support \
                 the composite determination. No contradictory signals detected.</li>",
                r.dimensions.len(),
            )?;
        } else {
            write!(
                html,
                "<li><strong>Dimension concordance:</strong> {} of {} dimensions scored below \
                 threshold, indicating potential anomalies in those areas.</li>",
                below,
                r.dimensions.len(),
            )?;
        }
    }

    writeln!(html, "</ol>")
}

// ---------------------------------------------------------------------------
// Methodology (with explicit hypotheses)
// ---------------------------------------------------------------------------

pub(super) fn write_methodology(html: &mut String, r: &WarReport) -> fmt::Result {
    write!(
        html,
        r#"<h2><span class="section-number">2.</span> Methodology</h2>

<h3>Competing Hypotheses</h3>
<div class="hypotheses">
<div class="hypothesis">
  <div class="hyp-label">H&#8321; (Prosecution/Proponent Hypothesis)</div>
  <p>The submitted document was composed through a human writing process, exhibiting behavioral patterns characteristic of natural cognitive composition, including variable keystroke timing, iterative revision, and organic pause structures.</p>
</div>
<div class="hypothesis">
  <div class="hyp-label">H&#8322; (Alternative Hypothesis)</div>
  <p>The submitted document was generated or substantially produced by automated means (including but not limited to large language models), potentially with superficial human editing to mask its origin.</p>
</div>
</div>

<h3>Examination Procedure</h3>
<p>This examination was conducted using the Cryptographic Proof-of-Process (CPOP) protocol, an automated forensic system that captures behavioral telemetry during document creation. The system records keystroke dynamics, inter-keystroke timing intervals, revision patterns, application focus events, and cursor movements in real time. These observations are cryptographically bound to sequential checkpoints using Verifiable Delay Functions (VDFs), producing a tamper-evident evidentiary chain that can be independently verified by any party.</p>

<p style="margin-top:8px">The assessment score is derived from a multi-dimensional analysis comparing observed writing patterns against established distributions for human-authored and machine-generated text. Each analytical dimension produces an independent likelihood ratio (LR). The per-dimension LRs are combined under the assumption of conditional independence to produce a composite LR, which is then classified on the ENFSI verbal equivalence scale. This approach follows the framework described in the ENFSI Guideline for Evaluative Reporting in Forensic Science (2015) and is consistent with the principles of FRE 702 (Daubert) for the admissibility of expert testimony.</p>
"#
    )?;

    if let Some(ref m) = r.methodology {
        write!(
            html,
            r#"<div class="methodology-grid">
<div class="methodology-card"><h4>LR Computation</h4><p>{}</p></div>
<div class="methodology-card"><h4>Confidence Interval</h4><p>{}</p></div>
<div class="methodology-card"><h4>Calibration</h4><p>{}</p></div>
</div>"#,
            html_escape(&m.lr_computation),
            html_escape(&m.confidence_interval),
            html_escape(&m.calibration),
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Chain of Evidence
// ---------------------------------------------------------------------------

pub(super) fn write_chain_of_custody(html: &mut String, r: &WarReport) -> fmt::Result {
    write!(
        html,
        r#"<h2><span class="section-number">3.</span> Chain of Evidence</h2>
<p>The following identifiers establish the provenance and integrity of the evidence examined in this report. The document hash can be independently computed from the original file to confirm it matches the evidence record.</p>
<div class="info-box"><table>"#
    )?;

    row(html, "Document Hash (SHA-256)", &r.document_hash)?;
    row(html, "Signing Key Fingerprint", &r.signing_key_fingerprint)?;

    let mut doc_len = String::new();
    if let Some(w) = r.document_words {
        write!(doc_len, "{} words", format_number(w))?;
    }
    if let Some(c) = r.document_chars {
        if !doc_len.is_empty() {
            doc_len.push_str("  |  ");
        }
        write!(doc_len, "{} characters", format_number(c))?;
    }
    if let Some(s) = r.document_sentences {
        if !doc_len.is_empty() {
            doc_len.push_str("  |  ");
        }
        write!(doc_len, "{} sentences", format_number(s))?;
    }
    if !doc_len.is_empty() {
        row(html, "Document Metrics", &doc_len)?;
    }

    let bundle = format!(
        "{} | {} session{} | {:.0} min total | {} revision events",
        r.evidence_bundle_version,
        r.session_count,
        if r.session_count == 1 { "" } else { "s" },
        r.total_duration_min,
        format_number(r.revision_events),
    );
    row(html, "Evidence Bundle", &bundle)?;
    row(html, "Device Attestation", &r.device_attestation)?;

    writeln!(html, "</table></div>")
}

// ---------------------------------------------------------------------------
// Category Scores + Writing Flow
// ---------------------------------------------------------------------------

pub(super) fn write_category_scores(html: &mut String, r: &WarReport) -> fmt::Result {
    if r.dimensions.is_empty() {
        return Ok(());
    }
    write!(
        html,
        r#"<div class="category-scores"><div class="score-bars"><h3>Dimension Scores</h3>"#
    )?;
    for d in &r.dimensions {
        write!(
            html,
            r#"<div class="score-bar-row">
<span class="score-bar-label" style="color:{color}">{name}</span>
<div class="score-bar-track"><div class="score-bar-fill" style="width:{score}%;background:{color}"></div></div>
<span class="score-bar-value">{score}</span>
</div>"#,
            name = html_escape(&d.name),
            score = d.score.min(100),
            color = sanitize_css_color(&d.color),
        )?;
    }
    write_category_composite_note(html, r)?;
    write!(html, "</div>")?;

    if !r.writing_flow.is_empty() {
        write_writing_flow(html, r)?;
    }

    writeln!(html, "</div>")
}

fn write_category_composite_note(html: &mut String, r: &WarReport) -> fmt::Result {
    let all_pass = r.dimensions.iter().all(|d| d.score >= 60);
    let contradicts = r.dimensions.iter().any(|d| d.score < 40);
    if contradicts {
        write!(
            html,
            r#"<p class="composite-note">Note: One or more dimensions scored below the acceptance threshold, indicating potential anomalies requiring further examination.</p>"#,
        )
    } else if all_pass {
        write!(
            html,
            r#"<p class="composite-note">All dimensions exceed the minimum threshold of 60. No dimension contradicts the composite determination.</p>"#
        )
    } else {
        Ok(())
    }
}

fn write_writing_flow(html: &mut String, r: &WarReport) -> fmt::Result {
    write!(
        html,
        r#"<div><h3>Writing Flow (Fig. 1)</h3><div class="flow-chart">"#
    )?;
    let max_intensity = r
        .writing_flow
        .iter()
        .map(|p| p.intensity)
        .fold(0.0_f64, f64::max)
        .max(0.01);
    for point in &r.writing_flow {
        let pct = (point.intensity / max_intensity * 100.0).min(100.0);
        let color = match point.phase.as_str() {
            "drafting" => "#3d7a4a",
            "revising" => "#2c5282",
            "polish" => "#5b3c8b",
            "pause" => "#d8d8d5",
            _ => "#6b6b6b",
        };
        write!(
            html,
            r#"<div class="flow-bar" style="height:{pct:.0}%;background:{color}"></div>"#
        )?;
    }
    write!(html, "</div>")?;
    if let (Some(first), Some(last)) = (r.writing_flow.first(), r.writing_flow.last()) {
        write!(
            html,
            r#"<div class="flow-labels"><span>{:.0}:00</span><span style="color:#3d7a4a">Drafting</span><span style="color:#d8d8d5">Pause</span><span style="color:#2c5282">Revising</span><span style="color:#5b3c8b">Polish</span><span>{:.0}:{:02.0}</span></div>"#,
            first.offset_min,
            last.offset_min as u64,
            ((last.offset_min % 1.0) * 60.0) as u64,
        )?;
    }
    write!(
        html,
        r#"<p class="flow-caption">Fig. 1: Keystroke intensity over time. Irregular cadence with natural pauses is characteristic of human cognitive processing; automated input typically produces uniform intensity without semantic-boundary pauses.</p>"#
    )?;
    write!(html, "</div>")
}

// ---------------------------------------------------------------------------
// Process Evidence (dynamic notes based on actual values)
// ---------------------------------------------------------------------------

pub(super) fn write_process_evidence(html: &mut String, r: &WarReport) -> fmt::Result {
    let p = &r.process;
    write!(
        html,
        r#"<h2><span class="section-number">4.</span> Findings: Process Evidence</h2>
<p>The following metrics were captured by the CPOP proof daemon during the writing process. Each metric is derived from real-time behavioral observation and is cryptographically bound to the checkpoint chain (see Section 8).</p>
<div class="evidence-grid">"#
    )?;

    write_evidence_revision_intensity(html, p)?;
    write_evidence_pause_distribution(html, p)?;
    write_evidence_paste_ratio(html, p)?;
    write_evidence_keystroke_dynamics(html, p)?;
    write_evidence_deletion_patterns(html, p)?;
    write_evidence_swf(html, p)?;

    writeln!(html, "</div>")
}

fn write_evidence_revision_intensity(html: &mut String, p: &ProcessEvidence) -> fmt::Result {
    write!(
        html,
        r#"<div class="evidence-card"><h4>Exhibit A: Revision Intensity</h4>"#
    )?;
    if let Some(ri) = p.revision_intensity {
        write!(
            html,
            r#"<div class="metric">{:.2} edits/sentence</div>"#,
            ri
        )?;
        let note = if ri > 2.0 {
            "Heavy revision activity; consistent with careful drafting and self-editing."
        } else if ri > 0.5 {
            "Moderate revision activity; within the expected range for natural composition."
        } else if ri > 0.1 {
            "Light revision activity; may indicate fluent single-pass writing or dictation."
        } else {
            "Minimal revision detected; atypical for multi-paragraph human composition."
        };
        write!(html, r#"<div class="note">{note}</div>"#)?;
    }
    if let Some(ref bl) = p.revision_baseline {
        write!(
            html,
            r#"<div class="note">Baseline: {}</div>"#,
            html_escape(bl)
        )?;
    }
    write!(html, "</div>")
}

fn write_evidence_pause_distribution(html: &mut String, p: &ProcessEvidence) -> fmt::Result {
    write!(
        html,
        r#"<div class="evidence-card"><h4>Exhibit B: Pause Distribution</h4>"#
    )?;
    if let Some(med) = p.pause_median_sec {
        write!(html, r#"<div class="metric">Median: {:.1}s"#, med)?;
        if let Some(p95) = p.pause_p95_sec {
            write!(html, " | P95: {:.1}s", p95)?;
        }
        if let Some(max) = p.pause_max_sec {
            write!(html, " | Max: {:.0}s", max)?;
        }
        write!(html, "</div>")?;
        let note = if med > 0.5 && med < 5.0 {
            "Median pause duration falls within the range reported in published studies of human \
             composition (0.5-5.0s), consistent with cognitive planning between clauses."
        } else if med <= 0.5 {
            "Median pause duration is short; may indicate rapid transcription, dictation, \
             or highly rehearsed content."
        } else {
            "Median pause duration is long; may indicate deliberate composition, \
             research-interleaved writing, or multi-tasking."
        };
        write!(html, r#"<div class="note">{note}</div>"#)?;
    }
    write!(html, "</div>")
}

fn write_evidence_paste_ratio(html: &mut String, p: &ProcessEvidence) -> fmt::Result {
    write!(
        html,
        r#"<div class="evidence-card"><h4>Exhibit C: Paste Analysis</h4>"#
    )?;
    if let Some(pr) = p.paste_ratio_pct {
        write!(html, r#"<div class="metric">{:.1}% of total text"#, pr)?;
        if let Some(ops) = p.paste_operations {
            write!(html, " ({} operations)", ops)?;
        }
        write!(html, "</div>")?;
        let note = if pr < 5.0 {
            "Minimal paste activity. Virtually all text was entered keystroke-by-keystroke, \
             strongly indicative of original composition."
        } else if pr < 20.0 {
            "Moderate paste activity, within the normal range for authors who self-edit \
             by cutting and rearranging their own text."
        } else if pr < 50.0 {
            "Elevated paste ratio. May include quoted material, references, or \
             restructuring of previously-typed content."
        } else {
            "High paste ratio. A substantial portion of the document was entered via paste. \
             This may indicate external sourcing and warrants further investigation."
        };
        write!(html, r#"<div class="note">{note}</div>"#)?;
    }
    if let Some(max) = p.paste_max_chars {
        write!(
            html,
            r#"<div class="note">Largest single paste: {} characters.</div>"#,
            format_number(max)
        )?;
    }
    write!(html, "</div>")
}

fn write_evidence_keystroke_dynamics(html: &mut String, p: &ProcessEvidence) -> fmt::Result {
    write!(
        html,
        r#"<div class="evidence-card"><h4>Exhibit D: Keystroke Dynamics</h4>"#
    )?;
    if let Some(cv) = p.iki_cv {
        write!(html, r#"<div class="metric">IKI CV: {:.2}"#, cv)?;
        if let Some(bg) = p.bigram_consistency {
            write!(html, " | Bigram consistency: {:.2}", bg)?;
        }
        write!(html, "</div>")?;
        let note = if cv > 0.4 {
            "High inter-keystroke interval variability indicates natural, human-like typing \
             rhythm with variable cognitive load throughout the session."
        } else if cv > 0.2 {
            "Moderate IKI variability, within the normal range for focused human typing. \
             Behavioral fingerprint is consistent with single-author composition."
        } else if cv > 0.1 {
            "Low IKI variability. Typing rhythm is unusually regular, though still within \
             the range observed for skilled touch-typists on familiar material."
        } else {
            "Very low IKI variability. The typing rhythm is highly uniform, which is atypical \
             for human composition and more consistent with automated or replayed input."
        };
        write!(html, r#"<div class="note">{note}</div>"#)?;
    }
    if let Some(ks) = p.total_keystrokes {
        write!(
            html,
            r#"<div class="note">{} total keystrokes captured.</div>"#,
            format_number(ks)
        )?;
    }
    write!(html, "</div>")
}

fn write_evidence_deletion_patterns(html: &mut String, p: &ProcessEvidence) -> fmt::Result {
    write!(
        html,
        r#"<div class="evidence-card"><h4>Exhibit E: Deletion Patterns</h4>"#
    )?;
    if let Some(ds) = p.deletion_sequences {
        write!(
            html,
            r#"<div class="metric">{} sequences"#,
            format_number(ds)
        )?;
        if let Some(avg) = p.avg_deletion_length {
            write!(html, " | Avg {:.1} chars", avg)?;
        }
        if let Some(sd) = p.select_delete_ops {
            write!(html, " | {} select-delete ops", sd)?;
        }
        write!(html, "</div>")?;
        let note = if let Some(avg) = p.avg_deletion_length {
            if avg < 3.0 {
                "Short deletion sequences (1-3 characters) indicate real-time typo correction, \
                 a hallmark of keystroke-level human composition."
            } else if avg < 10.0 {
                "Mixed short and medium deletions suggest both typo correction and \
                 word/phrase-level revision during composition."
            } else {
                "Long average deletion length may indicate structural revision or \
                 paragraph-level rewriting."
            }
        } else {
            "Deletion sequences detected, indicating iterative refinement during composition."
        };
        write!(html, r#"<div class="note">{note}</div>"#)?;
    }
    write!(html, "</div>")
}

fn write_evidence_swf(html: &mut String, p: &ProcessEvidence) -> fmt::Result {
    write!(
        html,
        r#"<div class="evidence-card"><h4>Exhibit F: Verifiable Delay Functions</h4>"#
    )?;
    if let Some(count) = p.swf_checkpoints {
        write!(
            html,
            r#"<div class="metric">{} checkpoints"#,
            format_number(count)
        )?;
        if let Some(avg) = p.swf_avg_compute_ms {
            write!(html, " | {:.0}ms avg compute", avg)?;
        }
        let verified = if p.swf_chain_verified {
            "Verified"
        } else {
            "Unverified"
        };
        write!(html, " | Chain: {}", verified)?;
        write!(html, "</div>")?;
    }
    if let Some(hrs) = p.swf_backdating_hours {
        write!(
            html,
            r#"<div class="note">Each checkpoint contains a VDF proof that required real wall-clock time to compute. \
            Fabricating this evidence chain after the fact would require approximately {:.0} hours of sequential computation, \
            making backdating computationally infeasible for practical purposes.</div>"#,
            hrs
        )?;
    } else {
        write!(
            html,
            r#"<div class="note">VDF checkpoints provide cryptographic proof that writing occurred over real elapsed time. \
            The sequential nature of VDF computation prevents after-the-fact fabrication.</div>"#
        )?;
    }
    write!(html, "</div>")
}

// ---------------------------------------------------------------------------
// Session Timeline
// ---------------------------------------------------------------------------

pub(super) fn write_session_timeline(html: &mut String, r: &WarReport) -> fmt::Result {
    if r.sessions.is_empty() {
        return Ok(());
    }
    writeln!(
        html,
        r#"<h2><span class="section-number">5.</span> Session Timeline</h2>
<p>The document was composed across {} session{}, totaling approximately {:.0} minutes of active writing time.</p>"#,
        r.session_count,
        if r.session_count == 1 { "" } else { "s" },
        r.total_duration_min,
    )?;
    for s in &r.sessions {
        write!(
            html,
            r#"<div class="session-box">
<h4>Session {idx} &mdash; {dur:.0} min</h4>
<p>{start} &ensp;|&ensp; {events} events &ensp;|&ensp; {summary}</p>
</div>
"#,
            idx = s.index,
            dur = s.duration_min,
            start = s.start.format("%B %-d, %Y %H:%M UTC"),
            events = s.event_count,
            summary = html_escape(&s.summary),
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Dimension Analysis
// ---------------------------------------------------------------------------

pub(super) fn write_dimension_analysis(html: &mut String, r: &WarReport) -> fmt::Result {
    if r.dimensions.is_empty() {
        return Ok(());
    }
    writeln!(
        html,
        r#"<h2><span class="section-number">6.</span> Detailed Dimension Analysis</h2>
<p>Each analytical dimension is evaluated independently against both H\u{{2081}} and H\u{{2082}}. \
The per-dimension scores and likelihood ratios below contribute to the composite determination in Section 1.</p>"#
    )?;
    for d in &r.dimensions {
        if d.analysis.is_empty() {
            continue;
        }
        write!(
            html,
            r#"<div class="dimension-card">
<h3 style="color:{color}">{name}</h3>
<div class="dimension-badge" style="background:{color}">{score}</div>
"#,
            name = html_escape(&d.name),
            score = d.score,
            color = sanitize_css_color(&d.color),
        )?;
        for detail in &d.analysis {
            write!(
                html,
                r#"<p class="dimension-detail"><strong>{}:</strong> {}</p>"#,
                html_escape(&detail.label),
                html_escape(&detail.text),
            )?;
        }
        writeln!(html, "</div>")?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Statistical Analysis (LR table)
// ---------------------------------------------------------------------------

pub(super) fn write_dimension_lr_table(html: &mut String, r: &WarReport) -> fmt::Result {
    if r.dimensions.is_empty() {
        return Ok(());
    }
    writeln!(
        html,
        r#"<h2><span class="section-number">7.</span> Statistical Analysis: Per-Dimension Likelihood Ratios</h2>
<p>The likelihood ratio (LR) quantifies the evidential weight of each dimension. An LR greater than 1 supports H\u{{2081}} \
(human authorship); an LR less than 1 supports H\u{{2082}} (automated generation). The log<sub>10</sub>(LR) is provided \
for comparison with published forensic scales. See the Glossary (Section 15) for term definitions.</p>"#
    )?;
    write!(
        html,
        r#"<table class="data"><thead><tr><th>Dimension</th><th>Score</th><th>LR</th><th>Log<sub>10</sub> LR</th><th>Confidence</th><th>Key Discriminator</th></tr></thead><tbody>"#
    )?;
    for d in &r.dimensions {
        let conf_pct = (d.confidence * 100.0).min(100.0);
        write!(
            html,
            r#"<tr><td style="color:{color};font-weight:600">{name}</td><td>{score}</td><td>{lr}</td><td>{log_lr:.2}</td><td><div class="confidence-bar" style="width:{conf_pct:.0}px;background:{color}"></div></td><td>{disc}</td></tr>"#,
            name = html_escape(&d.name),
            score = d.score,
            lr = format_lr(d.lr),
            log_lr = d.log_lr,
            conf_pct = conf_pct,
            color = sanitize_css_color(&d.color),
            disc = html_escape(&d.key_discriminator),
        )?;
    }
    let combined_log = if r.likelihood_ratio > 0.0 {
        r.likelihood_ratio.log10()
    } else {
        0.0
    };
    write!(
        html,
        r#"</tbody><tfoot><tr style="font-weight:700;border-top:2px solid var(--rule)"><td>Combined</td><td>{score}</td><td>{lr}</td><td>{log_lr:.2}</td><td><div class="confidence-bar" style="width:{conf_pct:.0}px;background:#1a4d2e"></div></td><td>All dimensions concordant</td></tr></tfoot>"#,
        score = r.score,
        lr = format_lr(r.likelihood_ratio),
        log_lr = combined_log,
        conf_pct = (r.score as f64).min(100.0),
    )?;
    writeln!(html, "</table>")
}

// ---------------------------------------------------------------------------
// Checkpoint Chain Integrity
// ---------------------------------------------------------------------------

pub(super) fn write_checkpoint_chain(html: &mut String, r: &WarReport) -> fmt::Result {
    if r.checkpoints.is_empty() {
        return Ok(());
    }
    writeln!(
        html,
        r#"<h2><span class="section-number">8.</span> Checkpoint Chain Integrity</h2>
<p>Each checkpoint records a cryptographic hash of the document state at a point in time. The chain is linked by including \
the previous checkpoint's hash in each successive entry, forming a tamper-evident log. Any modification to a checkpoint \
invalidates all subsequent entries, making undetected alteration computationally infeasible.</p>"#
    )?;
    write!(
        html,
        r#"<table class="data"><thead><tr><th>#</th><th>Timestamp</th><th>Content Hash (SHA-256)</th><th>Size</th><th>VDF Iterations</th><th>Elapsed</th></tr></thead><tbody>"#
    )?;
    for cp in &r.checkpoints {
        let hash_short = if cp.content_hash.len() > 16 {
            format!(
                "{}...{}",
                cp.content_hash.get(..8).unwrap_or(&cp.content_hash),
                cp.content_hash
                    .get(cp.content_hash.len().saturating_sub(8)..)
                    .unwrap_or(&cp.content_hash),
            )
        } else {
            cp.content_hash.clone()
        };
        let vdf = cp
            .vdf_iterations
            .map(format_number)
            .unwrap_or_else(|| "\u{2014}".into());
        let elapsed = cp
            .elapsed_ms
            .map(|ms| format!("{:.1}s", ms as f64 / 1000.0))
            .unwrap_or_else(|| "\u{2014}".into());
        write!(
            html,
            "<tr><td>{ord}</td><td>{ts}</td><td><code>{hash}</code></td><td>{size}</td><td>{vdf}</td><td>{elapsed}</td></tr>",
            ord = cp.ordinal,
            ts = cp.timestamp.format("%H:%M:%S UTC"),
            hash = hash_short,
            size = format_bytes(cp.content_size),
        )?;
    }
    writeln!(html, "</tbody></table>")
}

// ---------------------------------------------------------------------------
// Forgery Resistance
// ---------------------------------------------------------------------------

pub(super) fn write_forgery_resistance(html: &mut String, r: &WarReport) -> fmt::Result {
    if r.forgery.components.is_empty() {
        return Ok(());
    }
    writeln!(
        html,
        r#"<h2><span class="section-number">9.</span> Forgery Resistance Assessment</h2>
<p>The following analysis estimates the computational cost an adversary would incur to fabricate evidence equivalent to \
that presented in this report. Higher costs indicate stronger resistance to forgery.</p>"#
    )?;
    write!(html, r#"<div class="info-box"><table>"#)?;
    row(html, "Resistance Tier", &r.forgery.tier)?;
    let forge_time = format_duration_human(r.forgery.estimated_forge_time_sec);
    row(html, "Estimated Forge Time", &forge_time)?;
    if let Some(ref weak) = r.forgery.weakest_link {
        row(html, "Weakest Component", weak)?;
    }
    writeln!(html, "</table></div>")?;

    write!(
        html,
        r#"<table class="data"><thead><tr><th>Component</th><th>Present</th><th>CPU Cost</th><th>Explanation</th></tr></thead><tbody>"#
    )?;
    for c in &r.forgery.components {
        let present = if c.present {
            r#"<span style="color:var(--accent)">&#10003; Yes</span>"#
        } else {
            r#"<span style="color:var(--alert)">&#10007; No</span>"#
        };
        let cost = if c.cost_cpu_sec.is_infinite() {
            "Computationally infeasible".to_string()
        } else {
            format_duration_human(c.cost_cpu_sec)
        };
        write!(
            html,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&c.name),
            present,
            cost,
            html_escape(&c.explanation),
        )?;
    }
    writeln!(html, "</tbody></table>")
}

// ---------------------------------------------------------------------------
// Analysis Flags
// ---------------------------------------------------------------------------

pub(super) fn write_flags(html: &mut String, r: &WarReport) -> fmt::Result {
    if r.flags.is_empty() {
        return Ok(());
    }
    let pos = r
        .flags
        .iter()
        .filter(|f| f.signal == FlagSignal::Human)
        .count();
    let neg = r
        .flags
        .iter()
        .filter(|f| f.signal == FlagSignal::Synthetic)
        .count();
    writeln!(
        html,
        r#"<h2><span class="section-number">10.</span> Analysis Flags ({} human, {} synthetic)</h2>
<p>The following behavioral signals were detected during analysis. Human indicators corroborate H\u{{2081}}; \
synthetic indicators, if present, corroborate H\u{{2082}} and may warrant further investigation.</p>"#,
        pos, neg
    )?;
    write!(
        html,
        r#"<table class="data"><thead><tr><th>Category</th><th>Finding</th><th>Detail</th><th>Signal</th></tr></thead><tbody>"#
    )?;
    for f in &r.flags {
        let class = match f.signal {
            FlagSignal::Human => "flag-human",
            FlagSignal::Synthetic => "flag-synthetic",
            FlagSignal::Neutral => "flag-neutral",
        };
        let icon = match f.signal {
            FlagSignal::Human => "&#10003;",
            FlagSignal::Synthetic => "&#10007;",
            FlagSignal::Neutral => "&mdash;",
        };
        write!(
            html,
            r#"<tr><td>{cat}</td><td>{flag}</td><td>{detail}</td><td class="{class}">{icon} {label}</td></tr>"#,
            cat = html_escape(&f.category),
            flag = html_escape(&f.flag),
            detail = html_escape(&f.detail),
            label = f.signal.label(),
        )?;
    }
    writeln!(html, "</tbody></table>")
}

// ---------------------------------------------------------------------------
// Scope, Limitations, Admissibility
// ---------------------------------------------------------------------------

pub(super) fn write_scope(html: &mut String, r: &WarReport) -> fmt::Result {
    write!(
        html,
        r#"<h2><span class="section-number">11.</span> Scope, Limitations, and Admissibility</h2>
<div class="scope-grid">
<div>
<h3>This Examination Supports:</h3>
<ul>
<li>Evidence of human cognitive constraint patterns during composition</li>
<li>Stylometric and behavioral consistency with natural authorship</li>
<li>Documented, reproducible methodology suitable for dispute review</li>
<li>Cryptographic chain-of-custody from creation through examination</li>
</ul>
<h3>This Examination Does Not Establish:</h3>
<ul>
<li>The identity of the specific author (requires supplementary evidence)</li>
<li>That AI-assisted tools were never used during any phase of writing</li>
<li>That the text has not been subsequently edited, paraphrased, or translated</li>
<li>Definitive attribution beyond all reasonable doubt</li>
</ul>
</div>
<div>
<h3>Factors That May Affect Results:</h3>
<ul>
<li>Substantial post-hoc editing or translation of original text</li>
<li>Genre transitions (e.g., technical to creative writing mid-document)</li>
<li>Use of templates, outlines, or highly structured prompts</li>
<li>Collaborative or multi-author composition</li>
<li>Documents shorter than 200 words (reduced statistical power)</li>
</ul>
<h3>Evidentiary Standards:</h3>
<ul>
<li>Methodology consistent with FRE 702 (Daubert) reliability factors</li>
<li>Evidence generated by automated, verified process per FRE 902(13)/902(14)</li>
<li>Hash chain provides tamper-evident integrity under FRE 901(b)(9)</li>
<li>ENFSI-compliant evaluative reporting per European forensic science guidelines</li>
</ul>
</div>
</div>
"#
    )?;

    if !r.limitations.is_empty() {
        write!(
            html,
            r#"<h3>Additional Limitations Specific to This Examination:</h3><ul>"#
        )?;
        for lim in &r.limitations {
            write!(html, "<li>{}</li>", html_escape(lim))?;
        }
        writeln!(html, "</ul>")?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Analyzed Text
// ---------------------------------------------------------------------------

pub(super) fn write_analyzed_text(html: &mut String, r: &WarReport) -> fmt::Result {
    if let Some(ref text) = r.analyzed_text {
        write!(
            html,
            r#"<h2><span class="section-number">12.</span> Analyzed Text</h2>
<p>The following text was submitted for examination. Its SHA-256 hash has been verified against the chain-of-evidence record in Section 3.</p>
<div class="analyzed-text">{}</div>
"#,
            html_escape(text)
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Verification Instructions
// ---------------------------------------------------------------------------

pub(super) fn write_verification_instructions(html: &mut String) -> fmt::Result {
    write!(
        html,
        r#"<h2><span class="section-number">13.</span> Independent Verification</h2>
<p>The cryptographic evidence underlying this report can be independently verified by any party without reliance on the examiner or issuing organization:</p>
<ul style="margin:8px 0 8px 18px;font-size:12.5px;color:var(--text-secondary)">
<li><strong>Web verification:</strong> Upload the evidence file at <a href="https://writerslogic.com/verify" target="_blank" rel="noopener noreferrer">writerslogic.com/verify</a>. Verification executes entirely in the browser; no data is transmitted to the server.</li>
<li><strong>Command-line verification:</strong> Install the open-source CPOP tool and execute <code>cpop verify &lt;evidence-file&gt;</code>.</li>
<li><strong>Manual verification:</strong> The checkpoint chain hashes can be recomputed from the raw evidence data using SHA-256. VDF proofs can be verified by re-executing the delay function for the claimed number of iterations.</li>
</ul>
<p style="font-size:12px;color:var(--text-muted);font-style:italic">Verification confirms: cryptographic signatures, checkpoint chain integrity, VDF timing proof consistency, and behavioral metric plausibility.</p>
"#,
    )
}

// ---------------------------------------------------------------------------
// Glossary
// ---------------------------------------------------------------------------

pub(super) fn write_glossary(html: &mut String) -> fmt::Result {
    write!(
        html,
        r##"<h2><span class="section-number">14.</span> Glossary of Terms</h2>
<dl class="glossary">
<div class="glossary-entry"><dt>Assessment Score</dt>
<dd>A composite metric (0-100) derived from all analytical dimensions. Higher scores indicate stronger evidence of human authorship. The score is converted to a likelihood ratio for statistical interpretation.</dd></div>

<div class="glossary-entry"><dt>Bigram Consistency</dt>
<dd>A measure of how stable the timing patterns are between specific pairs of consecutive keystrokes (e.g., "th", "er"). Higher values indicate the author has a consistent, practiced typing style.</dd></div>

<div class="glossary-entry"><dt>CPOP (Cryptographic Proof-of-Process)</dt>
<dd>The protocol used to capture and cryptographically bind behavioral evidence during document creation. Defined in draft-condrey-rats-pop.</dd></div>

<div class="glossary-entry"><dt>ENFSI Verbal Equivalence Scale</dt>
<dd>A standardized scale for expressing the strength of forensic evidence, published by the European Network of Forensic Science Institutes (2015). Ranges from "Against" (LR &lt; 1) through "Very Strong Support" (LR &ge; 10,000).</dd></div>

<div class="glossary-entry"><dt>H&#8321; / H&#8322;</dt>
<dd>The two competing hypotheses under evaluation. H&#8321; (proponent): the document was composed through a human writing process. H&#8322; (alternative): the document was generated or substantially produced by automated means.</dd></div>

<div class="glossary-entry"><dt>IKI CV (Inter-Keystroke Interval Coefficient of Variation)</dt>
<dd>The coefficient of variation of time intervals between consecutive keystrokes. Higher values indicate more variable (human-like) typing rhythm; very low values (&lt;0.10) suggest automated or replayed input.</dd></div>

<div class="glossary-entry"><dt>Likelihood Ratio (LR)</dt>
<dd>The ratio of the probability of observing the evidence under H&#8321; to the probability under H&#8322;. An LR of 100 means the evidence is 100 times more probable if the document was human-authored than if it was machine-generated.</dd></div>

<div class="glossary-entry"><dt>Log&#8321;&#8320;(LR)</dt>
<dd>The base-10 logarithm of the likelihood ratio. A log-LR of 2.0 corresponds to LR = 100; a log-LR of 4.0 corresponds to LR = 10,000.</dd></div>

<div class="glossary-entry"><dt>SHA-256</dt>
<dd>A cryptographic hash function producing a 256-bit (32-byte) digest. Used throughout CPOP for document fingerprinting, checkpoint chaining, and integrity verification. Any change to the input produces a completely different hash.</dd></div>

<div class="glossary-entry"><dt>VDF (Verifiable Delay Function)</dt>
<dd>A cryptographic function that requires a specified amount of sequential computation to evaluate, but whose output can be quickly verified. Used in CPOP to prove that checkpoints were created at real wall-clock intervals, preventing after-the-fact fabrication of evidence.</dd></div>
</dl>
"##,
    )
}

// ---------------------------------------------------------------------------
// Certification (footer)
// ---------------------------------------------------------------------------

pub(super) fn write_footer(html: &mut String, r: &WarReport) -> fmt::Result {
    write!(
        html,
        r#"<div class="report-footer">
<p class="certification">This report was generated by an automated forensic examination system using standardized, reproducible methodology. Applying the same algorithm version to the same evidence will produce identical results. This report documents process analysis only; it does not constitute legal advice, and the determination herein should be evaluated alongside all other available evidence by the trier of fact.</p>
<p>Forensic Authorship Examination Report &ensp;|&ensp; {id} &ensp;|&ensp; Algorithm {alg} &ensp;|&ensp; Schema {schema}<br>
&copy; {year} WritersLogic, LLC. All rights reserved. CPOP Protocol per draft-condrey-rats-pop.</p>
</div>
"#,
        id = html_escape(&r.report_id),
        alg = html_escape(&r.algorithm_version),
        schema = html_escape(&r.schema_version),
        year = r.generated_at.format("%Y"),
    )
}
