// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Individual page section renderers for PDF reports (pages 2 and 3).

use super::layout::{
    fill_rect, text, wrap_text_lines, BLACK, CONTENT_WIDTH, GRAY, MARGIN_LEFT, PAGE_TOP,
};
use super::PdfFonts;
use crate::report::types::*;
use printpdf::*;

// ── Page 2 ────────────────────────────────────────────────────────────

pub fn draw_page2(layer: &PdfLayerReference, r: &WarReport, fonts: &PdfFonts) {
    let mut y = PAGE_TOP;

    // ── Session Timeline ──
    if !r.sessions.is_empty() {
        text(
            layer,
            "Session Timeline",
            10.0,
            MARGIN_LEFT,
            y,
            &fonts.bold,
            BLACK,
        );
        y -= 7.0;

        for s in &r.sessions {
            fill_rect(
                layer,
                MARGIN_LEFT,
                y - 3.0,
                CONTENT_WIDTH,
                10.0,
                (0.96, 0.96, 0.96),
            );
            // Green left border
            fill_rect(layer, MARGIN_LEFT, y - 3.0, 1.5, 10.0, (0.18, 0.49, 0.20));

            text(
                layer,
                &format!("Session {} — {:.0} min", s.index, s.duration_min),
                8.0,
                MARGIN_LEFT + 4.0,
                y + 2.0,
                &fonts.bold,
                BLACK,
            );
            text(
                layer,
                &s.summary,
                6.0,
                MARGIN_LEFT + 4.0,
                y - 2.0,
                &fonts.regular,
                GRAY,
            );
            y -= 14.0;
        }
    }
    y -= 4.0;

    // ── Process Evidence ──
    text(
        layer,
        "Writing Process Evidence",
        10.0,
        MARGIN_LEFT,
        y,
        &fonts.bold,
        BLACK,
    );
    y -= 7.0;

    let p = &r.process;
    let evidence_items: Vec<(&str, String)> = vec![
        (
            "Revision Intensity",
            p.revision_intensity
                .map(|v| format!("{:.2} edits/sentence", v))
                .unwrap_or_else(|| "—".into()),
        ),
        (
            "Pause Distribution",
            p.pause_median_sec
                .map(|v| {
                    let mut s = format!("Median: {:.1}s", v);
                    if let Some(p95) = p.pause_p95_sec {
                        s.push_str(&format!(" | P95: {:.1}s", p95));
                    }
                    s
                })
                .unwrap_or_else(|| "—".into()),
        ),
        (
            "Paste Ratio",
            p.paste_ratio_pct
                .map(|v| format!("{:.1}% of total text", v))
                .unwrap_or_else(|| "—".into()),
        ),
        (
            "Keystroke Dynamics",
            p.iki_cv
                .map(|v| {
                    let mut s = format!("IKI CV: {:.2}", v);
                    if let Some(bg) = p.bigram_consistency {
                        s.push_str(&format!(" | Bigram: {:.2}", bg));
                    }
                    s
                })
                .unwrap_or_else(|| "—".into()),
        ),
        (
            "Deletion Patterns",
            p.deletion_sequences
                .map(|v| {
                    let mut s = format!("{} sequences", v);
                    if let Some(avg) = p.avg_deletion_length {
                        s.push_str(&format!(" | Avg: {:.1} chars", avg));
                    }
                    s
                })
                .unwrap_or_else(|| "—".into()),
        ),
        (
            "Time Proofs",
            p.swf_checkpoints
                .map(|v| {
                    let mut s = format!("{} SWF checkpoints", v);
                    if p.swf_chain_verified {
                        s.push_str(" | Chain: verified");
                    }
                    s
                })
                .unwrap_or_else(|| "—".into()),
        ),
    ];

    let col_w = CONTENT_WIDTH / 2.0;
    for (i, (label, value)) in evidence_items.iter().enumerate() {
        let col = i % 2;
        let row = i / 2;
        let ex = MARGIN_LEFT + col as f32 * (col_w + 2.0);
        let ey = y - row as f32 * 14.0;

        fill_rect(layer, ex, ey - 4.0, col_w - 2.0, 12.0, (0.96, 0.96, 0.96));
        text(layer, label, 7.0, ex + 2.0, ey + 3.0, &fonts.bold, BLACK);
        text(layer, value, 6.5, ex + 2.0, ey - 1.5, &fonts.regular, GRAY);
    }
    y -= (evidence_items.len() as f32 / 2.0).ceil() * 14.0 + 6.0;

    // ── Analysis Flags ──
    if !r.flags.is_empty() {
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
        text(
            layer,
            &format!("Analysis Flags ({} positive, {} negative)", pos, neg),
            10.0,
            MARGIN_LEFT,
            y,
            &fonts.bold,
            BLACK,
        );
        y -= 6.0;

        // Table header
        text(
            layer,
            "CATEGORY",
            5.5,
            MARGIN_LEFT + 2.0,
            y,
            &fonts.bold,
            GRAY,
        );
        text(layer, "FLAG", 5.5, MARGIN_LEFT + 30.0, y, &fonts.bold, GRAY);
        text(
            layer,
            "SIGNAL",
            5.5,
            MARGIN_LEFT + 130.0,
            y,
            &fonts.bold,
            GRAY,
        );
        y -= 4.0;

        for f in &r.flags {
            let signal_color = match f.signal {
                FlagSignal::Human => (0.18_f32, 0.49, 0.20),
                FlagSignal::Synthetic => (0.78, 0.16, 0.16),
                FlagSignal::Neutral => (0.62, 0.62, 0.62),
            };
            let icon = match f.signal {
                FlagSignal::Human => "✓",
                FlagSignal::Synthetic => "✗",
                FlagSignal::Neutral => "—",
            };

            let category_display = if f.category.chars().count() > 40 {
                let truncated: String = f.category.chars().take(40).collect();
                format!("{truncated}...")
            } else {
                f.category.clone()
            };
            let flag_display = if f.flag.chars().count() > 60 {
                let truncated: String = f.flag.chars().take(60).collect();
                format!("{truncated}...")
            } else {
                f.flag.clone()
            };
            text(
                layer,
                &category_display,
                6.0,
                MARGIN_LEFT + 2.0,
                y,
                &fonts.regular,
                BLACK,
            );
            text(
                layer,
                &flag_display,
                6.0,
                MARGIN_LEFT + 30.0,
                y,
                &fonts.regular,
                BLACK,
            );
            text(
                layer,
                &format!("{} {}", icon, f.signal.label()),
                6.0,
                MARGIN_LEFT + 130.0,
                y,
                &fonts.bold,
                signal_color,
            );
            y -= 4.5;
        }
    }

    // Footer
    text(
        layer,
        &format!("CPOP Authorship Report | {} | Page 2", r.report_id),
        5.0,
        MARGIN_LEFT,
        10.0,
        &fonts.regular,
        GRAY,
    );
}

// ── Page 3 ────────────────────────────────────────────────────────────

pub fn draw_page3(layer: &PdfLayerReference, r: &WarReport, fonts: &PdfFonts) {
    let mut y = PAGE_TOP;

    // ── Scope & Limitations ──
    text(
        layer,
        "Scope and Limitations",
        10.0,
        MARGIN_LEFT,
        y,
        &fonts.bold,
        BLACK,
    );
    y -= 7.0;

    let supports = [
        "Evidence of human cognitive constraint patterns",
        "Stylometric consistency with natural authorship",
        "Documented methodology for dispute review",
        "Reproducible analysis (same text + algorithm = same results)",
    ];
    text(
        layer,
        "What This Report Supports:",
        7.0,
        MARGIN_LEFT + 2.0,
        y,
        &fonts.bold,
        BLACK,
    );
    y -= 4.0;
    for item in &supports {
        text(
            layer,
            &format!("• {}", item),
            6.0,
            MARGIN_LEFT + 4.0,
            y,
            &fonts.regular,
            BLACK,
        );
        y -= 4.0;
    }
    y -= 2.0;

    let does_not = [
        "Named author identity (requires additional evidence)",
        "AI was not used at any point in the process",
        "Text has not been edited, paraphrased, or translated",
        "Definitive attribution beyond reasonable doubt",
    ];
    text(
        layer,
        "What This Report Does NOT Prove:",
        7.0,
        MARGIN_LEFT + 2.0,
        y,
        &fonts.bold,
        BLACK,
    );
    y -= 4.0;
    for item in &does_not {
        text(
            layer,
            &format!("• {}", item),
            6.0,
            MARGIN_LEFT + 4.0,
            y,
            &fonts.regular,
            BLACK,
        );
        y -= 4.0;
    }
    y -= 6.0;

    // ── Verification Instructions ──
    text(
        layer,
        "How to Verify This Evidence",
        10.0,
        MARGIN_LEFT,
        y,
        &fonts.bold,
        BLACK,
    );
    y -= 8.0;

    // Offline box
    fill_rect(
        layer,
        MARGIN_LEFT,
        y - 20.0,
        CONTENT_WIDTH / 2.0 - 2.0,
        24.0,
        (0.96, 0.96, 0.96),
    );
    text(
        layer,
        "OFFLINE VERIFICATION",
        7.0,
        MARGIN_LEFT + 3.0,
        y,
        &fonts.bold,
        BLACK,
    );
    text(
        layer,
        "Extract WAR seal from PDF → verify Ed25519",
        5.5,
        MARGIN_LEFT + 3.0,
        y - 5.0,
        &fonts.regular,
        GRAY,
    );
    text(
        layer,
        "signature → verify enrollment cert chain",
        5.5,
        MARGIN_LEFT + 3.0,
        y - 9.0,
        &fonts.regular,
        GRAY,
    );
    text(
        layer,
        "Run: cpop verify <file.pdf>",
        6.0,
        MARGIN_LEFT + 3.0,
        y - 15.0,
        &fonts.mono,
        BLACK,
    );

    // Online box
    let ox = MARGIN_LEFT + CONTENT_WIDTH / 2.0 + 2.0;
    fill_rect(
        layer,
        ox,
        y - 20.0,
        CONTENT_WIDTH / 2.0 - 2.0,
        24.0,
        (0.96, 0.96, 0.96),
    );
    text(
        layer,
        "ONLINE VERIFICATION",
        7.0,
        ox + 3.0,
        y,
        &fonts.bold,
        BLACK,
    );
    text(
        layer,
        "All offline checks + transparency log",
        5.5,
        ox + 3.0,
        y - 5.0,
        &fonts.regular,
        GRAY,
    );
    text(
        layer,
        "anchor + certificate revocation check",
        5.5,
        ox + 3.0,
        y - 9.0,
        &fonts.regular,
        GRAY,
    );
    text(
        layer,
        "Scan QR or visit writerslogic.com/verify",
        6.0,
        ox + 3.0,
        y - 15.0,
        &fonts.mono,
        BLACK,
    );
    y -= 30.0;

    // ── Additional Limitations ──
    if !r.limitations.is_empty() {
        text(
            layer,
            "Additional Limitations:",
            7.0,
            MARGIN_LEFT + 2.0,
            y,
            &fonts.bold,
            BLACK,
        );
        y -= 4.0;
        for lim in &r.limitations {
            text(
                layer,
                &format!("• {}", lim),
                6.0,
                MARGIN_LEFT + 4.0,
                y,
                &fonts.regular,
                BLACK,
            );
            y -= 4.0;
        }
    }
    y -= 6.0;

    // ── Analyzed Text (if available) ──
    if let Some(ref analyzed) = r.analyzed_text {
        text(
            layer,
            "Analyzed Text",
            10.0,
            MARGIN_LEFT,
            y,
            &fonts.bold,
            BLACK,
        );
        y -= 3.0;
        text(
            layer,
            "Document hash verified against chain of custody record.",
            5.5,
            MARGIN_LEFT,
            y,
            &fonts.regular,
            GRAY,
        );
        y -= 5.0;

        fill_rect(
            layer,
            MARGIN_LEFT,
            y - 60.0,
            CONTENT_WIDTH,
            62.0,
            (0.98, 0.98, 0.98),
        );

        // Word-wrap the text into the box
        let mut ty = y - 2.0;
        for line in wrap_text_lines(analyzed, 100) {
            text(
                layer,
                &line,
                6.0,
                MARGIN_LEFT + 3.0,
                ty,
                &fonts.regular,
                BLACK,
            );
            ty -= 3.5;
            if ty < y - 58.0 {
                text(
                    layer,
                    "[continued...]",
                    5.5,
                    MARGIN_LEFT + 3.0,
                    ty,
                    &fonts.regular,
                    GRAY,
                );
                break;
            }
        }
    }

    // ── Disclaimer / Footer ──
    text(
        layer,
        "This report documents process analysis only. It does not constitute legal advice or definitive proof of authorship.",
        5.0,
        MARGIN_LEFT,
        15.0,
        &fonts.regular,
        GRAY,
    );
    text(
        layer,
        &format!(
            "CPOP Authorship Report | {} | {} | Page 3 | © {} WritersLogic",
            r.report_id,
            r.schema_version,
            r.generated_at.format("%Y"),
        ),
        5.0,
        MARGIN_LEFT,
        10.0,
        &fonts.regular,
        GRAY,
    );
}
