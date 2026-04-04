

//! Page layout and text placement for PDF reports.

use super::charts;
use super::security;
use super::PdfFonts;
use crate::report::types::*;
use printpdf::*;

/
pub(super) fn wrap_text_lines(text: &str, max_chars: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.is_empty() {
            current_line.push_str(word);
        } else if current_line.len() + 1 + word.len() > max_chars {
            lines.push(std::mem::take(&mut current_line));
            current_line.push_str(word);
        } else {
            current_line.push(' ');
            current_line.push_str(word);
        }
    }
    if !current_line.is_empty() {
        lines.push(current_line);
    }
    lines
}

pub(super) const MARGIN_LEFT: f32 = 20.0;

#[allow(dead_code)]
pub(super) const MARGIN_RIGHT: f32 = 190.0;
pub(super) const PAGE_TOP: f32 = 280.0;
pub(super) const CONTENT_WIDTH: f32 = 170.0;

/
fn tier_color(tier: &str) -> (f32, f32, f32) {
    match tier {
        "T1" => (0.62, 0.62, 0.62), 
        "T2" => (0.13, 0.59, 0.95), 
        "T3" => (0.18, 0.49, 0.20), 
        "T4" => (0.83, 0.68, 0.21), 
        _ => (0.62, 0.62, 0.62),
    }
}

fn verdict_color(verdict: &Verdict) -> (f32, f32, f32) {
    match verdict {
        Verdict::VerifiedHuman => (0.18, 0.49, 0.20),
        Verdict::LikelyHuman => (0.34, 0.55, 0.18),
        Verdict::Inconclusive => (0.96, 0.50, 0.09),
        Verdict::Suspicious => (0.90, 0.32, 0.00),
        Verdict::LikelySynthetic => (0.72, 0.11, 0.11),
    }
}

/
fn dimension_color(name: &str) -> (f32, f32, f32) {
    match name.to_lowercase().as_str() {
        "temporal" => (0.13, 0.59, 0.95),
        "behavioral" => (0.30, 0.69, 0.31),
        "linguistic" => (0.61, 0.15, 0.69),
        "structural" => (1.00, 0.60, 0.00),
        _ => (0.47, 0.56, 0.61),
    }
}

/
pub(super) fn fill_rect(
    layer: &PdfLayerReference,
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    color: (f32, f32, f32),
) {
    layer.set_fill_color(Color::Rgb(Rgb::new(color.0, color.1, color.2, None)));
    layer.add_rect(Rect::new(Mm(x), Mm(y), Mm(x + w), Mm(y + h)));
}

/
pub(super) fn stroke_rect(
    layer: &PdfLayerReference,
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    thickness: f32,
    color: (f32, f32, f32),
) {
    layer.set_outline_color(Color::Rgb(Rgb::new(color.0, color.1, color.2, None)));
    layer.set_outline_thickness(thickness);
    
    layer.set_fill_color(Color::Rgb(Rgb::new(1.0, 1.0, 1.0, None)));
    layer.add_rect(Rect::new(Mm(x), Mm(y), Mm(x + w), Mm(y + h)));
}

/
pub(super) fn draw_card(layer: &PdfLayerReference, x: f32, y: f32, w: f32, h: f32) {
    
    fill_rect(layer, x + 0.5, y - 0.5, w, h, (0.93, 0.93, 0.93));
    
    fill_rect(layer, x, y, w, h, WHITE);
    
    stroke_rect(layer, x, y, w, h, 0.3, (0.88, 0.88, 0.88));
}

/
pub(super) fn text(
    layer: &PdfLayerReference,
    s: &str,
    size: f32,
    x: f32,
    y: f32,
    font: &IndirectFontRef,
    color: (f32, f32, f32),
) {
    layer.set_fill_color(Color::Rgb(Rgb::new(color.0, color.1, color.2, None)));
    layer.use_text(s, size, Mm(x), Mm(y), font);
}

pub(super) const BLACK: (f32, f32, f32) = (0.13, 0.13, 0.13);
pub(super) const GRAY: (f32, f32, f32) = (0.38, 0.38, 0.38);
pub(super) const WHITE: (f32, f32, f32) = (1.0, 1.0, 1.0);



pub fn draw_page1(
    layer: &PdfLayerReference,
    r: &WarReport,
    fonts: &PdfFonts,
    security_seed: Option<&[u8; 64]>,
) {
    let mut y = PAGE_TOP;

    
    text(
        layer,
        "Written Authorship Report",
        18.0,
        MARGIN_LEFT,
        y,
        &fonts.bold,
        BLACK,
    );
    y -= 6.0;

    
    let subtitle = format!(
        "Report {} | Algorithm {} | {}",
        r.report_id,
        r.algorithm_version,
        r.generated_at.format("%B %-d, %Y"),
    );
    text(layer, &subtitle, 7.5, MARGIN_LEFT, y, &fonts.regular, GRAY);
    y -= 4.0;

    if r.is_sample {
        text(
            layer,
            "SAMPLE",
            7.0,
            MARGIN_LEFT + 140.0,
            y + 4.0,
            &fonts.bold,
            GRAY,
        );
    }

    
    if let Some(_seed) = security_seed {
        let micro = format!(
            "{} · {}",
            r.report_id,
            r.document_hash.get(..16).unwrap_or("")
        );
        security::draw_microtext(layer, &fonts.mono, y, &micro, 210.0);
    }
    y -= 6.0;

    
    
    let tier_label = match r.score {
        80..=100 => "T4",
        60..=79 => "T3",
        40..=59 => "T2",
        _ => "T1",
    };
    let tc = tier_color(tier_label);
    fill_rect(layer, MARGIN_LEFT, y - 2.0, 30.0, 12.0, tc);
    text(
        layer,
        tier_label,
        12.0,
        MARGIN_LEFT + 3.0,
        y,
        &fonts.bold,
        WHITE,
    );
    let tier_name = match tier_label {
        "T1" => "BASIC",
        "T2" => "STANDARD",
        "T3" => "ENHANCED",
        "T4" => "MAXIMUM",
        _ => "",
    };
    text(
        layer,
        tier_name,
        8.0,
        MARGIN_LEFT + 14.0,
        y + 1.0,
        &fonts.bold,
        WHITE,
    );
    y -= 16.0;

    
    let vc = verdict_color(&r.verdict);
    
    fill_rect(
        layer,
        MARGIN_LEFT + 0.5,
        y - 4.5,
        CONTENT_WIDTH,
        22.0,
        (0.93, 0.93, 0.93),
    );
    
    fill_rect(layer, MARGIN_LEFT, y - 4.0, CONTENT_WIDTH, 22.0, WHITE);
    
    stroke_rect(
        layer,
        MARGIN_LEFT,
        y - 4.0,
        CONTENT_WIDTH,
        22.0,
        0.3,
        (0.85, 0.85, 0.85),
    );
    
    fill_rect(layer, MARGIN_LEFT, y - 4.0, 4.0, 22.0, vc);

    
    text(
        layer,
        &format!("{}", r.score),
        28.0,
        MARGIN_LEFT + 8.0,
        y + 4.0,
        &fonts.bold,
        BLACK,
    );
    text(
        layer,
        "/ 100",
        9.0,
        MARGIN_LEFT + 26.0,
        y + 4.0,
        &fonts.regular,
        GRAY,
    );

    
    text(
        layer,
        r.verdict.label(),
        12.0,
        MARGIN_LEFT + 46.0,
        y + 8.0,
        &fonts.bold,
        BLACK,
    );
    text(
        layer,
        r.verdict.subtitle(),
        7.5,
        MARGIN_LEFT + 46.0,
        y + 2.0,
        &fonts.regular,
        GRAY,
    );

    
    let lr_str = if r.likelihood_ratio >= 100.0 {
        format!("{:.0}", r.likelihood_ratio)
    } else {
        format!("{:.1}", r.likelihood_ratio)
    };
    text(
        layer,
        &lr_str,
        16.0,
        MARGIN_LEFT + 140.0,
        y + 8.0,
        &fonts.bold,
        BLACK,
    );
    text(
        layer,
        "LR",
        6.0,
        MARGIN_LEFT + 140.0,
        y + 2.0,
        &fonts.regular,
        GRAY,
    );
    text(
        layer,
        r.enfsi_tier.label(),
        6.0,
        MARGIN_LEFT + 150.0,
        y + 2.0,
        &fonts.regular,
        GRAY,
    );
    y -= 28.0;

    
    text(
        layer,
        "ENFSI Verbal Equivalence Scale:",
        6.0,
        MARGIN_LEFT,
        y + 2.0,
        &fonts.regular,
        GRAY,
    );
    y -= 4.0;
    let tiers = [
        ("<1", (0.78_f32, 0.16, 0.16), EnfsiTier::Against),
        ("1-10", (0.90, 0.32, 0.00), EnfsiTier::Weak),
        ("10-100", (0.98, 0.66, 0.15), EnfsiTier::Moderate),
        ("100-1K", (0.40, 0.73, 0.42), EnfsiTier::ModeratelyStrong),
        ("1K-10K", (0.18, 0.49, 0.20), EnfsiTier::Strong),
        ("≥10K", (0.11, 0.37, 0.13), EnfsiTier::VeryStrong),
    ];
    let seg_w = CONTENT_WIDTH / 6.0;
    for (i, (label, color, tier)) in tiers.iter().enumerate() {
        let sx = MARGIN_LEFT + i as f32 * seg_w;
        let is_active = *tier == r.enfsi_tier;
        
        let seg_color = if is_active {
            *color
        } else {
            (
                color.0 * 0.4 + 1.0 * 0.6,
                color.1 * 0.4 + 1.0 * 0.6,
                color.2 * 0.4 + 1.0 * 0.6,
            )
        };
        fill_rect(layer, sx, y - 1.0, seg_w - 0.5, 3.5, seg_color);
        let text_color = if is_active { WHITE } else { GRAY };
        text(
            layer,
            label,
            5.0,
            sx + 1.0,
            y - 0.5,
            &fonts.regular,
            text_color,
        );
        if is_active {
            
            fill_rect(layer, sx, y - 2.0, seg_w - 0.5, 1.0, *color);
        }
    }
    y -= 10.0;

    
    text(
        layer,
        "Author Declaration",
        11.0,
        MARGIN_LEFT,
        y,
        &fonts.bold,
        BLACK,
    );
    y -= 7.0;

    
    draw_card(layer, MARGIN_LEFT, y - 24.0, CONTENT_WIDTH, 26.0);
    
    let decl_text = &r.verdict_description;
    let mut dy = y - 4.0;
    for line in wrap_text_lines(decl_text, 90) {
        text(
            layer,
            &line,
            7.5,
            MARGIN_LEFT + 4.0,
            dy,
            &fonts.regular,
            BLACK,
        );
        dy -= 4.0;
    }
    y -= 33.0;

    
    text(
        layer,
        "Document Identity",
        11.0,
        MARGIN_LEFT,
        y,
        &fonts.bold,
        BLACK,
    );
    y -= 7.0;

    let rows = [
        ("Document Hash:", &r.document_hash),
        ("Signing Key:", &r.signing_key_fingerprint),
        ("Evidence Bundle:", &r.evidence_bundle_version),
        ("Device Attestation:", &r.device_attestation),
    ];
    for (label, value) in &rows {
        text(layer, label, 7.5, MARGIN_LEFT + 2.0, y, &fonts.bold, BLACK);
        let display = if value.len() > 64 {
            format!(
                "{}...{}",
                value.get(..8).unwrap_or(value),
                value.get(value.len().saturating_sub(8)..).unwrap_or(value),
            )
        } else {
            value.to_string()
        };
        text(
            layer,
            &display,
            7.0,
            MARGIN_LEFT + 42.0,
            y,
            &fonts.mono,
            GRAY,
        );
        y -= 5.0;
    }

    if let Some(words) = r.document_words {
        text(
            layer,
            "Document Length:",
            7.5,
            MARGIN_LEFT + 2.0,
            y,
            &fonts.bold,
            BLACK,
        );
        let mut len_str = format!("{} words", words);
        if let Some(chars) = r.document_chars {
            len_str.push_str(&format!(" | {} chars", chars));
        }
        text(
            layer,
            &len_str,
            7.0,
            MARGIN_LEFT + 42.0,
            y,
            &fonts.mono,
            GRAY,
        );
        y -= 5.0;
    }
    y -= 7.0;

    
    if !r.dimensions.is_empty() {
        text(
            layer,
            "Category Scores",
            11.0,
            MARGIN_LEFT,
            y,
            &fonts.bold,
            BLACK,
        );
        y -= 8.0;

        for d in &r.dimensions {
            let dc = dimension_color(&d.name);
            charts::draw_score_bar(
                layer,
                &fonts.regular,
                &fonts.bold,
                &d.name,
                d.score,
                dc,
                MARGIN_LEFT + 2.0,
                y,
                100.0,
            );
            y -= 7.0;
        }
    }
    y -= 7.0;

    
    if !r.writing_flow.is_empty() {
        text(
            layer,
            "Writing Flow",
            11.0,
            MARGIN_LEFT,
            y,
            &fonts.bold,
            BLACK,
        );
        y -= 3.0;
        charts::draw_flow_chart(
            layer,
            &r.writing_flow,
            MARGIN_LEFT,
            y - 25.0,
            CONTENT_WIDTH,
            25.0,
        );
        y -= 30.0;
        text(
            layer,
            "Keystroke intensity over time. Dips = natural thinking pauses.",
            5.5,
            MARGIN_LEFT,
            y,
            &fonts.regular,
            GRAY,
        );
    }

    
    text(
        layer,
        &format!(
            "CPOP Authorship Report | {} | {} | {}",
            r.report_id, r.algorithm_version, r.schema_version,
        ),
        5.0,
        MARGIN_LEFT,
        10.0,
        &fonts.regular,
        GRAY,
    );
}


