

//! PDF report generation for Written Authorship Reports.
//!
//! Produces self-contained, signed PDF documents with anti-forgery security
//! features (guilloché, microtext, void pantograph) derived from the
//! cryptographic seal. The PDF embeds the WAR block for independent verification.

mod charts;
mod embed;
mod layout;
mod layout_sections;
mod security;

use crate::report::types::WarReport;
use printpdf::*;
use std::io::BufWriter;

/
/
/
/
/
/
/
/
/
/
/
/
/
/
/
pub fn render_pdf(report: &WarReport, security_seed: Option<&[u8; 64]>) -> Result<Vec<u8>, String> {
    let (doc, page1, layer1) = PdfDocument::new(
        format!("Written Authorship Report — {}", report.report_id),
        Mm(210.0), 
        Mm(297.0), 
        "Layer 1",
    );

    let font = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .map_err(|e| format!("failed to load Helvetica font: {e}"))?;
    let font_bold = doc
        .add_builtin_font(BuiltinFont::HelveticaBold)
        .map_err(|e| format!("failed to load HelveticaBold font: {e}"))?;
    let font_mono = doc
        .add_builtin_font(BuiltinFont::Courier)
        .map_err(|e| format!("failed to load Courier font: {e}"))?;

    let fonts = PdfFonts {
        regular: font,
        bold: font_bold,
        mono: font_mono,
    };

    
    let current_layer = doc.get_page(page1).get_layer(layer1);
    if let Some(seed) = security_seed {
        security::draw_guilloche_border(&current_layer, seed);
    }
    layout::draw_page1(&current_layer, report, &fonts, security_seed);

    
    let (page2, layer2) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
    let current_layer = doc.get_page(page2).get_layer(layer2);
    if let Some(seed) = security_seed {
        security::draw_guilloche_border(&current_layer, seed);
    }
    layout_sections::draw_page2(&current_layer, report, &fonts);

    
    let (page3, layer3) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
    let current_layer = doc.get_page(page3).get_layer(layer3);
    layout_sections::draw_page3(&current_layer, report, &fonts);

    
    let mut buf = BufWriter::new(Vec::new());
    doc.save(&mut buf)
        .map_err(|e| format!("PDF serialization failed: {e}"))?;
    buf.into_inner()
        .map_err(|e| format!("PDF buffer flush failed: {e}"))
}

/
pub(crate) struct PdfFonts {
    pub regular: IndirectFontRef,
    pub bold: IndirectFontRef,
    pub mono: IndirectFontRef,
}
