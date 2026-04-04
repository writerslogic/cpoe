

//! Embedding of WAR block and verification data in PDF metadata.
//!
//! The PDF embeds the ASCII-armored WAR block and compact reference
//! as custom metadata fields. This enables offline extraction and
//! verification without the WritersProof API.

/
/
/
/
#[allow(dead_code)]
pub fn generate_qr_png(data: &str) -> Option<Vec<u8>> {
    use qrcode::render::svg;
    use qrcode::QrCode;

    let code = QrCode::new(data.as_bytes()).ok()?;
    let svg_str = code.render::<svg::Color>().min_dimensions(100, 100).build();

    
    
    Some(svg_str.into_bytes())
}

/
/
/
/
#[allow(dead_code)]
pub fn format_qr_data(compact_ref: &str, pubkey_fingerprint: &str) -> String {
    format!("cpop:verify:1:{}:{}", compact_ref, pubkey_fingerprint)
}
