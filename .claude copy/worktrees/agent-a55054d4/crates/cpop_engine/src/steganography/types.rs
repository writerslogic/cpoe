

use serde::{Deserialize, Serialize};

/
pub(super) const ZWC_ALPHABET: [char; 4] = [
    '\u{200B}', 
    '\u{200C}', 
    '\u{200D}', 
    '\u{FEFF}', 
];

/
pub(super) const DEFAULT_ZWC_COUNT: usize = 32;

/
pub(super) const DST_WATERMARK: &[u8] = b"witnessd-stego-watermark-v1";

/
pub(super) const DST_POSITIONS: &[u8] = b"witnessd-stego-positions-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZwcParams {
    /
    pub zwc_count: usize,
    pub min_word_count: usize,
}

impl Default for ZwcParams {
    fn default() -> Self {
        Self {
            zwc_count: DEFAULT_ZWC_COUNT,
            min_word_count: 64,
        }
    }
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZwcBinding {
    /
    pub tag_hex: String,
    /
    pub zwc_count: usize,
    /
    pub document_hash: String,
    /
    pub mmr_root: String,
    /
    pub positions: Vec<usize>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZwcVerification {
    /
    pub valid: bool,
    /
    pub zwc_found: usize,
    /
    pub zwc_expected: usize,
    /
    pub extracted_tag: String,
    /
    pub expected_tag: Option<String>,
}
