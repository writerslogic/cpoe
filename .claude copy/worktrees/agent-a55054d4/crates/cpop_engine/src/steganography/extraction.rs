

use super::embedding::compute_watermark_tag;
use super::types::{ZwcBinding, ZwcParams, ZwcVerification, ZWC_ALPHABET};

/
pub struct ZwcExtractor {
    params: ZwcParams,
}

impl ZwcExtractor {
    /
    pub fn new(params: ZwcParams) -> Self {
        Self { params }
    }

    /
    pub fn strip_zwc(text: &str) -> String {
        text.chars().filter(|c| !ZWC_ALPHABET.contains(c)).collect()
    }

    /
    /
    /
    pub fn extract_tag(&self, watermarked_text: &str) -> Vec<u8> {
        watermarked_text
            .chars()
            .filter_map(|c| {
                ZWC_ALPHABET
                    .iter()
                    .position(|&zwc| zwc == c)
                    .map(|pos| pos as u8)
            })
            .collect()
    }

    /
    pub fn verify(
        &self,
        watermarked_text: &str,
        mmr_root: &[u8; 32],
        key: &[u8; 32],
    ) -> ZwcVerification {
        let extracted = self.extract_tag(watermarked_text);
        let clean_text = Self::strip_zwc(watermarked_text);
        let doc_hash = sha2_hash(clean_text.as_bytes());

        let expected = compute_watermark_tag(key, mmr_root, &doc_hash, self.params.zwc_count);

        let valid = extracted.len() == expected.len() && extracted == expected;

        ZwcVerification {
            valid,
            zwc_found: extracted.len(),
            zwc_expected: self.params.zwc_count,
            extracted_tag: hex::encode(&extracted),
            expected_tag: Some(hex::encode(&expected)),
        }
    }

    /
    /
    /
    pub fn verify_binding(&self, watermarked_text: &str, binding: &ZwcBinding) -> ZwcVerification {
        let extracted = self.extract_tag(watermarked_text);
        let stored_tag: Vec<u8> = hex::decode(&binding.tag_hex).unwrap_or_else(|e| {
            log::warn!("ZWC binding tag_hex is invalid hex: {e}");
            vec![]
        });

        let valid = extracted.len() == binding.zwc_count && extracted == stored_tag;

        ZwcVerification {
            valid,
            zwc_found: extracted.len(),
            zwc_expected: binding.zwc_count,
            extracted_tag: hex::encode(&extracted),
            expected_tag: Some(binding.tag_hex.clone()),
        }
    }

    pub fn has_watermark(text: &str) -> bool {
        text.chars().any(|c| ZWC_ALPHABET.contains(&c))
    }

    /
    pub fn count_zwc(text: &str) -> usize {
        text.chars().filter(|c| ZWC_ALPHABET.contains(c)).count()
    }
}

fn sha2_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}
