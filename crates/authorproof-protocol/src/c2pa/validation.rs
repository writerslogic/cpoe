// SPDX-License-Identifier: Apache-2.0

use sha2::{Digest, Sha256};

use super::types::{C2paManifest, ValidationResult};
use super::{ASSERTION_LABEL_ACTIONS, ASSERTION_LABEL_HASH_DATA};

/// §15.10.1.2 standard manifest validation.
///
/// Signature verification requires a caller-provided public key; this method
/// validates structure only and does not verify the COSE_Sign1 signature.
pub fn validate_manifest(manifest: &C2paManifest) -> ValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    let hard_binding_count = manifest
        .claim
        .created_assertions
        .iter()
        .filter(|a| a.url.contains(ASSERTION_LABEL_HASH_DATA))
        .count();
    if hard_binding_count != 1 {
        errors.push(format!(
            "Standard manifest requires exactly 1 hard binding, found {hard_binding_count}"
        ));
    }

    let actions_count = manifest
        .claim
        .created_assertions
        .iter()
        .filter(|a| a.url.contains(ASSERTION_LABEL_ACTIONS))
        .count();
    if actions_count != 1 {
        errors.push(format!(
            "Standard manifest requires exactly 1 actions assertion, found {actions_count}"
        ));
    }

    for (i, assertion) in manifest.claim.created_assertions.iter().enumerate() {
        if !assertion.url.contains(&manifest.manifest_label) {
            errors.push(format!(
                "created_assertions[{i}].url does not contain manifest label '{}'",
                manifest.manifest_label
            ));
        }
    }

    if !manifest.claim.signature.contains(&manifest.manifest_label) {
        errors.push(format!(
            "signature URI does not contain manifest label '{}'",
            manifest.manifest_label
        ));
    }

    if manifest.claim.claim_generator_info.is_empty() {
        errors.push("claim_generator_info must have at least one entry".to_string());
    } else if manifest.claim.claim_generator_info[0].name.is_empty() {
        // Safe: is_empty() guard above ensures [0] exists.
        errors.push("claim_generator_info[0].name must not be empty".to_string());
    }

    if manifest.claim.instance_id.is_empty() {
        errors.push("instanceID must not be empty".to_string());
    }

    if manifest.claim.signature.is_empty() {
        errors.push("signature URI must not be empty".to_string());
    }

    for (i, assertion) in manifest.claim.created_assertions.iter().enumerate() {
        if assertion.hash.len() != 32 {
            errors.push(format!(
                "created_assertions[{i}] hash length {} != 32",
                assertion.hash.len()
            ));
        }
        if assertion.url.is_empty() {
            errors.push(format!("created_assertions[{i}] has empty URL"));
        }
    }

    if manifest.assertion_boxes.len() != manifest.claim.created_assertions.len() {
        errors.push(format!(
            "assertion_boxes count ({}) != created_assertions count ({})",
            manifest.assertion_boxes.len(),
            manifest.claim.created_assertions.len()
        ));
    }

    for (i, (assertion_ref, box_bytes)) in manifest
        .claim
        .created_assertions
        .iter()
        .zip(manifest.assertion_boxes.iter())
        .enumerate()
    {
        if box_bytes.len() < 8 {
            errors.push(format!("assertion_boxes[{i}] too short"));
            continue;
        }
        let computed_hash = Sha256::digest(&box_bytes[8..]);
        if assertion_ref.hash != computed_hash.as_slice() {
            errors.push(format!(
                "created_assertions[{i}] hash mismatch: claim has {}, box hashes to {}",
                hex::encode(&assertion_ref.hash),
                hex::encode(computed_hash)
            ));
        }
    }

    if manifest.signature.is_empty() {
        errors.push("COSE_Sign1 signature is empty".to_string());
    }

    if manifest.manifest_label.is_empty() {
        warnings.push("manifest_label is empty".to_string());
    }

    ValidationResult { errors, warnings }
}
