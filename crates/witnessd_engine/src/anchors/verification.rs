// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::{AnchorError, Proof};

/// Validate the structural format of a proof (non-empty data, non-zero hash).
///
/// NOTE: This does NOT perform cryptographic verification of the proof against
/// its anchor provider. It only checks basic format validity.
pub fn verify_proof_format(proof: &Proof) -> Result<bool, AnchorError> {
    if proof.proof_data.is_empty() {
        return Err(AnchorError::InvalidFormat("empty proof data".into()));
    }
    if proof.anchored_hash.iter().all(|b| *b == 0) {
        return Err(AnchorError::HashMismatch);
    }
    Ok(true)
}
