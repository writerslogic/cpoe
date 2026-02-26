// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::crypto::{hkdf_expand, RATCHET_INIT_DOMAIN};
use super::error::KeyHierarchyError;
use super::identity::derive_master_identity;
use super::types::{PUFProvider, RatchetState, Session, SessionRecoveryState};
use super::verification::verify_session_certificate;

pub fn recover_session(
    puf: &dyn PUFProvider,
    recovery: &SessionRecoveryState,
    document_hash: [u8; 32],
) -> Result<Session, KeyHierarchyError> {
    if recovery.certificate.session_id == [0u8; 32] {
        return Err(KeyHierarchyError::NoRecoveryData);
    }

    verify_session_certificate(&recovery.certificate)?;

    if recovery.certificate.document_hash != document_hash {
        return Err(KeyHierarchyError::SessionRecoveryFailed);
    }

    let identity = derive_master_identity(puf)?;
    if identity.public_key != recovery.certificate.master_pubkey {
        return Err(KeyHierarchyError::SessionRecoveryFailed);
    }

    if !recovery.last_ratchet_state.is_empty() {
        return recover_session_with_ratchet(puf, recovery);
    }

    recover_session_with_new_ratchet(puf, recovery)
}

fn recover_session_with_ratchet(
    puf: &dyn PUFProvider,
    recovery: &SessionRecoveryState,
) -> Result<Session, KeyHierarchyError> {
    let challenge = Sha256::digest(b"witnessd-ratchet-recovery-v1");
    let response = puf.get_response(&challenge)?;
    let mut key = hkdf_expand(&response, b"ratchet-recovery-key", &[])?;

    if recovery.last_ratchet_state.len() < 40 {
        return Err(KeyHierarchyError::SessionRecoveryFailed);
    }

    let mut ratchet_state = [0u8; 32];
    for i in 0..32 {
        ratchet_state[i] = recovery.last_ratchet_state[i] ^ key[i % 32];
    }
    let ordinal = u64::from_be_bytes(
        recovery.last_ratchet_state[32..40]
            .try_into()
            .map_err(|_| KeyHierarchyError::SessionRecoveryFailed)?,
    );
    key.zeroize();

    Ok(Session {
        certificate: recovery.certificate.clone(),
        ratchet: RatchetState {
            current: crate::crypto::ProtectedKey::new(ratchet_state),
            ordinal,
            wiped: false,
        },
        signatures: recovery.signatures.clone(),
    })
}

fn recover_session_with_new_ratchet(
    puf: &dyn PUFProvider,
    recovery: &SessionRecoveryState,
) -> Result<Session, KeyHierarchyError> {
    let mut next_ordinal = 0u64;
    if let Some(last) = recovery.signatures.last() {
        next_ordinal = last.ordinal + 1;
    }

    let challenge = Sha256::digest(b"witnessd-ratchet-continuation-v1");
    let response = puf.get_response(&challenge)?;

    let mut last_hash = [0u8; 32];
    if let Some(last) = recovery.signatures.last() {
        last_hash = last.checkpoint_hash;
    }

    let mut continuation_input = Vec::new();
    continuation_input.extend_from_slice(&response);
    continuation_input.extend_from_slice(&last_hash);
    continuation_input.extend_from_slice(&recovery.certificate.session_id);

    let ratchet_init = hkdf_expand(
        &continuation_input,
        RATCHET_INIT_DOMAIN.as_bytes(),
        b"continuation",
    )?;

    Ok(Session {
        certificate: recovery.certificate.clone(),
        ratchet: RatchetState {
            current: crate::crypto::ProtectedKey::new(ratchet_init),
            ordinal: next_ordinal,
            wiped: false,
        },
        signatures: recovery.signatures.clone(),
    })
}
