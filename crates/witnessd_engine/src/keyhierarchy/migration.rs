// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::DateTimeNanosExt;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

use super::crypto::{build_cert_data, hkdf_expand, RATCHET_INIT_DOMAIN, SESSION_DOMAIN};
use super::error::KeyHierarchyError;
use super::identity::derive_master_identity;
use super::types::{
    LegacyKeyMigration, MasterIdentity, PUFProvider, RatchetState, Session, SessionCertificate,
    VERSION,
};

pub fn migrate_from_legacy_key(
    puf: &dyn PUFProvider,
    legacy_key_path: impl AsRef<Path>,
) -> Result<(LegacyKeyMigration, MasterIdentity), KeyHierarchyError> {
    let legacy_key = load_legacy_private_key(legacy_key_path)?;
    let legacy_pub = legacy_key.verifying_key().to_bytes().to_vec();

    let new_identity = derive_master_identity(puf)?;

    let migration_ts = Utc::now();
    let data = build_migration_data(&legacy_pub, &new_identity.public_key, migration_ts);
    let signature = legacy_key.sign(&data).to_bytes();

    Ok((
        LegacyKeyMigration {
            legacy_public_key: legacy_pub,
            new_master_public_key: new_identity.public_key.clone(),
            migration_timestamp: migration_ts,
            transition_signature: signature,
            version: VERSION,
        },
        new_identity,
    ))
}

pub fn verify_legacy_migration(migration: &LegacyKeyMigration) -> Result<(), KeyHierarchyError> {
    if migration.legacy_public_key.len() != 32 || migration.new_master_public_key.len() != 32 {
        return Err(KeyHierarchyError::InvalidMigration);
    }

    let data = build_migration_data(
        &migration.legacy_public_key,
        &migration.new_master_public_key,
        migration.migration_timestamp,
    );

    let pubkey = VerifyingKey::from_bytes(
        migration
            .legacy_public_key
            .as_slice()
            .try_into()
            .map_err(|_| KeyHierarchyError::InvalidMigration)?,
    )
    .map_err(|_| KeyHierarchyError::InvalidMigration)?;
    let signature = Signature::from_bytes(&migration.transition_signature);
    pubkey
        .verify(&data, &signature)
        .map_err(|_| KeyHierarchyError::InvalidMigration)
}

fn build_migration_data(
    legacy_pub: &[u8],
    new_master_pub: &[u8],
    timestamp: DateTime<Utc>,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"witnessd-key-migration-v1");
    data.extend_from_slice(legacy_pub);
    data.extend_from_slice(new_master_pub);
    data.extend_from_slice(&(timestamp.timestamp_nanos_safe() as u64).to_be_bytes());
    data
}

fn load_legacy_private_key(path: impl AsRef<Path>) -> Result<SigningKey, KeyHierarchyError> {
    let data = fs::read(path)?;

    if data.len() == 32 {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&data);
        return Ok(SigningKey::from_bytes(&seed));
    }

    if data.len() == 64 {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&data[0..32]);
        return Ok(SigningKey::from_bytes(&seed));
    }

    Err(KeyHierarchyError::LegacyKeyNotFound)
}

pub fn start_session_from_legacy_key(
    legacy_key_path: impl AsRef<Path>,
    document_hash: [u8; 32],
) -> Result<Session, KeyHierarchyError> {
    let legacy_key = load_legacy_private_key(legacy_key_path)?;
    let legacy_pub = legacy_key.verifying_key().to_bytes().to_vec();

    let mut session_id = [0u8; 32];
    rand::rng().fill_bytes(&mut session_id);

    let session_input = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&session_id);
        bytes.extend_from_slice(Utc::now().to_rfc3339().as_bytes());
        bytes
    };

    let mut session_seed = hkdf_expand(
        legacy_key.to_bytes().as_slice(),
        SESSION_DOMAIN.as_bytes(),
        &session_input,
    )?;
    let session_key = SigningKey::from_bytes(&session_seed);
    let session_pub = session_key.verifying_key().to_bytes().to_vec();

    let created_at = Utc::now();
    let cert_data = build_cert_data(session_id, &session_pub, created_at, document_hash);
    let signature = legacy_key.sign(&cert_data).to_bytes();

    let certificate = SessionCertificate {
        session_id,
        session_pubkey: session_pub,
        created_at,
        document_hash,
        master_pubkey: legacy_pub,
        signature,
        version: VERSION,
        start_quote: None,
        end_quote: None,
        start_counter: None,
        end_counter: None,
        start_reset_count: None,
        start_restart_count: None,
        end_reset_count: None,
        end_restart_count: None,
    };

    let ratchet_init = hkdf_expand(&session_seed, RATCHET_INIT_DOMAIN.as_bytes(), &[])?;
    session_seed.zeroize();

    Ok(Session {
        certificate,
        ratchet: RatchetState {
            current: crate::crypto::ProtectedKey::new(ratchet_init),
            ordinal: 0,
            wiped: false,
        },
        signatures: Vec::new(),
    })
}
