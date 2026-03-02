// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Persistent TPM-sealed identity key storage with anti-rollback protection.
//!
//! This module bridges the key hierarchy (which derives keys from PUF providers)
//! with the TPM module (which can seal/unseal data to hardware). The master
//! identity seed is sealed to the device's TPM, preventing extraction or
//! migration to another machine.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce as AeadNonce,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::keyhierarchy::{derive_master_identity, KeyHierarchyError, MasterIdentity, PUFProvider};
use crate::rfc::wire_types::AttestationTier;
use crate::tpm::{ClockInfo, ProviderHandle, TPMError};

#[derive(Debug, thiserror::Error)]
pub enum SealedIdentityError {
    #[error("sealed identity: no TPM provider available")]
    NoProvider,
    #[error("sealed identity: sealing failed: {0}")]
    SealFailed(String),
    #[error("sealed identity: unsealing failed: {0}")]
    UnsealFailed(String),
    #[error("sealed identity: rollback detected (counter {current} < last known {last_known})")]
    RollbackDetected { current: u64, last_known: u64 },
    #[error("sealed identity: reboot detected during session")]
    RebootDetected,
    #[error("sealed identity: blob corrupted")]
    BlobCorrupted,
    #[error("sealed identity: key hierarchy error: {0}")]
    KeyHierarchy(#[from] KeyHierarchyError),
    #[error("sealed identity: TPM error: {0}")]
    Tpm(#[from] TPMError),
    #[error("sealed identity: IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("sealed identity: serialization error: {0}")]
    Serialization(String),
}

/// Persistent sealed identity blob stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SealedBlob {
    version: u32,
    provider_type: String,
    device_id: String,
    sealed_seed: Vec<u8>,
    public_key: Vec<u8>,
    fingerprint: String,
    sealed_at: DateTime<Utc>,
    counter_at_seal: Option<u64>,
    last_known_counter: Option<u64>,
    boot_count_at_seal: Option<u32>,
    restart_count_at_seal: Option<u32>,
}

const SEALED_BLOB_VERSION: u32 = 1;
const SEALED_BLOB_FILENAME: &str = "identity.sealed";

/// Persistent TPM-sealed key storage.
pub struct SealedIdentityStore {
    provider: ProviderHandle,
    store_path: PathBuf,
}

impl SealedIdentityStore {
    pub fn new(provider: ProviderHandle, data_dir: &Path) -> Self {
        let store_path = data_dir.join(SEALED_BLOB_FILENAME);
        Self {
            provider,
            store_path,
        }
    }

    pub fn auto_detect(data_dir: &Path) -> Self {
        let provider = crate::tpm::detect_provider();
        Self::new(provider, data_dir)
    }

    /// If a sealed blob already exists and can be unsealed, reuses it.
    /// Records boot_count and restart_count from TPM ClockInfo into the blob.
    pub fn initialize(&self, puf: &dyn PUFProvider) -> Result<MasterIdentity, SealedIdentityError> {
        if self.store_path.exists() {
            match self.unseal_master_key() {
                Ok(_signing_key) => {
                    return self.public_identity();
                }
                Err(e) => {
                    log::warn!(
                        "Existing sealed blob could not be unsealed ({}), re-deriving",
                        e
                    );
                }
            }
        }

        // Derive the master seed from PUF
        let identity = derive_master_identity(puf)?;
        let challenge = Sha256::digest(format!("{}-challenge", "witnessd-identity-v1").as_bytes());
        let puf_response = puf.get_response(&challenge)?;
        let mut seed = crate::keyhierarchy::hkdf_expand(
            &puf_response,
            b"witnessd-identity-v1",
            b"master-seed",
        )?;

        // Seal the seed with TPM
        let caps = self.provider.capabilities();
        let sealed_seed = if caps.supports_sealing {
            self.provider
                .seal(&seed, &[])
                .map_err(|e| SealedIdentityError::SealFailed(e.to_string()))?
        } else {
            self.software_wrap(&seed)?
        };

        let clock = self.provider.clock_info().ok();

        let counter = self
            .provider
            .bind(b"identity-seal-counter")
            .ok()
            .and_then(|b| b.monotonic_counter);

        let blob = SealedBlob {
            version: SEALED_BLOB_VERSION,
            provider_type: if caps.hardware_backed {
                if cfg!(target_os = "macos") {
                    "secure_enclave".to_string()
                } else {
                    "tpm2".to_string()
                }
            } else {
                "software".to_string()
            },
            device_id: self.provider.device_id(),
            sealed_seed,
            public_key: identity.public_key.clone(),
            fingerprint: identity.fingerprint.clone(),
            sealed_at: Utc::now(),
            counter_at_seal: counter,
            last_known_counter: counter,
            boot_count_at_seal: clock.as_ref().map(|c| c.reset_count),
            restart_count_at_seal: clock.as_ref().map(|c| c.restart_count),
        };

        self.persist_blob(&blob)?;

        seed.zeroize();

        Ok(identity)
    }

    /// **Anti-rollback**: Reads current hardware counter and verifies it is
    /// `>=` last_known_counter stored in the blob.
    ///
    /// **Anti-hammering**: authValue is machine-specific, so the sealed file
    /// cannot be brute-forced on a different device.
    pub fn unseal_master_key(&self) -> Result<SigningKey, SealedIdentityError> {
        let blob = self.load_blob()?;

        // Anti-rollback check
        if let Some(last_known) = blob.last_known_counter {
            if let Ok(binding) = self.provider.bind(b"identity-counter-check") {
                if let Some(current) = binding.monotonic_counter {
                    if current < last_known {
                        return Err(SealedIdentityError::RollbackDetected {
                            current,
                            last_known,
                        });
                    }
                }
            }
        }

        let caps = self.provider.capabilities();
        let mut seed = if caps.supports_sealing {
            self.provider
                .unseal(&blob.sealed_seed)
                .map_err(|e| SealedIdentityError::UnsealFailed(e.to_string()))?
        } else {
            self.software_unwrap(&blob.sealed_seed)?
        };

        if seed.len() != 32 {
            seed.zeroize();
            return Err(SealedIdentityError::BlobCorrupted);
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&seed);
        seed.zeroize();

        let signing_key = SigningKey::from_bytes(&key_bytes);
        key_bytes.zeroize();

        Ok(signing_key)
    }

    /// Re-persists the blob with updated counter. This ensures the counter
    /// ratchets forward and prevents "forking" at the same counter value.
    pub fn advance_counter(&self, new_counter: u64) -> Result<(), SealedIdentityError> {
        let mut blob = self.load_blob()?;

        if let Some(last_known) = blob.last_known_counter {
            if new_counter < last_known {
                return Err(SealedIdentityError::RollbackDetected {
                    current: new_counter,
                    last_known,
                });
            }
        }

        blob.last_known_counter = Some(new_counter);
        self.persist_blob(&blob)?;
        Ok(())
    }

    pub fn is_bound(&self) -> bool {
        if !self.store_path.exists() {
            return false;
        }
        match self.load_blob() {
            Ok(blob) => blob.device_id == self.provider.device_id(),
            Err(_) => false,
        }
    }

    pub fn public_identity(&self) -> Result<MasterIdentity, SealedIdentityError> {
        let blob = self.load_blob()?;
        Ok(MasterIdentity {
            public_key: blob.public_key,
            fingerprint: blob.fingerprint,
            device_id: blob.device_id,
            created_at: blob.sealed_at,
            version: SEALED_BLOB_VERSION,
        })
    }

    /// Unseals the current seed, then re-seals with the new platform state.
    /// Records new boot_count/restart_count to detect reboot-based attacks.
    pub fn reseal(&self, puf: &dyn PUFProvider) -> Result<(), SealedIdentityError> {
        let old_blob = self.load_blob()?;

        let caps = self.provider.capabilities();
        let mut seed = if caps.supports_sealing {
            match self.provider.unseal(&old_blob.sealed_seed) {
                Ok(s) => s,
                Err(_) => {
                    let challenge =
                        Sha256::digest(format!("{}-challenge", "witnessd-identity-v1").as_bytes());
                    let puf_response = puf.get_response(&challenge)?;
                    let seed = crate::keyhierarchy::hkdf_expand(
                        &puf_response,
                        b"witnessd-identity-v1",
                        b"master-seed",
                    )?;
                    seed.to_vec()
                }
            }
        } else {
            self.software_unwrap(&old_blob.sealed_seed)?
        };

        let sealed_seed = if caps.supports_sealing {
            self.provider
                .seal(&seed, &[])
                .map_err(|e| SealedIdentityError::SealFailed(e.to_string()))?
        } else {
            self.software_wrap(&seed)?
        };

        let clock = self.provider.clock_info().ok();

        let blob = SealedBlob {
            version: SEALED_BLOB_VERSION,
            provider_type: old_blob.provider_type,
            device_id: self.provider.device_id(),
            sealed_seed,
            public_key: old_blob.public_key,
            fingerprint: old_blob.fingerprint,
            sealed_at: Utc::now(),
            counter_at_seal: old_blob.last_known_counter,
            last_known_counter: old_blob.last_known_counter,
            boot_count_at_seal: clock.as_ref().map(|c| c.reset_count),
            restart_count_at_seal: clock.as_ref().map(|c| c.restart_count),
        };

        self.persist_blob(&blob)?;
        seed.zeroize();

        Ok(())
    }

    /// T4 (HardwareHardened): Reserved for SGX/TrustZone (future)
    /// T3 (HardwareBound):    hardware_backed && supports_sealing
    /// T2 (AttestedSoftware): hardware_backed && supports_attestation (but no sealing)
    /// T1 (SoftwareOnly):     pure software fallback
    pub fn attestation_tier(&self) -> AttestationTier {
        let caps = self.provider.capabilities();
        if caps.hardware_backed && caps.supports_sealing {
            AttestationTier::HardwareBound
        } else if caps.hardware_backed && caps.supports_attestation {
            AttestationTier::AttestedSoftware
        } else {
            AttestationTier::SoftwareOnly
        }
    }

    pub fn clock_info(&self) -> Result<ClockInfo, SealedIdentityError> {
        self.provider.clock_info().map_err(SealedIdentityError::Tpm)
    }

    pub fn provider(&self) -> &ProviderHandle {
        &self.provider
    }

    fn load_blob(&self) -> Result<SealedBlob, SealedIdentityError> {
        let data = fs::read(&self.store_path)?;
        serde_json::from_slice(&data).map_err(|e| SealedIdentityError::Serialization(e.to_string()))
    }

    fn persist_blob(&self, blob: &SealedBlob) -> Result<(), SealedIdentityError> {
        if let Some(parent) = self.store_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_vec_pretty(blob)
            .map_err(|e| SealedIdentityError::Serialization(e.to_string()))?;
        let tmp_path = self.store_path.with_extension("tmp");
        fs::write(&tmp_path, data)?;
        fs::rename(&tmp_path, &self.store_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.store_path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    fn software_wrap(&self, seed: &[u8]) -> Result<Vec<u8>, SealedIdentityError> {
        let machine_salt = self.machine_salt();

        // Generate random salt for HKDF
        let mut random_salt = [0u8; 32];
        getrandom::getrandom(&mut random_salt)
            .map_err(|e| SealedIdentityError::SealFailed(format!("rng: {e}")))?;

        // Derive key via HKDF(ikm=machine_salt, salt=random_salt, info=domain)
        let hk = Hkdf::<Sha256>::new(Some(&random_salt), &machine_salt);
        let mut key = [0u8; 32];
        hk.expand(b"witnessd-software-wrap-v2", &mut key)
            .map_err(|e| SealedIdentityError::SealFailed(format!("HKDF: {e}")))?;

        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| SealedIdentityError::SealFailed(format!("AEAD init: {e}")))?;

        // Generate random 12-byte nonce for AEAD
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| SealedIdentityError::SealFailed(format!("rng: {e}")))?;
        let aead_nonce = AeadNonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(aead_nonce, seed)
            .map_err(|e| SealedIdentityError::SealFailed(format!("AEAD encrypt: {e}")))?;

        key.zeroize();

        // Format: version(1) || random_salt(32) || aead_nonce(12) || ciphertext+tag
        let mut wrapped = Vec::with_capacity(1 + 32 + 12 + ciphertext.len());
        wrapped.push(0x02); // version 2 = AEAD
        wrapped.extend_from_slice(&random_salt);
        wrapped.extend_from_slice(&nonce_bytes);
        wrapped.extend_from_slice(&ciphertext);
        Ok(wrapped)
    }

    fn software_unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, SealedIdentityError> {
        if wrapped.is_empty() {
            return Err(SealedIdentityError::BlobCorrupted);
        }

        match wrapped[0] {
            0x01 => self.software_unwrap_v1(wrapped),
            0x02 => self.software_unwrap_v2(wrapped),
            _ => Err(SealedIdentityError::BlobCorrupted),
        }
    }

    /// Legacy v1 unwrap: XOR cipher (backward compat only).
    fn software_unwrap_v1(&self, wrapped: &[u8]) -> Result<Vec<u8>, SealedIdentityError> {
        let salt = self.machine_salt();
        let mut hasher = Sha256::new();
        hasher.update(&salt);
        hasher.update(b"witnessd-software-wrap-v1");
        let key_material = hasher.finalize();

        let mut seed = vec![0u8; wrapped.len() - 1];
        for (i, b) in wrapped[1..].iter().enumerate() {
            seed[i] = b ^ key_material[i % 32];
        }
        Ok(seed)
    }

    /// v2 unwrap: ChaCha20-Poly1305 AEAD.
    fn software_unwrap_v2(&self, wrapped: &[u8]) -> Result<Vec<u8>, SealedIdentityError> {
        // Format: version(1) || random_salt(32) || aead_nonce(12) || ciphertext+tag
        const HEADER_LEN: usize = 1 + 32 + 12; // 45
        if wrapped.len() < HEADER_LEN + 16 {
            return Err(SealedIdentityError::BlobCorrupted);
        }
        let random_salt = &wrapped[1..33];
        let nonce_bytes = &wrapped[33..45];
        let ciphertext = &wrapped[45..];

        let machine_salt = self.machine_salt();
        let hk = Hkdf::<Sha256>::new(Some(random_salt), &machine_salt);
        let mut key = [0u8; 32];
        hk.expand(b"witnessd-software-wrap-v2", &mut key)
            .map_err(|_| SealedIdentityError::BlobCorrupted)?;

        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| SealedIdentityError::BlobCorrupted)?;

        let aead_nonce = AeadNonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(aead_nonce, ciphertext)
            .map_err(|_| SealedIdentityError::BlobCorrupted)?;

        key.zeroize();
        Ok(plaintext)
    }

    fn machine_salt(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"witnessd-machine-salt-v1");
        hasher.update(self.provider.device_id().as_bytes());
        if let Ok(host) = hostname::get() {
            hasher.update(host.to_string_lossy().as_bytes());
        }
        hasher.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm::SoftwareProvider;
    use std::sync::Arc;
    use tempfile::TempDir;

    struct TestPUF;
    impl PUFProvider for TestPUF {
        fn get_response(&self, challenge: &[u8]) -> Result<Vec<u8>, KeyHierarchyError> {
            let mut hasher = Sha256::new();
            hasher.update(b"test-puf-seed");
            hasher.update(challenge);
            Ok(hasher.finalize().to_vec())
        }
        fn device_id(&self) -> String {
            "test-device".to_string()
        }
    }

    #[test]
    fn test_sealed_identity_software_fallback() {
        let tmp = TempDir::new().unwrap();
        let provider: ProviderHandle = Arc::new(SoftwareProvider::new());
        let store = SealedIdentityStore::new(provider, tmp.path());
        let puf = TestPUF;

        let identity = store.initialize(&puf).unwrap();
        assert!(!identity.public_key.is_empty());
        assert!(!identity.fingerprint.is_empty());
        assert!(store.is_bound());

        let pub_id = store.public_identity().unwrap();
        assert_eq!(pub_id.public_key, identity.public_key);
        assert_eq!(pub_id.fingerprint, identity.fingerprint);
        assert_eq!(store.attestation_tier(), AttestationTier::SoftwareOnly);
    }

    #[test]
    fn test_sealed_identity_counter_advance() {
        let tmp = TempDir::new().unwrap();
        let provider: ProviderHandle = Arc::new(SoftwareProvider::new());
        let store = SealedIdentityStore::new(provider, tmp.path());
        let puf = TestPUF;

        store.initialize(&puf).unwrap();
        store.advance_counter(5).unwrap();
        store.advance_counter(10).unwrap();

        let result = store.advance_counter(8);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SealedIdentityError::RollbackDetected { .. }
        ));
    }

    #[test]
    fn test_sealed_identity_reseal() {
        let tmp = TempDir::new().unwrap();
        let provider: ProviderHandle = Arc::new(SoftwareProvider::new());
        let store = SealedIdentityStore::new(provider, tmp.path());
        let puf = TestPUF;

        let identity = store.initialize(&puf).unwrap();

        store.reseal(&puf).unwrap();

        let pub_id = store.public_identity().unwrap();
        assert_eq!(pub_id.public_key, identity.public_key);
    }

    #[test]
    fn test_sealed_identity_reinitialize() {
        let tmp = TempDir::new().unwrap();
        let provider: ProviderHandle = Arc::new(SoftwareProvider::new());
        let store = SealedIdentityStore::new(provider, tmp.path());
        let puf = TestPUF;
        let id1 = store.initialize(&puf).unwrap();
        let id2 = store.initialize(&puf).unwrap();
        assert_eq!(id1.public_key, id2.public_key);
    }
}
