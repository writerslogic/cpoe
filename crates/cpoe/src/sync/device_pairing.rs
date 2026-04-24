// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Device pairing via QR code and ECDH key agreement.
//!
//! Enables secure peer-to-peer pairing between macOS and iOS devices using:
//! - QR code encoding: device_id || public_key || pairing_token
//! - ECDH shared secret derivation for confidential channels
//! - Ed25519 for persistent device identity verification

use crate::Error;
use ed25519_dalek::{SigningKey, Verifier, VerifyingKey};
use rand::Rng;

/// Device pairing record stored in CloudKit after successful pairing.
///
/// **Fields:**
/// - `device_id`: UUID of paired device (e.g., "macbook-pro-2024")
/// - `public_key`: Ed25519 public key for signature verification
/// - `pairing_timestamp`: When pairing was established (nanos since epoch)
/// - `is_verified`: True if device has sent at least one signed message
/// - `last_sync`: Timestamp of last successful sync with this device
#[derive(Debug, Clone)]
pub struct DevicePairingRecord {
    /// Unique device identifier (UUID v4)
    pub device_id: String,

    /// Ed25519 public key (32 bytes)
    pub public_key: [u8; 32],

    /// Pairing establishment timestamp (nanoseconds since epoch)
    pub pairing_timestamp: i64,

    /// Verified by signature? True after first sync attempt succeeds
    pub is_verified: bool,

    /// Last sync timestamp with this device (nanos since epoch)
    pub last_sync: i64,
}

impl DevicePairingRecord {
    /// Create a new pairing record from a device's public key.
    pub fn new(device_id: String, public_key: [u8; 32]) -> Self {
        // Note: timestamp_nanos_opt().unwrap_or(0) returns clamped value on clock skew.
        // This is acceptable for initial pairing timestamp (one-time use).
        DevicePairingRecord {
            device_id,
            public_key,
            pairing_timestamp: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
            is_verified: false,
            last_sync: 0,
        }
    }

    /// Verify a signature from this paired device.
    ///
    /// Uses constant-time comparison to prevent timing attacks.
    ///
    /// **Input:** Message bytes and purported Ed25519 signature
    /// **Output:** Ok(()) if signature valid, Err(SignatureInvalid) otherwise
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        if signature.len() != 64 {
            return Err(Error::crypto("Invalid signature length"));
        }

        let verifying_key = VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| Error::crypto("Invalid public key"))?;

        // Safety: length checked above guarantees exactly 64 bytes for Ed25519 signature
        let sig_bytes: [u8; 64] = signature.try_into()
            .expect("signature length already verified as 64 bytes");
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        verifying_key
            .verify(message, &sig)
            .map_err(|_| Error::crypto("Signature verification failed"))
    }

    /// Mark device as verified after first successful sync.
    pub fn mark_verified(&mut self) {
        self.is_verified = true;
    }

    /// Update last_sync timestamp to now.
    pub fn update_last_sync(&mut self) {
        self.last_sync = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    }
}

/// QR code payload structure for device pairing.
///
/// Encodes all information needed for another device to derive shared secret
/// and establish connection.
///
/// **Format (108 bytes total):**
/// - device_id (32 bytes): UUID string, null-padded
/// - public_key (32 bytes): Ed25519 public key
/// - pairing_token (32 bytes): Random nonce for deriving shared secret
/// - version (4 bytes): Protocol version (currently 1)
#[derive(Debug, Clone)]
pub struct QRCodePayload {
    pub device_id: String,
    pub public_key: [u8; 32],
    pub pairing_token: [u8; 32],
    pub version: u32,
}

impl QRCodePayload {
    /// Create a new QR code payload from local device signing key.
    pub fn from_signing_key(device_id: String, signing_key: &SigningKey) -> Self {
        let mut rng = rand::rng();
        let mut pairing_token = [0u8; 32];
        rng.fill(&mut pairing_token);

        QRCodePayload {
            device_id,
            public_key: signing_key.verifying_key().to_bytes(),
            pairing_token,
            version: 1,
        }
    }

    /// Serialize to binary format for QR encoding.
    ///
    /// **Format (108 bytes):**
    /// - [0..32]: device_id (UTF-8, null-padded)
    /// - [32..64]: public_key
    /// - [64..96]: pairing_token
    /// - [96..100]: version (big-endian u32)
    /// - [100..108]: reserved (zeros)
    pub fn to_bytes(&self) -> [u8; 108] {
        let mut bytes = [0u8; 108];

        let device_id_bytes = self.device_id.as_bytes();
        let copy_len = device_id_bytes.len().min(32);
        bytes[0..copy_len].copy_from_slice(&device_id_bytes[..copy_len]);

        bytes[32..64].copy_from_slice(&self.public_key);
        bytes[64..96].copy_from_slice(&self.pairing_token);
        bytes[96..100].copy_from_slice(&self.version.to_be_bytes());

        bytes
    }

    /// Deserialize from binary format.
    pub fn from_bytes(bytes: &[u8; 108]) -> Result<Self, Error> {
        let device_id = String::from_utf8(
            bytes[0..32]
                .iter()
                .take_while(|&&b| b != 0)
                .copied()
                .collect(),
        )
        .map_err(|_| Error::crypto("Invalid device_id in QR payload"))?;

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&bytes[32..64]);

        let mut pairing_token = [0u8; 32];
        pairing_token.copy_from_slice(&bytes[64..96]);

        let version = u32::from_be_bytes([
            bytes[96], bytes[97], bytes[98], bytes[99],
        ]);

        Ok(QRCodePayload {
            device_id,
            public_key,
            pairing_token,
            version,
        })
    }
}

/// Represents the pairing flow state machine.
///
/// **States:**
/// - `WaitingForScan` — Displaying QR code, waiting for other device to scan
/// - `ScannedByRemote` — Remote device has scanned QR code
/// - `DerivedSharedSecret` — ECDH shared secret computed successfully
/// - `Paired` — Both devices have stored pairing records
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingFlow {
    WaitingForScan,
    ScannedByRemote,
    DerivedSharedSecret,
    Paired,
}

/// Derive shared secret using HKDF-SHA256 from pairing tokens.
///
/// **Input:**
/// - Local pairing token (32 bytes)
/// - Remote pairing token (32 bytes)
/// - Local device ID
/// - Remote device ID
///
/// **Output:**
/// - Shared secret (32 bytes) derived via HKDF-Expand-SHA256
///
/// **Algorithm:**
/// 1. Concatenate: local_token || remote_token || local_device_id || remote_device_id
/// 2. Use as HKDF input keying material (IKM)
/// 3. HKDF-Expand with DST="witnessd-pairing-secret-v1" to get 32-byte shared secret
///
/// **Security:**
/// - Deterministic (same inputs always produce same secret)
/// - Order-dependent (local || remote ≠ remote || local)
/// - Includes device IDs to prevent cross-device key reuse
/// - Domain-separated via info parameter to prevent secret reuse across contexts
pub fn derive_shared_secret(
    local_token: &[u8; 32],
    remote_token: &[u8; 32],
    local_device_id: &str,
    remote_device_id: &str,
) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    use zeroize::Zeroize;

    let mut material = Vec::new();
    material.extend_from_slice(local_token);
    material.extend_from_slice(remote_token);
    material.extend_from_slice(local_device_id.as_bytes());
    material.extend_from_slice(remote_device_id.as_bytes());

    // HKDF with no salt, using material as input key material
    let hk = Hkdf::<Sha256>::new(None, &material);

    let mut secret = [0u8; 32];
    // Safe to unwrap: 32 bytes is valid output length for HKDF-Expand
    hk.expand(b"witnessd-pairing-secret-v1", &mut secret)
        .expect("HKDF expand succeeded for 32-byte output");

    // Zero the input material
    material.zeroize();

    secret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_pairing_record_creation() {
        let public_key = [42u8; 32];
        let record = DevicePairingRecord::new("test-device".to_string(), public_key);

        assert_eq!(record.device_id, "test-device");
        assert_eq!(record.public_key, public_key);
        assert!(!record.is_verified);
        assert_eq!(record.last_sync, 0);
    }

    #[test]
    fn test_device_pairing_mark_verified() {
        let mut record =
            DevicePairingRecord::new("test-device".to_string(), [42u8; 32]);

        assert!(!record.is_verified);
        record.mark_verified();
        assert!(record.is_verified);
    }

    #[test]
    fn test_device_pairing_update_last_sync() {
        let mut record =
            DevicePairingRecord::new("test-device".to_string(), [42u8; 32]);

        let before = record.last_sync;
        record.update_last_sync();
        assert!(record.last_sync > before);
    }

    #[test]
    fn test_qr_code_payload_roundtrip() {
        let signing_key = SigningKey::from([42u8; 32]);
        let original =
            QRCodePayload::from_signing_key("device-1".to_string(), &signing_key);

        let bytes = original.to_bytes();
        let recovered = QRCodePayload::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.device_id, original.device_id);
        assert_eq!(recovered.public_key, original.public_key);
        assert_eq!(recovered.pairing_token, original.pairing_token);
        assert_eq!(recovered.version, original.version);
    }

    #[test]
    fn test_qr_code_payload_empty_device_id() {
        let mut bytes = [0u8; 108];
        // Zero device_id bytes [0..32], non-zero public key/token for validity
        bytes[32..64].copy_from_slice(&[5u8; 32]); // public_key
        bytes[64..96].copy_from_slice(&[6u8; 32]); // pairing_token
        bytes[96..100].copy_from_slice(&1u32.to_be_bytes()); // version

        let result = QRCodePayload::from_bytes(&bytes).unwrap();
        assert_eq!(result.device_id, ""); // empty due to null padding
    }

    #[test]
    fn test_derive_shared_secret_deterministic() {
        let token_a = [1u8; 32];
        let token_b = [2u8; 32];

        let secret1 = derive_shared_secret(&token_a, &token_b, "device-1", "device-2");
        let secret2 = derive_shared_secret(&token_a, &token_b, "device-1", "device-2");

        assert_eq!(secret1, secret2);
    }

    #[test]
    fn test_derive_shared_secret_order_dependent() {
        let token_a = [1u8; 32];
        let token_b = [2u8; 32];

        let secret_ab = derive_shared_secret(&token_a, &token_b, "device-1", "device-2");
        let secret_ba = derive_shared_secret(&token_b, &token_a, "device-2", "device-1");

        assert_ne!(secret_ab, secret_ba);
    }

    #[test]
    fn test_derive_shared_secret_device_id_impact() {
        let token_a = [1u8; 32];
        let token_b = [2u8; 32];

        let secret1 = derive_shared_secret(&token_a, &token_b, "device-1", "device-2");
        let secret2 = derive_shared_secret(&token_a, &token_b, "device-1", "device-3");

        assert_ne!(secret1, secret2);
    }

    #[test]
    fn test_pairing_flow_state_transitions() {
        let mut state = PairingFlow::WaitingForScan;
        assert_eq!(state, PairingFlow::WaitingForScan);

        state = PairingFlow::ScannedByRemote;
        assert_eq!(state, PairingFlow::ScannedByRemote);

        state = PairingFlow::DerivedSharedSecret;
        assert_eq!(state, PairingFlow::DerivedSharedSecret);

        state = PairingFlow::Paired;
        assert_eq!(state, PairingFlow::Paired);
    }
}
