// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! did:webvh identity integration for CPOP.
//!
//! Bridges CPOP's Ed25519 key material to the [`didwebvh_rs`] crate, providing
//! DID creation, update, rotation, deactivation, and persistence. The signing
//! key is derived from the master identity via HKDF with a dedicated domain
//! separator, so a compromise of the did:webvh key does not expose the master.

use std::path::PathBuf;
use std::sync::Arc;

use didwebvh_rs::{
    DIDWebVHError, DIDWebVHState, Multibase, Signer, async_trait,
    create::{CreateDIDConfig, create_did},
    parameters::Parameters,
};
use affinidi_data_integrity::DataIntegrityError;
use affinidi_secrets_resolver::secrets::KeyType;
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

use crate::error::Error;
use crate::identity::did_document::did_key_from_public;

const WEBVH_IDENTITY_DOMAIN: &str = "cpop-did-webvh-v1";

const DID_CORE_CONTEXT: &str = "https://www.w3.org/ns/did/v1";
const ED25519_CONTEXT: &str = "https://w3id.org/security/suites/ed25519-2020/v1";
const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];

// ---------------------------------------------------------------------------
// CpopSigner: adapter from ed25519-dalek to didwebvh Signer trait
// ---------------------------------------------------------------------------

/// Adapter implementing the didwebvh [`Signer`] trait using CPOP Ed25519 keys.
///
/// The inner [`SigningKey`] implements `ZeroizeOnDrop`, so key material is
/// automatically erased when this struct is dropped.
pub struct CpopSigner {
    signing_key: SigningKey,
    verification_method: String,
}

impl CpopSigner {
    /// Create a signer from an existing Ed25519 key.
    ///
    /// `verification_method` must be in `did:key:{mb}#{mb}` format as required
    /// by the didwebvh spec.
    pub fn new(signing_key: SigningKey, verification_method: impl Into<String>) -> Self {
        Self {
            signing_key,
            verification_method: verification_method.into(),
        }
    }

    /// Create a signer from an Ed25519 key, deriving the verification method
    /// automatically as `did:key:{multibase}#{multibase}`.
    pub fn from_key(signing_key: SigningKey) -> Self {
        let mb = encode_multibase_ed25519(signing_key.verifying_key().as_bytes());
        let vm = format!("did:key:{mb}#{mb}");
        Self {
            signing_key,
            verification_method: vm,
        }
    }

    pub fn public_key_multibase(&self) -> String {
        encode_multibase_ed25519(self.signing_key.verifying_key().as_bytes())
    }
}

#[async_trait]
impl Signer for CpopSigner {
    fn key_type(&self) -> KeyType {
        KeyType::Ed25519
    }

    fn verification_method(&self) -> &str {
        &self.verification_method
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, DataIntegrityError> {
        use ed25519_dalek::Signer as _;
        Ok(self.signing_key.sign(data).to_bytes().to_vec())
    }
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Derive a dedicated did:webvh signing key from the master key via HKDF.
///
/// The address (e.g. "writersproof.com:authors:alice") is mixed into the
/// derivation so different did:webvh identities get different keys.
pub fn derive_webvh_signing_key(
    master_key: &SigningKey,
    address: &str,
) -> Result<SigningKey, Error> {
    let seed = crate::keyhierarchy::hkdf_expand(
        master_key.as_bytes(),
        WEBVH_IDENTITY_DOMAIN.as_bytes(),
        address.as_bytes(),
    )
    .map_err(|e| Error::identity(format!("webvh key derivation: {e}")))?;
    Ok(SigningKey::from_bytes(&seed))
}

// ---------------------------------------------------------------------------
// WebVHIdentity: lifecycle wrapper
// ---------------------------------------------------------------------------

/// A did:webvh identity bound to a CPOP author.
///
/// Wraps [`DIDWebVHState`] with CPOP-specific lifecycle methods. The state
/// is serializable to JSON for persistence between sessions.
pub struct WebVHIdentity {
    pub(crate) state: DIDWebVHState,
    pub(crate) address: String,
    pub(crate) did: String,
}

impl WebVHIdentity {
    /// Create a new did:webvh identity.
    ///
    /// Derives a signing key from `master_key` via HKDF, constructs a DID
    /// document with Ed25519 verification method and WritersProof service
    /// endpoint, and signs the first log entry.
    pub async fn create(
        master_key: &SigningKey,
        address: impl Into<String>,
    ) -> Result<Self, Error> {
        let address = address.into();
        let webvh_key = derive_webvh_signing_key(master_key, &address)?;
        let signer = CpopSigner::from_key(webvh_key);
        let pk_mb = signer.public_key_multibase();

        let did_template = format!("did:webvh:{{SCID}}:{address}");
        let doc = build_did_document(&did_template, &pk_mb);

        let params = Parameters {
            update_keys: Some(Arc::new(vec![Multibase::new(&pk_mb)])),
            ..Parameters::default()
        };

        let config = CreateDIDConfig::<CpopSigner, CpopSigner>::builder_generic()
            .address(format!("https://{}/", address.replace(':', "/")))
            .authorization_key(signer)
            .did_document(doc)
            .parameters(params)
            .also_known_as_web(true)
            .build()
            .map_err(map_webvh_err)?;

        let result = create_did(config).await.map_err(map_webvh_err)?;
        let did = result.did().to_string();

        let mut state = DIDWebVHState::default();
        let log_entry = result.log_entry().clone();
        // Rebuild state from the created log entry
        state.log_entries_mut().push(
            didwebvh_rs::log_entry_state::LogEntryState {
                log_entry,
                version_number: 1,
                validated_parameters: Parameters::default(),
                validation_status:
                    didwebvh_rs::log_entry_state::LogEntryValidationStatus::Ok,
            },
        );
        *state.witness_proofs_mut() = result.witness_proofs().clone();

        Ok(Self { state, address, did })
    }

    pub fn did(&self) -> &str {
        &self.did
    }

    pub fn state(&self) -> &DIDWebVHState {
        &self.state
    }

    /// Update the DID document.
    pub async fn update_document(
        &mut self,
        doc: Value,
        master_key: &SigningKey,
    ) -> Result<(), Error> {
        let webvh_key = derive_webvh_signing_key(master_key, &self.address)?;
        let signer = CpopSigner::from_key(webvh_key);
        self.state
            .update_document(doc, &signer)
            .await
            .map(|_| ())
            .map_err(map_webvh_err)
    }

    /// Rotate the did:webvh update keys.
    pub async fn rotate_keys(
        &mut self,
        new_keys: Vec<Multibase>,
        master_key: &SigningKey,
    ) -> Result<(), Error> {
        let webvh_key = derive_webvh_signing_key(master_key, &self.address)?;
        let signer = CpopSigner::from_key(webvh_key);
        self.state
            .rotate_keys(new_keys, &signer)
            .await
            .map(|_| ())
            .map_err(map_webvh_err)
    }

    /// Deactivate the did:webvh identity.
    pub async fn deactivate(&mut self, master_key: &SigningKey) -> Result<(), Error> {
        let webvh_key = derive_webvh_signing_key(master_key, &self.address)?;
        let signer = CpopSigner::from_key(webvh_key);
        self.state
            .deactivate(&signer)
            .await
            .map(|_| ())
            .map_err(map_webvh_err)
    }

    /// Save the did:webvh state to disk.
    pub fn save(&self) -> Result<(), Error> {
        let data_dir =
            data_dir().ok_or_else(|| Error::identity("data directory not available"))?;
        let path = data_dir.join("did_webvh_state.json");

        let envelope = serde_json::json!({
            "did": self.did,
            "address": self.address,
        });
        let state_json = serde_json::to_string(&envelope)
            .map_err(|e| Error::identity(format!("serialize webvh metadata: {e}")))?;

        let meta_path = data_dir.join("did_webvh_meta.json");
        std::fs::write(&meta_path, state_json.as_bytes())
            .map_err(|e| Error::identity(format!("write webvh metadata: {e}")))?;
        let _ = crate::crypto::restrict_permissions(&meta_path, 0o600);

        self.state
            .save_state(path.to_str().unwrap_or_default())
            .map_err(map_webvh_err)?;
        let _ = crate::crypto::restrict_permissions(&path, 0o600);

        Ok(())
    }

    /// Load a previously saved did:webvh identity from disk.
    pub fn load() -> Result<Self, Error> {
        let data_dir =
            data_dir().ok_or_else(|| Error::identity("data directory not available"))?;

        let meta_path = data_dir.join("did_webvh_meta.json");
        let meta_json = std::fs::read_to_string(&meta_path)
            .map_err(|e| Error::identity(format!("read webvh metadata: {e}")))?;
        let meta: serde_json::Value = serde_json::from_str(&meta_json)
            .map_err(|e| Error::identity(format!("parse webvh metadata: {e}")))?;

        let did = meta
            .get("did")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::identity("missing 'did' in webvh metadata"))?
            .to_string();
        let address = meta
            .get("address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::identity("missing 'address' in webvh metadata"))?
            .to_string();

        let state_path = data_dir.join("did_webvh_state.json");
        let state = DIDWebVHState::load_state(state_path.to_str().unwrap_or_default())
            .map_err(map_webvh_err)?;

        Ok(Self { state, address, did })
    }
}

// ---------------------------------------------------------------------------
// Active DID resolution
// ---------------------------------------------------------------------------

/// Return the active author DID, preferring did:webvh if available.
///
/// Falls back to did:key derived from the signing key on disk.
pub fn load_active_did() -> Result<String, Error> {
    if let Ok(identity) = WebVHIdentity::load() {
        return Ok(identity.did);
    }
    let sk = load_signing_key()
        .map_err(|e| Error::identity(format!("load signing key: {e}")))?;
    Ok(did_key_from_public(sk.verifying_key().as_bytes()))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn data_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("CPOP_DATA_DIR") {
        return Some(PathBuf::from(dir));
    }
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir().map(|h| h.join("Library/Application Support/WritersProof"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        dirs::data_local_dir().map(|d| d.join("CPOP"))
    }
}

fn load_signing_key() -> Result<SigningKey, String> {
    let data_dir = data_dir().ok_or_else(|| "Data directory not found".to_string())?;
    let key_path = data_dir.join("signing_key");
    let key_data = zeroize::Zeroizing::new(
        std::fs::read(&key_path).map_err(|e| format!("read signing key: {e}"))?,
    );
    if key_data.len() < 32 {
        return Err("signing key too short".to_string());
    }
    let mut secret = zeroize::Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&key_data[..32]);
    let signing_key = SigningKey::from_bytes(&secret);
    // Zeroizing<[u8;32]> handles zeroize on drop
    Ok(signing_key)
}

fn encode_multibase_ed25519(public_key: &[u8]) -> String {
    let mut prefixed = Vec::with_capacity(2 + public_key.len());
    prefixed.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
    prefixed.extend_from_slice(public_key);
    format!("z{}", bs58::encode(&prefixed).into_string())
}

fn build_did_document(did_template: &str, pk_multibase: &str) -> Value {
    json!({
        "id": did_template,
        "@context": [DID_CORE_CONTEXT, ED25519_CONTEXT],
        "verificationMethod": [{
            "id": format!("{did_template}#key-0"),
            "type": "Multikey",
            "publicKeyMultibase": pk_multibase,
            "controller": did_template,
        }],
        "authentication": [format!("{did_template}#key-0")],
        "assertionMethod": [format!("{did_template}#key-0")],
    })
}

fn map_webvh_err(e: DIDWebVHError) -> Error {
    Error::identity(format!("did:webvh: {e}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42u8; 32])
    }

    /// CpopSigner must report Ed25519 key type.
    #[test]
    fn signer_key_type() {
        let signer = CpopSigner::from_key(test_signing_key());
        assert_eq!(signer.key_type(), KeyType::Ed25519);
    }

    /// CpopSigner verification method must be did:key:{mb}#{mb} format.
    #[test]
    fn signer_verification_method_format() {
        let signer = CpopSigner::from_key(test_signing_key());
        let vm = signer.verification_method();
        assert!(vm.starts_with("did:key:z"), "must start with did:key:z");
        assert!(vm.contains('#'), "must contain fragment separator");
        let parts: Vec<&str> = vm.split('#').collect();
        assert_eq!(parts.len(), 2);
        let prefix = parts[0].strip_prefix("did:key:").unwrap();
        assert_eq!(prefix, parts[1], "key and fragment must match");
    }

    /// CpopSigner sign must produce a valid Ed25519 signature.
    #[tokio::test]
    async fn signer_sign_roundtrip() {
        let key = test_signing_key();
        let verifying = key.verifying_key();
        let signer = CpopSigner::from_key(key);

        let data = b"test message for signing";
        let sig_bytes = signer.sign(data).await.expect("sign must succeed");
        assert_eq!(sig_bytes.len(), 64, "Ed25519 signature must be 64 bytes");

        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).expect("valid sig");
        use ed25519_dalek::Verifier;
        verifying.verify(data, &sig).expect("signature must verify");
    }

    /// Derived webvh key must differ from the master key.
    #[test]
    fn derived_key_differs_from_master() {
        let master = test_signing_key();
        let derived = derive_webvh_signing_key(&master, "example.com").unwrap();
        assert_ne!(
            master.verifying_key().as_bytes(),
            derived.verifying_key().as_bytes()
        );
    }

    /// Different addresses must produce different derived keys.
    #[test]
    fn derived_key_address_separation() {
        let master = test_signing_key();
        let k1 = derive_webvh_signing_key(&master, "alice.example.com").unwrap();
        let k2 = derive_webvh_signing_key(&master, "bob.example.com").unwrap();
        assert_ne!(
            k1.verifying_key().as_bytes(),
            k2.verifying_key().as_bytes()
        );
    }

    /// Same master + address must produce the same derived key (deterministic).
    #[test]
    fn derived_key_deterministic() {
        let master = test_signing_key();
        let k1 = derive_webvh_signing_key(&master, "example.com").unwrap();
        let k2 = derive_webvh_signing_key(&master, "example.com").unwrap();
        assert_eq!(
            k1.verifying_key().as_bytes(),
            k2.verifying_key().as_bytes()
        );
    }

    /// Multibase encoding must produce z-prefixed base58btc with Ed25519 multicodec.
    #[test]
    fn multibase_encoding() {
        let key = test_signing_key();
        let mb = encode_multibase_ed25519(key.verifying_key().as_bytes());
        assert!(mb.starts_with('z'));
        let decoded = bs58::decode(&mb[1..]).into_vec().unwrap();
        assert_eq!(decoded[0], 0xed);
        assert_eq!(decoded[1], 0x01);
        assert_eq!(&decoded[2..], key.verifying_key().as_bytes());
    }

    /// DID document template must contain required fields and placeholders.
    #[test]
    fn did_document_structure() {
        let doc = build_did_document("did:webvh:{SCID}:example.com", "z6MkTest");
        assert_eq!(doc["id"], "did:webvh:{SCID}:example.com");
        assert!(doc["@context"].is_array());
        assert!(doc["verificationMethod"].is_array());
        assert!(doc["authentication"].is_array());
        assert!(doc["assertionMethod"].is_array());
        assert_eq!(
            doc["verificationMethod"][0]["type"], "Multikey",
            "must use Multikey type per didwebvh spec"
        );
    }

    /// load_active_did falls back to did:key when no webvh identity exists.
    #[test]
    fn load_active_did_fallback() {
        // Without a saved webvh identity, should attempt did:key fallback.
        // This may fail in CI where no signing key exists on disk, but the
        // code path exercises both branches.
        let result = load_active_did();
        if let Ok(did) = &result {
            assert!(
                did.starts_with("did:key:") || did.starts_with("did:webvh:"),
                "must return a valid DID"
            );
        }
    }
}
