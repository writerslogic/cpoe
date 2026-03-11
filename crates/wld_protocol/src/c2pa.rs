// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! C2PA (Coalition for Content Provenance and Authenticity) manifest generation.
//!
//! Produces sidecar `.c2pa` manifests containing PoP evidence assertions
//! per C2PA 2.0 specification. The manifest uses JUMBF (ISO 19566-5) box
//! format with COSE_Sign1 signatures.

use crate::crypto::PoPSigner;
use crate::error::{Error, Result};
use crate::rfc::EvidencePacket;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// C2PA assertion types
// ---------------------------------------------------------------------------

/// Custom PoP assertion embedded in C2PA manifests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoPAssertion {
    pub label: String,
    pub version: u32,
    pub evidence_id: String,
    /// SHA-256 digest of the original evidence packet bytes.
    pub evidence_hash: String,
    pub jitter_seals: Vec<JitterSeal>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitterSeal {
    pub sequence: u64,
    pub timestamp: u64,
    pub seal_hash: String,
}

impl PoPAssertion {
    pub fn from_evidence(packet: &EvidencePacket, original_bytes: &[u8]) -> Self {
        let hash = Sha256::digest(original_bytes);

        let jitter_seals = packet
            .checkpoints
            .iter()
            .map(|cp| JitterSeal {
                sequence: cp.sequence,
                timestamp: cp.timestamp,
                seal_hash: hex::encode(&cp.checkpoint_hash.digest),
            })
            .collect();

        Self {
            label: ASSERTION_LABEL_POP.to_string(),
            version: packet.version,
            evidence_id: hex::encode(&packet.packet_id),
            evidence_hash: hex::encode(hash),
            jitter_seals,
        }
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| Error::Serialization(e.to_string()))
    }
}

/// Standard C2PA action assertion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionsAssertion {
    pub actions: Vec<Action>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
    #[serde(rename = "softwareAgent", skip_serializing_if = "Option::is_none")]
    pub software_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<ActionParameters>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// C2PA hash-data assertion binding manifest to the asset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashDataAssertion {
    pub name: String,
    /// SHA-256 of the document content.
    pub hash: String,
    pub algorithm: String,
    /// Byte length of the asset.
    pub length: u64,
}

// ---------------------------------------------------------------------------
// C2PA claim
// ---------------------------------------------------------------------------

/// C2PA claim referencing assertions within the manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2paClaim {
    /// Claim generator identifier.
    pub claim_generator: String,
    /// Claim generator version info.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_generator_info: Option<Vec<ClaimGeneratorInfo>>,
    /// Title of the asset.
    #[serde(rename = "dc:title", skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// ISO-8601 creation timestamp.
    pub instance_id: String,
    /// References to assertions in the assertion store.
    pub assertions: Vec<AssertionRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimGeneratorInfo {
    pub name: String,
    pub version: String,
}

/// Reference to an assertion within the JUMBF assertion store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionRef {
    pub url: String,
    pub hash: String,
    pub algorithm: String,
}

// ---------------------------------------------------------------------------
// Full manifest
// ---------------------------------------------------------------------------

/// A complete C2PA manifest ready for JUMBF serialization.
#[derive(Debug, Clone)]
pub struct C2paManifest {
    pub claim: C2paClaim,
    pub pop_assertion: PoPAssertion,
    pub actions_assertion: ActionsAssertion,
    pub hash_data_assertion: HashDataAssertion,
    /// COSE_Sign1 signature bytes over the claim.
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// JUMBF constants
// ---------------------------------------------------------------------------

/// C2PA manifest store superbox UUID (per C2PA 2.0 §8.1).
const C2PA_MANIFEST_STORE_UUID: [u8; 16] = [
    0x63, 0x32, 0x70, 0x61, // "c2pa"
    0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

/// C2PA manifest UUID.
const C2PA_MANIFEST_UUID: [u8; 16] = [
    0x63, 0x32, 0x6D, 0x61, // "c2ma"
    0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

/// C2PA claim UUID.
const C2PA_CLAIM_UUID: [u8; 16] = [
    0x63, 0x32, 0x63, 0x6C, // "c2cl"
    0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

/// C2PA assertion store UUID.
const C2PA_ASSERTION_STORE_UUID: [u8; 16] = [
    0x63, 0x32, 0x61, 0x73, // "c2as"
    0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

/// C2PA signature UUID.
const C2PA_SIGNATURE_UUID: [u8; 16] = [
    0x63, 0x32, 0x63, 0x73, // "c2cs"
    0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

/// CBOR content box UUID (JUMBF).
#[allow(dead_code)]
const JUMBF_CBOR_UUID: [u8; 16] = [
    0x63, 0x62, 0x6F, 0x72, // "cbor"
    0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

/// JSON content box UUID (JUMBF).
const JUMBF_JSON_UUID: [u8; 16] = [
    0x6A, 0x73, 0x6F, 0x6E, // "json"
    0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

/// COSE_Sign1 content box UUID (JUMBF).
#[allow(dead_code)]
const JUMBF_COSE_SIGN1_UUID: [u8; 16] = [
    0x63, 0x6F, 0x73, 0x65, // "cose"
    0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

/// Custom PoP assertion label.
pub const ASSERTION_LABEL_POP: &str = "org.pop.evidence";

/// Standard C2PA actions label.
pub const ASSERTION_LABEL_ACTIONS: &str = "c2pa.actions";

/// Standard C2PA hash-data label.
pub const ASSERTION_LABEL_HASH_DATA: &str = "c2pa.hash.data";

const CLAIM_GENERATOR: &str = "WritersLogic/0.3.0 wld_protocol/0.1.0";

// ---------------------------------------------------------------------------
// JUMBF box writer
// ---------------------------------------------------------------------------

/// Minimal JUMBF (ISO 19566-5) box writer for C2PA manifests.
struct JumbfWriter {
    buf: Vec<u8>,
}

impl JumbfWriter {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(4096),
        }
    }

    /// Write a JUMBF description box ("jumd").
    fn write_description(&mut self, uuid: &[u8; 16], label: Option<&str>, toggles: u8) {
        let label_bytes = label.map(|l| l.as_bytes());
        // jumd box: 8 (header) + 16 (UUID) + 1 (toggles) + label + NUL
        let label_len = label_bytes.map_or(0, |b| b.len() + 1); // +1 for NUL
        let box_len = 8 + 16 + 1 + label_len;
        self.write_box_header(box_len as u32, b"jumd");
        self.buf.extend_from_slice(uuid);
        self.buf.push(toggles);
        if let Some(bytes) = label_bytes {
            self.buf.extend_from_slice(bytes);
            self.buf.push(0); // NUL terminator
        }
    }

    /// Write a JUMBF content box ("jcbr" for CBOR content).
    fn write_content_cbor(&mut self, data: &[u8]) {
        let box_len = (8 + data.len()) as u32;
        self.write_box_header(box_len, b"jcbr");
        self.buf.extend_from_slice(data);
    }

    /// Write a JUMBF content box ("json" for JSON content).
    fn write_content_json(&mut self, data: &[u8]) {
        let box_len = (8 + data.len()) as u32;
        self.write_box_header(box_len, b"json");
        self.buf.extend_from_slice(data);
    }

    /// Write a JUMBF content box for COSE_Sign1 data.
    fn write_content_cose(&mut self, data: &[u8]) {
        let box_len = (8 + data.len()) as u32;
        self.write_box_header(box_len, b"cose");
        self.buf.extend_from_slice(data);
    }

    /// Write a JUMBF superbox ("jumb") wrapping nested content.
    /// Returns the offset where the box length was written, for back-patching.
    fn begin_superbox(&mut self) -> usize {
        let offset = self.buf.len();
        // Placeholder length; patched by end_superbox
        self.write_box_header(0, b"jumb");
        offset
    }

    /// Patch the superbox length after all children are written.
    fn end_superbox(&mut self, offset: usize) {
        let total_len = (self.buf.len() - offset) as u32;
        self.buf[offset..offset + 4].copy_from_slice(&total_len.to_be_bytes());
    }

    fn write_box_header(&mut self, size: u32, box_type: &[u8; 4]) {
        self.buf.extend_from_slice(&size.to_be_bytes());
        self.buf.extend_from_slice(box_type);
    }

    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

// ---------------------------------------------------------------------------
// Manifest builder
// ---------------------------------------------------------------------------

/// Builds a C2PA sidecar manifest from PoP evidence.
pub struct C2paManifestBuilder {
    document_hash: [u8; 32],
    document_filename: Option<String>,
    document_byte_length: u64,
    evidence_bytes: Vec<u8>,
    evidence_packet: EvidencePacket,
    title: Option<String>,
}

impl C2paManifestBuilder {
    /// Create a builder from a decoded evidence packet and its raw CBOR bytes.
    pub fn new(
        evidence_packet: EvidencePacket,
        evidence_bytes: Vec<u8>,
        document_hash: [u8; 32],
        document_byte_length: u64,
    ) -> Self {
        Self {
            document_hash,
            document_filename: None,
            document_byte_length,
            evidence_bytes,
            evidence_packet,
            title: None,
        }
    }

    pub fn document_filename(mut self, name: impl Into<String>) -> Self {
        self.document_filename = Some(name.into());
        self
    }

    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Build and sign the C2PA manifest, returning JUMBF binary.
    pub fn build_jumbf(self, signer: &dyn PoPSigner) -> Result<Vec<u8>> {
        let manifest = self.build_manifest(signer)?;
        encode_jumbf(&manifest)
    }

    /// Build the manifest structure (for testing/inspection).
    pub fn build_manifest(self, signer: &dyn PoPSigner) -> Result<C2paManifest> {
        let pop_assertion =
            PoPAssertion::from_evidence(&self.evidence_packet, &self.evidence_bytes);

        let now = chrono::Utc::now().to_rfc3339();

        let actions_assertion = ActionsAssertion {
            actions: vec![Action {
                action: "c2pa.created".to_string(),
                when: Some(now.clone()),
                software_agent: Some(CLAIM_GENERATOR.to_string()),
                parameters: Some(ActionParameters {
                    description: Some(
                        "Document authored with WritersLogic Proof-of-Process witnessing"
                            .to_string(),
                    ),
                }),
            }],
        };

        let hash_data_assertion = HashDataAssertion {
            name: self
                .document_filename
                .clone()
                .unwrap_or_else(|| "document".to_string()),
            hash: hex::encode(self.document_hash),
            algorithm: "sha256".to_string(),
            length: self.document_byte_length,
        };

        // Serialize assertions for hashing
        let pop_json =
            serde_json::to_vec(&pop_assertion).map_err(|e| Error::Serialization(e.to_string()))?;
        let actions_json = serde_json::to_vec(&actions_assertion)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        let hash_data_json = serde_json::to_vec(&hash_data_assertion)
            .map_err(|e| Error::Serialization(e.to_string()))?;

        // Build assertion references with hashes
        let assertion_refs = vec![
            AssertionRef {
                url: format!("self#jumbf=/c2pa/urn:writerslogic:manifest/c2pa.assertions/{ASSERTION_LABEL_POP}"),
                hash: hex::encode(Sha256::digest(&pop_json)),
                algorithm: "sha256".to_string(),
            },
            AssertionRef {
                url: format!("self#jumbf=/c2pa/urn:writerslogic:manifest/c2pa.assertions/{ASSERTION_LABEL_ACTIONS}"),
                hash: hex::encode(Sha256::digest(&actions_json)),
                algorithm: "sha256".to_string(),
            },
            AssertionRef {
                url: format!("self#jumbf=/c2pa/urn:writerslogic:manifest/c2pa.assertions/{ASSERTION_LABEL_HASH_DATA}"),
                hash: hex::encode(Sha256::digest(&hash_data_json)),
                algorithm: "sha256".to_string(),
            },
        ];

        let instance_id = format!(
            "urn:writerslogic:{}",
            hex::encode(&self.evidence_packet.packet_id)
        );

        let claim = C2paClaim {
            claim_generator: CLAIM_GENERATOR.to_string(),
            claim_generator_info: Some(vec![
                ClaimGeneratorInfo {
                    name: "WritersLogic".to_string(),
                    version: "0.3.0".to_string(),
                },
                ClaimGeneratorInfo {
                    name: "wld_protocol".to_string(),
                    version: "0.1.0".to_string(),
                },
            ]),
            title: self.title,
            instance_id,
            assertions: assertion_refs,
        };

        // Sign the claim with COSE_Sign1
        let claim_cbor = ciborium_to_vec(&claim)?;
        let signature = crate::crypto::sign_evidence_cose(&claim_cbor, signer)?;

        Ok(C2paManifest {
            claim,
            pop_assertion,
            actions_assertion,
            hash_data_assertion,
            signature,
        })
    }
}

/// Serialize a value to CBOR bytes via ciborium.
fn ciborium_to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| Error::Serialization(format!("CBOR encode: {e}")))?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// JUMBF encoding
// ---------------------------------------------------------------------------

/// Encode a C2PA manifest as JUMBF binary suitable for a `.c2pa` sidecar file.
pub fn encode_jumbf(manifest: &C2paManifest) -> Result<Vec<u8>> {
    let mut w = JumbfWriter::new();

    // Manifest store superbox
    let store_off = w.begin_superbox();
    w.write_description(
        &C2PA_MANIFEST_STORE_UUID,
        Some("c2pa"),
        0x03, // requestable + label present
    );

    // Manifest superbox
    let manifest_off = w.begin_superbox();
    w.write_description(&C2PA_MANIFEST_UUID, Some("urn:writerslogic:manifest"), 0x03);

    // --- Claim box ---
    let claim_off = w.begin_superbox();
    w.write_description(&C2PA_CLAIM_UUID, Some("c2pa.claim"), 0x03);
    let claim_cbor = ciborium_to_vec(&manifest.claim)?;
    w.write_content_cbor(&claim_cbor);
    w.end_superbox(claim_off);

    // --- Assertion store superbox ---
    let astore_off = w.begin_superbox();
    w.write_description(&C2PA_ASSERTION_STORE_UUID, Some("c2pa.assertions"), 0x03);

    // PoP assertion (JSON content box)
    let pop_off = w.begin_superbox();
    w.write_description(&JUMBF_JSON_UUID, Some(ASSERTION_LABEL_POP), 0x03);
    let pop_json = serde_json::to_vec(&manifest.pop_assertion)
        .map_err(|e| Error::Serialization(e.to_string()))?;
    w.write_content_json(&pop_json);
    w.end_superbox(pop_off);

    // Actions assertion (JSON content box)
    let actions_off = w.begin_superbox();
    w.write_description(&JUMBF_JSON_UUID, Some(ASSERTION_LABEL_ACTIONS), 0x03);
    let actions_json = serde_json::to_vec(&manifest.actions_assertion)
        .map_err(|e| Error::Serialization(e.to_string()))?;
    w.write_content_json(&actions_json);
    w.end_superbox(actions_off);

    // Hash-data assertion (JSON content box)
    let hash_off = w.begin_superbox();
    w.write_description(&JUMBF_JSON_UUID, Some(ASSERTION_LABEL_HASH_DATA), 0x03);
    let hash_json = serde_json::to_vec(&manifest.hash_data_assertion)
        .map_err(|e| Error::Serialization(e.to_string()))?;
    w.write_content_json(&hash_json);
    w.end_superbox(hash_off);

    w.end_superbox(astore_off); // end assertion store

    // --- Signature box (COSE_Sign1) ---
    let sig_off = w.begin_superbox();
    w.write_description(&C2PA_SIGNATURE_UUID, Some("c2pa.signature"), 0x03);
    w.write_content_cose(&manifest.signature);
    w.end_superbox(sig_off);

    w.end_superbox(manifest_off); // end manifest
    w.end_superbox(store_off); // end manifest store

    Ok(w.finish())
}

/// Verify basic structural integrity of a C2PA JUMBF sidecar.
/// Returns the claim JSON if valid.
pub fn verify_jumbf_structure(data: &[u8]) -> Result<()> {
    if data.len() < 8 {
        return Err(Error::Validation("JUMBF data too short".to_string()));
    }
    let box_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if box_len > data.len() {
        return Err(Error::Validation(
            "JUMBF box length exceeds data".to_string(),
        ));
    }
    let box_type = &data[4..8];
    if box_type != b"jumb" {
        return Err(Error::Validation(format!(
            "Expected JUMBF superbox, got {:?}",
            String::from_utf8_lossy(box_type)
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rfc::{Checkpoint, DocumentRef, HashAlgorithm, HashValue};
    use ed25519_dalek::SigningKey;

    fn test_evidence_packet() -> EvidencePacket {
        EvidencePacket {
            version: 1,
            profile_uri: "urn:ietf:params:rats:eat:profile:pop:1.0".to_string(),
            packet_id: vec![0u8; 16],
            created: 1710000000000,
            document: DocumentRef {
                content_hash: HashValue {
                    algorithm: HashAlgorithm::Sha256,
                    digest: vec![0xAB; 32],
                },
                filename: Some("test.txt".to_string()),
                byte_length: 1024,
                char_count: 512,
            },
            checkpoints: vec![
                make_checkpoint(0, 1710000001000),
                make_checkpoint(1, 1710000002000),
                make_checkpoint(2, 1710000003000),
            ],
            attestation_tier: None,
            baseline_verification: None,
        }
    }

    fn make_checkpoint(seq: u64, ts: u64) -> Checkpoint {
        Checkpoint {
            sequence: seq,
            checkpoint_id: vec![0u8; 16],
            timestamp: ts,
            content_hash: HashValue {
                algorithm: HashAlgorithm::Sha256,
                digest: vec![seq as u8; 32],
            },
            char_count: 100 + seq * 50,
            prev_hash: HashValue {
                algorithm: HashAlgorithm::Sha256,
                digest: vec![0u8; 32],
            },
            checkpoint_hash: HashValue {
                algorithm: HashAlgorithm::Sha256,
                digest: vec![seq as u8 + 0x10; 32],
            },
            jitter_hash: None,
        }
    }

    #[test]
    fn pop_assertion_from_evidence() {
        let packet = test_evidence_packet();
        let evidence_bytes = b"fake evidence cbor";
        let assertion = PoPAssertion::from_evidence(&packet, evidence_bytes);

        assert_eq!(assertion.label, ASSERTION_LABEL_POP);
        assert_eq!(assertion.version, 1);
        assert_eq!(assertion.jitter_seals.len(), 3);
        assert!(!assertion.evidence_hash.is_empty());
    }

    #[test]
    fn build_manifest_and_jumbf() {
        let packet = test_evidence_packet();
        let evidence_bytes = b"fake evidence cbor".to_vec();
        let doc_hash = [0xABu8; 32];

        let signing_key = SigningKey::from_bytes(&[1u8; 32]);

        let builder = C2paManifestBuilder::new(packet, evidence_bytes, doc_hash, 1024)
            .document_filename("test.txt")
            .title("Test Document");

        let manifest = builder.build_manifest(&signing_key).unwrap();

        assert_eq!(manifest.claim.claim_generator, CLAIM_GENERATOR);
        assert_eq!(manifest.claim.assertions.len(), 3);
        assert!(!manifest.signature.is_empty());
        assert_eq!(manifest.pop_assertion.jitter_seals.len(), 3);
    }

    #[test]
    fn encode_jumbf_roundtrip() {
        let packet = test_evidence_packet();
        let evidence_bytes = b"fake evidence cbor".to_vec();
        let doc_hash = [0xABu8; 32];

        let signing_key = SigningKey::from_bytes(&[2u8; 32]);

        let builder = C2paManifestBuilder::new(packet, evidence_bytes, doc_hash, 1024)
            .document_filename("test.txt");

        let jumbf = builder.build_jumbf(&signing_key).unwrap();

        // Validate JUMBF structure
        assert!(jumbf.len() > 100);
        verify_jumbf_structure(&jumbf).unwrap();

        // First box must be "jumb"
        assert_eq!(&jumbf[4..8], b"jumb");

        // Box length matches total data
        let box_len = u32::from_be_bytes([jumbf[0], jumbf[1], jumbf[2], jumbf[3]]) as usize;
        assert_eq!(box_len, jumbf.len());
    }

    #[test]
    fn jumbf_structure_validation() {
        assert!(verify_jumbf_structure(&[]).is_err());
        assert!(verify_jumbf_structure(&[0; 4]).is_err());
        // Wrong box type
        let mut bad = vec![0, 0, 0, 16];
        bad.extend_from_slice(b"xxxx");
        bad.extend_from_slice(&[0; 8]);
        assert!(verify_jumbf_structure(&bad).is_err());
    }
}
