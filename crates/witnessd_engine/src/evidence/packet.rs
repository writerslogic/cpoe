// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Packet impl block: verification, signing, encoding/decoding, and hashing.

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::time::Duration;
use subtle::ConstantTimeEq;

use crate::codec::{self, Format, CBOR_TAG_PPP};
use crate::error::Error;
use crate::keyhierarchy;
use crate::rfc;
use crate::tpm;
use crate::vdf;
use crate::DateTimeNanosExt;

use super::types::Packet;

impl Packet {
    pub fn verify(&self, _vdf_params: vdf::Parameters) -> crate::error::Result<()> {
        if let Some(last) = self.checkpoints.last() {
            let expected_chain_hash = last.hash.clone();
            if self
                .chain_hash
                .as_bytes()
                .ct_eq(expected_chain_hash.as_bytes())
                .unwrap_u8()
                == 0
            {
                return Err(Error::evidence("chain hash mismatch"));
            }
            if self
                .document
                .final_hash
                .as_bytes()
                .ct_eq(last.content_hash.as_bytes())
                .unwrap_u8()
                == 0
            {
                return Err(Error::evidence("document final hash mismatch"));
            }
            if self.document.final_size != last.content_size {
                return Err(Error::evidence("document final size mismatch"));
            }
        } else if !self.chain_hash.is_empty() {
            return Err(Error::evidence("chain hash present with no checkpoints"));
        }

        let mut prev_hash = String::new();
        for (i, cp) in self.checkpoints.iter().enumerate() {
            if i == 0 {
                if cp.previous_hash != hex::encode([0u8; 32]) {
                    return Err(Error::evidence("checkpoint 0: non-zero previous hash"));
                }
            } else if cp.previous_hash != prev_hash {
                return Err(Error::evidence(format!(
                    "checkpoint {i}: broken chain link"
                )));
            }
            prev_hash = cp.hash.clone();

            if let (Some(iterations), Some(input_hex), Some(output_hex)) = (
                cp.vdf_iterations,
                cp.vdf_input.as_ref(),
                cp.vdf_output.as_ref(),
            ) {
                let input = hex::decode(input_hex)
                    .map_err(|e| Error::evidence(format!("invalid hex: {e}")))?;
                let output = hex::decode(output_hex)
                    .map_err(|e| Error::evidence(format!("invalid hex: {e}")))?;
                if input.len() != 32 || output.len() != 32 {
                    return Err(Error::evidence(format!(
                        "checkpoint {i}: VDF input/output size mismatch"
                    )));
                }
                let mut input_arr = [0u8; 32];
                let mut output_arr = [0u8; 32];
                input_arr.copy_from_slice(&input);
                output_arr.copy_from_slice(&output);
                let proof = vdf::VdfProof {
                    input: input_arr,
                    output: output_arr,
                    iterations,
                    duration: Duration::from_secs(0),
                };
                if !vdf::verify(&proof) {
                    return Err(Error::evidence(format!(
                        "checkpoint {i}: VDF verification failed"
                    )));
                }
            }
        }

        if let Some(decl) = &self.declaration {
            if !decl.verify() {
                return Err(Error::evidence("declaration signature invalid"));
            }
        }

        if let Some(hardware) = &self.hardware {
            if let Err(err) = tpm::verify_binding_chain(&hardware.bindings, &[]) {
                return Err(Error::evidence(format!(
                    "hardware attestation invalid: {:?}",
                    err
                )));
            }
        }

        if let Some(kh) = &self.key_hierarchy {
            let master_pub = hex::decode(&kh.master_public_key)
                .map_err(|e| Error::evidence(format!("invalid master_public_key hex: {e}")))?;
            let session_pub = hex::decode(&kh.session_public_key)
                .map_err(|e| Error::evidence(format!("invalid session_public_key hex: {e}")))?;
            let cert_raw = general_purpose::STANDARD
                .decode(&kh.session_certificate)
                .map_err(|e| Error::evidence(format!("invalid session_certificate base64: {e}")))?;

            if let Err(err) =
                keyhierarchy::verify_session_certificate_bytes(&master_pub, &session_pub, &cert_raw)
            {
                return Err(Error::evidence(format!(
                    "key hierarchy verification failed: {err}"
                )));
            }

            for sig in &kh.checkpoint_signatures {
                if sig.ratchet_index < 0 {
                    return Err(Error::evidence(format!(
                        "negative ratchet index {}",
                        sig.ratchet_index
                    )));
                }
                let ratchet_index = sig.ratchet_index as usize;
                let ratchet_hex = kh.ratchet_public_keys.get(ratchet_index).ok_or_else(|| {
                    Error::evidence(format!(
                        "ratchet index {} out of range (have {} keys)",
                        ratchet_index,
                        kh.ratchet_public_keys.len()
                    ))
                })?;
                let ratchet_pub = hex::decode(ratchet_hex)
                    .map_err(|e| Error::evidence(format!("invalid ratchet key hex: {e}")))?;
                let checkpoint_hash = hex::decode(&sig.checkpoint_hash)
                    .map_err(|e| Error::evidence(format!("invalid checkpoint_hash hex: {e}")))?;
                let signature = general_purpose::STANDARD
                    .decode(&sig.signature)
                    .map_err(|e| Error::evidence(format!("invalid signature base64: {e}")))?;

                keyhierarchy::verify_ratchet_signature(&ratchet_pub, &checkpoint_hash, &signature)
                    .map_err(|e| {
                        Error::evidence(format!("key hierarchy verification failed: {e}"))
                    })?;
            }
        }

        // --- Step 6: Behavioral Baseline Verification ---
        if let Some(bv) = &self.baseline_verification {
            if let Some(digest) = &bv.digest {
                // 1. Verify digest signature if present
                if let Some(sig) = &bv.digest_signature {
                    // Assuming Ed25519 signer for now
                    let public_key_bytes = self.signing_public_key.ok_or_else(|| {
                        Error::Signature("missing signing public key for baseline".into())
                    })?;
                    let public_key = VerifyingKey::from_bytes(&public_key_bytes)
                        .map_err(|e| Error::Signature(format!("invalid public key: {e}")))?;

                    // Decode signature
                    let signature = Signature::from_bytes(
                        sig.as_slice()
                            .try_into()
                            .map_err(|_| Error::evidence("invalid signature length"))?,
                    );

                    // Encode digest to CBOR for verification
                    let digest_cbor = serde_json::to_vec(digest)
                        .map_err(|e| Error::evidence(format!("digest serialize failed: {e}")))?;

                    public_key.verify(&digest_cbor, &signature).map_err(|e| {
                        Error::Signature(format!("baseline digest signature invalid: {e}"))
                    })?;
                }

                // 2. Verify identity fingerprint
                let public_key_bytes = self
                    .signing_public_key
                    .ok_or_else(|| Error::Signature("missing signing public key".into()))?;
                let mut hasher = Sha256::new();
                hasher.update(public_key_bytes);
                let actual_fp = hasher.finalize();
                if digest.identity_fingerprint != actual_fp.as_slice() {
                    return Err(Error::evidence("baseline identity fingerprint mismatch"));
                }

                // 3. Compare session vs digest
                let similarity =
                    crate::baseline::verify_against_baseline(digest, &bv.session_summary);
                if similarity < 0.7 {
                    // Log warning or record in metadata - for now just informative
                    log::warn!("Behavioral consistency low: {:.2}", similarity);
                }
            }
        }

        Ok(())
    }

    pub fn total_elapsed_time(&self) -> Duration {
        let mut total = Duration::from_secs(0);
        for cp in &self.checkpoints {
            if let Some(elapsed) = cp.elapsed_time {
                total += elapsed;
            }
        }
        total
    }

    /// Encode the packet to CBOR with PPP semantic tag (RFC-compliant default).
    pub fn encode(&self) -> crate::error::Result<Vec<u8>> {
        codec::cbor::encode_ppp(self).map_err(|e| Error::evidence(format!("encode failed: {e}")))
    }

    /// Encode the packet in the specified format.
    pub fn encode_with_format(&self, format: Format) -> crate::error::Result<Vec<u8>> {
        match format {
            Format::Cbor => codec::cbor::encode_ppp(self)
                .map_err(|e| Error::evidence(format!("encode failed: {e}"))),
            Format::Json => serde_json::to_vec_pretty(self)
                .map_err(|e| Error::evidence(format!("encode failed: {e}"))),
        }
    }

    /// Decode a packet, auto-detecting format and validating CBOR tag.
    pub fn decode(data: &[u8]) -> crate::error::Result<Packet> {
        let format =
            Format::detect(data).ok_or_else(|| Error::evidence("unable to detect format"))?;

        match format {
            Format::Cbor => {
                // Validate PPP semantic tag is present
                if !codec::cbor::has_tag(data, CBOR_TAG_PPP) {
                    return Err(Error::evidence("missing or invalid CBOR PPP tag"));
                }
                codec::cbor::decode_ppp(data)
                    .map_err(|e| Error::evidence(format!("decode failed: {e}")))
            }
            Format::Json => serde_json::from_slice(data)
                .map_err(|e| Error::evidence(format!("decode failed: {e}"))),
        }
    }

    /// Decode a packet with explicit format (skips format detection).
    pub fn decode_with_format(data: &[u8], format: Format) -> crate::error::Result<Packet> {
        match format {
            Format::Cbor => {
                // Validate PPP semantic tag is present
                if !codec::cbor::has_tag(data, CBOR_TAG_PPP) {
                    return Err(Error::evidence("missing or invalid CBOR PPP tag"));
                }
                codec::cbor::decode_ppp(data)
                    .map_err(|e| Error::evidence(format!("decode failed: {e}")))
            }
            Format::Json => serde_json::from_slice(data)
                .map_err(|e| Error::evidence(format!("decode failed: {e}"))),
        }
    }

    /// Compute the deterministic hash of this packet using raw CBOR encoding.
    ///
    /// Uses untagged CBOR for deterministic, compact hashing (RFC 8949 Section 4.2).
    pub fn hash(&self) -> crate::error::Result<[u8; 32]> {
        // Use raw CBOR (no tag) for deterministic hashing
        let data = codec::cbor::encode(self)
            .map_err(|e| Error::evidence(format!("packet hash encode failed: {e}")))?;
        Ok(Sha256::digest(data).into())
    }

    /// Compute the hash used for verifier nonce binding.
    ///
    /// This creates a hash of the packet content excluding signature-related
    /// fields (verifier_nonce, packet_signature, signing_public_key) to prevent
    /// circular dependencies in the signature.
    pub fn content_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"witnessd-packet-content-v2");
        hasher.update(self.version.to_be_bytes());
        hasher.update(self.exported_at.timestamp_nanos_safe().to_be_bytes());
        hasher.update((self.strength as i32).to_be_bytes());

        // Length-prefix variable-length fields to prevent concatenation collisions
        let final_hash_bytes = self.document.final_hash.as_bytes();
        hasher.update((final_hash_bytes.len() as u32).to_be_bytes());
        hasher.update(final_hash_bytes);

        hasher.update(self.document.final_size.to_be_bytes());

        let chain_hash_bytes = self.chain_hash.as_bytes();
        hasher.update((chain_hash_bytes.len() as u32).to_be_bytes());
        hasher.update(chain_hash_bytes);

        // Include checkpoint hashes with length prefixes
        hasher.update((self.checkpoints.len() as u64).to_be_bytes());
        for cp in &self.checkpoints {
            let hash_bytes = cp.hash.as_bytes();
            hasher.update((hash_bytes.len() as u32).to_be_bytes());
            hasher.update(hash_bytes);
        }

        // Include declaration if present
        if let Some(decl) = &self.declaration {
            hasher.update(b"decl");
            hasher.update((decl.signature.len() as u32).to_be_bytes());
            hasher.update(&decl.signature);
        }

        // Include VDF params
        hasher.update(self.vdf_params.iterations_per_second.to_be_bytes());
        hasher.update(self.vdf_params.min_iterations.to_be_bytes());

        hasher.finalize().into()
    }

    /// Compute the signing payload for verifier nonce binding.
    ///
    /// Returns SHA-256(content_hash || verifier_nonce) if nonce is present,
    /// or content_hash if no nonce.
    pub fn signing_payload(&self) -> [u8; 32] {
        let content = self.content_hash();
        match &self.verifier_nonce {
            Some(nonce) => {
                let mut hasher = Sha256::new();
                hasher.update(b"witnessd-nonce-binding-v1");
                hasher.update(content);
                hasher.update(nonce);
                hasher.finalize().into()
            }
            None => content,
        }
    }

    /// Set a verifier-provided freshness nonce.
    ///
    /// The nonce should be a random 32-byte value provided by the verifier
    /// to prove the evidence was generated in response to their specific request.
    pub fn set_verifier_nonce(&mut self, nonce: [u8; 32]) {
        self.verifier_nonce = Some(nonce);
        // Clear any existing signature since the payload has changed
        self.packet_signature = None;
        self.signing_public_key = None;
    }

    /// Sign the packet with the given signing key.
    ///
    /// This creates an Ed25519 signature over the signing payload, which includes
    /// the verifier nonce if one has been set. The signature proves that the
    /// evidence packet was generated by the holder of the signing key.
    ///
    /// If a verifier nonce is present, the signature proves the packet was
    /// created in response to that specific verification request.
    pub fn sign(&mut self, signing_key: &SigningKey) -> crate::error::Result<()> {
        let payload = self.signing_payload();
        let signature = signing_key.sign(&payload);
        self.packet_signature = Some(signature.to_bytes());
        self.signing_public_key = Some(signing_key.verifying_key().to_bytes());
        Ok(())
    }

    /// Sign the packet with a verifier-provided nonce.
    ///
    /// This is a convenience method that sets the nonce and signs in one call.
    pub fn sign_with_nonce(
        &mut self,
        signing_key: &SigningKey,
        nonce: [u8; 32],
    ) -> crate::error::Result<()> {
        self.set_verifier_nonce(nonce);
        self.sign(signing_key)
    }

    /// Verify the packet signature.
    ///
    /// Returns Ok(()) if the signature is valid, or an error describing
    /// why verification failed.
    ///
    /// If expected_nonce is provided, verification will fail if the packet's
    /// verifier_nonce doesn't match, preventing replay attacks.
    pub fn verify_signature(&self, expected_nonce: Option<&[u8; 32]>) -> crate::error::Result<()> {
        // Check nonce expectation
        match (expected_nonce, &self.verifier_nonce) {
            (Some(expected), Some(actual)) => {
                if expected != actual {
                    return Err(Error::Signature("verifier nonce mismatch".into()));
                }
            }
            (Some(_), None) => {
                return Err(Error::Signature(
                    "expected verifier nonce but none present".into(),
                ));
            }
            (None, Some(_)) => {
                // Verifier didn't expect a nonce but one is present - this is ok,
                // it just means the signature binds to that nonce
            }
            (None, None) => {
                // No nonce expected and none present - ok
            }
        }

        // Get signature and public key
        let signature_bytes = self
            .packet_signature
            .ok_or_else(|| Error::Signature("packet not signed".into()))?;
        let public_key_bytes = self
            .signing_public_key
            .ok_or_else(|| Error::Signature("missing signing public key".into()))?;

        // Parse public key
        let public_key = VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|e| Error::Signature(format!("invalid public key: {e}")))?;

        // Parse signature
        let signature = Signature::from_bytes(&signature_bytes);

        // Verify
        let payload = self.signing_payload();
        public_key
            .verify(&payload, &signature)
            .map_err(|e| Error::Signature(format!("signature verification failed: {e}")))?;

        Ok(())
    }

    /// Check if this packet has a verifier nonce.
    pub fn has_verifier_nonce(&self) -> bool {
        self.verifier_nonce.is_some()
    }

    /// Check if this packet has been signed.
    pub fn is_signed(&self) -> bool {
        self.packet_signature.is_some() && self.signing_public_key.is_some()
    }

    /// Get the verifier nonce if present.
    pub fn get_verifier_nonce(&self) -> Option<&[u8; 32]> {
        self.verifier_nonce.as_ref()
    }

    /// Compute the trust tier based on current packet state.
    ///
    /// - `Attested` (4): WritersProof certificate issued
    /// - `NonceBound` (3): Signed + verifier nonce (freshness proven)
    /// - `Signed` (2): Signed, no verifier nonce
    /// - `Local` (1): No signature, no nonce
    pub fn compute_trust_tier(&self) -> super::types::TrustTier {
        use super::types::TrustTier;

        if self.writersproof_certificate_id.is_some() {
            TrustTier::Attested
        } else if self.is_signed() && self.has_verifier_nonce() {
            TrustTier::NonceBound
        } else if self.is_signed() {
            TrustTier::Signed
        } else {
            TrustTier::Local
        }
    }

    /// Convert to RFC-compliant wire format.
    ///
    /// Creates a `PacketRfc` structure with integer keys suitable for
    /// compact CBOR encoding per the RATS specification.
    pub fn to_rfc(&self) -> rfc::PacketRfc {
        rfc::PacketRfc::from(self)
    }
}
