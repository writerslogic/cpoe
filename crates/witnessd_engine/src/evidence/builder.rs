// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Evidence packet builder with validation and claim generation.

use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::time::Duration;

use crate::analysis::{calculate_hurst_rs, BehavioralFingerprint};
use crate::anchors;
use crate::checkpoint;
use crate::collaboration;
use crate::continuation;
use crate::declaration;
use crate::error::Error;
use crate::jitter;
use crate::keyhierarchy;
use crate::platform::HIDDeviceInfo;
use crate::presence;
use crate::provenance;
use crate::rfc::{self, BiologyInvariantClaim, BiologyMeasurements, JitterBinding, TimeEvidence};
use crate::tpm;
use crate::vdf;

use super::types::*;

pub struct Builder {
    packet: Packet,
    errors: Vec<String>,
}

impl Builder {
    pub fn new(title: &str, chain: &checkpoint::Chain) -> Self {
        let mut packet = Packet {
            version: 1,
            exported_at: Utc::now(),
            strength: Strength::Basic,
            provenance: None,
            document: DocumentInfo {
                title: title.to_string(),
                path: chain.document_path.clone(),
                final_hash: String::new(),
                final_size: 0,
            },
            checkpoints: Vec::with_capacity(chain.checkpoints.len()),
            vdf_params: chain.vdf_params,
            chain_hash: String::new(),
            declaration: None,
            presence: None,
            hardware: None,
            keystroke: None,
            behavioral: None,
            contexts: Vec::new(),
            external: None,
            key_hierarchy: None,
            jitter_binding: None,
            time_evidence: None,
            provenance_links: None,
            continuation: None,
            collaboration: None,
            vdf_aggregate: None,
            verifier_nonce: None,
            packet_signature: None,
            signing_public_key: None,
            biology_claim: None,
            trust_tier: None,
            mmr_root: None,
            mmr_proof: None,
            writersproof_certificate_id: None,
            baseline_verification: None,
            claims: Vec::new(),
            limitations: Vec::new(),
        };

        if let Some(latest) = chain.latest() {
            packet.document.final_hash = hex::encode(latest.content_hash);
            packet.document.final_size = latest.content_size;
        }

        for cp in &chain.checkpoints {
            let mut proof = CheckpointProof {
                ordinal: cp.ordinal,
                content_hash: hex::encode(cp.content_hash),
                content_size: cp.content_size,
                timestamp: cp.timestamp,
                message: cp.message.clone(),
                vdf_input: None,
                vdf_output: None,
                vdf_iterations: None,
                elapsed_time: None,
                previous_hash: hex::encode(cp.previous_hash),
                hash: hex::encode(cp.hash),
                signature: None,
            };

            if let Some(sig) = &cp.signature {
                proof.signature = Some(hex::encode(sig));
            }

            if let Some(vdf_proof) = &cp.vdf {
                proof.vdf_input = Some(hex::encode(vdf_proof.input));
                proof.vdf_output = Some(hex::encode(vdf_proof.output));
                proof.vdf_iterations = Some(vdf_proof.iterations);
                proof.elapsed_time = Some(vdf_proof.min_elapsed_time(chain.vdf_params));
            }

            packet.checkpoints.push(proof);
        }

        if let Some(latest) = chain.latest() {
            packet.chain_hash = hex::encode(latest.hash);
        }

        Self {
            packet,
            errors: Vec::new(),
        }
    }

    pub fn with_declaration(mut self, decl: &declaration::Declaration) -> Self {
        if !decl.verify() {
            self.errors
                .push("declaration signature invalid".to_string());
            return self;
        }
        self.packet.declaration = Some(decl.clone());
        self
    }

    pub fn with_presence(mut self, sessions: &[presence::Session]) -> Self {
        if sessions.is_empty() {
            return self;
        }
        let evidence = presence::compile_evidence(sessions);
        self.packet.presence = Some(evidence);
        if self.packet.strength < Strength::Standard {
            self.packet.strength = Strength::Standard;
        }
        self
    }

    /// Add hardware attestation evidence with TPM bindings.
    ///
    /// # Arguments
    /// * `bindings` - TPM binding chain for checkpoint attestation
    /// * `device_id` - Unique device identifier from TPM
    /// * `attestation_nonce` - Optional 32-byte nonce used for TPM quote freshness
    pub fn with_hardware(
        mut self,
        bindings: Vec<tpm::Binding>,
        device_id: String,
        attestation_nonce: Option<[u8; 32]>,
    ) -> Self {
        if bindings.is_empty() {
            return self;
        }
        self.packet.hardware = Some(HardwareEvidence {
            bindings,
            device_id,
            attestation_nonce,
        });
        if self.packet.strength < Strength::Enhanced {
            self.packet.strength = Strength::Enhanced;
        }
        self
    }

    pub fn with_keystroke(mut self, evidence: &jitter::Evidence) -> Self {
        if evidence.statistics.total_keystrokes == 0 {
            return self;
        }
        if evidence.verify().is_err() {
            self.errors.push("keystroke evidence invalid".to_string());
            return self;
        }

        let keystroke = KeystrokeEvidence {
            session_id: evidence.session_id.clone(),
            started_at: evidence.started_at,
            ended_at: evidence.ended_at,
            duration: evidence.statistics.duration,
            total_keystrokes: evidence.statistics.total_keystrokes,
            total_samples: evidence.statistics.total_samples,
            keystrokes_per_minute: evidence.statistics.keystrokes_per_min,
            unique_doc_states: evidence.statistics.unique_doc_hashes,
            chain_valid: evidence.statistics.chain_valid,
            plausible_human_rate: evidence.is_plausible_human_typing(),
            samples: evidence.samples.clone(),
            phys_ratio: None,
        };

        self.packet.keystroke = Some(keystroke);
        if self.packet.strength < Strength::Standard {
            self.packet.strength = Strength::Standard;
        }
        self
    }

    /// Add hybrid keystroke evidence with hardware entropy metrics.
    ///
    /// If phys_ratio > 0.8 (80% hardware entropy), boosts evidence strength
    /// to Enhanced level, providing stronger assurance that keystrokes
    /// originated from real hardware rather than software injection.
    #[cfg(feature = "witnessd_jitter")]
    pub fn with_hybrid_keystroke(
        mut self,
        evidence: &crate::witnessd_jitter_bridge::HybridEvidence,
    ) -> Self {
        if evidence.statistics.total_keystrokes == 0 {
            return self;
        }
        if evidence.verify().is_err() {
            self.errors
                .push("hybrid keystroke evidence invalid".to_string());
            return self;
        }

        // Convert HybridSample to jitter::Sample for backward compatibility
        let samples: Vec<jitter::Sample> = evidence
            .samples
            .iter()
            .map(|hs| jitter::Sample {
                timestamp: hs.timestamp,
                keystroke_count: hs.keystroke_count,
                document_hash: hs.document_hash,
                jitter_micros: hs.jitter_micros,
                hash: hs.hash,
                previous_hash: hs.previous_hash,
            })
            .collect();

        let keystroke = KeystrokeEvidence {
            session_id: evidence.session_id.clone(),
            started_at: evidence.started_at,
            ended_at: evidence.ended_at,
            duration: evidence.statistics.duration,
            total_keystrokes: evidence.statistics.total_keystrokes,
            total_samples: evidence.statistics.total_samples,
            keystrokes_per_minute: evidence.statistics.keystrokes_per_min,
            unique_doc_states: evidence.statistics.unique_doc_hashes,
            chain_valid: evidence.statistics.chain_valid,
            plausible_human_rate: evidence.is_plausible_human_typing(),
            samples,
            phys_ratio: Some(evidence.entropy_quality.phys_ratio),
        };

        self.packet.keystroke = Some(keystroke);

        // Boost to Standard for any keystroke evidence
        if self.packet.strength < Strength::Standard {
            self.packet.strength = Strength::Standard;
        }

        // Boost to Enhanced if >80% hardware entropy
        // High hardware entropy strongly indicates genuine human input
        if evidence.entropy_quality.phys_ratio > 0.8 {
            if self.packet.strength < Strength::Enhanced {
                self.packet.strength = Strength::Enhanced;
            }
            self.packet.claims.push(Claim {
                claim_type: ClaimType::KeystrokesVerified,
                description: format!(
                    "Hardware entropy ratio {:.0}% - strong assurance of genuine input",
                    evidence.entropy_quality.phys_ratio * 100.0
                ),
                confidence: "high".to_string(),
            });
        }

        self
    }

    pub fn with_behavioral(
        mut self,
        regions: Vec<EditRegion>,
        metrics: Option<ForensicMetrics>,
    ) -> Self {
        if regions.is_empty() && metrics.is_none() {
            return self;
        }
        self.packet.behavioral = Some(BehavioralEvidence {
            edit_topology: regions,
            metrics,
            fingerprint: None,
            forgery_analysis: None,
        });
        if self.packet.strength < Strength::Maximum {
            self.packet.strength = Strength::Maximum;
        }
        self
    }

    /// Add behavioral evidence with full analysis including forgery detection.
    pub fn with_behavioral_full(
        mut self,
        regions: Vec<EditRegion>,
        metrics: Option<ForensicMetrics>,
        samples: &[jitter::SimpleJitterSample],
    ) -> Self {
        let fingerprint = if samples.len() >= 2 {
            Some(BehavioralFingerprint::from_samples(samples))
        } else {
            None
        };

        let forgery_analysis = if samples.len() >= 10 {
            Some(BehavioralFingerprint::detect_forgery(samples))
        } else {
            None
        };

        self.packet.behavioral = Some(BehavioralEvidence {
            edit_topology: regions,
            metrics,
            fingerprint,
            forgery_analysis,
        });

        if self.packet.strength < Strength::Maximum {
            self.packet.strength = Strength::Maximum;
        }
        self
    }

    pub fn with_contexts(mut self, contexts: Vec<ContextPeriod>) -> Self {
        if contexts.is_empty() {
            return self;
        }
        self.packet.contexts = contexts;
        self
    }

    pub fn with_provenance(mut self, prov: RecordProvenance) -> Self {
        self.packet.provenance = Some(prov);
        self
    }

    /// Populate input_devices in provenance from HID device enumeration.
    ///
    /// This converts a list of HIDDeviceInfo (from platform enumeration) into
    /// InputDeviceInfo records with transport type and fingerprint.
    ///
    /// # Arguments
    /// * `devices` - HID device information from keyboard enumeration
    pub fn with_input_devices(mut self, devices: &[HIDDeviceInfo]) -> Self {
        if let Some(ref mut prov) = self.packet.provenance {
            prov.input_devices = devices.iter().map(InputDeviceInfo::from).collect();
        } else {
            // Create minimal provenance with just input devices
            self.errors
                .push("with_input_devices requires with_provenance to be called first".to_string());
        }
        self
    }

    pub fn with_external_anchors(mut self, ots: Vec<OTSProof>, rfc: Vec<RFC3161Proof>) -> Self {
        if ots.is_empty() && rfc.is_empty() {
            return self;
        }
        self.packet.external = Some(ExternalAnchors {
            opentimestamps: ots,
            rfc3161: rfc,
            proofs: Vec::new(),
        });
        if self.packet.strength < Strength::Maximum {
            self.packet.strength = Strength::Maximum;
        }
        self
    }

    pub fn with_anchors(mut self, proofs: &[anchors::Proof]) -> Self {
        if proofs.is_empty() {
            return self;
        }

        if self.packet.external.is_none() {
            self.packet.external = Some(ExternalAnchors {
                opentimestamps: Vec::new(),
                rfc3161: Vec::new(),
                proofs: Vec::new(),
            });
        }

        let ext = self.packet.external.as_mut().unwrap();
        for proof in proofs {
            ext.proofs.push(convert_anchor_proof(proof));
        }

        if self.packet.strength < Strength::Maximum {
            self.packet.strength = Strength::Maximum;
        }
        self
    }

    pub fn with_key_hierarchy(mut self, evidence: &keyhierarchy::KeyHierarchyEvidence) -> Self {
        let packet = KeyHierarchyEvidencePacket {
            version: evidence.version,
            master_fingerprint: evidence.master_fingerprint.clone(),
            master_public_key: hex::encode(&evidence.master_public_key),
            device_id: evidence.device_id.clone(),
            session_id: evidence.session_id.clone(),
            session_public_key: hex::encode(&evidence.session_public_key),
            session_started: evidence.session_started,
            session_certificate: general_purpose::STANDARD
                .encode(&evidence.session_certificate_raw),
            ratchet_count: evidence.ratchet_count,
            ratchet_public_keys: evidence
                .ratchet_public_keys
                .iter()
                .map(hex::encode)
                .collect(),
            checkpoint_signatures: evidence
                .checkpoint_signatures
                .iter()
                .enumerate()
                .map(|(idx, sig)| CheckpointSignature {
                    ordinal: sig.ordinal,
                    checkpoint_hash: hex::encode(sig.checkpoint_hash),
                    ratchet_index: i32::try_from(idx).unwrap_or(i32::MAX),
                    signature: general_purpose::STANDARD.encode(sig.signature),
                })
                .collect(),
        };

        self.packet.key_hierarchy = Some(packet);
        if self.packet.strength < Strength::Enhanced {
            self.packet.strength = Strength::Enhanced;
        }
        self
    }

    /// Add provenance links for cross-document relationships
    pub fn with_provenance_links(mut self, section: provenance::ProvenanceSection) -> Self {
        if section.parent_links.is_empty() {
            return self;
        }
        self.packet.provenance_links = Some(section);
        self
    }

    /// Add continuation section for multi-packet series
    pub fn with_continuation(mut self, section: continuation::ContinuationSection) -> Self {
        self.packet.continuation = Some(section);
        self
    }

    /// Add collaboration section for multi-author attestations
    pub fn with_collaboration(mut self, section: collaboration::CollaborationSection) -> Self {
        if section.participants.is_empty() {
            return self;
        }
        self.packet.collaboration = Some(section);
        self
    }

    /// Add VDF aggregate proof for efficient verification
    pub fn with_vdf_aggregate(mut self, proof: vdf::VdfAggregateProof) -> Self {
        self.packet.vdf_aggregate = Some(proof);
        self
    }

    /// Add RFC-compliant jitter binding for behavioral entropy evidence.
    ///
    /// Includes entropy commitment, statistical summary, active probes (Galton Invariant,
    /// Reflex Gate), and labyrinth structure (phase space topology).
    pub fn with_jitter_binding(mut self, binding: JitterBinding) -> Self {
        self.packet.jitter_binding = Some(binding);
        if self.packet.strength < Strength::Enhanced {
            self.packet.strength = Strength::Enhanced;
        }
        self
    }

    /// Add RFC-compliant time evidence for temporal binding.
    ///
    /// Includes TSA responses, blockchain anchors, and Roughtime samples.
    pub fn with_time_evidence(mut self, evidence: TimeEvidence) -> Self {
        self.packet.time_evidence = Some(evidence);
        if self.packet.strength < Strength::Enhanced {
            self.packet.strength = Strength::Enhanced;
        }
        self
    }

    /// Add RFC-compliant biology invariant claim.
    ///
    /// Contains behavioral biometric evidence with millibits scoring for
    /// Hurst exponent, pink noise (1/f), and error topology analysis.
    pub fn with_biology_claim(mut self, claim: BiologyInvariantClaim) -> Self {
        self.packet.biology_claim = Some(claim);
        if self.packet.strength < Strength::Enhanced {
            self.packet.strength = Strength::Enhanced;
        }
        self
    }

    /// Build jitter binding from keystroke evidence.
    ///
    /// Automatically computes entropy commitment, statistical summary,
    /// Hurst exponent, and forgery analysis from raw samples.
    ///
    /// `previous_commitment_hash` should be the entropy commitment hash from
    /// the previous jitter binding in the chain. Pass `None` (or `[0u8; 32]`)
    /// for the first binding in a chain.
    pub fn with_jitter_from_keystroke(
        mut self,
        keystroke: &KeystrokeEvidence,
        document_hash: &[u8; 32],
        previous_commitment_hash: Option<[u8; 32]>,
    ) -> Self {
        if keystroke.samples.len() < 10 {
            self.errors
                .push("insufficient jitter samples for binding".to_string());
            return self;
        }

        // Compute statistics from jitter_micros (already in microseconds)
        let intervals_us: Vec<f64> = keystroke
            .samples
            .iter()
            .map(|s| s.jitter_micros as f64)
            .filter(|&i| i > 0.0 && i < 5_000_000.0) // Filter outliers > 5s
            .collect();

        if intervals_us.is_empty() {
            self.errors
                .push("no valid jitter intervals found".to_string());
            return self;
        }

        let mean = intervals_us.iter().sum::<f64>() / intervals_us.len() as f64;
        let variance = intervals_us.iter().map(|x| (x - mean).powi(2)).sum::<f64>()
            / intervals_us.len() as f64;
        let std_dev = variance.sqrt();
        let cv = if mean > 0.0 { std_dev / mean } else { 0.0 };

        // Compute percentiles using O(n) selection instead of O(n log n) sort
        let cmp = |a: &f64, b: &f64| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal);
        let percentiles = if intervals_us.len() >= 10 {
            let mut buf = intervals_us.clone();
            let n = buf.len();
            let indices = [n / 10, n / 4, n / 2, 3 * n / 4, 9 * n / 10];
            let mut vals = [0.0f64; 5];
            for (i, &idx) in indices.iter().enumerate() {
                buf.select_nth_unstable_by(idx, cmp);
                vals[i] = buf[idx];
            }
            vals
        } else {
            [mean; 5] // Fallback to mean for small samples
        };

        // Compute Hurst exponent (requires at least 20 samples)
        let hurst_exponent = if intervals_us.len() >= 20 {
            calculate_hurst_rs(&intervals_us).ok().map(|h| h.exponent)
        } else {
            None
        };

        // Compute entropy commitment using sample timestamps
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"witnessd-jitter-entropy-v1");
        for s in &keystroke.samples {
            hasher.update(s.timestamp.timestamp_millis().to_be_bytes());
        }
        let entropy_hash: [u8; 32] = hasher.finalize().into();

        // Create binding MAC using HMAC-SHA256 (must match verify_binding in jitter_binding.rs)
        let timestamp_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
        let mac: [u8; 32] = {
            use hmac::{Hmac, Mac};
            type HmacSha256 = Hmac<sha2::Sha256>;
            let mut mac_hmac =
                HmacSha256::new_from_slice(&entropy_hash).expect("HMAC accepts any key size");
            mac_hmac.update(document_hash);
            mac_hmac.update(&keystroke.total_keystrokes.to_be_bytes());
            mac_hmac.update(&timestamp_ms.to_be_bytes());
            mac_hmac.update(&entropy_hash);
            mac_hmac.finalize().into_bytes().into()
        };

        let binding = JitterBinding {
            entropy_commitment: rfc::EntropyCommitment {
                hash: entropy_hash,
                timestamp_ms,
                previous_hash: previous_commitment_hash.unwrap_or([0u8; 32]),
            },
            sources: vec![rfc::jitter_binding::SourceDescriptor {
                source_type: "keyboard".to_string(),
                weight: 1000,
                device_fingerprint: None,
                transport_calibration: None,
            }],
            summary: rfc::JitterSummary {
                sample_count: keystroke.samples.len() as u64,
                mean_interval_us: mean,
                std_dev,
                coefficient_of_variation: cv,
                percentiles,
                // Conservative lower bound: log2(n) bits from n independent samples.
                // True Shannon entropy depends on the interval distribution, but
                // log2(n) is a defensible minimum without distribution assumptions.
                entropy_bits: (keystroke.samples.len() as f64).log2(),
                hurst_exponent,
            },
            binding_mac: rfc::BindingMac {
                mac,
                document_hash: *document_hash,
                keystroke_count: keystroke.total_keystrokes,
                timestamp_ms,
            },
            raw_intervals: None,
            active_probes: None,
            labyrinth_structure: None,
        };

        self.packet.jitter_binding = Some(binding);
        if self.packet.strength < Strength::Enhanced {
            self.packet.strength = Strength::Enhanced;
        }
        self
    }

    /// Attach active probes (Galton invariant and reflex gate) to jitter binding.
    ///
    /// Must be called after `with_jitter_from_keystroke` or `with_jitter_binding`.
    /// Active probes provide adversarial stimulus-response measurements.
    pub fn with_active_probes(
        mut self,
        probes: &crate::analysis::active_probes::ActiveProbeResults,
    ) -> Self {
        if let Some(ref mut binding) = self.packet.jitter_binding {
            binding.active_probes = Some(probes.into());
        } else {
            self.errors
                .push("jitter_binding required before active_probes".to_string());
        }
        self
    }

    /// Attach labyrinth structure (Takens embedding) to jitter binding.
    ///
    /// Must be called after `with_jitter_from_keystroke` or `with_jitter_binding`.
    /// Labyrinth structure captures topological properties of timing dynamics.
    pub fn with_labyrinth_structure(
        mut self,
        analysis: &crate::analysis::labyrinth::LabyrinthAnalysis,
    ) -> Self {
        if let Some(ref mut binding) = self.packet.jitter_binding {
            binding.labyrinth_structure = Some(analysis.into());
        } else {
            self.errors
                .push("jitter_binding required before labyrinth_structure".to_string());
        }
        self
    }

    /// Build biology invariant claim from analysis results.
    ///
    /// Creates an RFC-compliant biology claim with millibits scoring
    /// from Hurst exponent, pink noise, and error topology analyses.
    pub fn with_biology_from_analysis(
        mut self,
        measurements: BiologyMeasurements,
        hurst: Option<&crate::analysis::hurst::HurstAnalysis>,
        pink_noise: Option<&crate::analysis::pink_noise::PinkNoiseAnalysis>,
        error_topology: Option<&crate::analysis::error_topology::ErrorTopology>,
    ) -> Self {
        let claim =
            BiologyInvariantClaim::from_analysis(measurements, hurst, pink_noise, error_topology);
        self.packet.biology_claim = Some(claim);
        if self.packet.strength < Strength::Enhanced {
            self.packet.strength = Strength::Enhanced;
        }
        self
    }

    /// Add MMR proof for anti-deletion verification.
    ///
    /// Includes the MMR root hash and serialized range proof covering
    /// all checkpoints. A verifier can independently confirm no checkpoints
    /// were deleted from the chain.
    pub fn with_mmr_proof(mut self, mmr_root: [u8; 32], range_proof: &[u8]) -> Self {
        self.packet.mmr_root = Some(hex::encode(mmr_root));
        self.packet.mmr_proof = Some(hex::encode(range_proof));
        self
    }

    /// Set a WritersProof verifier nonce for freshness binding.
    ///
    /// When the WritersProof service is online and auto_attest is enabled,
    /// a nonce is requested before signing the evidence packet. This proves
    /// the evidence was generated in response to a specific verification request.
    pub fn with_baseline_verification(
        mut self,
        bv: witnessd_protocol::baseline::BaselineVerification,
    ) -> Self {
        self.packet.baseline_verification = Some(bv);
        self
    }

    pub fn with_writersproof_nonce(mut self, nonce: [u8; 32]) -> Self {
        self.packet.verifier_nonce = Some(nonce);
        self
    }

    /// Set the WritersProof attestation certificate ID.
    pub fn with_writersproof_certificate(mut self, certificate_id: String) -> Self {
        self.packet.writersproof_certificate_id = Some(certificate_id);
        self
    }

    pub fn build(mut self) -> crate::error::Result<Packet> {
        if self.packet.declaration.is_none() {
            self.errors.push("declaration is required".to_string());
        }
        if !self.errors.is_empty() {
            return Err(Error::evidence(format!("build errors: {:?}", self.errors)));
        }
        self.generate_claims();
        self.generate_limitations();
        self.packet.trust_tier = Some(self.packet.compute_trust_tier());
        Ok(self.packet)
    }

    fn generate_claims(&mut self) {
        self.packet.claims.push(Claim {
            claim_type: ClaimType::ChainIntegrity,
            description: "Content states form an unbroken cryptographic chain".to_string(),
            confidence: "cryptographic".to_string(),
        });

        let mut total_time = Duration::from_secs(0);
        for cp in &self.packet.checkpoints {
            if let Some(elapsed) = cp.elapsed_time {
                total_time += elapsed;
            }
        }
        if total_time > Duration::from_secs(0) {
            self.packet.claims.push(Claim {
                claim_type: ClaimType::TimeElapsed,
                description: format!(
                    "At least {:?} elapsed during documented composition",
                    total_time
                ),
                confidence: "cryptographic".to_string(),
            });
        }

        if let Some(decl) = &self.packet.declaration {
            let ai_desc = if decl.has_ai_usage() {
                format!(
                    "AI assistance declared: {} extent",
                    crate::declaration::ai_extent_str(&decl.max_ai_extent())
                )
            } else {
                "No AI tools declared".to_string()
            };
            self.packet.claims.push(Claim {
                claim_type: ClaimType::ProcessDeclared,
                description: format!("Author signed declaration of creative process. {ai_desc}"),
                confidence: "attestation".to_string(),
            });
        }

        if let Some(presence) = &self.packet.presence {
            self.packet.claims.push(Claim {
                claim_type: ClaimType::PresenceVerified,
                description: format!(
                    "Author presence verified {:.0}% of challenged sessions",
                    presence.overall_rate * 100.0
                ),
                confidence: "cryptographic".to_string(),
            });
        }

        if let Some(keystroke) = &self.packet.keystroke {
            let mut desc = format!(
                "{} keystrokes recorded over {:?} ({:.0}/min)",
                keystroke.total_keystrokes, keystroke.duration, keystroke.keystrokes_per_minute
            );
            if keystroke.plausible_human_rate {
                desc.push_str(", consistent with human typing");
            }
            self.packet.claims.push(Claim {
                claim_type: ClaimType::KeystrokesVerified,
                description: desc,
                confidence: "cryptographic".to_string(),
            });
        }

        if self.packet.hardware.is_some() {
            self.packet.claims.push(Claim {
                claim_type: ClaimType::HardwareAttested,
                description: "TPM attests chain was not rolled back or modified".to_string(),
                confidence: "cryptographic".to_string(),
            });
        }

        if self.packet.behavioral.is_some() {
            self.packet.claims.push(Claim {
                claim_type: ClaimType::BehaviorAnalyzed,
                description: "Edit patterns captured for forensic analysis".to_string(),
                confidence: "statistical".to_string(),
            });
        }

        if !self.packet.contexts.is_empty() {
            let mut assisted = 0;
            let mut external = 0;
            for ctx in &self.packet.contexts {
                if ctx.period_type == "assisted" {
                    assisted += 1;
                }
                if ctx.period_type == "external" {
                    external += 1;
                }
            }
            let mut desc = format!("{} context periods recorded", self.packet.contexts.len());
            if assisted > 0 {
                desc.push_str(&format!(" ({assisted} AI-assisted)"));
            }
            if external > 0 {
                desc.push_str(&format!(" ({external} external)"));
            }
            self.packet.claims.push(Claim {
                claim_type: ClaimType::ContextsRecorded,
                description: desc,
                confidence: "attestation".to_string(),
            });
        }

        if let Some(external) = &self.packet.external {
            let count =
                external.opentimestamps.len() + external.rfc3161.len() + external.proofs.len();
            self.packet.claims.push(Claim {
                claim_type: ClaimType::ExternalAnchored,
                description: format!("Chain anchored to {count} external timestamp authorities"),
                confidence: "cryptographic".to_string(),
            });
        }

        if let Some(kh) = &self.packet.key_hierarchy {
            let mut desc = format!(
                "Identity {} with {} ratchet generations",
                if kh.master_fingerprint.len() > 16 {
                    format!("{}...", &kh.master_fingerprint[..16])
                } else {
                    kh.master_fingerprint.clone()
                },
                kh.ratchet_count
            );
            if !kh.checkpoint_signatures.is_empty() {
                desc.push_str(&format!(
                    ", {} checkpoint signatures",
                    kh.checkpoint_signatures.len()
                ));
            }
            self.packet.claims.push(Claim {
                claim_type: ClaimType::KeyHierarchy,
                description: desc,
                confidence: "cryptographic".to_string(),
            });
        }
    }

    fn generate_limitations(&mut self) {
        self.packet
            .limitations
            .push("Cannot prove cognitive origin of ideas".to_string());
        self.packet
            .limitations
            .push("Cannot prove absence of AI involvement in ideation".to_string());

        if self.packet.presence.is_none() {
            self.packet.limitations.push(
                "No presence verification - cannot confirm human was at keyboard".to_string(),
            );
        }

        if self.packet.keystroke.is_none() {
            self.packet
                .limitations
                .push("No keystroke evidence - cannot verify real typing occurred".to_string());
        }

        if self.packet.hardware.is_none() {
            self.packet
                .limitations
                .push("No hardware attestation - software-only security".to_string());
        }

        if let Some(decl) = &self.packet.declaration {
            if decl.has_ai_usage() {
                self.packet.limitations.push(
                    "Author declares AI tool usage - verify institutional policy compliance"
                        .to_string(),
                );
            }
        }
    }
}

pub fn convert_anchor_proof(proof: &anchors::Proof) -> AnchorProof {
    let provider = format!("{:?}", proof.provider).to_lowercase();
    let timestamp = proof.confirmed_at.unwrap_or(proof.submitted_at);
    let mut anchor = AnchorProof {
        provider: provider.clone(),
        provider_name: provider,
        legal_standing: String::new(),
        regions: Vec::new(),
        hash: hex::encode(proof.anchored_hash),
        timestamp,
        status: format!("{:?}", proof.status).to_lowercase(),
        raw_proof: general_purpose::STANDARD.encode(&proof.proof_data),
        blockchain: None,
        verify_url: proof.location.clone(),
    };

    if matches!(
        proof.provider,
        anchors::ProviderType::Bitcoin | anchors::ProviderType::Ethereum
    ) {
        let chain = match proof.provider {
            anchors::ProviderType::Bitcoin => "bitcoin",
            anchors::ProviderType::Ethereum => "ethereum",
            _ => "unknown",
        };
        let block_height = proof
            .extra
            .get("block_height")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let block_hash = proof
            .extra
            .get("block_hash")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let block_time = proof
            .extra
            .get("block_time")
            .and_then(|v| v.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or(timestamp);
        let tx_id = proof.location.clone();

        anchor.blockchain = Some(BlockchainAnchorInfo {
            chain: chain.to_string(),
            block_height,
            block_hash,
            block_time,
            tx_id,
        });
    }

    anchor
}

/// Compute a binding hash for a set of secure events.
///
/// Includes the event count to prevent truncation attacks where an attacker
/// removes events and recomputes a valid hash from a subset.
pub fn compute_events_binding_hash(events: &[crate::store::SecureEvent]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"witnessd-events-binding-v1");
    hasher.update((events.len() as u64).to_be_bytes());
    for e in events {
        hasher.update(e.event_hash);
    }
    hasher.finalize().into()
}
