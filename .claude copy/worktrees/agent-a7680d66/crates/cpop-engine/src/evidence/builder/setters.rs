

//! Builder setter methods (`with_*`) for attaching evidence layers.

use base64::{engine::general_purpose, Engine as _};
use sha2::Digest;

use crate::analysis::BehavioralFingerprint;
use crate::anchors;
use crate::collaboration;
use crate::continuation;
use crate::declaration;
use crate::jitter;
use crate::keyhierarchy;
use crate::platform::HidDeviceInfo;
use crate::presence;
use crate::provenance;
use crate::rfc_conversions::BiologyInvariantClaimExt;
use crate::tpm;
use crate::vdf;
use cpop_protocol::rfc::{
    self, BiologyInvariantClaim, BiologyMeasurements, JitterBinding, TimeEvidence,
};

use super::helpers::convert_anchor_proof;
use super::{Builder, MAX_INTERVAL_US, MIN_JITTER_SAMPLES_FOR_BINDING, MIN_SAMPLES_FOR_HURST};
use crate::analysis::compute_hurst_rs;
use crate::evidence::types::*;

#[cfg(feature = "cpop_jitter")]
use super::HARDWARE_ENTROPY_RATIO_THRESHOLD;

impl Builder {
    /
    pub fn with_declaration(mut self, decl: &declaration::Declaration) -> Self {
        if !decl.verify() {
            self.errors
                .push("declaration signature invalid".to_string());
            return self;
        }
        self.packet.declaration = Some(decl.clone());
        self
    }

    /
    pub fn with_presence(mut self, sessions: &[presence::Session]) -> Self {
        if sessions.is_empty() {
            return self;
        }
        let evidence = presence::compile_evidence(sessions);
        self.packet.presence = Some(evidence);
        self
    }

    /
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
        self
    }

    /
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
        self
    }

    /
    /
    /
    /
    #[cfg(feature = "cpop_jitter")]
    pub fn with_hybrid_keystroke(
        mut self,
        evidence: &crate::cpop_jitter_bridge::HybridEvidence,
    ) -> Self {
        if evidence.statistics.total_keystrokes == 0 {
            return self;
        }
        if evidence.verify().is_err() {
            self.errors
                .push("hybrid keystroke evidence invalid".to_string());
            return self;
        }

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

        let phys_ratio = evidence.entropy_quality.phys_ratio;
        if phys_ratio.is_finite() && phys_ratio > HARDWARE_ENTROPY_RATIO_THRESHOLD {
            self.add_claim(
                ClaimType::KeystrokesVerified,
                format!(
                    "Hardware entropy ratio {:.0}% - strong assurance of genuine input",
                    phys_ratio * 100.0
                ),
                "high",
            );
        }

        self
    }

    /
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
        self
    }

    /
    pub fn with_behavioral_full(
        mut self,
        regions: Vec<EditRegion>,
        metrics: Option<ForensicMetrics>,
        samples: &[jitter::SimpleJitterSample],
    ) -> Self {
        if regions.is_empty() && metrics.is_none() && samples.len() < 2 {
            return self;
        }
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

        self
    }

    /
    pub fn with_contexts(mut self, contexts: Vec<ContextPeriod>) -> Self {
        if contexts.is_empty() {
            return self;
        }
        self.packet.contexts = contexts;
        self
    }

    /
    pub fn with_provenance(mut self, prov: RecordProvenance) -> Self {
        self.packet.provenance = Some(prov);
        self
    }

    /
    /
    /
    pub fn with_input_devices(mut self, devices: &[HidDeviceInfo]) -> Self {
        if let Some(ref mut prov) = self.packet.provenance {
            prov.input_devices = devices.iter().map(InputDeviceInfo::from).collect();
        } else {
            self.errors
                .push("with_input_devices requires with_provenance to be called first".to_string());
        }
        self
    }

    /
    pub fn with_external_anchors(mut self, ots: Vec<OtsProof>, rfc: Vec<Rfc3161Proof>) -> Self {
        if ots.is_empty() && rfc.is_empty() {
            return self;
        }
        self.packet.external = Some(ExternalAnchors {
            opentimestamps: ots,
            rfc3161: rfc,
            proofs: Vec::new(),
        });
        self
    }

    /
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

        let ext = self
            .packet
            .external
            .as_mut()
            .expect("just ensured Some above");
        for proof in proofs {
            ext.proofs.push(convert_anchor_proof(proof));
        }

        self
    }

    /
    pub fn with_key_hierarchy(
        mut self,
        evidence: &keyhierarchy::KeyHierarchyEvidence,
    ) -> crate::error::Result<Self> {
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
                .map(|(idx, sig)| {
                    Ok(CheckpointSignature {
                        ordinal: sig.ordinal,
                        checkpoint_hash: hex::encode(sig.checkpoint_hash),
                        
                        
                        ratchet_index: i32::try_from(idx).map_err(|_| {
                            crate::error::Error::evidence(format!(
                                "ratchet index {idx} exceeds i32::MAX"
                            ))
                        })?,
                        signature: general_purpose::STANDARD.encode(sig.signature),
                    })
                })
                .collect::<crate::error::Result<Vec<_>>>()?,
            session_document_hash: evidence
                .session_certificate
                .as_ref()
                .map(|cert| hex::encode(cert.document_hash)),
        };

        self.packet.key_hierarchy = Some(packet);
        Ok(self)
    }

    /
    pub fn with_provenance_links(mut self, section: provenance::ProvenanceSection) -> Self {
        if section.parent_links.is_empty() {
            return self;
        }
        self.packet.provenance_links = Some(section);
        self
    }

    /
    pub fn with_continuation(mut self, section: continuation::ContinuationSection) -> Self {
        self.packet.continuation = Some(section);
        self
    }

    /
    pub fn with_collaboration(mut self, section: collaboration::CollaborationSection) -> Self {
        if section.participants.is_empty() {
            return self;
        }
        self.packet.collaboration = Some(section);
        self
    }

    /
    pub fn with_vdf_aggregate(mut self, proof: vdf::VdfAggregateProof) -> Self {
        self.packet.vdf_aggregate = Some(proof);
        self
    }

    /
    pub fn with_jitter_binding(mut self, binding: JitterBinding) -> Self {
        self.packet.jitter_binding = Some(binding);
        self
    }

    /
    pub fn with_time_evidence(mut self, evidence: TimeEvidence) -> Self {
        self.packet.time_evidence = Some(evidence);
        self
    }

    /
    /
    /
    pub fn with_biology_claim(mut self, claim: BiologyInvariantClaim) -> Self {
        self.packet.biology_claim = Some(claim);
        self
    }

    /
    /
    /
    /
    pub fn with_physical_context(mut self, ctx: &crate::physics::PhysicalContext) -> Self {
        self.packet.physical_context = Some(PhysicalContextEvidence {
            clock_skew: ctx.clock_skew,
            thermal_proxy: ctx.thermal_proxy,
            silicon_puf_hash: hex::encode(ctx.silicon_puf),
            io_latency_ns: ctx.io_latency_ns,
            combined_hash: hex::encode(ctx.combined_hash),
        });
        if ctx.is_virtualized {
            self.packet.limitations.push(
                "Virtualized environment detected; physical hardware measurements may be \
                 unreliable"
                    .to_string(),
            );
        }
        self
    }

    /
    /
    /
    /
    /
    pub fn with_jitter_from_keystroke(
        mut self,
        keystroke: &KeystrokeEvidence,
        document_hash: &[u8; 32],
        previous_commitment_hash: Option<[u8; 32]>,
    ) -> Self {
        if keystroke.samples.len() < MIN_JITTER_SAMPLES_FOR_BINDING {
            self.errors
                .push("insufficient jitter samples for binding".to_string());
            return self;
        }

        let intervals_us: Vec<f64> = keystroke
            .samples
            .iter()
            
            .map(|s| s.jitter_micros as f64)
            .filter(|&i| i > 0.0 && i < MAX_INTERVAL_US)
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

        
        let percentiles = if intervals_us.len() >= 10 {
            let mut buf = intervals_us.clone();
            buf.sort_unstable_by(|a, b| a.total_cmp(b));
            let n = buf.len();
            [
                buf[n / 10],
                buf[n / 4],
                buf[n / 2],
                buf[3 * n / 4],
                buf[9 * n / 10],
            ]
        } else {
            [mean; 5] 
        };

        let hurst_exponent = if intervals_us.len() >= MIN_SAMPLES_FOR_HURST {
            compute_hurst_rs(&intervals_us).ok().map(|h| h.exponent)
        } else {
            None
        };

        let mut hasher = sha2::Sha256::new();
        hasher.update(b"witnessd-jitter-entropy-v1");
        for s in &keystroke.samples {
            hasher.update(s.timestamp.timestamp_millis().to_be_bytes());
        }
        let entropy_hash: [u8; 32] = hasher.finalize().into();

        let timestamp_ms = u64::try_from(chrono::Utc::now().timestamp_millis().max(0)).unwrap_or(0);

        let binding = JitterBinding {
            entropy_commitment: rfc::EntropyCommitment {
                hash: entropy_hash,
                timestamp_ms,
                previous_hash: previous_commitment_hash.unwrap_or([0u8; 32]),
            },
            sources: vec![rfc::jitter_binding::SourceDescriptor {
                source_type: cpop_protocol::rfc::SourceType::Other("keyboard".to_string()),
                weight: 1000,
                device_fingerprint: None,
                transport_calibration: None,
            }],
            summary: rfc::JitterSummary {
                sample_count: u64::try_from(intervals_us.len()).unwrap_or(0),
                mean_interval_us: mean,
                std_dev,
                coefficient_of_variation: cv,
                percentiles,
                
                
                
                
                
                
                entropy_bits: {
                    let n = intervals_us.len() as f64;
                    if n > 1.0 {
                        (n - 1.0).log2()
                    } else {
                        0.0
                    }
                },
                hurst_exponent,
            },
            binding_mac: {
                use hkdf::Hkdf;
                use zeroize::Zeroizing;
                let hk = Hkdf::<sha2::Sha256>::new(None, &entropy_hash);
                let mut mac_key = Zeroizing::new([0u8; 32]);
                hk.expand(b"witnessd-binding-mac-key-v1", mac_key.as_mut())
                    .expect("32 bytes is valid HKDF-Expand length");
                rfc::BindingMac::compute(
                    mac_key.as_ref(),
                    *document_hash,
                    keystroke.total_keystrokes,
                    timestamp_ms,
                    &entropy_hash,
                )
            },
            raw_intervals: None,
            active_probes: None,
            labyrinth_structure: None,
        };

        self.packet.jitter_binding = Some(binding);
        self
    }

    /
    /
    /
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

    /
    /
    /
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

    /
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
        self
    }

    /
    pub fn with_mmr_proof(mut self, mmr_root: [u8; 32], range_proof: &[u8]) -> Self {
        self.packet.mmr_root = Some(hex::encode(mmr_root));
        self.packet.mmr_proof = Some(hex::encode(range_proof));
        self
    }

    /
    pub fn with_baseline_verification(
        mut self,
        bv: cpop_protocol::baseline::BaselineVerification,
    ) -> Self {
        self.packet.baseline_verification = Some(bv);
        self
    }

    /
    pub fn with_writersproof_nonce(mut self, nonce: [u8; 32]) -> Self {
        self.packet.verifier_nonce = Some(nonce);
        self
    }

    /
    pub fn with_writersproof_certificate(mut self, certificate_id: String) -> Self {
        self.packet.writersproof_certificate_id = Some(certificate_id);
        self
    }

    /
    /
    /
    /
    pub fn with_dictation_events(mut self, events: Vec<DictationEvent>) -> Self {
        if events.is_empty() {
            return self;
        }
        let mut scored = events;
        for event in &mut scored {
            if event.plausibility_score <= 0.0 || event.plausibility_score.is_nan() {
                event.plausibility_score =
                    crate::forensics::dictation::score_dictation_plausibility(event);
            }
        }
        self.packet.dictation_events = scored;
        self
    }
}
