

//! Full verification pipeline for evidence packets.
//!
//! Orchestrates structural verification, HMAC seal re-derivation,
//! duration cross-checks, key provenance validation, forensic analysis,
//! and WAR appraisal into a single `FullVerificationResult`.

mod pipeline;
mod seals;
mod verdict;

#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};

use crate::evidence::Packet;
use crate::forensics::{ForensicMetrics, PerCheckpointResult};
use crate::vdf;
use cpop_protocol::forensics::ForensicVerdict;

/
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    /
    pub vdf_params: vdf::Parameters,
    /
    pub expected_nonce: Option<[u8; 32]>,
    /
    pub run_forensics: bool,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealVerification {
    /
    pub jitter_tag_present: Option<bool>,
    /
    pub entangled_binding_valid: Option<bool>,
    /
    pub checkpoints_checked: usize,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DurationCheck {
    /
    pub computed_min_seconds: f64,
    /
    pub claimed_seconds: f64,
    /
    pub ratio: f64,
    /
    pub plausible: bool,
}

/
const SWF_DURATION_RATIO_MIN: f64 = 0.5;
const SWF_DURATION_RATIO_MAX: f64 = 3.0;

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyProvenanceCheck {
    /
    pub hierarchy_consistent: Option<bool>,
    /
    pub signing_key_consistent: bool,
    /
    pub ratchet_monotonic: bool,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullVerificationResult {
    /
    pub structural: bool,
    /
    pub signature: Option<bool>,
    /
    pub seals: SealVerification,
    /
    pub duration: DurationCheck,
    /
    pub key_provenance: KeyProvenanceCheck,
    /
    pub forensics: Option<ForensicMetrics>,
    /
    pub per_checkpoint: Option<PerCheckpointResult>,
    /
    pub verdict: ForensicVerdict,
    /
    pub warnings: Vec<String>,
}

/
pub fn full_verify(packet: &Packet, opts: &VerifyOptions) -> FullVerificationResult {
    let mut warnings = Vec::new();

    
    let structural = match packet.verify(opts.vdf_params) {
        Ok(()) => true,
        Err(e) => {
            warnings.push(format!("Structural verification failed: {}", e));
            false
        }
    };

    
    let signature = if packet.packet_signature.is_some() {
        match packet.verify_signature(opts.expected_nonce.as_ref()) {
            Ok(()) => Some(true),
            Err(e) => {
                warnings.push(format!("Signature verification failed: {}", e));
                Some(false)
            }
        }
    } else {
        warnings.push("Packet is unsigned".to_string());
        None
    };

    
    let declaration_valid = if let Some(decl) = &packet.declaration {
        if !decl.verify() {
            warnings.push("Declaration signature is invalid".to_string());
            false
        } else {
            true
        }
    } else {
        warnings.push("No declaration present".to_string());
        false
    };

    
    
    let (seals, duration, key_provenance, forensics, per_checkpoint) = if !structural {
        (
            SealVerification {
                jitter_tag_present: None,
                entangled_binding_valid: None,
                checkpoints_checked: 0,
            },
            DurationCheck {
                plausible: false,
                computed_min_seconds: 0.0,
                claimed_seconds: 0.0,
                ratio: 0.0,
            },
            KeyProvenanceCheck {
                hierarchy_consistent: None,
                signing_key_consistent: false,
                ratchet_monotonic: false,
            },
            None,
            None,
        )
    } else {
        
        let seals = seals::verify_seals_structural(packet, &mut warnings);

        
        let duration = seals::verify_duration(packet, &opts.vdf_params, &mut warnings);

        
        let key_provenance = seals::verify_key_provenance(packet, &mut warnings);

        
        let (forensics, per_checkpoint) = if opts.run_forensics {
            pipeline::run_forensics(packet, &mut warnings)
        } else {
            (None, None)
        };

        (seals, duration, key_provenance, forensics, per_checkpoint)
    };

    
    let verdict = verdict::compute_verdict(
        structural,
        signature,
        declaration_valid,
        &seals,
        &duration,
        &key_provenance,
        forensics.as_ref(),
        per_checkpoint.as_ref(),
    );

    FullVerificationResult {
        structural,
        signature,
        seals,
        duration,
        key_provenance,
        forensics,
        per_checkpoint,
        verdict,
        warnings,
    }
}
