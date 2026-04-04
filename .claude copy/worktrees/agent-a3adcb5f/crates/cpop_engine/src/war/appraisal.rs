

//! RATS Verifier appraisal function.
//!
//! Takes an evidence [`Packet`] and an [`AppraisalPolicy`], runs all
//! verification checks, maps results onto an AR4SI trust vector, and
//! produces an [`EarToken`].

use std::collections::BTreeMap;

use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::evidence::Packet;
use crate::trust_policy::AppraisalPolicy;
use crate::war::ear::{
    Ar4siStatus, EarAppraisal, EarToken, SealClaims, TrustworthinessVector, VerifierId,
    POP_EAR_PROFILE,
};
use crate::war::verification::{
    compute_seal, verify_declaration, verify_hash_chain, verify_vdf_proofs,
};
use cpop_protocol::rfc::wire_types::enums::AttestationTier;

/
const MIN_CHECKPOINTS: usize = 3;

/
/
const MIN_AFFIRMING_DURATION_SECS: u64 = 30;

/
const MAX_PLAUSIBLE_KEYSTROKES_PER_SEC: f64 = 20.0;

/
/
/
/
pub fn appraise(packet: &Packet, policy: &AppraisalPolicy) -> Result<EarToken> {
    let declaration = packet
        .declaration
        .as_ref()
        .ok_or_else(|| Error::evidence("evidence packet missing declaration"))?;

    let version = if declaration.has_jitter_seal() {
        crate::war::types::Version::V1_1
    } else {
        crate::war::types::Version::V1_0
    };

    let mut tv = TrustworthinessVector::default();
    let mut warnings: Vec<String> = Vec::new();

    if packet.checkpoints.len() < MIN_CHECKPOINTS {
        warnings.push(format!(
            "Insufficient checkpoints: {} (minimum {} required)",
            packet.checkpoints.len(),
            MIN_CHECKPOINTS
        ));
    }

    
    let decl_check = verify_declaration(packet);
    tv.configuration = if decl_check.passed {
        Ar4siStatus::Affirming as i8
    } else {
        warnings.push(decl_check.message.clone());
        Ar4siStatus::Contraindicated as i8
    };

    
    let seal = compute_seal(packet, declaration)
        .map_err(|e| Error::evidence(format!("seal computation failed: {e}")))?;
    let chain_check = verify_hash_chain(&seal, packet, version);
    tv.file_system = if chain_check.passed {
        Ar4siStatus::Affirming as i8
    } else {
        warnings.push(chain_check.message.clone());
        Ar4siStatus::Contraindicated as i8
    };

    
    let vdf_check = verify_vdf_proofs(packet);
    tv.runtime_opaque = if vdf_check.passed {
        let elapsed = packet.total_elapsed_time();
        let elapsed_secs = elapsed.as_secs();
        let cp_count = packet.checkpoints.len() as u64;

        
        const MAX_PLAUSIBLE_ELAPSED_SECS: u64 = 31_536_000; 
        if elapsed_secs > MAX_PLAUSIBLE_ELAPSED_SECS {
            warnings.push(format!(
                "Implausible elapsed time: {}s exceeds maximum {}s (corrupted timestamp?)",
                elapsed_secs, MAX_PLAUSIBLE_ELAPSED_SECS
            ));
            Ar4siStatus::Contraindicated as i8
        } else if elapsed_secs == 0 {
            warnings.push("VDF proofs verified but total elapsed time is zero".to_string());
            Ar4siStatus::Contraindicated as i8
        } else if elapsed_secs < MIN_AFFIRMING_DURATION_SECS {
            warnings.push(format!(
                "Elapsed time {}s below minimum {}s for affirming",
                elapsed_secs, MIN_AFFIRMING_DURATION_SECS
            ));
            Ar4siStatus::Warning as i8
        } else if cp_count > 1 && elapsed_secs / cp_count == 0 {
            warnings.push(format!(
                "Implausible timing: {} checkpoints in {}s",
                cp_count, elapsed_secs
            ));
            Ar4siStatus::Warning as i8
        } else {
            Ar4siStatus::Affirming as i8
        }
    } else {
        warnings.push(vdf_check.message.clone());
        Ar4siStatus::Contraindicated as i8
    };

    
    let hw_tier = packet
        .hardware
        .as_ref()
        .map(|hw| {
            let has_attestation = hw.bindings.iter().any(|b| {
                b.attestation
                    .as_ref()
                    .is_some_and(|a| !a.payload.is_empty())
            });
            let has_binding = !hw.bindings.is_empty();
            if has_attestation {
                AttestationTier::HardwareBound
            } else if has_binding {
                AttestationTier::AttestedSoftware
            } else {
                AttestationTier::SoftwareOnly
            }
        })
        .unwrap_or(AttestationTier::SoftwareOnly);

    let (id_status, hw_status) = match hw_tier {
        AttestationTier::HardwareHardened => {
            (Ar4siStatus::Affirming as i8, Ar4siStatus::Affirming as i8)
        }
        AttestationTier::HardwareBound => {
            (Ar4siStatus::Affirming as i8, Ar4siStatus::Affirming as i8)
        }
        AttestationTier::AttestedSoftware => {
            (Ar4siStatus::Warning as i8, Ar4siStatus::Warning as i8)
        }
        AttestationTier::SoftwareOnly => (Ar4siStatus::None as i8, Ar4siStatus::None as i8),
    };
    tv.instance_identity = id_status;
    tv.hardware = hw_status;

    
    tv.storage_opaque = match &packet.key_hierarchy {
        Some(kh) if !kh.session_certificate.is_empty() && !kh.master_public_key.is_empty() => {
            Ar4siStatus::Affirming as i8
        }
        Some(_) => {
            warnings.push(
                "Key hierarchy present but missing session certificate or master key".to_string(),
            );
            Ar4siStatus::Warning as i8
        }
        None => Ar4siStatus::None as i8,
    };

    
    tv.executables = if packet
        .hardware
        .as_ref()
        .map(|h| h.bindings.iter().any(|b| b.attestation.is_some()))
        .unwrap_or(false)
    {
        Ar4siStatus::Affirming as i8
    } else {
        Ar4siStatus::None as i8
    };

    
    let has_jitter = declaration.has_jitter_seal();
    let behavioral_quality = packet
        .behavioral
        .as_ref()
        .map(|b| !b.edit_topology.is_empty());
    tv.sourced_data = match (has_jitter, behavioral_quality) {
        (true, Some(true)) => Ar4siStatus::Affirming as i8,
        (true, Some(false)) => {
            warnings.push("Behavioral evidence present but edit topology is empty".to_string());
            Ar4siStatus::Warning as i8
        }
        (true, None) | (false, Some(true)) => Ar4siStatus::Warning as i8,
        (false, Some(false)) => {
            warnings.push("Behavioral evidence present but edit topology is empty".to_string());
            Ar4siStatus::None as i8
        }
        (false, None) => Ar4siStatus::None as i8,
    };

    
    if let Some(ks) = &packet.keystroke {
        let elapsed_secs = packet.total_elapsed_time().as_secs_f64();
        if elapsed_secs > 0.0 {
            let rate = ks.total_keystrokes as f64 / elapsed_secs;
            if rate > MAX_PLAUSIBLE_KEYSTROKES_PER_SEC {
                warnings.push(format!(
                    "Implausible keystroke rate: {:.1}/sec (max plausible: {:.0}/sec)",
                    rate, MAX_PLAUSIBLE_KEYSTROKES_PER_SEC
                ));
                if tv.sourced_data > Ar4siStatus::Warning as i8
                    || tv.sourced_data == Ar4siStatus::Affirming as i8
                {
                    tv.sourced_data = Ar4siStatus::Warning as i8;
                }
            }
        }
    }

    let overall = tv.overall_status();

    let seal_claims = SealClaims {
        h1: seal.h1,
        h2: seal.h2,
        h3: seal.h3,
        signature: seal.signature,
        public_key: seal.public_key,
    };

    let evidence_ref = packet_hash(packet)?;

    let appraisal = EarAppraisal {
        ear_status: overall,
        ear_trustworthiness_vector: Some(tv),
        ear_appraisal_policy_id: Some(policy.policy_uri.clone()),
        pop_seal: Some(seal_claims),
        pop_evidence_ref: Some(evidence_ref.to_vec()),
        pop_entropy_report: None,
        pop_forgery_cost: None,
        pop_forensic_summary: None,
        pop_chain_length: Some(packet.checkpoints.len() as u64),
        pop_chain_duration: Some(packet.total_elapsed_time().as_secs()),
        pop_absence_claims: None,
        pop_warnings: if warnings.is_empty() {
            None
        } else {
            Some(warnings)
        },
    };

    let mut submods = BTreeMap::new();
    submods.insert("pop".to_string(), appraisal);

    Ok(EarToken {
        eat_profile: POP_EAR_PROFILE.to_string(),
        iat: Utc::now().timestamp(),
        ear_verifier_id: VerifierId::default(),
        submods,
    })
}

/
fn packet_hash(packet: &Packet) -> Result<[u8; 32]> {
    let data = serde_json::to_vec(packet)
        .map_err(|e| Error::evidence(format!("packet serialization failed: {e}")))?;
    let digest = Sha256::digest(&data);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    Ok(hash)
}
