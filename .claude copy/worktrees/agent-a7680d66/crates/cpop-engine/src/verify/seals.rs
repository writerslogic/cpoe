

//! Seal verification and duration/key-provenance checks.

use base64::Engine;

use crate::evidence::Packet;
use crate::vdf;

use super::{
    DurationCheck, KeyProvenanceCheck, SealVerification, SWF_DURATION_RATIO_MAX,
    SWF_DURATION_RATIO_MIN,
};

/
/
/
/
/
/
pub(super) fn verify_seals_structural(
    packet: &Packet,
    warnings: &mut Vec<String>,
) -> SealVerification {
    let mut jitter_tag_present: Option<bool> = None;
    
    
    let entangled_binding_valid: Option<bool> = None;
    let mut checkpoints_checked = 0;

    
    if let Some(decl) = &packet.declaration {
        if let Some(ref sealed) = decl.jitter_sealed {
            
            
            if sealed.jitter_hash == [0u8; 32] {
                warnings.push("Declaration jitter seal has zero hash".to_string());
                jitter_tag_present = Some(false);
            } else {
                jitter_tag_present = Some(true);
                checkpoints_checked += 1;
            }
        }
    }

    
    for cp in &packet.checkpoints {
        if let (Some(vdf_in), Some(vdf_out)) = (&cp.vdf_input, &cp.vdf_output) {
            
            let in_ok = hex::decode(vdf_in).map(|b| b.len() == 32).unwrap_or(false);
            let out_ok = hex::decode(vdf_out).map(|b| b.len() == 32).unwrap_or(false);

            if !in_ok || !out_ok {
                warnings.push(format!(
                    "Checkpoint {} has malformed VDF input/output",
                    cp.ordinal
                ));
            }
            checkpoints_checked += 1;
        }
    }

    
    if let Some(ref jb) = packet.jitter_binding {
        if jb.entropy_commitment.hash == [0u8; 32] {
            warnings.push("Jitter binding has zero entropy commitment hash".to_string());
            jitter_tag_present = Some(false);
        } else if jitter_tag_present.is_none() {
            jitter_tag_present = Some(true);
        }
    }

    SealVerification {
        jitter_tag_present,
        entangled_binding_valid,
        checkpoints_checked,
    }
}

/
/
/
/
/
pub(super) fn verify_duration(
    packet: &Packet,
    vdf_params: &vdf::Parameters,
    warnings: &mut Vec<String>,
) -> DurationCheck {
    if vdf_params.iterations_per_second == 0 {
        warnings.push(
            "VDF iterations_per_second is zero — duration check cannot be performed".to_string(),
        );
        return DurationCheck {
            computed_min_seconds: 0.0,
            claimed_seconds: 0.0,
            ratio: 0.0,
            plausible: false,
        };
    }

    let total_iterations: u64 = packet
        .checkpoints
        .iter()
        .filter_map(|cp| cp.vdf_iterations)
        .sum();

    
    
    
    let computed_min_seconds = total_iterations as f64 / vdf_params.iterations_per_second as f64;

    
    let claimed_seconds = if packet.checkpoints.len() >= 2 {
        let min_ts = packet.checkpoints.iter().map(|cp| cp.timestamp).min();
        let max_ts = packet.checkpoints.iter().map(|cp| cp.timestamp).max();
        match (min_ts, max_ts) {
            (Some(min), Some(max)) => (max - min).num_milliseconds().max(0) as f64 / 1000.0,
            _ => 0.0,
        }
    } else {
        0.0
    };

    let ratio = if computed_min_seconds > 0.0 {
        claimed_seconds / computed_min_seconds
    } else {
        
        
        0.0
    };

    let plausible = if computed_min_seconds > 0.0 {
        (SWF_DURATION_RATIO_MIN..=SWF_DURATION_RATIO_MAX).contains(&ratio)
    } else if !packet.checkpoints.is_empty() {
        
        
        warnings.push("No VDF proof data found".to_string());
        false
    } else {
        
        true
    };

    
    if !plausible && computed_min_seconds > 0.0 {
        if ratio < SWF_DURATION_RATIO_MIN {
            warnings.push(format!(
                "Duration implausible: claimed {:.1}s but VDF requires minimum {:.1}s (ratio {:.2}x)",
                claimed_seconds, computed_min_seconds, ratio
            ));
        } else {
            warnings.push(format!(
                "Duration suspicious: claimed {:.1}s vs VDF minimum {:.1}s (ratio {:.2}x, max {:.1}x)",
                claimed_seconds, computed_min_seconds, ratio, SWF_DURATION_RATIO_MAX
            ));
        }
    }

    DurationCheck {
        computed_min_seconds,
        claimed_seconds,
        ratio,
        plausible,
    }
}

/
pub(super) fn verify_key_provenance(
    packet: &Packet,
    warnings: &mut Vec<String>,
) -> KeyProvenanceCheck {
    let mut hierarchy_consistent: Option<bool> = None;
    let mut signing_key_consistent = true;
    let mut ratchet_monotonic = true;

    if let Some(ref kh) = packet.key_hierarchy {
        
        let master_bytes_opt = hex::decode(&kh.master_public_key)
            .ok()
            .filter(|b| b.len() == 32);
        let session_bytes_opt = hex::decode(&kh.session_public_key)
            .ok()
            .filter(|b| b.len() == 32);
        let master_ok = master_bytes_opt.is_some();
        let session_ok = session_bytes_opt.is_some();
        let cert_ok = base64_decode_len(&kh.session_certificate) == Some(64);

        if !master_ok || !session_ok || !cert_ok {
            warnings.push("Key hierarchy has invalid key/certificate lengths".to_string());
            hierarchy_consistent = Some(false);
        } else if let Some(ref doc_hash_hex) = kh.session_document_hash {
            
            
            let master_bytes = master_bytes_opt.expect("master_ok is true");
            let session_bytes = session_bytes_opt.expect("session_ok is true");
            let session_id_result = hex::decode(&kh.session_id).ok().filter(|b| b.len() == 32);
            let doc_hash_result = hex::decode(doc_hash_hex).ok().filter(|b| b.len() == 32);
            match (session_id_result, doc_hash_result) {
                (Some(sid_bytes), Some(dh_bytes)) => {
                    let mut session_id_arr = [0u8; 32];
                    let mut doc_hash_arr = [0u8; 32];
                    session_id_arr.copy_from_slice(&sid_bytes);
                    doc_hash_arr.copy_from_slice(&dh_bytes);
                    match crate::keyhierarchy::verification::validate_cert_byte_lengths(
                        &master_bytes,
                        &session_bytes,
                        &base64_decode(&kh.session_certificate),
                        &session_id_arr,
                        kh.session_started,
                        &doc_hash_arr,
                    ) {
                        Ok(()) => hierarchy_consistent = Some(true),
                        Err(e) => {
                            warnings.push(format!("Key hierarchy certificate invalid: {}", e));
                            hierarchy_consistent = Some(false);
                        }
                    }
                }
                _ => {
                    warnings.push(
                        "Key hierarchy session_id or session_document_hash has invalid length"
                            .to_string(),
                    );
                    hierarchy_consistent = Some(false);
                }
            }
        } else {
            
            hierarchy_consistent = Some(true);
        }

        
        
        let mut prev_index = -1i64;
        for sig in &kh.checkpoint_signatures {
            let idx = sig.ratchet_index as i64;
            if idx < 0 {
                ratchet_monotonic = false;
                signing_key_consistent = false;
                warnings.push(format!(
                    "Ratchet index negative ({}) at checkpoint {}",
                    idx, sig.ordinal
                ));
                continue;
            }
            if idx <= prev_index {
                ratchet_monotonic = false;
                warnings.push(format!(
                    "Ratchet index non-monotonic at checkpoint {}",
                    sig.ordinal
                ));
                continue;
            }
            prev_index = idx;

            let uidx = sig.ratchet_index as usize;
            if uidx >= kh.ratchet_public_keys.len() {
                signing_key_consistent = false;
                warnings.push(format!(
                    "Checkpoint {} references ratchet index {} but only {} keys exist",
                    sig.ordinal,
                    uidx,
                    kh.ratchet_public_keys.len()
                ));
                continue;
            }
        }
    } else {
        warnings.push("No key hierarchy present".to_string());
    }

    
    if let Some(ref pubkey) = packet.signing_public_key {
        if let Some(ref kh) = packet.key_hierarchy {
            
            let pubkey_hex = hex::encode(pubkey).to_lowercase();
            let found = kh
                .ratchet_public_keys
                .iter()
                .any(|k| k.to_lowercase() == pubkey_hex)
                || kh.session_public_key.to_lowercase() == pubkey_hex;
            if !found {
                warnings
                    .push("Packet signing key does not match any key in the hierarchy".to_string());
                signing_key_consistent = false;
            }
        }
    }

    KeyProvenanceCheck {
        hierarchy_consistent,
        signing_key_consistent,
        ratchet_monotonic,
    }
}

/
fn base64_decode(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .unwrap_or_default()
}

/
fn base64_decode_len(s: &str) -> Option<usize> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .ok()
        .map(|b| b.len())
}
