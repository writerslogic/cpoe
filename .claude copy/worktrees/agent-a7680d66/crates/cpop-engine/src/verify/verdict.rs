

//! Verdict computation from all verification phases.

use crate::forensics::{ForensicMetrics, PerCheckpointResult};
use cpop_protocol::forensics::ForensicVerdict;

use super::{
    DurationCheck, KeyProvenanceCheck, SealVerification, SWF_DURATION_RATIO_MAX,
    SWF_DURATION_RATIO_MIN,
};

/
#[allow(clippy::too_many_arguments)]
pub(super) fn compute_verdict(
    structural: bool,
    signature: Option<bool>,
    declaration_valid: bool,
    seals: &SealVerification,
    duration: &DurationCheck,
    key_provenance: &KeyProvenanceCheck,
    forensics: Option<&ForensicMetrics>,
    per_checkpoint: Option<&PerCheckpointResult>,
) -> ForensicVerdict {
    
    if !structural {
        return ForensicVerdict::V5ConfirmedForgery;
    }

    
    if signature == Some(false) {
        return ForensicVerdict::V5ConfirmedForgery;
    }

    
    if seals.jitter_tag_present == Some(false) || seals.entangled_binding_valid == Some(false) {
        return ForensicVerdict::V5ConfirmedForgery;
    }

    
    if !duration.plausible && duration.ratio < SWF_DURATION_RATIO_MIN {
        return ForensicVerdict::V4LikelySynthetic;
    }

    
    if key_provenance.hierarchy_consistent == Some(false)
        || !key_provenance.ratchet_monotonic
        || !key_provenance.signing_key_consistent
    {
        return ForensicVerdict::V4LikelySynthetic;
    }

    
    
    if !duration.plausible && duration.ratio > SWF_DURATION_RATIO_MAX {
        return ForensicVerdict::V3Suspicious;
    }

    
    if let Some(pcp) = per_checkpoint {
        if pcp.suspicious {
            return ForensicVerdict::V3Suspicious;
        }
    }

    
    if !declaration_valid {
        
        
    }

    
    
    
    let seals_structural_only = seals.entangled_binding_valid.is_none();
    let capped = !declaration_valid || seals_structural_only;

    
    
    
    
    let no_vdf = duration.computed_min_seconds == 0.0;

    
    if let Some(fm) = forensics {
        let fv = fm.map_to_protocol_verdict();
        if (no_vdf || capped) && fv == ForensicVerdict::V1VerifiedHuman {
            return ForensicVerdict::V2LikelyHuman;
        }
        return fv;
    }

    
    if !duration.plausible {
        return ForensicVerdict::V3Suspicious;
    }

    
    if signature.is_none() {
        return ForensicVerdict::V2LikelyHuman;
    }

    
    
    
    
    if !no_vdf
        && !capped
        && signature == Some(true)
        && key_provenance.signing_key_consistent
        && key_provenance.hierarchy_consistent != Some(false)
    {
        return ForensicVerdict::V1VerifiedHuman;
    }

    ForensicVerdict::V2LikelyHuman
}
