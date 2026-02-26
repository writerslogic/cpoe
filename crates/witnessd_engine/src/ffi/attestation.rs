// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::ffi::helpers::{detect_attestation_tier_info, get_data_dir};
use crate::ffi::types::{FfiAttestationInfo, FfiResult};
use crate::rfc::wire_types::AttestationTier;

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_attestation_info() -> FfiAttestationInfo {
    let (_, tier_num, tier_label) = detect_attestation_tier_info();

    let provider = crate::tpm::detect_provider();
    let caps = provider.capabilities();
    FfiAttestationInfo {
        tier: tier_num,
        tier_label,
        provider_type: provider.device_id(),
        hardware_bound: caps.hardware_backed && caps.supports_sealing,
        supports_sealing: caps.supports_sealing,
        has_monotonic_counter: caps.monotonic_counter,
        has_secure_clock: caps.secure_clock,
        device_id: provider.device_id(),
    }
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_reseal_identity() -> FfiResult {
    let data_dir = match get_data_dir() {
        Some(d) => d,
        None => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some("Could not determine data directory".to_string()),
            };
        }
    };

    let store = crate::sealed_identity::SealedIdentityStore::auto_detect(&data_dir);

    if !store.is_bound() {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some("No sealed identity found on this device".to_string()),
        };
    }

    let puf_seed_path = data_dir.join("puf_seed");
    let puf = match crate::keyhierarchy::SoftwarePUF::new_with_path(&puf_seed_path) {
        Ok(p) => p,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to initialize PUF: {}", e)),
            };
        }
    };

    match store.reseal(&puf) {
        Ok(()) => FfiResult {
            success: true,
            message: Some("Identity re-sealed under current platform state".to_string()),
            error_message: None,
        },
        Err(e) => FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Reseal failed: {}", e)),
        },
    }
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_is_hardware_bound() -> bool {
    let data_dir = match get_data_dir() {
        Some(d) => d,
        None => return false,
    };

    let store = crate::sealed_identity::SealedIdentityStore::auto_detect(&data_dir);
    if !store.is_bound() {
        return false;
    }

    store.attestation_tier() == AttestationTier::HardwareBound
        || store.attestation_tier() == AttestationTier::HardwareHardened
}
