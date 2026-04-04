// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::helpers::load_signing_key;
use crate::ffi::types::FfiResult;
use crate::identity::did_webvh::WebVHIdentity;

/// Create a new did:webvh identity bound to the given address.
///
/// Loads the signing key from disk, derives a did:webvh key via HKDF,
/// creates the DID document, and persists the state. Returns the DID
/// string in `message` on success.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_create_webvh_identity(address: String) -> FfiResult {
    let signing_key = match load_signing_key() {
        Ok(k) => k,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(e),
            };
        }
    };

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to create async runtime: {e}")),
            };
        }
    };

    let identity = match rt.block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            WebVHIdentity::create(&signing_key, &address),
        )
        .await
    }) {
        Ok(Ok(id)) => id,
        Ok(Err(e)) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to create did:webvh identity: {e}")),
            };
        }
        Err(_) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some("did:webvh identity creation timed out".to_string()),
            };
        }
    };

    if let Err(e) = identity.save() {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Failed to save did:webvh state: {e}")),
        };
    }

    FfiResult {
        success: true,
        message: Some(identity.did().to_string()),
        error_message: None,
    }
}

/// Return the current did:webvh DID string.
///
/// Loads the persisted did:webvh identity from disk. Returns success=false
/// if no did:webvh identity has been created.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_webvh_did() -> FfiResult {
    match WebVHIdentity::load() {
        Ok(identity) => FfiResult {
            success: true,
            message: Some(identity.did().to_string()),
            error_message: None,
        },
        Err(e) => FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("No did:webvh identity configured: {e}")),
        },
    }
}

/// Return the active author DID, preferring did:webvh over did:key.
///
/// Calls `load_active_did()` which tries did:webvh first, then falls
/// back to did:key derived from the signing key on disk.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_active_did() -> FfiResult {
    match crate::identity::did_webvh::load_active_did() {
        Ok(did) => FfiResult {
            success: true,
            message: Some(did),
            error_message: None,
        },
        Err(e) => FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Failed to resolve active DID: {e}")),
        },
    }
}

/// Deactivate the did:webvh identity.
///
/// Loads the signing key and persisted identity, calls deactivate on the
/// did:webvh state, and saves the updated (deactivated) state to disk.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_deactivate_webvh_identity() -> FfiResult {
    let signing_key = match load_signing_key() {
        Ok(k) => k,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(e),
            };
        }
    };

    let mut identity = match WebVHIdentity::load() {
        Ok(id) => id,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("No did:webvh identity to deactivate: {e}")),
            };
        }
    };

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to create async runtime: {e}")),
            };
        }
    };

    match rt.block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            identity.deactivate(&signing_key),
        )
        .await
    }) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some(format!("Failed to deactivate did:webvh identity: {e}")),
            };
        }
        Err(_) => {
            return FfiResult {
                success: false,
                message: None,
                error_message: Some("did:webvh deactivation timed out".to_string()),
            };
        }
    }

    if let Err(e) = identity.save() {
        return FfiResult {
            success: false,
            message: None,
            error_message: Some(format!("Failed to save deactivated state: {e}")),
        };
    }

    FfiResult {
        success: true,
        message: Some("did:webvh identity deactivated".to_string()),
        error_message: None,
    }
}
