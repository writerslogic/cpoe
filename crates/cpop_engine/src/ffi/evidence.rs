// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Evidence FFI bindings: shared helpers and re-exports.
//!
//! The actual FFI functions are split across submodules:
//! - `evidence_export`: `ffi_export_evidence`, `ffi_get_compact_ref`
//! - `evidence_checkpoint`: `ffi_create_checkpoint`
//! - `evidence_derivative`: `ffi_link_derivative`, `ffi_export_c2pa_manifest`

use std::sync::OnceLock;

/// Cached device identity for populating evidence events (EH-013).
static DEVICE_IDENTITY: OnceLock<([u8; 16], String)> = OnceLock::new();

pub(crate) fn device_identity() -> &'static ([u8; 16], String) {
    DEVICE_IDENTITY.get_or_init(|| {
        crate::identity::secure_storage::SecureStorage::load_device_identity()
            .ok()
            .flatten()
            .unwrap_or_else(|| {
                let machine_id =
                    sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string());
                ([0u8; 16], machine_id)
            })
    })
}
