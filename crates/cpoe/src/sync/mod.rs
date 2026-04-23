// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! CloudKit synchronization engine for multi-device evidence sync.
//!
//! Coordinates evidence packet distribution across user's iCloud container,
//! handles device pairing with Ed25519 keys, and resolves conflicts via
//! timestamp-based last-write-wins strategy.
//!
//! **Module Organization:**
//! - `cloudkit_manager` — push/pull to iCloud, query execution, record marshaling
//! - `device_pairing` — QR code generation, ECDH shared secret derivation
//! - `conflict_resolver` — deterministic conflict resolution logic

pub mod cloudkit_manager;
pub mod conflict_resolver;
pub mod device_pairing;

pub use cloudkit_manager::{CloudKitManager, SyncStats};
pub use conflict_resolver::{ConflictResolution, ConflictResolver};
pub use device_pairing::{DevicePairingRecord, PairingFlow};
