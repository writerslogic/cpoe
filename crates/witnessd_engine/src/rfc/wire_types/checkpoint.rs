// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Wire-format checkpoint type per CDDL `checkpoint`.

use serde::{Deserialize, Serialize};

use super::components::{
    ActiveProbe, EditDelta, JitterBindingWire, PhysicalState, ProcessProof, SelfReceipt,
};
use super::hash::HashValue;
use super::serde_helpers::{fixed_bytes_16, serde_bytes_opt};

/// Wire-format checkpoint per CDDL `checkpoint`.
///
/// ```cddl
/// checkpoint = {
///     1 => uint,               ; sequence
///     2 => uuid,               ; checkpoint-id
///     3 => pop-timestamp,      ; timestamp
///     4 => hash-value,         ; content-hash
///     5 => uint,               ; char-count
///     6 => edit-delta,         ; delta
///     7 => hash-value,         ; prev-hash
///     8 => hash-value,         ; checkpoint-hash
///     9 => process-proof,      ; SWF proof
///     ? 10 => jitter-binding,
///     ? 11 => physical-state,
///     ? 12 => hash-digest,     ; entangled-mac
///     ? 13 => [+ self-receipt],
///     ? 14 => [+ active-probe],
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointWire {
    /// Monotonically increasing sequence number
    #[serde(rename = "1")]
    pub sequence: u64,

    /// Unique checkpoint identifier (UUID as 16-byte array)
    #[serde(rename = "2", with = "fixed_bytes_16")]
    pub checkpoint_id: [u8; 16],

    /// Local timestamp (epoch milliseconds)
    #[serde(rename = "3")]
    pub timestamp: u64,

    /// Hash of document content at this checkpoint
    #[serde(rename = "4")]
    pub content_hash: HashValue,

    /// Character count at this checkpoint
    #[serde(rename = "5")]
    pub char_count: u64,

    /// Edit delta since previous checkpoint
    #[serde(rename = "6")]
    pub delta: EditDelta,

    /// Hash of the previous checkpoint (zeros for first)
    #[serde(rename = "7")]
    pub prev_hash: HashValue,

    /// Hash of this checkpoint structure
    #[serde(rename = "8")]
    pub checkpoint_hash: HashValue,

    /// Sequential work function proof
    #[serde(rename = "9")]
    pub process_proof: ProcessProof,

    /// Behavioral entropy binding (ENHANCED+)
    #[serde(rename = "10", default, skip_serializing_if = "Option::is_none")]
    pub jitter_binding: Option<JitterBindingWire>,

    /// Physical state binding (ENHANCED+)
    #[serde(rename = "11", default, skip_serializing_if = "Option::is_none")]
    pub physical_state: Option<PhysicalState>,

    /// Entangled MAC (ENHANCED+)
    #[serde(
        rename = "12",
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_bytes_opt"
    )]
    pub entangled_mac: Option<Vec<u8>>,

    /// Cross-tool composition receipts
    #[serde(rename = "13", default, skip_serializing_if = "Option::is_none")]
    pub self_receipts: Option<Vec<SelfReceipt>>,

    /// Active liveness probes
    #[serde(rename = "14", default, skip_serializing_if = "Option::is_none")]
    pub active_probes: Option<Vec<ActiveProbe>>,
}
