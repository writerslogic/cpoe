// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Wire-format evidence packet type per CDDL `evidence-packet`.

use serde::{Deserialize, Serialize};

use super::checkpoint::CheckpointWire;
use super::components::{
    ChannelBinding, DocumentRef, PhysicalLiveness, PresenceChallenge, ProfileDeclarationWire,
};
use super::enums::{AttestationTier, ContentTier};
use super::hash::HashValue;
use super::serde_helpers::fixed_bytes_16;
use super::CBOR_TAG_EVIDENCE_PACKET;
use crate::codec::{self, CodecError};

/// Wire-format evidence packet per CDDL `evidence-packet`.
///
/// Wrapped with CBOR tag 1129336656 for transmission.
///
/// ```cddl
/// evidence-packet = {
///     1 => uint,                    ; version
///     2 => tstr,                    ; profile-uri
///     3 => uuid,                    ; packet-id
///     4 => pop-timestamp,           ; created
///     5 => document-ref,            ; document
///     6 => [3* checkpoint],         ; checkpoints (min 3)
///     ? 7 => attestation-tier,
///     ? 8 => [* tstr],              ; limitations
///     ? 9 => profile-declaration,
///     ? 10 => [+ presence-challenge],
///     ? 11 => channel-binding,
///     ? 13 => content-tier,
///     ? 14 => hash-value,           ; previous-packet-ref
///     ? 15 => uint,                 ; packet-sequence
///     ? 18 => physical-liveness,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePacketWire {
    /// Schema version (MUST be 1)
    #[serde(rename = "1")]
    pub version: u64,

    /// Profile URI
    #[serde(rename = "2")]
    pub profile_uri: String,

    /// Packet identifier (UUID as 16-byte array)
    #[serde(rename = "3", with = "fixed_bytes_16")]
    pub packet_id: [u8; 16],

    /// Creation timestamp (epoch milliseconds)
    #[serde(rename = "4")]
    pub created: u64,

    /// Document reference
    #[serde(rename = "5")]
    pub document: DocumentRef,

    /// Checkpoint chain (minimum 3 required)
    #[serde(rename = "6")]
    pub checkpoints: Vec<CheckpointWire>,

    /// Attestation tier (T1-T4)
    #[serde(rename = "7", default, skip_serializing_if = "Option::is_none")]
    pub attestation_tier: Option<AttestationTier>,

    /// Known limitations
    #[serde(rename = "8", default, skip_serializing_if = "Option::is_none")]
    pub limitations: Option<Vec<String>>,

    /// Profile declaration
    #[serde(rename = "9", default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileDeclarationWire>,

    /// Presence challenges (QR/OOB proofs)
    #[serde(rename = "10", default, skip_serializing_if = "Option::is_none")]
    pub presence_challenges: Option<Vec<PresenceChallenge>>,

    /// Channel binding (TLS EKM)
    #[serde(rename = "11", default, skip_serializing_if = "Option::is_none")]
    pub channel_binding: Option<ChannelBinding>,

    /// Evidence content tier
    #[serde(rename = "13", default, skip_serializing_if = "Option::is_none")]
    pub content_tier: Option<ContentTier>,

    /// Reference to previous evidence packet in a chain
    #[serde(rename = "14", default, skip_serializing_if = "Option::is_none")]
    pub previous_packet_ref: Option<HashValue>,

    /// Sequence number within a packet chain (1-based)
    #[serde(rename = "15", default, skip_serializing_if = "Option::is_none")]
    pub packet_sequence: Option<u64>,

    /// Physical liveness markers
    #[serde(rename = "18", default, skip_serializing_if = "Option::is_none")]
    pub physical_liveness: Option<PhysicalLiveness>,
}

impl EvidencePacketWire {
    /// Encode this evidence packet to CBOR with the standard tag (1129336656).
    pub fn encode_cbor(&self) -> Result<Vec<u8>, CodecError> {
        codec::cbor::encode_tagged(self, CBOR_TAG_EVIDENCE_PACKET)
    }

    /// Decode an evidence packet from tagged CBOR bytes.
    pub fn decode_cbor(data: &[u8]) -> Result<Self, CodecError> {
        codec::cbor::decode_tagged(data, CBOR_TAG_EVIDENCE_PACKET)
    }

    /// Encode this evidence packet to untagged CBOR.
    pub fn encode_cbor_untagged(&self) -> Result<Vec<u8>, CodecError> {
        codec::cbor::encode(self)
    }

    /// Decode an evidence packet from untagged CBOR bytes.
    pub fn decode_cbor_untagged(data: &[u8]) -> Result<Self, CodecError> {
        codec::cbor::decode(data)
    }
}
