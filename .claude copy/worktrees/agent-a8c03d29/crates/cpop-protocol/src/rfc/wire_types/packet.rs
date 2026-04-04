

//! Wire-format evidence packet type per CDDL `evidence-packet`.

use serde::{Deserialize, Serialize};

use super::checkpoint::CheckpointWire;
use super::components::{
    BaselineVerification, ChannelBinding, DocumentRef, PhysicalLiveness, PresenceChallenge,
    ProfileDeclarationWire,
};
use super::enums::{AttestationTier, ContentTier};
use super::hash::HashValue;
use super::serde_helpers::fixed_bytes_16;
use super::CBOR_TAG_EVIDENCE_PACKET;
use crate::codec::{self, CodecError};

/
/
/
/
/
/
/
/
/
/
/
/
/
/
/
/
/
/
/
/
/
/
/
/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePacketWire {
    /
    #[serde(rename = "1")]
    pub version: u64,

    #[serde(rename = "2")]
    pub profile_uri: String,

    #[serde(rename = "3", with = "fixed_bytes_16")]
    pub packet_id: [u8; 16],

    /
    #[serde(rename = "4")]
    pub created: u64,

    #[serde(rename = "5")]
    pub document: DocumentRef,

    /
    #[serde(rename = "6")]
    pub checkpoints: Vec<CheckpointWire>,

    #[serde(rename = "7", default, skip_serializing_if = "Option::is_none")]
    pub attestation_tier: Option<AttestationTier>,

    #[serde(rename = "8", default, skip_serializing_if = "Option::is_none")]
    pub limitations: Option<Vec<String>>,

    #[serde(rename = "9", default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileDeclarationWire>,

    #[serde(rename = "10", default, skip_serializing_if = "Option::is_none")]
    pub presence_challenges: Option<Vec<PresenceChallenge>>,

    #[serde(rename = "11", default, skip_serializing_if = "Option::is_none")]
    pub channel_binding: Option<ChannelBinding>,

    /
    #[serde(rename = "12", default, skip_serializing_if = "Option::is_none")]
    pub signing_public_key: Option<serde_bytes::ByteBuf>,

    #[serde(rename = "13", default, skip_serializing_if = "Option::is_none")]
    pub content_tier: Option<ContentTier>,

    #[serde(rename = "14", default, skip_serializing_if = "Option::is_none")]
    pub previous_packet_ref: Option<HashValue>,

    /
    #[serde(rename = "15", default, skip_serializing_if = "Option::is_none")]
    pub packet_sequence: Option<u64>,

    #[serde(rename = "18", default, skip_serializing_if = "Option::is_none")]
    pub physical_liveness: Option<PhysicalLiveness>,

    #[serde(rename = "19", default, skip_serializing_if = "Option::is_none")]
    pub baseline_verification: Option<BaselineVerification>,
}

/
const MIN_CHECKPOINTS: usize = 3;
/
const MAX_CHECKPOINTS: usize = 10_000;
/
const MAX_LIMITATIONS: usize = 100;
/
const MAX_PRESENCE_CHALLENGES: usize = 100;
use super::MAX_STRING_LEN;

impl EvidencePacketWire {
    /
    pub fn encode_cbor(&self) -> Result<Vec<u8>, CodecError> {
        codec::cbor::encode_tagged(self, CBOR_TAG_EVIDENCE_PACKET)
    }

    /
    pub fn decode_cbor(data: &[u8]) -> Result<Self, CodecError> {
        let packet: Self = codec::cbor::decode_tagged(data, CBOR_TAG_EVIDENCE_PACKET)?;
        packet.validate()?;
        Ok(packet)
    }

    /
    pub fn encode_cbor_untagged(&self) -> Result<Vec<u8>, CodecError> {
        codec::cbor::encode(self)
    }

    /
    pub fn decode_cbor_untagged(data: &[u8]) -> Result<Self, CodecError> {
        let packet: Self = codec::cbor::decode(data)?;
        packet.validate()?;
        Ok(packet)
    }

    /
    pub fn validate(&self) -> Result<(), CodecError> {
        if self.version != 1 {
            return Err(CodecError::Validation(format!(
                "unsupported version {}, expected 1",
                self.version
            )));
        }

        if self.profile_uri.is_empty() || self.profile_uri.len() > MAX_STRING_LEN {
            return Err(CodecError::Validation(format!(
                "profile_uri length {} out of range [1, {}]",
                self.profile_uri.len(),
                MAX_STRING_LEN
            )));
        }

        if self.packet_id == [0u8; 16] {
            return Err(CodecError::Validation(
                "packet_id must not be all zeros".into(),
            ));
        }

        if self.created == 0 {
            return Err(CodecError::Validation(
                "created timestamp must not be zero".into(),
            ));
        }

        if self.checkpoints.len() < MIN_CHECKPOINTS {
            return Err(CodecError::Validation(format!(
                "need at least {} checkpoints, got {}",
                MIN_CHECKPOINTS,
                self.checkpoints.len()
            )));
        }
        if self.checkpoints.len() > MAX_CHECKPOINTS {
            return Err(CodecError::Validation(format!(
                "too many checkpoints: {} (max {})",
                self.checkpoints.len(),
                MAX_CHECKPOINTS
            )));
        }

        if let Some(ref lims) = self.limitations {
            if lims.len() > MAX_LIMITATIONS {
                return Err(CodecError::Validation(format!(
                    "too many limitations: {} (max {})",
                    lims.len(),
                    MAX_LIMITATIONS
                )));
            }
            for (i, s) in lims.iter().enumerate() {
                if s.len() > MAX_STRING_LEN {
                    return Err(CodecError::Validation(format!(
                        "limitation[{}] too long: {} (max {})",
                        i,
                        s.len(),
                        MAX_STRING_LEN
                    )));
                }
            }
        }
        if let Some(ref pcs) = self.presence_challenges {
            if pcs.is_empty() {
                return Err(CodecError::Validation(
                    "presence_challenges must be non-empty if present".into(),
                ));
            }
            if pcs.len() > MAX_PRESENCE_CHALLENGES {
                return Err(CodecError::Validation(format!(
                    "too many presence_challenges: {} (max {})",
                    pcs.len(),
                    MAX_PRESENCE_CHALLENGES
                )));
            }
            for (i, pc) in pcs.iter().enumerate() {
                pc.validate().map_err(|e| {
                    CodecError::Validation(format!("presence_challenge[{}]: {}", i, e))
                })?;
            }
        }

        self.document.validate().map_err(CodecError::Validation)?;
        if let Some(ref name) = self.document.filename {
            if name.len() > MAX_STRING_LEN {
                return Err(CodecError::Validation(format!(
                    "document filename too long: {} (max {})",
                    name.len(),
                    MAX_STRING_LEN
                )));
            }
        }

        for (i, cp) in self.checkpoints.iter().enumerate() {
            cp.validate()
                .map_err(|e| CodecError::Validation(format!("checkpoint[{}]: {}", i, e)))?;
        }

        if let Some(ref pl) = self.physical_liveness {
            pl.validate().map_err(CodecError::Validation)?;
        }

        if let Some(ref prof) = self.profile {
            prof.validate().map_err(CodecError::Validation)?;
        }

        if let Some(seq) = self.packet_sequence {
            if seq == 0 {
                return Err(CodecError::Validation(
                    "packet_sequence is 1-based, got 0".into(),
                ));
            }
        }

        Ok(())
    }
}
