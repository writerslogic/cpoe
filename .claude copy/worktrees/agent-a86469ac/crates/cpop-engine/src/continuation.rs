

//! Continuation tokens for multi-packet Evidence series.
//!
//! Allows a single authorship effort (e.g., a novel spanning months) to be
//! documented across multiple Evidence packets with cryptographic continuity:
//! previous chain hash feeds into VDF input, series-id is bound into the chain,
//! and signing keys must be consistent (verified via series-binding-signature).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuationSummary {
    pub total_checkpoints: u64,
    pub total_chars: u64,
    pub total_vdf_time_seconds: f64,
    /
    /
    pub total_entropy_bits: f64,
    /
    pub packets_in_series: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub series_started_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_elapsed_seconds: Option<f64>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuationSection {
    /
    pub series_id: Uuid,
    /
    pub packet_sequence: u32,
    /
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_packet_chain_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_packet_id: Option<Uuid>,
    pub cumulative_summary: ContinuationSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub series_binding_signature: Option<String>,
}

impl ContinuationSection {
    /
    pub fn new_series() -> Self {
        Self {
            series_id: Uuid::new_v4(),
            packet_sequence: 0,
            prev_packet_chain_hash: None,
            prev_packet_id: None,
            cumulative_summary: ContinuationSummary {
                total_checkpoints: 0,
                total_chars: 0,
                total_vdf_time_seconds: 0.0,
                total_entropy_bits: 0.0,
                packets_in_series: 1,
                series_started_at: Some(Utc::now()),
                total_elapsed_seconds: None,
            },
            series_binding_signature: None,
        }
    }

    /
    /
    /
    pub fn continue_from(
        prev_series_id: Uuid,
        prev_sequence: u32,
        prev_chain_hash: String,
        prev_packet_id: Uuid,
        prev_summary: &ContinuationSummary,
    ) -> Result<Self, String> {
        let next_sequence = prev_sequence
            .checked_add(1)
            .ok_or_else(|| "packet_sequence overflow: u32::MAX reached".to_string())?;
        let next_packets = prev_summary
            .packets_in_series
            .checked_add(1)
            .ok_or_else(|| "packets_in_series overflow: u32::MAX reached".to_string())?;

        Ok(Self {
            series_id: prev_series_id,
            packet_sequence: next_sequence,
            prev_packet_chain_hash: Some(prev_chain_hash),
            prev_packet_id: Some(prev_packet_id),
            cumulative_summary: ContinuationSummary {
                total_checkpoints: prev_summary.total_checkpoints,
                total_chars: prev_summary.total_chars,
                total_vdf_time_seconds: prev_summary.total_vdf_time_seconds,
                total_entropy_bits: prev_summary.total_entropy_bits,
                packets_in_series: next_packets,
                series_started_at: prev_summary.series_started_at,
                total_elapsed_seconds: None,
            },
            series_binding_signature: None,
        })
    }

    /
    pub fn add_packet_stats(
        &mut self,
        checkpoints: u64,
        chars: u64,
        vdf_time: f64,
        entropy_bits: f64,
    ) {
        self.cumulative_summary.total_checkpoints = self
            .cumulative_summary
            .total_checkpoints
            .saturating_add(checkpoints);
        self.cumulative_summary.total_chars =
            self.cumulative_summary.total_chars.saturating_add(chars);
        self.cumulative_summary.total_vdf_time_seconds += vdf_time;
        self.cumulative_summary.total_entropy_bits += entropy_bits;
    }

    /
    pub fn with_signature(mut self, signature: String) -> Self {
        self.series_binding_signature = Some(signature);
        self
    }

    /
    pub fn is_first(&self) -> bool {
        self.packet_sequence == 0
    }

    /
    /
    pub fn validate(&self) -> Result<(), String> {
        if self.packet_sequence > 0 {
            if self.prev_packet_chain_hash.is_none() {
                return Err("Non-first packet must have prev_packet_chain_hash".to_string());
            }
        } else if self.prev_packet_chain_hash.is_some() {
            return Err(
                "First packet (sequence 0) must not have prev_packet_chain_hash".to_string(),
            );
        }

        let expected = self
            .packet_sequence
            .checked_add(1)
            .ok_or_else(|| "packet_sequence overflow: u32::MAX reached".to_string())?;
        if self.cumulative_summary.packets_in_series != expected {
            return Err(format!(
                "packets_in_series ({}) does not match sequence + 1 ({})",
                self.cumulative_summary.packets_in_series, expected
            ));
        }

        Ok(())
    }

    /
    /
    /
    /
    /
    /
    /
    pub fn generate_vdf_context(&self, content_hash: &[u8]) -> Vec<u8> {
        
        
        let mut context = Vec::with_capacity(128);

        if let Some(ref prev_hash) = self.prev_packet_chain_hash {
            let bytes = prev_hash.as_bytes();
            context.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            context.extend_from_slice(bytes);
        }

        
        
        context.extend_from_slice(&(content_hash.len() as u32).to_be_bytes());
        context.extend_from_slice(content_hash);

        
        context.extend_from_slice(self.series_id.as_bytes());
        context.extend_from_slice(&self.packet_sequence.to_be_bytes());

        context
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_series() {
        let section = ContinuationSection::new_series();
        assert_eq!(section.packet_sequence, 0);
        assert!(section.prev_packet_chain_hash.is_none());
        assert!(section.is_first());
        assert!(section.validate().is_ok());
    }

    #[test]
    fn test_continuation() {
        let first = ContinuationSection::new_series();

        let second = ContinuationSection::continue_from(
            first.series_id,
            first.packet_sequence,
            "chain_hash_abc".to_string(),
            Uuid::new_v4(),
            &first.cumulative_summary,
        )
        .expect("continue_from should succeed");

        assert_eq!(second.packet_sequence, 1);
        assert!(!second.is_first());
        assert_eq!(second.series_id, first.series_id);
        assert_eq!(second.cumulative_summary.packets_in_series, 2);
        assert!(second.validate().is_ok());
    }

    #[test]
    fn test_continue_from_overflow() {
        let first = ContinuationSection::new_series();
        let result = ContinuationSection::continue_from(
            first.series_id,
            u32::MAX,
            "hash".to_string(),
            Uuid::new_v4(),
            &first.cumulative_summary,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("overflow"));
    }

    #[test]
    fn test_invalid_first_packet() {
        let mut section = ContinuationSection::new_series();
        section.prev_packet_chain_hash = Some("should_not_exist".to_string());
        assert!(section.validate().is_err());
    }

    #[test]
    fn test_invalid_continuation() {
        let section = ContinuationSection {
            series_id: Uuid::new_v4(),
            packet_sequence: 1,
            prev_packet_chain_hash: None,
            prev_packet_id: None,
            cumulative_summary: ContinuationSummary {
                total_checkpoints: 0,
                total_chars: 0,
                total_vdf_time_seconds: 0.0,
                total_entropy_bits: 0.0,
                packets_in_series: 2,
                series_started_at: None,
                total_elapsed_seconds: None,
            },
            series_binding_signature: None,
        };
        assert!(section.validate().is_err());
    }

    #[test]
    fn test_vdf_context_deterministic() {
        let section = ContinuationSection::new_series();
        let ctx1 = section.generate_vdf_context(b"test_content_hash");
        let ctx2 = section.generate_vdf_context(b"test_content_hash");
        assert_eq!(ctx1, ctx2);
        
        assert_eq!(ctx1.len(), 41);
    }

    #[test]
    fn test_vdf_context_with_prev_hash() {
        let first = ContinuationSection::new_series();
        let second = ContinuationSection::continue_from(
            first.series_id,
            first.packet_sequence,
            "prev_chain".to_string(),
            Uuid::new_v4(),
            &first.cumulative_summary,
        )
        .unwrap();

        let ctx = second.generate_vdf_context(b"content");
        
        
        assert_eq!(ctx.len(), 45);
    }

    #[test]
    fn test_vdf_context_no_boundary_ambiguity() {
        let section = ContinuationSection::new_series();
        let ctx_short = section.generate_vdf_context(b"ab");
        let ctx_long = section.generate_vdf_context(b"abc");
        
        assert_ne!(ctx_short, ctx_long);
    }

    #[test]
    fn test_add_packet_stats_saturates() {
        let mut section = ContinuationSection::new_series();
        section.add_packet_stats(u64::MAX, 0, 0.0, 0.0);
        section.add_packet_stats(1, 0, 0.0, 0.0);
        assert_eq!(section.cumulative_summary.total_checkpoints, u64::MAX);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let section = ContinuationSection::new_series();
        let json = serde_json::to_string(&section).unwrap();
        let parsed: ContinuationSection = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.series_id, section.series_id);
        assert_eq!(parsed.packet_sequence, section.packet_sequence);
        assert_eq!(
            parsed.cumulative_summary.packets_in_series,
            section.cumulative_summary.packets_in_series
        );
    }
}
