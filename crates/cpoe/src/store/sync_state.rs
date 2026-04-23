// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Sync state of a text fragment in the CloudKit sync pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncState {
    /// Fragment exists only locally, not yet pushed to CloudKit.
    Pending,
    /// Fragment successfully synced to CloudKit.
    Synced,
    /// Fragment verified by beacon server after sync.
    Verified,
}

impl SyncState {
    pub fn as_str(&self) -> &'static str {
        match self {
            SyncState::Pending => "pending",
            SyncState::Synced => "synced",
            SyncState::Verified => "verified",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(SyncState::Pending),
            "synced" => Some(SyncState::Synced),
            "verified" => Some(SyncState::Verified),
            _ => None,
        }
    }
}

/// Remote CloudKit record for a text fragment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudKitRecord {
    /// CloudKit record ID (server-assigned unique identifier).
    pub record_id: String,
    /// Device that created this fragment (for conflict resolution).
    pub device_created: String,
    /// Timestamp when fragment was pushed to CloudKit (ISO8601).
    pub synced_at: DateTime<Utc>,
    /// Fragment hash for deduplication.
    pub fragment_hash: Vec<u8>,
    /// Session ID linking this fragment to a local session.
    pub session_id: String,
    /// Keystroke confidence score from source device [0.0-1.0].
    pub keystroke_confidence: Option<f64>,
    /// Whether source device verified this as high-confidence authorship.
    pub verified: bool,
}

/// Conflict resolution result when the same fragment exists locally and remotely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictResolution {
    /// Keep local version (higher confidence or newer modification).
    KeepLocal,
    /// Replace with remote version (remote has higher confidence).
    ReplaceWithRemote,
    /// Merge both versions (semantically different, keep both).
    MergeBoth,
}

/// Sync metrics for monitoring and debugging.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncMetrics {
    /// Total fragments synced to CloudKit.
    pub total_synced: usize,
    /// Fragments received from other devices.
    pub total_received: usize,
    /// Conflict resolutions performed.
    pub total_conflicts: usize,
    /// Sync failures (retried on next sync window).
    pub sync_failures: usize,
    /// Last successful sync timestamp.
    pub last_sync_at: Option<DateTime<Utc>>,
    /// Average sync latency in milliseconds.
    pub avg_sync_latency_ms: u64,
}

impl SyncMetrics {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_state_roundtrip() {
        let states = [SyncState::Pending, SyncState::Synced, SyncState::Verified];
        for state in &states {
            let s = state.as_str();
            assert_eq!(SyncState::from_str(s), Some(*state));
        }
    }

    #[test]
    fn test_sync_state_invalid() {
        assert_eq!(SyncState::from_str("invalid"), None);
        assert_eq!(SyncState::from_str(""), None);
    }

    #[test]
    fn test_sync_metrics_default() {
        let metrics = SyncMetrics::new();
        assert_eq!(metrics.total_synced, 0);
        assert_eq!(metrics.total_received, 0);
        assert_eq!(metrics.last_sync_at, None);
    }

    #[test]
    fn test_cloudkit_record_serialize() {
        let record = CloudKitRecord {
            record_id: "test-id-123".to_string(),
            device_created: "MacBook-Pro".to_string(),
            synced_at: Utc::now(),
            fragment_hash: vec![1, 2, 3],
            session_id: "session-abc".to_string(),
            keystroke_confidence: Some(0.92),
            verified: true,
        };

        let json = serde_json::to_string(&record).expect("serialize failed");
        let deserialized: CloudKitRecord = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(deserialized.record_id, record.record_id);
        assert_eq!(deserialized.keystroke_confidence, record.keystroke_confidence);
    }
}
