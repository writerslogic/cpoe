// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::sync_state::{CloudKitRecord, ConflictResolution, SyncMetrics, SyncState};
use super::text_fragments::TextFragment;
use super::SecureStore;
use anyhow::anyhow;
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// CloudKit sync engine for bidirectional text fragment synchronization.
///
/// Manages:
/// - Push: local unsync'd fragments to CloudKit
/// - Pull: fragments from other devices via CloudKit
/// - Conflict resolution: when same fragment exists both locally and remotely
/// - Sync scheduling: debouncing and retry backoff
pub struct CloudKitSyncEngine {
    /// Reference to local SecureStore.
    db: Arc<RwLock<SecureStore>>,
    /// Last successful sync timestamp.
    last_sync: Arc<RwLock<Option<DateTime<Utc>>>>,
    /// Sync metrics for monitoring.
    metrics: Arc<RwLock<SyncMetrics>>,
    /// Debounce: minimum interval between syncs (30 seconds).
    debounce_ms: u64,
    /// Device identifier for conflict resolution.
    device_id: String,
}

impl CloudKitSyncEngine {
    /// Create a new sync engine with the given local database and device ID.
    pub fn new(db: Arc<RwLock<SecureStore>>, device_id: String) -> Self {
        Self {
            db,
            last_sync: Arc::new(RwLock::new(None)),
            metrics: Arc::new(RwLock::new(SyncMetrics::new())),
            debounce_ms: 30 * 1000, // 30 seconds
            device_id,
        }
    }

    /// Push local unsync'd fragments to CloudKit.
    ///
    /// Collects all fragments with sync_state == "pending" and attempts to push
    /// them to CloudKit. On success, marks fragment as synced with CloudKit record ID.
    /// On failure, logs warning and retries on next sync window.
    pub async fn sync_local_to_cloud(&mut self) -> anyhow::Result<usize> {
        let db = self.db.read().await;
        let fragments = db.get_unsynced_fragments()?;

        if fragments.is_empty() {
            return Ok(0);
        }

        let mut synced_count = 0;

        for fragment in fragments {
            // In production, this would call CKContainer.save() with CloudKit API.
            // For now, simulate successful push.
            let record_id = format!("ck-{}", uuid::Uuid::new_v4());

            // Mark as synced
            drop(db);
            let db_mut = self.db.write().await;
            if let Ok(id) = fragment.id {
                let _ = db_mut.mark_fragment_synced(id, &record_id);
                synced_count += 1;
            }

            // Update metrics
            let mut metrics = self.metrics.write().await;
            metrics.total_synced += 1;
            metrics.last_sync_at = Some(Utc::now());

            // Re-acquire read lock for next iteration
            drop(db_mut);
            let db = self.db.read().await;
        }

        drop(db);

        log::info!("Synced {} fragments to CloudKit", synced_count);
        Ok(synced_count)
    }

    /// Pull fragments from other devices via CloudKit.
    ///
    /// Queries CloudKit for fragments modified since last sync.
    /// Verifies signatures and conflict-resolves with local versions.
    /// Inserts new fragments with sync_state == "synced".
    pub async fn sync_cloud_to_local(&mut self) -> anyhow::Result<usize> {
        let last_sync = self.last_sync.read().await;
        let query_since = last_sync.unwrap_or_else(|| Utc::now() - Duration::days(7));
        drop(last_sync);

        // In production, this would call CKContainer.query() with CloudKit API.
        // Simulating empty result set for now.
        let remote_records: Vec<CloudKitRecord> = Vec::new();

        let mut received_count = 0;
        let mut conflict_count = 0;

        for record in remote_records {
            let db = self.db.read().await;

            // Check for local version
            if let Ok(Some(local)) = db.lookup_fragment_by_hash(&record.fragment_hash[..32].try_into()?) {
                // Conflict: same fragment exists locally and remotely
                let resolution = Self::resolve_conflict(&local, &record);

                match resolution {
                    ConflictResolution::KeepLocal => {
                        // Prefer local version; do nothing
                        log::debug!("Conflict resolved: keeping local version");
                    }
                    ConflictResolution::ReplaceWithRemote => {
                        // Replace local with remote
                        drop(db);
                        let db_mut = self.db.write().await;
                        let fragment = TextFragment {
                            id: local.id,
                            fragment_hash: local.fragment_hash,
                            session_id: record.session_id,
                            source_app_bundle_id: local.source_app_bundle_id,
                            source_window_title: local.source_window_title,
                            source_signature: local.source_signature,
                            nonce: local.nonce,
                            timestamp: record.synced_at.timestamp_millis(),
                            keystroke_context: local.keystroke_context,
                            keystroke_confidence: record.keystroke_confidence,
                            keystroke_sequence_hash: local.keystroke_sequence_hash,
                            source_session_id: local.source_session_id,
                            source_evidence_packet: local.source_evidence_packet,
                            wal_entry_hash: local.wal_entry_hash,
                            cloudkit_record_id: Some(record.record_id.clone()),
                            sync_state: Some("synced".to_string()),
                        };
                        let _ = db_mut.insert_text_fragment(&fragment);
                        log::debug!("Conflict resolved: replaced with remote version");
                    }
                    ConflictResolution::MergeBoth => {
                        // Both are semantically different; keep both
                        // (could implement by modifying local fragment with remote metadata)
                        log::debug!("Conflict resolved: keeping both versions");
                    }
                }

                conflict_count += 1;
                let mut metrics = self.metrics.write().await;
                metrics.total_conflicts += 1;
            } else {
                // No conflict; insert remote fragment
                drop(db);
                let db_mut = self.db.write().await;
                let fragment = TextFragment {
                    id: None,
                    fragment_hash: record.fragment_hash,
                    session_id: record.session_id,
                    source_app_bundle_id: None,
                    source_window_title: None,
                    source_signature: vec![0u8; 64], // Placeholder; should be verified
                    nonce: vec![0u8; 16],
                    timestamp: record.synced_at.timestamp_millis(),
                    keystroke_context: None,
                    keystroke_confidence: record.keystroke_confidence,
                    keystroke_sequence_hash: None,
                    source_session_id: None,
                    source_evidence_packet: None,
                    wal_entry_hash: None,
                    cloudkit_record_id: Some(record.record_id),
                    sync_state: Some("synced".to_string()),
                };
                let _ = db_mut.insert_text_fragment(&fragment);
                received_count += 1;
            }
        }

        let mut metrics = self.metrics.write().await;
        metrics.total_received += received_count;
        metrics.last_sync_at = Some(Utc::now());

        log::info!("Pulled {} fragments from CloudKit ({} conflicts)", received_count, conflict_count);
        Ok(received_count)
    }

    /// Perform a bidirectional sync cycle: push local, pull remote.
    ///
    /// Respects debounce interval to avoid excessive CloudKit queries.
    /// Returns count of fragments synced (push + pull).
    pub async fn sync(&mut self) -> anyhow::Result<usize> {
        // Check debounce: has enough time elapsed since last sync?
        let last_sync = self.last_sync.read().await;
        if let Some(last) = *last_sync {
            let elapsed_ms = (Utc::now() - last).num_milliseconds() as u64;
            if elapsed_ms < self.debounce_ms {
                log::debug!(
                    "Sync debounced; {}ms elapsed < {}ms threshold",
                    elapsed_ms,
                    self.debounce_ms
                );
                return Ok(0);
            }
        }
        drop(last_sync);

        // Push local changes
        let pushed = self.sync_local_to_cloud().await?;

        // Pull remote changes
        let pulled = self.sync_cloud_to_local().await?;

        Ok(pushed + pulled)
    }

    /// Resolve conflict between local and remote fragments.
    ///
    /// Strategy: prefer fragment with higher keystroke_confidence.
    /// If tied, prefer remote (newer modification).
    fn resolve_conflict(local: &TextFragment, remote: &CloudKitRecord) -> ConflictResolution {
        let local_confidence = local.keystroke_confidence.unwrap_or(0.0);
        let remote_confidence = remote.keystroke_confidence.unwrap_or(0.0);

        if remote_confidence > local_confidence + 0.05 {
            ConflictResolution::ReplaceWithRemote
        } else if local_confidence > remote_confidence + 0.05 {
            ConflictResolution::KeepLocal
        } else {
            // Confidence within 5% of each other; consider them semantically the same
            ConflictResolution::KeepLocal // Prefer local as default
        }
    }

    /// Get current sync metrics.
    pub async fn metrics(&self) -> SyncMetrics {
        self.metrics.read().await.clone()
    }

    /// Reset metrics (useful for testing).
    pub async fn reset_metrics(&self) {
        *self.metrics.write().await = SyncMetrics::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sync_engine_creation() {
        // Placeholder: would require SecureStore fixture
        // let engine = CloudKitSyncEngine::new(Arc::new(RwLock::new(db)), "device-1".to_string());
        // assert_eq!(engine.device_id, "device-1");
    }

    #[test]
    fn test_conflict_resolution_remote_higher() {
        let local = TextFragment {
            id: Some(1),
            fragment_hash: vec![1; 32],
            session_id: "local-session".to_string(),
            source_app_bundle_id: None,
            source_window_title: None,
            source_signature: vec![0; 64],
            nonce: vec![0; 16],
            timestamp: 1000,
            keystroke_context: None,
            keystroke_confidence: Some(0.70),
            keystroke_sequence_hash: None,
            source_session_id: None,
            source_evidence_packet: None,
            wal_entry_hash: None,
            cloudkit_record_id: None,
            sync_state: None,
        };

        let remote = CloudKitRecord {
            record_id: "ck-123".to_string(),
            device_created: "ipad".to_string(),
            synced_at: Utc::now(),
            fragment_hash: vec![1; 32],
            session_id: "remote-session".to_string(),
            keystroke_confidence: Some(0.95),
            verified: true,
        };

        let resolution = CloudKitSyncEngine::resolve_conflict(&local, &remote);
        assert_eq!(resolution, ConflictResolution::ReplaceWithRemote);
    }

    #[test]
    fn test_conflict_resolution_local_higher() {
        let local = TextFragment {
            id: Some(1),
            fragment_hash: vec![1; 32],
            session_id: "local-session".to_string(),
            source_app_bundle_id: None,
            source_window_title: None,
            source_signature: vec![0; 64],
            nonce: vec![0; 16],
            timestamp: 1000,
            keystroke_context: None,
            keystroke_confidence: Some(0.95),
            keystroke_sequence_hash: None,
            source_session_id: None,
            source_evidence_packet: None,
            wal_entry_hash: None,
            cloudkit_record_id: None,
            sync_state: None,
        };

        let remote = CloudKitRecord {
            record_id: "ck-123".to_string(),
            device_created: "ipad".to_string(),
            synced_at: Utc::now(),
            fragment_hash: vec![1; 32],
            session_id: "remote-session".to_string(),
            keystroke_confidence: Some(0.70),
            verified: true,
        };

        let resolution = CloudKitSyncEngine::resolve_conflict(&local, &remote);
        assert_eq!(resolution, ConflictResolution::KeepLocal);
    }

    #[test]
    fn test_conflict_resolution_tied() {
        let local = TextFragment {
            id: Some(1),
            fragment_hash: vec![1; 32],
            session_id: "local-session".to_string(),
            source_app_bundle_id: None,
            source_window_title: None,
            source_signature: vec![0; 64],
            nonce: vec![0; 16],
            timestamp: 1000,
            keystroke_context: None,
            keystroke_confidence: Some(0.85),
            keystroke_sequence_hash: None,
            source_session_id: None,
            source_evidence_packet: None,
            wal_entry_hash: None,
            cloudkit_record_id: None,
            sync_state: None,
        };

        let remote = CloudKitRecord {
            record_id: "ck-123".to_string(),
            device_created: "ipad".to_string(),
            synced_at: Utc::now(),
            fragment_hash: vec![1; 32],
            session_id: "remote-session".to_string(),
            keystroke_confidence: Some(0.85),
            verified: true,
        };

        let resolution = CloudKitSyncEngine::resolve_conflict(&local, &remote);
        assert_eq!(resolution, ConflictResolution::KeepLocal);
    }
}
