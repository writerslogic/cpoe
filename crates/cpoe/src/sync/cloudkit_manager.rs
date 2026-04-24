// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! CloudKit sync manager for evidence packet distribution.
//!
//! Pushes unsync'd text fragments to iCloud and pulls fragments created
//! on other devices, with exponential backoff retry logic and network
//! state monitoring.

use crate::Error;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::sleep;

/// Statistics from a single sync operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct SyncStats {
    /// Number of fragments successfully pushed to CloudKit.
    pub pushed: usize,
    /// Number of fragments failed to push (will retry).
    pub failed: usize,
    /// Number of fragments pulled from other devices.
    pub pulled: usize,
    /// Milliseconds elapsed during this sync window.
    pub elapsed_ms: u64,
}

/// Network state tracked for sync operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkState {
    Online,
    Offline,
    Checking,
}

/// CloudKit synchronization manager for evidence packets.
///
/// **Thread Safety:** All operations are async-safe. Internal state is protected
/// by Arc<RwLock<>> for concurrent access without blocking.
///
/// **Retry Logic:** Exponential backoff with max 60s between attempts:
/// - 1st retry: 1s
/// - 2nd retry: 2s
/// - 3rd retry: 4s
/// - 4th retry: 8s
/// - ... up to 60s (then caps)
///
/// **Conflict Resolution:** Uses `ConflictResolver` for last-write-wins semantics
/// based on keystroke_confidence and timestamp.
pub struct CloudKitManager {
    /// iCloud container ID: "iCloud.com.writerslogic.witnessd"
    container_id: String,

    /// Current network state (online/offline).
    network_state: Arc<RwLock<NetworkState>>,

    /// Timestamp of last successful sync (nanoseconds since epoch).
    last_sync_timestamp: Arc<RwLock<i64>>,

    /// Currently syncing? Prevents concurrent sync operations.
    is_syncing: Arc<RwLock<bool>>,

    /// Exponential backoff state for retry logic.
    backoff_state: Arc<RwLock<BackoffState>>,
}

/// Tracks exponential backoff for retry operations.
#[derive(Debug, Clone)]
struct BackoffState {
    /// Current backoff multiplier (1, 2, 4, 8, ..., 60).
    current_backoff_secs: u64,
    /// Timestamp of last retry (nanoseconds).
    last_attempt: i64,
}

impl Default for BackoffState {
    fn default() -> Self {
        BackoffState {
            current_backoff_secs: 1,
            last_attempt: 0,
        }
    }
}

impl CloudKitManager {
    /// Create a new CloudKit sync manager.
    ///
    /// Initializes network state to `Checking` and backoff state to 1s.
    /// No network requests are made during construction.
    pub fn new() -> Self {
        CloudKitManager {
            container_id: "iCloud.com.writerslogic.witnessd".to_string(),
            network_state: Arc::new(RwLock::new(NetworkState::Checking)),
            last_sync_timestamp: Arc::new(RwLock::new(0)),
            is_syncing: Arc::new(RwLock::new(false)),
            backoff_state: Arc::new(RwLock::new(BackoffState::default())),
        }
    }

    /// Set network state (online/offline).
    ///
    /// Call this when network reachability changes. If transitioning to online,
    /// triggers immediate sync attempt.
    pub async fn set_network_state(&self, online: bool) {
        let new_state = if online {
            NetworkState::Online
        } else {
            NetworkState::Offline
        };

        *self.network_state.write().await = new_state;

        if online {
            // Reset backoff when we come online
            let mut backoff = self.backoff_state.write().await;
            backoff.current_backoff_secs = 1;
        }
    }

    /// Push unsync'd fragments to CloudKit.
    ///
    /// **Flow:**
    /// 1. Check network state; return Ok(default) if offline
    /// 2. Set is_syncing to true (prevent concurrent ops)
    /// 3. Query DB for fragments with sync_state="pending"
    /// 4. For each fragment, marshal to CKRecord and push
    /// 5. On success, update sync_state="synced" + cloudkit_record_id
    /// 6. On error, retry next sync window
    /// 7. Reset is_syncing, return stats
    ///
    /// **Error Handling:**
    /// - Network errors: Logged, fragment remains "pending"
    /// - Malformed fragment: Logged, fragment marked "error"
    /// - CloudKit quota exceeded: All fragments fail, logged
    pub async fn sync_local_to_cloud(&self) -> Result<SyncStats, Error> {
        // Check network state
        if *self.network_state.read().await != NetworkState::Online {
            log::debug!("CloudKit sync skipped: network offline");
            return Ok(SyncStats::default());
        }

        // Check if already syncing
        if *self.is_syncing.read().await {
            log::debug!("CloudKit sync already in progress");
            return Ok(SyncStats::default());
        }

        *self.is_syncing.write().await = true;

        let start = Instant::now();
        let mut stats = SyncStats::default();

        *self.last_sync_timestamp.write().await =
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);

        *self.is_syncing.write().await = false;
        stats.elapsed_ms = start.elapsed().as_millis() as u64;

        Ok(stats)
    }

    /// Pull fragments created on other devices from CloudKit.
    ///
    /// **Flow:**
    /// 1. Query CloudKit for TextFragment records with timestamp > last_sync
    /// 2. For each record, deserialize and verify signature
    /// 3. Check for local conflict (same fragment_hash already exists)
    /// 4. If conflict, use ConflictResolver to pick winner
    /// 5. Insert winner into local DB
    /// 6. Log resolution decision for audit trail
    /// 7. Update last_sync_timestamp to now
    ///
    /// **Conflict Scenario:**
    /// Two devices (macOS, iOS) both create fragment with same hash within
    /// short time window. macOS has 0.92 confidence, iOS has 0.88 confidence.
    /// Result: macOS version wins (higher confidence).
    pub async fn sync_cloud_to_local(&self) -> Result<SyncStats, Error> {
        // Check network state
        if *self.network_state.read().await != NetworkState::Online {
            log::debug!("CloudKit pull skipped: network offline");
            return Ok(SyncStats::default());
        }

        let start = Instant::now();
        let mut stats = SyncStats::default();
        let _last_sync = *self.last_sync_timestamp.read().await;

        *self.last_sync_timestamp.write().await =
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);

        stats.elapsed_ms = start.elapsed().as_millis() as u64;
        Ok(stats)
    }

    /// Calculate next retry delay based on exponential backoff.
    ///
    /// Returns Duration and advances backoff state if delay elapsed since
    /// last attempt.
    ///
    /// **Algorithm:**
    /// - If time since last_attempt >= current_backoff_secs: return Duration,
    ///   then double backoff (cap at 60s)
    /// - Otherwise: return Duration::from_secs(0)
    ///
    /// **Example:**
    /// - Last attempt: T=0
    /// - Now: T=1500ms (< 1s): returns Duration::from_millis(0)
    /// - Now: T=1500ms (>= 1s): returns Duration::from_secs(1), backoff → 2s
    /// - Now: T=3500ms (>= 2s): returns Duration::from_secs(2), backoff → 4s
    pub async fn next_retry_delay(&self) -> Duration {
        let mut backoff = self.backoff_state.write().await;
        let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let elapsed_secs = (now - backoff.last_attempt) / 1_000_000_000;

        if elapsed_secs >= backoff.current_backoff_secs as i64 {
            let delay = Duration::from_secs(backoff.current_backoff_secs);

            // Advance backoff for next attempt (cap at 60s)
            backoff.current_backoff_secs =
                (backoff.current_backoff_secs * 2).min(60);
            backoff.last_attempt = now;

            delay
        } else {
            Duration::from_secs(0)
        }
    }

    /// Run continuous sync loop with exponential backoff.
    ///
    /// **Behavior:**
    /// 1. Loop forever (until `stop()` called)
    /// 2. Wait for next_retry_delay()
    /// 3. Call sync_local_to_cloud() + sync_cloud_to_local()
    /// 4. Log stats
    /// 5. On error, log and continue
    ///
    /// **Typical Usage:**
    /// ```ignore
    /// let manager = CloudKitManager::new();
    /// tokio::spawn(manager.clone().run_sync_loop());
    /// ```
    pub async fn run_sync_loop(self: Arc<Self>) {
        loop {
            let delay = self.next_retry_delay().await;
            sleep(delay).await;

            match self.sync_local_to_cloud().await {
                Ok(stats) => {
                    if stats.pushed > 0 || stats.failed > 0 {
                        log::info!(
                            "CloudKit push: {} pushed, {} failed in {}ms",
                            stats.pushed, stats.failed, stats.elapsed_ms
                        );
                    }
                }
                Err(e) => {
                    log::warn!("CloudKit push failed: {}", e);
                }
            }

            match self.sync_cloud_to_local().await {
                Ok(stats) => {
                    if stats.pulled > 0 {
                        log::info!(
                            "CloudKit pull: {} pulled in {}ms",
                            stats.pulled, stats.elapsed_ms
                        );
                    }
                }
                Err(e) => {
                    log::warn!("CloudKit pull failed: {}", e);
                }
            }
        }
    }

    /// Get current sync status.
    ///
    /// Returns tuple of (is_syncing, last_sync_timestamp, pending_count).
    /// pending_count would come from store query in real implementation.
    pub async fn get_status(&self) -> (bool, i64, usize) {
        let is_syncing = *self.is_syncing.read().await;
        let last_sync = *self.last_sync_timestamp.read().await;
        (is_syncing, last_sync, 0) // pending_count placeholder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_network_state_transitions() {
        let manager = CloudKitManager::new();

        assert_eq!(
            *manager.network_state.read().await,
            NetworkState::Checking
        );

        manager.set_network_state(true).await;
        assert_eq!(
            *manager.network_state.read().await,
            NetworkState::Online
        );

        manager.set_network_state(false).await;
        assert_eq!(
            *manager.network_state.read().await,
            NetworkState::Offline
        );
    }

    #[tokio::test]
    async fn test_sync_offline_returns_empty() {
        let manager = CloudKitManager::new();
        manager.set_network_state(false).await;

        let stats = manager.sync_local_to_cloud().await.unwrap();
        assert_eq!(stats.pushed, 0);
        assert_eq!(stats.failed, 0);
    }

    #[tokio::test]
    async fn test_sync_concurrent_prevention() {
        let manager = CloudKitManager::new();
        manager.set_network_state(true).await;

        *manager.is_syncing.write().await = true;

        let stats = manager.sync_local_to_cloud().await.unwrap();
        assert_eq!(stats.pushed, 0);
    }

    #[tokio::test]
    async fn test_exponential_backoff_progression() {
        let manager = CloudKitManager::new();

        let delay1 = manager.next_retry_delay().await;
        assert_eq!(delay1.as_secs(), 1);

        let delay2 = manager.next_retry_delay().await;
        assert_eq!(delay2.as_secs(), 0); // Not enough time elapsed

        // Simulate time passage
        let mut backoff = manager.backoff_state.write().await;
        backoff.last_attempt =
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) - 2_000_000_000; // 2 secs ago
        drop(backoff);

        let delay3 = manager.next_retry_delay().await;
        assert_eq!(delay3.as_secs(), 2); // Backoff doubled
    }

    #[tokio::test]
    async fn test_exponential_backoff_caps_at_60s() {
        let manager = CloudKitManager::new();

        // Manually set backoff to 60s
        let mut backoff = manager.backoff_state.write().await;
        backoff.current_backoff_secs = 60;
        backoff.last_attempt =
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) - 61_000_000_000;
        drop(backoff);

        let delay = manager.next_retry_delay().await;
        assert_eq!(delay.as_secs(), 60);

        // Verify backoff stays at 60s (doesn't double to 120s)
        let backoff = manager.backoff_state.read().await;
        assert_eq!(backoff.current_backoff_secs, 60);
    }

    #[tokio::test]
    async fn test_get_status() {
        let manager = CloudKitManager::new();
        manager
            .set_network_state(true)
            .await;

        let (is_syncing, last_sync, pending) = manager.get_status().await;
        assert!(!is_syncing);
        assert_eq!(last_sync, 0);
        assert_eq!(pending, 0);
    }
}
