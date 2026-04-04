

//! Session management for the Sentinel: start/stop witnessing, baseline updates.

use super::helpers::*;
use super::types::*;
use crate::crypto::ObfuscatedString;
use crate::ipc::IpcErrorCode;
use crate::wal::{EntryType, Wal};
use crate::{MutexRecover, RwLockRecover};
use ed25519_dalek::{Signer, SigningKey};
use sha2::Digest;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

use super::core::Sentinel;

impl Sentinel {
    /
    fn open_event_store(&self) -> anyhow::Result<crate::store::SecureStore> {
        let signing_key_local = {
            let guard = self.signing_key.read_recover();
            guard
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("signing key not initialized"))?
                .clone()
        };
        let db_path = self.config.writersproof_dir.join("events.db");
        crate::store::open_store_with_signing_key(&signing_key_local, &db_path)
    }

    /
    pub fn start_witnessing(
        &self,
        file_path: &Path,
    ) -> std::result::Result<(), (IpcErrorCode, String)> {
        if !file_path.exists() {
            return Err((
                IpcErrorCode::FileNotFound,
                format!("File not found: {}", file_path.display()),
            ));
        }

        let path_str = file_path.to_string_lossy().to_string();

        
        let key = self.signing_key.read_recover().clone();

        
        let mut sessions = self.sessions.write_recover();
        if sessions.contains_key(&path_str) {
            return Err((
                IpcErrorCode::AlreadyTracking,
                format!("Already tracking: {}", file_path.display()),
            ));
        }
        let mut session = DocumentSession::new(
            path_str.clone(),
            "cli".to_string(),          
            "writerslogic".to_string(), 
            ObfuscatedString::new(&path_str),
        );

        if let Ok(hash) = compute_file_hash(&path_str) {
            session.initial_hash = Some(hash.clone());
            session.current_hash = Some(hash);
        }

        
        match self.open_event_store() {
            Ok(store) => match store.load_document_stats(&path_str) {
                Ok(Some(stats)) => {
                    session.cumulative_keystrokes_base =
                        u64::try_from(stats.total_keystrokes).unwrap_or(0);
                    session.cumulative_focus_ms_base = stats.total_focus_ms;
                    session.session_number = u32::try_from(stats.session_count).unwrap_or(0);
                    session.first_tracked_at = Some(
                        UNIX_EPOCH
                            + Duration::from_secs(
                                u64::try_from(stats.first_tracked_at).unwrap_or(0),
                            ),
                    );
                }
                Ok(None) => {
                    session.first_tracked_at = Some(SystemTime::now());
                }
                Err(e) => {
                    log::warn!("Failed to load document stats for {path_str}: {e}");
                    session.first_tracked_at = Some(SystemTime::now());
                }
            },
            Err(e) => {
                log::warn!("Failed to open store for document stats: {e}");
                session.first_tracked_at = Some(SystemTime::now());
            }
        }

        let wal_path = self
            .config
            .wal_dir
            .join(format!("{}.wal", session.session_id));
        
        
        let mut session_id_bytes = [0u8; 32];
        let hex_str = &session.session_id[..64.min(session.session_id.len())];
        if hex::decode_to_slice(hex_str, &mut session_id_bytes).is_ok() {
            if let Some(ref signing_key) = key {
                
                
                
                let mut key_bytes = signing_key.to_bytes();
                let wal_key = SigningKey::from_bytes(&key_bytes);
                key_bytes.zeroize();
                match Wal::open(&wal_path, session_id_bytes, wal_key) {
                    Ok(wal) => {
                        let payload = create_session_start_payload(&session);
                        if let Err(e) = wal.append(EntryType::SessionStart, payload) {
                            log::warn!(
                                "WAL append failed for session {}: {}",
                                session.session_id,
                                e
                            );
                        }
                    }
                    Err(e) => {
                        log::error!(
                            "WAL::open() failed for session {}: {}; session continues without persistent proof",
                            session.session_id,
                            e
                        );
                    }
                }
            } else {
                log::warn!(
                    "Signing key not initialized, skipping WAL for session {}",
                    session.session_id
                );
            }
        } else {
            log::warn!(
                "Invalid session ID hex '{}', skipping WAL",
                session.session_id
            );
        }

        if self
            .session_events_tx
            .send(SessionEvent {
                event_type: SessionEventType::Started,
                session_id: session.session_id.clone(),
                document_path: path_str.clone(),
                timestamp: SystemTime::now(),
            })
            .is_err()
        {
            log::debug!("no session event listeners for Started");
        }

        sessions.insert(path_str.clone(), session);
        drop(sessions);
        super::trace!(
            "[START_WITNESSING] session created, setting current_focus={:?}",
            path_str
        );
        *self.current_focus.write_recover() = Some(path_str);
        Ok(())
    }

    /
    /
    pub fn commit_checkpoint_for_path(&self, path: &str) -> bool {
        let needs_checkpoint = {
            let sessions = self.sessions.read_recover();
            sessions
                .get(path)
                .is_some_and(|s| s.keystroke_count > s.last_checkpoint_keystrokes)
        };
        if !needs_checkpoint {
            return false;
        }

        
        if path.starts_with("shadow:
            return false;
        }

        let file_path = std::path::Path::new(path);
        if !file_path.exists() {
            log::warn!("Cannot auto-checkpoint; file not found: {path}");
            return false;
        }

        let (content_hash, raw_size) = match crate::crypto::hash_file_with_size(file_path) {
            Ok(pair) => pair,
            Err(e) => {
                log::warn!("Auto-checkpoint hash failed for {path}: {e}");
                return false;
            }
        };
        let file_size = i64::try_from(raw_size).unwrap_or(i64::MAX);

        let mut store = match self.open_event_store() {
            Ok(s) => s,
            Err(e) => {
                log::warn!("Auto-checkpoint store open failed: {e}");
                return false;
            }
        };

        let mut event = crate::store::SecureEvent::new(
            path.to_string(),
            content_hash,
            file_size,
            Some("Auto-checkpoint".to_string()),
        );

        let sk_guard = self.signing_key.read_recover();
        let sk_ref = sk_guard.as_ref();
        match store.add_secure_event_with_signer(&mut event, sk_ref) {
            Ok(_) => {
                log::info!("Auto-checkpoint committed for {path}");
                
                let mut sessions = self.sessions.write_recover();
                if let Some(session) = sessions.get_mut(path) {
                    session.last_checkpoint_keystrokes = session.keystroke_count;
                }
                true
            }
            Err(e) => {
                log::warn!("Auto-checkpoint store write failed for {path}: {e}");
                false
            }
        }
    }

    /
    pub fn stop_witnessing(
        &self,
        file_path: &Path,
    ) -> std::result::Result<(), (IpcErrorCode, String)> {
        let path_str = file_path.to_string_lossy().to_string();

        
        
        self.commit_checkpoint_for_path(&path_str);

        let session = self.sessions.write_recover().remove(&path_str);

        if let Some(session) = session {
            
            let now_ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let elapsed_secs = session.start_time.elapsed().unwrap_or_default().as_secs();
            let first_tracked = session
                .first_tracked_at
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(now_ts);
            match self.open_event_store() {
                Ok(store) => {
                    let prev_dur = store
                        .load_document_stats(&path_str)
                        .ok()
                        .flatten()
                        .map(|s| s.total_duration_secs)
                        .unwrap_or(0);
                    let stats = crate::store::DocumentStats {
                        file_path: path_str.clone(),
                        total_keystrokes: i64::try_from(session.total_keystrokes())
                            .unwrap_or(i64::MAX),
                        total_focus_ms: session.total_focus_ms_cumulative(),
                        session_count: i64::from(session.session_number + 1),
                        total_duration_secs: prev_dur
                            + i64::try_from(elapsed_secs).unwrap_or(i64::MAX),
                        first_tracked_at: first_tracked,
                        last_tracked_at: now_ts,
                    };
                    if let Err(e) = store.save_document_stats(&stats) {
                        log::warn!("Failed to save document stats for {path_str}: {e}");
                    }
                }
                Err(e) => {
                    log::warn!("Failed to open store to save document stats: {e}");
                }
            }

            if self
                .session_events_tx
                .send(SessionEvent {
                    event_type: SessionEventType::Ended,
                    session_id: session.session_id,
                    document_path: path_str,
                    timestamp: SystemTime::now(),
                })
                .is_err()
            {
                log::debug!("no session event listeners for Ended");
            }

            if let Some(shadow_id) = session.shadow_id {
                if let Err(e) = self.shadow.delete(&shadow_id) {
                    log::warn!("shadow buffer delete failed for {shadow_id}: {e}");
                }
            }

            if let Err(e) = self.update_baseline() {
                log::error!("Failed to update baseline: {}", e);
            }

            Ok(())
        } else {
            Err((
                IpcErrorCode::NotTracking,
                format!("Not tracking: {}", file_path.display()),
            ))
        }
    }

    /
    pub fn tracked_files(&self) -> Vec<String> {
        self.sessions.read_recover().keys().cloned().collect()
    }

    /
    pub fn start_time(&self) -> Option<SystemTime> {
        *self.start_time.lock_recover()
    }

    /
    pub fn update_baseline(&self) -> anyhow::Result<()> {
        let summary = self
            .activity_accumulator
            .read_recover()
            .to_session_summary();
        if summary.keystroke_count < 10 {
            return Ok(());
        }

        
        
        let signing_key_local = {
            let guard = self.signing_key.read_recover();
            guard
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("signing key not initialized"))?
                .clone()
        };
        let public_key = signing_key_local.verifying_key().to_bytes();
        let mut hasher = sha2::Sha256::new();
        hasher.update(public_key);
        let identity_fingerprint = hasher.finalize().to_vec();

        let db_path = self.config.writersproof_dir.join("events.db");
        let mut key_bytes = signing_key_local.to_bytes();
        let hmac_key = crate::crypto::derive_hmac_key(&key_bytes);
        key_bytes.zeroize();
        let store = crate::store::SecureStore::open(&db_path, hmac_key.to_vec())?;

        let current_digest =
            if let Some((cbor, _)) = store.get_baseline_digest(&identity_fingerprint)? {
                serde_json::from_slice::<cpop_protocol::baseline::BaselineDigest>(&cbor)?
            } else {
                crate::baseline::compute_initial_digest(identity_fingerprint.clone())
            };

        let updated_digest = crate::baseline::update_digest(current_digest, &summary);

        let digest_json = serde_json::to_vec(&updated_digest)?;
        let signature = signing_key_local.sign(&digest_json);
        
        drop(signing_key_local);

        store.save_baseline_digest(&identity_fingerprint, &digest_json, &signature.to_bytes())?;

        log::info!(
            "Authorship baseline updated. Tier: {:?}",
            updated_digest.confidence_tier
        );
        Ok(())
    }
}
