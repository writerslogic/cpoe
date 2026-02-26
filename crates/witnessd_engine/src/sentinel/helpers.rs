// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::shadow::ShadowManager;
use super::types::*;
use crate::config::SentinelConfig;
use crate::wal::{EntryType, Wal};
use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

// Event handling functions (synchronous to avoid Send issues with RwLock guards)
#[allow(clippy::too_many_arguments)]
pub fn handle_focus_event_sync(
    event: FocusEvent,
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    config: &SentinelConfig,
    shadow: &Arc<ShadowManager>,
    signing_key: &Arc<RwLock<SigningKey>>,
    current_focus: &Arc<RwLock<Option<String>>>,
    wal_dir: &Path,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    // Check if app should be tracked
    if !config.is_app_allowed(&event.app_bundle_id, &event.app_name) {
        // Unfocus current document if moving to untracked app
        let path_to_unfocus = {
            let focus = current_focus.read().unwrap();
            focus.clone()
        };
        if let Some(path) = path_to_unfocus {
            unfocus_document_sync(&path, sessions, session_events_tx);
            *current_focus.write().unwrap() = None;
        }
        return;
    }

    match event.event_type {
        FocusEventType::FocusGained => {
            let doc_path = if event.path.is_empty() {
                // If path is empty but we have a shadow ID, use the shadow ID as the path
                if !event.shadow_id.is_empty() {
                    format!("shadow://{}", event.shadow_id)
                } else {
                    return;
                }
            } else {
                event.path.clone()
            };

            // If switching documents, unfocus the old one
            let path_to_unfocus = {
                let focus = current_focus.read().unwrap();
                if let Some(ref current) = *focus {
                    if *current != doc_path {
                        Some(current.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

            if let Some(path) = path_to_unfocus {
                unfocus_document_sync(&path, sessions, session_events_tx);
                *current_focus.write().unwrap() = None;
            }

            focus_document_sync(
                &doc_path,
                &event,
                sessions,
                config,
                shadow,
                signing_key,
                wal_dir,
                session_events_tx,
            );
            *current_focus.write().unwrap() = Some(doc_path);
        }
        FocusEventType::FocusLost => {
            let prev_path = {
                let focus = current_focus.read().unwrap();
                focus.clone()
            };
            if let Some(path) = prev_path {
                unfocus_document_sync(&path, sessions, session_events_tx);
                *current_focus.write().unwrap() = None;
            }
        }
        FocusEventType::FocusUnknown => {
            let prev_path = {
                let focus = current_focus.read().unwrap();
                focus.clone()
            };
            if let Some(path) = prev_path {
                unfocus_document_sync(&path, sessions, session_events_tx);
                *current_focus.write().unwrap() = None;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn focus_document_sync(
    path: &str,
    event: &FocusEvent,
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    _config: &SentinelConfig,
    _shadow: &Arc<ShadowManager>,
    signing_key: &Arc<RwLock<SigningKey>>,
    wal_dir: &Path,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    let key = signing_key.read().unwrap().clone();
    let mut sessions_map = sessions.write().unwrap();

    let session = sessions_map.entry(path.to_string()).or_insert_with(|| {
        let mut session = DocumentSession::new(
            path.to_string(),
            event.app_bundle_id.clone(),
            event.app_name.clone(),
            event.window_title.clone(),
        );

        // Compute initial hash if file exists
        if let Ok(hash) = compute_file_hash(path) {
            session.initial_hash = Some(hash.clone());
            session.current_hash = Some(hash);
        }

        // Open WAL for session
        let wal_path = wal_dir.join(format!("{}.wal", session.session_id));
        let mut session_id_bytes = [0u8; 32];
        if session.session_id.len() >= 32 {
            hex::decode_to_slice(
                &session.session_id[..64.min(session.session_id.len() * 2)],
                &mut session_id_bytes,
            )
            .ok();
        }

        if let Ok(wal) = Wal::open(&wal_path, session_id_bytes, key) {
            // Write session start entry
            let payload = create_session_start_payload(&session);
            let _ = wal.append(EntryType::SessionStart, payload);
        }

        // Emit session started event
        let _ = session_events_tx.send(SessionEvent {
            event_type: SessionEventType::Started,
            session_id: session.session_id.clone(),
            document_path: path.to_string(),
            timestamp: SystemTime::now(),
        });

        session
    });

    session.focus_gained();
    session.window_title = event.window_title.clone();

    let _ = session_events_tx.send(SessionEvent {
        event_type: SessionEventType::Focused,
        session_id: session.session_id.clone(),
        document_path: path.to_string(),
        timestamp: SystemTime::now(),
    });
}

pub fn unfocus_document_sync(
    path: &str,
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    let mut sessions_map = sessions.write().unwrap();

    if let Some(session) = sessions_map.get_mut(path) {
        session.focus_lost();

        let _ = session_events_tx.send(SessionEvent {
            event_type: SessionEventType::Unfocused,
            session_id: session.session_id.clone(),
            document_path: path.to_string(),
            timestamp: SystemTime::now(),
        });
    }
}

pub fn handle_change_event_sync(
    event: &ChangeEvent,
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    signing_key: &Arc<RwLock<SigningKey>>,
    wal_dir: &Path,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    let mut sessions_map = sessions.write().unwrap();

    if let Some(session) = sessions_map.get_mut(&event.path) {
        match event.event_type {
            ChangeEventType::Saved => {
                session.save_count += 1;

                // Compute new hash
                let current_hash = event
                    .hash
                    .clone()
                    .or_else(|| compute_file_hash(&event.path).ok());
                session.current_hash = current_hash.clone();

                // Write to WAL
                if let Some(hash) = current_hash {
                    let wal_path = wal_dir.join(format!("{}.wal", session.session_id));
                    let mut session_id_bytes = [0u8; 32];
                    hex::decode_to_slice(
                        &session.session_id[..64.min(session.session_id.len() * 2)],
                        &mut session_id_bytes,
                    )
                    .ok();
                    let key = signing_key.read().unwrap().clone();

                    if let Ok(wal) = Wal::open(&wal_path, session_id_bytes, key) {
                        let payload = create_document_hash_payload(&hash, event.size.unwrap_or(0));
                        let _ = wal.append(EntryType::DocumentHash, payload);
                    }
                }

                let _ = session_events_tx.send(SessionEvent {
                    event_type: SessionEventType::Saved,
                    session_id: session.session_id.clone(),
                    document_path: event.path.clone(),
                    timestamp: SystemTime::now(),
                });
            }
            ChangeEventType::Modified => {
                session.change_count += 1;
                if let Some(hash) = &event.hash {
                    session.current_hash = Some(hash.clone());
                }
            }
            ChangeEventType::Deleted => {
                // End the session - need to drop lock first
                let event_path = event.path.clone();
                drop(sessions_map);
                end_session_sync(&event_path, sessions, session_events_tx);
            }
            ChangeEventType::Created => {
                // New document - will be picked up on focus
            }
        }
    }
}

pub fn check_idle_sessions_sync(
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    idle_timeout: std::time::Duration,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    let sessions_to_end: Vec<String> = {
        let sessions_map = sessions.read().unwrap();
        sessions_map
            .iter()
            .filter(|(_, session)| {
                !session.is_focused()
                    && session
                        .last_focus_time
                        .elapsed()
                        .map(|d| d > idle_timeout)
                        .unwrap_or(false)
            })
            .map(|(path, _)| path.clone())
            .collect()
    };

    for path in sessions_to_end {
        end_session_sync(&path, sessions, session_events_tx);
    }
}

pub fn end_session_sync(
    path: &str,
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    let session = sessions.write().unwrap().remove(path);

    if let Some(session) = session {
        let _ = session_events_tx.send(SessionEvent {
            event_type: SessionEventType::Ended,
            session_id: session.session_id,
            document_path: path.to_string(),
            timestamp: SystemTime::now(),
        });
    }
}

pub fn end_all_sessions_sync(
    sessions: &Arc<RwLock<HashMap<String, DocumentSession>>>,
    shadow: &Arc<ShadowManager>,
    session_events_tx: &broadcast::Sender<SessionEvent>,
) {
    let all_sessions: Vec<_> = sessions.write().unwrap().drain().collect();

    for (path, session) in all_sessions {
        let _ = session_events_tx.send(SessionEvent {
            event_type: SessionEventType::Ended,
            session_id: session.session_id,
            document_path: path,
            timestamp: SystemTime::now(),
        });

        // Clean up shadow buffer if exists
        if let Some(shadow_id) = session.shadow_id {
            let _ = shadow.delete(&shadow_id);
        }
    }
}

// Helper functions
pub fn compute_file_hash(path: &str) -> std::io::Result<String> {
    let hash = crate::crypto::hash_file(Path::new(path))?;
    Ok(hex::encode(hash))
}

pub fn create_session_start_payload(session: &DocumentSession) -> Vec<u8> {
    // Simple binary format: path_len(4) + path + hash(32) + timestamp(8)
    let path_bytes = session.path.as_bytes();
    let mut payload = Vec::with_capacity(4 + path_bytes.len() + 32 + 8);

    payload.extend_from_slice(&(path_bytes.len() as u32).to_be_bytes());
    payload.extend_from_slice(path_bytes);

    let hash_bytes = session
        .initial_hash
        .as_ref()
        .and_then(|h| {
            hex::decode(h)
                .map_err(|e| {
                    log::warn!("Failed to decode initial hash '{}': {}", h, e);
                    e
                })
                .ok()
        })
        .unwrap_or_else(|| {
            log::debug!("No initial hash available for session, using zero hash");
            vec![0u8; 32]
        });
    payload.extend_from_slice(&hash_bytes[..32.min(hash_bytes.len())]);
    payload.resize(payload.len() + (32 - hash_bytes.len().min(32)), 0);

    let timestamp = session
        .start_time
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);
    payload.extend_from_slice(&timestamp.to_be_bytes());

    payload
}

pub fn create_document_hash_payload(hash: &str, size: i64) -> Vec<u8> {
    let hash_bytes = hex::decode(hash).unwrap_or_else(|e| {
        log::warn!("Failed to decode hash '{}': {}, using zero hash", hash, e);
        vec![0u8; 32]
    });
    let mut payload = Vec::with_capacity(32 + 8 + 8);

    payload.extend_from_slice(&hash_bytes[..32.min(hash_bytes.len())]);
    payload.resize(payload.len() + (32 - hash_bytes.len().min(32)), 0);
    payload.extend_from_slice(&(size as u64).to_be_bytes());

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);
    payload.extend_from_slice(&timestamp.to_be_bytes());

    payload
}

/// Validate a user-provided path to prevent path traversal attacks.
///
/// Returns the canonicalized absolute path.
pub fn validate_path(path: impl AsRef<Path>) -> Result<PathBuf, String> {
    let path = path.as_ref();

    // If path exists, canonicalize it directly
    if path.exists() {
        let canonical = path
            .canonicalize()
            .map_err(|e| format!("Invalid path '{}': {}", path.display(), e))?;
        validate_canonical_path(&canonical)?;
        return Ok(canonical);
    }

    // If path doesn't exist, validate its parent directory
    let parent = path
        .parent()
        .ok_or_else(|| "Invalid path: no parent".to_string())?;
    let canonical_parent = parent
        .canonicalize()
        .map_err(|e| format!("Invalid parent directory for '{}': {}", path.display(), e))?;

    let file_name = path
        .file_name()
        .ok_or_else(|| "Invalid path: no file name".to_string())?;
    let canonical = canonical_parent.join(file_name);

    validate_canonical_path(&canonical)?;
    Ok(canonical)
}

fn validate_canonical_path(path: &Path) -> Result<(), String> {
    // Additional security: Ensure the path is not a sensitive system directory
    #[cfg(unix)]
    {
        let path_str = path.to_string_lossy();
        if path_str.starts_with("/etc/")
            || path_str.starts_with("/var/root/")
            || path_str.starts_with("/System/")
        {
            return Err("Access to system directory denied".to_string());
        }
    }
    Ok(())
}
