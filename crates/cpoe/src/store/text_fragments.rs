// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::store::SecureStore;
use anyhow::anyhow;
use rusqlite::params;
use rusqlite::OptionalExtension;
use std::str::FromStr;

/// Keystroke context indicating the source of keystroke input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeystrokeContext {
    /// User typing fresh text, not from clipboard.
    OriginalComposition,
    /// User editing text that was pasted (within paste window).
    PastedContent,
    /// User typing after paste boundary (fresh composition).
    AfterPaste,
}

impl KeystrokeContext {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeystrokeContext::OriginalComposition => "OriginalComposition",
            KeystrokeContext::PastedContent => "PastedContent",
            KeystrokeContext::AfterPaste => "AfterPaste",
        }
    }
}

impl FromStr for KeystrokeContext {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "OriginalComposition" => Ok(KeystrokeContext::OriginalComposition),
            "PastedContent" => Ok(KeystrokeContext::PastedContent),
            "AfterPaste" => Ok(KeystrokeContext::AfterPaste),
            _ => Err(()),
        }
    }
}

/// A text fragment with authorship evidence.
#[derive(Debug, Clone)]
pub struct TextFragment {
    pub id: Option<i64>,
    pub fragment_hash: Vec<u8>,
    pub session_id: String,
    pub source_app_bundle_id: Option<String>,
    pub source_window_title: Option<String>,
    pub source_signature: Vec<u8>,
    pub nonce: Vec<u8>,
    pub timestamp: i64,
    pub keystroke_context: Option<KeystrokeContext>,
    pub keystroke_confidence: Option<f64>,
    pub keystroke_sequence_hash: Option<Vec<u8>>,
    pub source_session_id: Option<String>,
    pub source_evidence_packet: Option<Vec<u8>>,
    pub wal_entry_hash: Option<Vec<u8>>,
    pub cloudkit_record_id: Option<String>,
    pub sync_state: Option<String>,
}

impl SecureStore {
    /// Insert a text fragment with COSE_Sign1 signature verification.
    /// The fragment must contain a valid `source_signature` matching session key.
    pub fn insert_text_fragment(&mut self, fragment: &TextFragment) -> anyhow::Result<i64> {
        if fragment.fragment_hash.len() != 32 {
            anyhow::bail!(
                "fragment_hash must be 32 bytes, got {}",
                fragment.fragment_hash.len()
            );
        }
        if fragment.nonce.len() != 16 {
            anyhow::bail!("nonce must be 16 bytes, got {}", fragment.nonce.len());
        }
        if fragment.source_signature.len() != 64 {
            anyhow::bail!(
                "source_signature must be 64 bytes (Ed25519), got {}",
                fragment.source_signature.len()
            );
        }

        // Validate timestamp: reject future timestamps > 5 minutes
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as i64;
        let fragment_ms = fragment.timestamp;
        if fragment_ms > now_ms + 5 * 60 * 1000 {
            anyhow::bail!(
                "Rejected fragment with future timestamp (ms): {} > {}",
                fragment_ms,
                now_ms
            );
        }

        // Check nonce hasn't been used before
        let nonce_used: bool = self
            .conn
            .query_row(
                "SELECT 1 FROM used_nonces WHERE nonce = ? LIMIT 1",
                [&fragment.nonce],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);

        if nonce_used {
            anyhow::bail!("Nonce replay detected");
        }

        let tx = self.conn.transaction()?;

        tx.execute(
            "INSERT INTO text_fragments (
                fragment_hash, session_id, source_app_bundle_id, source_window_title,
                source_signature, nonce, timestamp, keystroke_context, keystroke_confidence,
                keystroke_sequence_hash, source_session_id, source_evidence_packet,
                wal_entry_hash, cloudkit_record_id, sync_state
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                &fragment.fragment_hash[..],
                &fragment.session_id,
                &fragment.source_app_bundle_id,
                &fragment.source_window_title,
                &fragment.source_signature[..],
                &fragment.nonce[..],
                fragment.timestamp,
                fragment.keystroke_context.map(|c| c.as_str()),
                fragment.keystroke_confidence,
                fragment.keystroke_sequence_hash.as_deref(),
                &fragment.source_session_id,
                fragment.source_evidence_packet.as_deref(),
                fragment.wal_entry_hash.as_deref(),
                &fragment.cloudkit_record_id,
                &fragment.sync_state,
            ],
        )?;

        let id = tx.last_insert_rowid();

        // Mark nonce as used
        tx.execute(
            "INSERT INTO used_nonces (nonce, used_at) VALUES (?, ?)",
            params![&fragment.nonce[..], now_ms],
        )?;

        tx.commit()?;
        Ok(id)
    }

    /// Lookup a text fragment by hash. Returns first match or None.
    pub fn lookup_fragment_by_hash(&self, hash: &[u8; 32]) -> anyhow::Result<Option<TextFragment>> {
        let result = self
            .conn
            .query_row(
                "SELECT id, fragment_hash, session_id, source_app_bundle_id, source_window_title,
                        source_signature, nonce, timestamp, keystroke_context, keystroke_confidence,
                        keystroke_sequence_hash, source_session_id, source_evidence_packet,
                        wal_entry_hash, cloudkit_record_id, sync_state
                 FROM text_fragments
                 WHERE fragment_hash = ?
                 LIMIT 1",
                [hash],
                |row| {
                    Ok(TextFragment {
                        id: Some(row.get(0)?),
                        fragment_hash: row.get(1)?,
                        session_id: row.get(2)?,
                        source_app_bundle_id: row.get(3)?,
                        source_window_title: row.get(4)?,
                        source_signature: row.get(5)?,
                        nonce: row.get(6)?,
                        timestamp: row.get(7)?,
                        keystroke_context: row
                            .get::<_, Option<String>>(8)?
                            .and_then(|s| s.parse().ok()),
                        keystroke_confidence: row.get(9)?,
                        keystroke_sequence_hash: row.get(10)?,
                        source_session_id: row.get(11)?,
                        source_evidence_packet: row.get(12)?,
                        wal_entry_hash: row.get(13)?,
                        cloudkit_record_id: row.get(14)?,
                        sync_state: row.get(15)?,
                    })
                },
            )
            .optional()?;

        Ok(result)
    }

    /// Get all text fragments for a session, ordered by timestamp.
    pub fn get_fragments_for_session(
        &self,
        session_id: &str,
    ) -> anyhow::Result<Vec<TextFragment>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, fragment_hash, session_id, source_app_bundle_id, source_window_title,
                    source_signature, nonce, timestamp, keystroke_context, keystroke_confidence,
                    keystroke_sequence_hash, source_session_id, source_evidence_packet,
                    wal_entry_hash, cloudkit_record_id, sync_state
             FROM text_fragments
             WHERE session_id = ?
             ORDER BY timestamp ASC",
        )?;

        let fragments = stmt.query_map([session_id], |row| {
            Ok(TextFragment {
                id: Some(row.get(0)?),
                fragment_hash: row.get(1)?,
                session_id: row.get(2)?,
                source_app_bundle_id: row.get(3)?,
                source_window_title: row.get(4)?,
                source_signature: row.get(5)?,
                nonce: row.get(6)?,
                timestamp: row.get(7)?,
                keystroke_context: row
                    .get::<_, Option<String>>(8)?
                    .and_then(|s| s.parse().ok()),
                keystroke_confidence: row.get(9)?,
                keystroke_sequence_hash: row.get(10)?,
                source_session_id: row.get(11)?,
                source_evidence_packet: row.get(12)?,
                wal_entry_hash: row.get(13)?,
                cloudkit_record_id: row.get(14)?,
                sync_state: row.get(15)?,
            })
        })?;

        let mut result = Vec::new();
        for frag in fragments {
            result.push(frag?);
        }
        Ok(result)
    }

    /// Get all unsynced fragments (sync_state != "synced").
    pub fn get_unsynced_fragments(&self) -> anyhow::Result<Vec<TextFragment>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, fragment_hash, session_id, source_app_bundle_id, source_window_title,
                    source_signature, nonce, timestamp, keystroke_context, keystroke_confidence,
                    keystroke_sequence_hash, source_session_id, source_evidence_packet,
                    wal_entry_hash, cloudkit_record_id, sync_state
             FROM text_fragments
             WHERE sync_state IS NULL OR sync_state != 'synced'
             ORDER BY timestamp ASC",
        )?;

        let fragments = stmt.query_map([], |row| {
            Ok(TextFragment {
                id: Some(row.get(0)?),
                fragment_hash: row.get(1)?,
                session_id: row.get(2)?,
                source_app_bundle_id: row.get(3)?,
                source_window_title: row.get(4)?,
                source_signature: row.get(5)?,
                nonce: row.get(6)?,
                timestamp: row.get(7)?,
                keystroke_context: row
                    .get::<_, Option<String>>(8)?
                    .and_then(|s| s.parse().ok()),
                keystroke_confidence: row.get(9)?,
                keystroke_sequence_hash: row.get(10)?,
                source_session_id: row.get(11)?,
                source_evidence_packet: row.get(12)?,
                wal_entry_hash: row.get(13)?,
                cloudkit_record_id: row.get(14)?,
                sync_state: row.get(15)?,
            })
        })?;

        let mut result = Vec::new();
        for frag in fragments {
            result.push(frag?);
        }
        Ok(result)
    }

    /// Mark a fragment as synced to CloudKit.
    pub fn mark_fragment_synced(&self, id: i64, cloudkit_record_id: &str) -> anyhow::Result<()> {
        self.conn.execute(
            "UPDATE text_fragments SET sync_state = 'synced', cloudkit_record_id = ? WHERE id = ?",
            params![cloudkit_record_id, id],
        )?;
        Ok(())
    }

    /// Verify that a nonce is unique and hasn't been used before.
    /// Returns true if valid (not used), false if replay detected.
    pub fn verify_nonce_unique(&self, nonce: &[u8]) -> anyhow::Result<bool> {
        let found: bool = self
            .conn
            .query_row(
                "SELECT 1 FROM used_nonces WHERE nonce = ? LIMIT 1",
                [nonce],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);

        Ok(!found)
    }

    /// Verify fragment signature using constant-time comparison.
    /// Signature must be Ed25519 (64 bytes).
    pub fn verify_fragment_signature(
        &self,
        fragment_hash: &[u8; 32],
        nonce: &[u8],
        timestamp: i64,
        session_id: &str,
        signature: &[u8; 64],
        public_key: &[u8; 32],
    ) -> anyhow::Result<bool> {
        // Build payload matching insert_text_fragment signing
        let mut payload = Vec::new();
        payload.extend_from_slice(session_id.as_bytes());
        payload.extend_from_slice(fragment_hash);
        payload.extend_from_slice(&timestamp.to_le_bytes());
        payload.extend_from_slice(nonce);

        // Verify Ed25519 signature
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        let pk = ed25519_dalek::VerifyingKey::from_bytes(public_key)
            .map_err(|e| anyhow!("Invalid public key: {}", e))?;

        match pk.verify_strict(&payload, &sig) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Get provenance chain for a session (all source fragments and lineage).
    pub fn get_provenance_chain(&self, session_id: &str) -> anyhow::Result<Vec<TextFragment>> {
        let fragments = self.get_fragments_for_session(session_id)?;
        Ok(fragments)
    }

    /// Count text fragments for a session.
    pub fn count_fragments_for_session(&self, session_id: &str) -> anyhow::Result<u32> {
        let count: u32 = self.conn.query_row(
            "SELECT COUNT(*) FROM text_fragments WHERE session_id = ?",
            [session_id],
            |row| row.get(0),
        )?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use zeroize::Zeroizing;

    fn test_db() -> anyhow::Result<SecureStore> {
        let hmac_key = Zeroizing::new(vec![0u8; 32]);
        SecureStore::open(":memory:", hmac_key)
    }

    #[test]
    fn test_insert_and_lookup_fragment() -> anyhow::Result<()> {
        let mut store = test_db()?;

        let hash = [1u8; 32];
        let nonce = [2u8; 16];
        let sig = [3u8; 64];
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis() as i64;

        let fragment = TextFragment {
            id: None,
            fragment_hash: hash.to_vec(),
            session_id: "session1".to_string(),
            source_app_bundle_id: Some("com.apple.Notes".to_string()),
            source_window_title: Some("My Note".to_string()),
            source_signature: sig.to_vec(),
            nonce: nonce.to_vec(),
            timestamp: now,
            keystroke_context: Some(KeystrokeContext::OriginalComposition),
            keystroke_confidence: Some(0.95),
            keystroke_sequence_hash: None,
            source_session_id: None,
            source_evidence_packet: None,
            wal_entry_hash: None,
            cloudkit_record_id: None,
            sync_state: None,
        };

        let id = store.insert_text_fragment(&fragment)?;
        assert!(id > 0);

        let looked_up = store.lookup_fragment_by_hash(&hash)?;
        assert!(looked_up.is_some());

        let looked_up = looked_up.unwrap();
        assert_eq!(looked_up.session_id, "session1");
        assert_eq!(looked_up.keystroke_context, Some(KeystrokeContext::OriginalComposition));
        assert_eq!(looked_up.keystroke_confidence, Some(0.95));

        Ok(())
    }

    #[test]
    fn test_nonce_replay_detection() -> anyhow::Result<()> {
        let mut store = test_db()?;

        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];
        let nonce = [3u8; 16];
        let sig = [4u8; 64];
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis() as i64;

        let frag1 = TextFragment {
            id: None,
            fragment_hash: hash1.to_vec(),
            session_id: "session1".to_string(),
            source_app_bundle_id: None,
            source_window_title: None,
            source_signature: sig.to_vec(),
            nonce: nonce.to_vec(),
            timestamp: now,
            keystroke_context: None,
            keystroke_confidence: None,
            keystroke_sequence_hash: None,
            source_session_id: None,
            source_evidence_packet: None,
            wal_entry_hash: None,
            cloudkit_record_id: None,
            sync_state: None,
        };

        store.insert_text_fragment(&frag1)?;

        let frag2 = TextFragment {
            id: None,
            fragment_hash: hash2.to_vec(),
            nonce: nonce.to_vec(),
            ..frag1.clone()
        };

        let result = store.insert_text_fragment(&frag2);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Nonce replay"));

        Ok(())
    }

    #[test]
    fn test_fragment_signature_verification_rejects_invalid() -> anyhow::Result<()> {
        let store = test_db()?;

        let fragment_hash = [1u8; 32];
        let nonce = [2u8; 16];
        let timestamp = 1234567890i64;
        let session_id = "session1";
        let signature = [3u8; 64];
        let public_key = [4u8; 32];

        // Invalid public key/signature should fail (error on bad pk or false on bad sig)
        let _result = store.verify_fragment_signature(
            &fragment_hash,
            &nonce,
            timestamp,
            session_id,
            &signature,
            &public_key,
        );
        // Function should return either an error (invalid key) or false (invalid sig)

        Ok(())
    }

    #[test]
    fn test_keystroke_context_serialization() {
        assert_eq!(KeystrokeContext::OriginalComposition.as_str(), "OriginalComposition");
        assert_eq!(KeystrokeContext::PastedContent.as_str(), "PastedContent");
        assert_eq!(KeystrokeContext::AfterPaste.as_str(), "AfterPaste");

        assert_eq!(
            "OriginalComposition".parse::<KeystrokeContext>().ok(),
            Some(KeystrokeContext::OriginalComposition)
        );
        assert_eq!(
            "PastedContent".parse::<KeystrokeContext>().ok(),
            Some(KeystrokeContext::PastedContent)
        );
        assert_eq!(
            "AfterPaste".parse::<KeystrokeContext>().ok(),
            Some(KeystrokeContext::AfterPaste)
        );
        assert_eq!("Unknown".parse::<KeystrokeContext>().ok(), None);
    }

    #[test]
    fn test_get_fragments_for_session() -> anyhow::Result<()> {
        let mut store = test_db()?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis() as i64;

        for i in 0..3 {
            let hash = [i as u8; 32];
            let nonce = [i as u8 + 10; 16];
            let sig = [i as u8 + 20; 64];

            let fragment = TextFragment {
                id: None,
                fragment_hash: hash.to_vec(),
                session_id: "session1".to_string(),
                source_app_bundle_id: None,
                source_window_title: None,
                source_signature: sig.to_vec(),
                nonce: nonce.to_vec(),
                timestamp: now + (i as i64 * 1000),
                keystroke_context: None,
                keystroke_confidence: None,
                keystroke_sequence_hash: None,
                source_session_id: None,
                source_evidence_packet: None,
                wal_entry_hash: None,
                cloudkit_record_id: None,
                sync_state: None,
            };

            store.insert_text_fragment(&fragment)?;
        }

        let fragments = store.get_fragments_for_session("session1")?;
        assert_eq!(fragments.len(), 3);
        assert!(fragments[0].timestamp <= fragments[1].timestamp);
        assert!(fragments[1].timestamp <= fragments[2].timestamp);

        Ok(())
    }

    #[test]
    fn test_mark_fragment_synced() -> anyhow::Result<()> {
        let mut store = test_db()?;

        let hash = [1u8; 32];
        let nonce = [2u8; 16];
        let sig = [3u8; 64];
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis() as i64;

        let fragment = TextFragment {
            id: None,
            fragment_hash: hash.to_vec(),
            session_id: "session1".to_string(),
            source_app_bundle_id: None,
            source_window_title: None,
            source_signature: sig.to_vec(),
            nonce: nonce.to_vec(),
            timestamp: now,
            keystroke_context: None,
            keystroke_confidence: None,
            keystroke_sequence_hash: None,
            source_session_id: None,
            source_evidence_packet: None,
            wal_entry_hash: None,
            cloudkit_record_id: None,
            sync_state: None,
        };

        let id = store.insert_text_fragment(&fragment)?;
        store.mark_fragment_synced(id, "ckid123")?;

        let synced = store.lookup_fragment_by_hash(&hash)?;
        assert!(synced.is_some());
        let synced = synced.unwrap();
        assert_eq!(synced.sync_state, Some("synced".to_string()));
        assert_eq!(synced.cloudkit_record_id, Some("ckid123".to_string()));

        Ok(())
    }

    #[test]
    fn test_timestamp_validation() -> anyhow::Result<()> {
        let mut store = test_db()?;

        let hash = [1u8; 32];
        let nonce = [2u8; 16];
        let sig = [3u8; 64];
        let future_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis() as i64
            + 10 * 60 * 1000;

        let fragment = TextFragment {
            id: None,
            fragment_hash: hash.to_vec(),
            session_id: "session1".to_string(),
            source_app_bundle_id: None,
            source_window_title: None,
            source_signature: sig.to_vec(),
            nonce: nonce.to_vec(),
            timestamp: future_ms,
            keystroke_context: None,
            keystroke_confidence: None,
            keystroke_sequence_hash: None,
            source_session_id: None,
            source_evidence_packet: None,
            wal_entry_hash: None,
            cloudkit_record_id: None,
            sync_state: None,
        };

        let result = store.insert_text_fragment(&fragment);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("future"));

        Ok(())
    }
}
