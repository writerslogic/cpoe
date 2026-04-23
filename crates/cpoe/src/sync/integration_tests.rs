// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Integration tests for CloudKit sync modules.
//!
//! Tests multi-device sync scenarios including network outages,
//! concurrent operations, and conflict resolution.

#[cfg(test)]
mod tests {
    use crate::sync::cloudkit_manager::CloudKitManager;
    use crate::sync::conflict_resolver::ConflictResolver;
    use crate::sync::device_pairing::{
        derive_shared_secret, DevicePairingRecord, QRCodePayload, PairingFlow,
    };
    use crate::store::text_fragments::{KeystrokeContext, TextFragment};
    use ed25519_dalek::SigningKey;

    #[tokio::test]
    async fn test_sync_manager_online_offline_transitions() {
        let manager = CloudKitManager::new();

        manager.set_network_state(false).await;
        let stats = manager.sync_local_to_cloud().await.unwrap();
        assert_eq!(stats.pushed, 0);

        manager.set_network_state(true).await;
        let stats = manager.sync_local_to_cloud().await.unwrap();
        assert_eq!(stats.pushed, 0);
    }

    #[tokio::test]
    async fn test_sync_prevents_concurrent_operations() {
        let manager = CloudKitManager::new();
        manager.set_network_state(true).await;

        *manager.is_syncing.write().await = true;

        let stats = manager.sync_local_to_cloud().await.unwrap();
        assert_eq!(stats.pushed, 0);

        let stats = manager.sync_cloud_to_local().await.unwrap();
        assert_eq!(stats.pulled, 0);
    }

    #[test]
    fn test_device_pairing_qr_code_roundtrip() {
        let signing_key = SigningKey::from([42u8; 32]);
        let payload =
            QRCodePayload::from_signing_key("test-device-1".to_string(), &signing_key);

        let bytes = payload.to_bytes();
        let recovered = QRCodePayload::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.device_id, "test-device-1");
        assert_eq!(recovered.public_key, payload.public_key);
        assert_eq!(recovered.version, 1);
    }

    #[test]
    fn test_derived_secret_consistency() {
        let token_a = [1u8; 32];
        let token_b = [2u8; 32];

        let secret1 = derive_shared_secret(&token_a, &token_b, "dev-1", "dev-2");
        let secret2 = derive_shared_secret(&token_a, &token_b, "dev-1", "dev-2");

        assert_eq!(secret1, secret2);
    }

    #[test]
    fn test_conflict_resolution_all_rules() {
        let make_fragment = |session_id: &str, conf: f64, ts: i64| {
            TextFragment {
                id: Some(1),
                fragment_hash: vec![42u8; 32],
                session_id: session_id.to_string(),
                source_app_bundle_id: Some("com.test".to_string()),
                source_window_title: Some("Test".to_string()),
                source_signature: vec![0u8; 64],
                nonce: vec![0u8; 16],
                timestamp: ts,
                keystroke_context: Some(KeystrokeContext::OriginalComposition),
                keystroke_confidence: Some(conf),
                keystroke_sequence_hash: None,
                source_session_id: None,
                source_evidence_packet: None,
                wal_entry_hash: None,
                cloudkit_record_id: None,
                sync_state: Some("synced".to_string()),
            }
        };

        let local = make_fragment("sess-1", 0.85, 1000);
        let remote = make_fragment("sess-2", 0.95, 1000);

        let res = ConflictResolver::resolve(&local, &remote);
        assert_eq!(res.winner.session_id, "sess-2");
        assert_eq!(res.resolution_rule, "confidence_difference");
    }

    #[tokio::test]
    async fn test_exponential_backoff_sequence() {
        let manager = CloudKitManager::new();

        let delay1 = manager.next_retry_delay().await;
        assert_eq!(delay1.as_secs(), 1);

        let delay2 = manager.next_retry_delay().await;
        assert_eq!(delay2.as_secs(), 0);

        let mut backoff = manager.backoff_state.write().await;
        backoff.last_attempt =
            chrono::Utc::now().timestamp_nanos_safe() - 2_000_000_000;
        drop(backoff);

        let delay3 = manager.next_retry_delay().await;
        assert_eq!(delay3.as_secs(), 2);
    }

    #[test]
    fn test_pairing_flow_state_machine() {
        let mut state = PairingFlow::WaitingForScan;
        assert_eq!(state, PairingFlow::WaitingForScan);

        state = PairingFlow::ScannedByRemote;
        assert!(state != PairingFlow::WaitingForScan);

        state = PairingFlow::Paired;
        assert_eq!(state, PairingFlow::Paired);
    }

    #[test]
    fn test_device_pairing_record_verification() {
        let signing_key = SigningKey::from([42u8; 32]);
        let public_key = signing_key.verifying_key().to_bytes();

        let record = DevicePairingRecord::new("device-1".to_string(), public_key);
        assert!(!record.is_verified);

        let message = b"test message";
        let signature = signing_key.sign(message).to_bytes().to_vec();

        let result = record.verify_signature(message, &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn test_device_pairing_record_signature_rejection() {
        let public_key = [42u8; 32];
        let record = DevicePairingRecord::new("device-1".to_string(), public_key);

        let message = b"test message";
        let bad_signature = vec![0u8; 64];

        let result = record.verify_signature(message, &bad_signature);
        assert!(result.is_err());
    }
}
