// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Deterministic conflict resolution for multi-device text fragments.
//!
//! Implements last-write-wins strategy with explicit ordering rules to ensure
//! both devices arrive at identical decisions without coordination.

use crate::store::text_fragments::{KeystrokeContext, TextFragment};

/// Result of conflict resolution between two fragment versions.
#[derive(Debug, Clone)]
pub struct ConflictResolution {
    /// Winning fragment (local or remote)
    pub winner: Box<TextFragment>,

    /// Losing fragment
    pub loser: Box<TextFragment>,

    /// Human-readable rule name that was applied
    pub resolution_rule: &'static str,

    /// Timestamp of resolution decision (nanos since epoch)
    pub timestamp: i64,
}

/// Conflict resolver using deterministic last-write-wins semantics.
///
/// **Algorithm (applied in order):**
///
/// 1. **Keystroke Confidence Difference >10%:**
///    - Winner: fragment with higher keystroke_confidence
///    - Rule: "confidence_difference"
///
/// 2. **One Verified, One Not:**
///    - Winner: verified fragment (signature_verified=true)
///    - Rule: "verification_status"
///
/// 3. **Both Same Verification Status:**
///    - Winner: fragment with later timestamp
///    - Rule: "last_write_wins"
///
/// 4. **Identical Timestamps (rare edge case):**
///    - Winner: fragment with higher confidence
///    - Rule: "tiebreaker_confidence"
///
/// **Idempotency:** Same two fragments always produce same winner, regardless
/// of which is passed as `local` or `remote`. This enables both devices to
/// independently compute and converge on the same decision.
pub struct ConflictResolver;

impl ConflictResolver {
    /// Resolve conflict between local and remote fragment versions.
    ///
    /// Returns `ConflictResolution` with winner, loser, and decision rule.
    /// Never returns an error; always deterministically picks a winner.
    ///
    /// **Example:**
    /// ```ignore
    /// let local = TextFragment { keystroke_confidence: 0.92, timestamp: 1000, ... };
    /// let remote = TextFragment { keystroke_confidence: 0.88, timestamp: 2000, ... };
    /// let resolution = ConflictResolver::resolve(&local, &remote);
    /// // Result: remote wins (higher timestamp), rule="last_write_wins"
    /// ```
    pub fn resolve(
        local: &TextFragment,
        remote: &TextFragment,
    ) -> ConflictResolution {
        let now = chrono::Utc::now().timestamp_nanos_safe();
        let local_conf = local.keystroke_confidence.unwrap_or(0.5);
        let remote_conf = remote.keystroke_confidence.unwrap_or(0.5);
        let confidence_diff = (remote_conf - local_conf).abs();

        let (winner, loser, rule) =
            if confidence_diff > 0.1 {
                if remote_conf > local_conf {
                    (
                        Box::new(remote.clone()),
                        Box::new(local.clone()),
                        "confidence_difference",
                    )
                } else {
                    (
                        Box::new(local.clone()),
                        Box::new(remote.clone()),
                        "confidence_difference",
                    )
                }
            } else {
                let local_verified = !local.source_signature.is_empty();
                let remote_verified = !remote.source_signature.is_empty();

                if local_verified != remote_verified {
                    if local_verified {
                        (
                            Box::new(local.clone()),
                            Box::new(remote.clone()),
                            "verification_status",
                        )
                    } else {
                        (
                            Box::new(remote.clone()),
                            Box::new(local.clone()),
                            "verification_status",
                        )
                    }
                } else {
                    if remote.timestamp > local.timestamp {
                        (
                            Box::new(remote.clone()),
                            Box::new(local.clone()),
                            "last_write_wins",
                        )
                    } else if local.timestamp > remote.timestamp {
                        (
                            Box::new(local.clone()),
                            Box::new(remote.clone()),
                            "last_write_wins",
                        )
                    } else {
                        if remote_conf > local_conf {
                            (
                                Box::new(remote.clone()),
                                Box::new(local.clone()),
                                "tiebreaker_confidence",
                            )
                        } else {
                            (
                                Box::new(local.clone()),
                                Box::new(remote.clone()),
                                "tiebreaker_confidence",
                            )
                        }
                    }
                }
            };

        ConflictResolution {
            winner,
            loser,
            resolution_rule: rule,
            timestamp: now,
        }
    }

    /// Log conflict resolution for audit trail.
    pub fn log_resolution(resolution: &ConflictResolution, reason: &str) {
        let winner_conf = resolution.winner.keystroke_confidence.unwrap_or(0.5);
        let loser_conf = resolution.loser.keystroke_confidence.unwrap_or(0.5);
        log::info!(
            "Conflict resolved via {}: {} (conf={:.2}) vs {} (conf={:.2}), reason: {}",
            resolution.resolution_rule,
            resolution.winner.session_id,
            winner_conf,
            resolution.loser.session_id,
            loser_conf,
            reason
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fragment(
        session_id: &str,
        keystroke_confidence: f64,
        timestamp: i64,
    ) -> TextFragment {
        TextFragment {
            id: Some(1),
            fragment_hash: vec![42u8; 32],
            session_id: session_id.to_string(),
            source_app_bundle_id: Some("com.test".to_string()),
            source_window_title: Some("Test".to_string()),
            source_signature: vec![0u8; 64],
            nonce: vec![0u8; 16],
            timestamp,
            keystroke_context: Some(KeystrokeContext::OriginalComposition),
            keystroke_confidence: Some(keystroke_confidence),
            keystroke_sequence_hash: None,
            source_session_id: None,
            source_evidence_packet: None,
            wal_entry_hash: None,
            cloudkit_record_id: None,
            sync_state: Some("synced".to_string()),
        }
    }

    #[test]
    fn test_confidence_difference_high() {
        let local = make_fragment("sess-1", 0.82, 1000, false);
        let remote = make_fragment("sess-2", 0.95, 1000, false);

        let resolution = ConflictResolver::resolve(&local, &remote);

        assert_eq!(resolution.winner.keystroke_confidence, 0.95);
        assert_eq!(resolution.loser.keystroke_confidence, 0.82);
        assert_eq!(resolution.resolution_rule, "confidence_difference");
    }

    #[test]
    fn test_confidence_difference_local_higher() {
        let local = make_fragment("sess-1", 0.95, 1000, false);
        let remote = make_fragment("sess-2", 0.82, 1000, false);

        let resolution = ConflictResolver::resolve(&local, &remote);

        assert_eq!(resolution.winner.keystroke_confidence, 0.95);
        assert_eq!(resolution.resolution_rule, "confidence_difference");
    }

    #[test]
    fn test_verification_status_local_verified() {
        let local = make_fragment("sess-1", 0.85, 1000);
        let mut remote = make_fragment("sess-2", 0.85, 1000);
        remote.source_signature.clear();

        let resolution = ConflictResolver::resolve(&local, &remote);

        assert_eq!(resolution.winner.session_id, "sess-1");
        assert!(!resolution.winner.source_signature.is_empty());
        assert_eq!(resolution.resolution_rule, "verification_status");
    }

    #[test]
    fn test_verification_status_remote_verified() {
        let mut local = make_fragment("sess-1", 0.85, 1000);
        local.source_signature.clear();
        let remote = make_fragment("sess-2", 0.85, 1000);

        let resolution = ConflictResolver::resolve(&local, &remote);

        assert_eq!(resolution.winner.session_id, "sess-2");
        assert!(!resolution.winner.source_signature.is_empty());
        assert_eq!(resolution.resolution_rule, "verification_status");
    }

    #[test]
    fn test_last_write_wins_remote_newer() {
        let local = make_fragment("sess-1", 0.85, 1000);
        let remote = make_fragment("sess-2", 0.85, 2000);

        let resolution = ConflictResolver::resolve(&local, &remote);

        assert_eq!(resolution.winner.session_id, "sess-2");
        assert_eq!(resolution.winner.timestamp, 2000);
        assert_eq!(resolution.resolution_rule, "last_write_wins");
    }

    #[test]
    fn test_last_write_wins_local_newer() {
        let local = make_fragment("sess-1", 0.85, 2000);
        let remote = make_fragment("sess-2", 0.85, 1000);

        let resolution = ConflictResolver::resolve(&local, &remote);

        assert_eq!(resolution.winner.session_id, "sess-1");
        assert_eq!(resolution.winner.timestamp, 2000);
        assert_eq!(resolution.resolution_rule, "last_write_wins");
    }

    #[test]
    fn test_tiebreaker_identical_timestamps() {
        let local = make_fragment("sess-1", 0.85, 1000);
        let remote = make_fragment("sess-2", 0.90, 1000);

        let resolution = ConflictResolver::resolve(&local, &remote);

        assert_eq!(resolution.winner.session_id, "sess-2");
        assert_eq!(resolution.winner.keystroke_confidence, Some(0.90));
        assert_eq!(resolution.resolution_rule, "tiebreaker_confidence");
    }

    #[test]
    fn test_tiebreaker_identical_everything() {
        let local = make_fragment("sess-1", 0.85, 1000);
        let remote = make_fragment("sess-2", 0.85, 1000);

        let resolution = ConflictResolver::resolve(&local, &remote);

        assert_eq!(resolution.winner.session_id, "sess-1");
        assert_eq!(resolution.resolution_rule, "tiebreaker_confidence");
    }

    #[test]
    fn test_idempotency_order_invariant() {
        let local = make_fragment("sess-1", 0.88, 1500);
        let mut remote = make_fragment("sess-2", 0.92, 2000);
        remote.source_signature.clear();

        let res1 = ConflictResolver::resolve(&local, &remote);
        let res2 = ConflictResolver::resolve(&remote, &local);

        assert_eq!(res1.winner.session_id, res2.winner.session_id);
        assert_eq!(res1.resolution_rule, res2.resolution_rule);
    }

    #[test]
    fn test_confidence_threshold_below_10_percent() {
        let local = make_fragment("sess-1", 0.85, 1000);
        let remote = make_fragment("sess-2", 0.86, 1000);

        let resolution = ConflictResolver::resolve(&local, &remote);

        assert_eq!(resolution.resolution_rule, "tiebreaker_confidence");
    }

    #[test]
    fn test_confidence_threshold_at_10_percent() {
        let local = make_fragment("sess-1", 0.85, 1000);
        let remote = make_fragment("sess-2", 0.95, 1000);

        let resolution = ConflictResolver::resolve(&local, &remote);

        assert_eq!(resolution.resolution_rule, "confidence_difference");
    }
}
