// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Jitter chain: timing jitter analysis, typing profiles, zone-based detection.
//!
//! ## Submodules
//!
//! - [`simple`] — Simple jitter session (legacy capture used by platform hooks)
//! - [`session`] — Core jitter chain types (Parameters, Sample, Session, Evidence)
//! - [`verification`] — Chain verification and encoding for seeded jitter chains
//! - [`codec`] — Binary codec, chain comparison/continuity, format validation
//! - [`engine`] — Zone-committed jitter engine for real-time keystroke monitoring
//! - [`profile`] — Typing profile analysis and plausibility checking
//! - [`content`] — Content-based verification and zone analysis
//! - [`zones`] — QWERTY keyboard zone mapping and zone transition types

mod codec;
mod content;
mod engine;
mod profile;
mod session;
mod simple;
mod verification;
mod zones;

#[cfg(test)]
mod tests;

use crate::DateTimeNanosExt;
use chrono::{DateTime, Utc};

/// Convert a timestamp to nanoseconds as u64 for hashing/encoding.
///
/// Falls back to millisecond precision (x1_000_000) for timestamps beyond
/// ~2262 CE where nanosecond representation overflows i64.
pub(crate) fn timestamp_nanos_u64(ts: DateTime<Utc>) -> u64 {
    let nanos = ts.timestamp_nanos_safe();
    if nanos < 0 {
        0
    } else {
        nanos as u64
    }
}

// === Re-exports: simple ===
pub use self::simple::{SimpleJitterSample, SimpleJitterSession};

// === Re-exports: session ===
pub use self::session::{
    default_parameters, Evidence, Parameters, Sample, Session, SessionData, Statistics,
};
#[cfg(test)]
pub(crate) use self::session::{MAX_JITTER, MIN_JITTER};

// === Re-exports: verification ===
pub use self::verification::{
    verify_chain, verify_chain_detailed, verify_chain_with_seed, verify_sample, VerificationResult,
};

// === Re-exports: verification (JSON codec + chain data) ===
pub use self::verification::{decode_chain, encode_chain, ChainData};

// === Re-exports: codec (binary codec + chain operations) ===
pub use self::codec::{
    compare_chains, compare_samples, decode_chain_binary, decode_sample_binary,
    encode_chain_binary, encode_sample_binary, extract_chain_hashes, find_chain_divergence,
    hash_chain_root, marshal_sample_for_signing, validate_sample_format, verify_chain_continuity,
};

// === Re-exports: engine ===
pub use self::engine::{JitterEngine, JitterSample, TypingProfile};

// === Re-exports: profile ===
pub use self::profile::{
    compare_profiles, interval_to_bucket, is_human_plausible, profile_distance,
    quick_verify_profile,
};

// === Re-exports: content ===
pub use self::content::{
    analyze_document_zones, expected_transition_histogram, extract_recorded_zones,
    extract_transition_histogram, transition_histogram_divergence, verify_jitter_chain,
    verify_with_content, verify_with_secret, zone_kl_divergence, ContentVerificationResult,
    ZoneTransitionHistogram,
};

// === Re-exports: zones ===
pub use self::zones::{
    char_to_zone, decode_zone_transition, encode_zone_transition, is_valid_zone_transition,
    keycode_to_zone, text_to_zone_sequence, ZoneTransition,
};
