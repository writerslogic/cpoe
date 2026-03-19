// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

pub const PROFILE_URI: &str = "urn:ietf:params:pop:profile:1.0";
pub const EAT_PROFILE_URI: &str = "urn:ietf:params:rats:eat:profile:pop:1.0";
pub const MIN_CHECKPOINTS_PER_PACKET: usize = 3;

/// WritersProof Root CA public key (Ed25519, hex-encoded).
/// kid: e58a2aacaad69b37 | Valid: 2026-03-19 to 2036-03-18
/// Verify at: https://api.writersproof.com/v1/ca/root
#[allow(dead_code)]
pub const WRITERSPROOF_ROOT_CA_PUBKEY: &str =
    "b48f36054b9160dff06ac4329898523f441914442958a01e84b719ac539ca053";

/// WritersProof Root CA key identifier.
#[allow(dead_code)]
pub const WRITERSPROOF_ROOT_CA_KID: &str = "e58a2aacaad69b37";

/// Map CLI tier name to CDDL content-tier: basic/standard=1, enhanced=2, maximum=3.
///
/// Logs a warning for unrecognized tier names and defaults to basic (1).
pub fn content_tier_from_cli(tier: &str) -> u8 {
    match tier.to_lowercase().as_str() {
        "basic" | "standard" => 1,
        "enhanced" => 2,
        "maximum" => 3,
        other => {
            eprintln!(
                "Warning: unknown content tier '{}', defaulting to 'basic'. \
                 Valid tiers: basic, standard, enhanced, maximum",
                other
            );
            1
        }
    }
}

pub fn profile_uri_from_cli(_tier: &str) -> &'static str {
    PROFILE_URI
}

/// Map TPM capabilities to attestation tier: T1 (software), T2 (TPM), T3 (hardware-backed).
pub fn attestation_tier_value(has_tpm: bool, tpm_hardware_backed: bool) -> u8 {
    if tpm_hardware_backed {
        3
    } else if has_tpm {
        2
    } else {
        1
    }
}
