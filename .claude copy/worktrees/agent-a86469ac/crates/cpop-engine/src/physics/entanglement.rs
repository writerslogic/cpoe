

use crate::vdf;
use crate::PhysicalContext;
use crate::VdfProof;
use sha2::Digest;
use std::time::Duration;

/
pub struct Entanglement;

impl Entanglement {
    /
    pub fn create_seed(content_hash: [u8; 32], physics: &PhysicalContext) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, b"witnessd-entanglement-v1");
        sha2::Digest::update(&mut hasher, content_hash);
        sha2::Digest::update(&mut hasher, physics.combined_hash);

        let result = sha2::Digest::finalize(hasher);
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /
    pub fn entangle(seed: [u8; 32], duration: Duration) -> Result<VdfProof, String> {
        vdf::compute(seed, duration, vdf::default_parameters())
    }
}
