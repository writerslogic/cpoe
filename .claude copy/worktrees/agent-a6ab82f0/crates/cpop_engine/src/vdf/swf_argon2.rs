

//! Argon2id-based Sequential Work Function (SWF) per draft-condrey-rats-pop.
//!
//! Replaces the legacy SHA-256 chain with a memory-hard Argon2id function.
//! Each iteration produces an output that is accumulated into a Merkle tree.
//! Fiat-Shamir challenge selects sampled indices for compact verification.

use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

/
/
/
/
/
/
/
fn lower_thread_priority() -> i32 {
    #[cfg(target_os = "macos")]
    unsafe {
        
        
        const PRIO_DARWIN_THREAD: i32 = 3;
        const PRIO_DARWIN_BG: i32 = 0x1000;
        let prev = libc::getpriority(PRIO_DARWIN_THREAD, 0);
        libc::setpriority(PRIO_DARWIN_THREAD, 0, PRIO_DARWIN_BG);
        prev
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    unsafe {
        
        
        let mut old_param: libc::sched_param = std::mem::zeroed();
        let _ = libc::pthread_getschedparam(
            libc::pthread_self(),
            &mut 0i32 as *mut i32,
            &mut old_param,
        );
        let idle_param: libc::sched_param = std::mem::zeroed();
        libc::pthread_setschedparam(libc::pthread_self(), 5 , &idle_param);
        0 
    }
    #[cfg(windows)]
    unsafe {
        extern "system" {
            fn GetCurrentThread() -> isize;
            fn SetThreadPriority(thread: isize, priority: i32) -> i32;
        }
        const THREAD_PRIORITY_IDLE: i32 = -15;
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);
        0 
    }
    #[cfg(not(any(unix, windows)))]
    {
        0
    }
}

/
fn restore_thread_priority(prev: i32) {
    #[cfg(target_os = "macos")]
    unsafe {
        const PRIO_DARWIN_THREAD: i32 = 3;
        libc::setpriority(PRIO_DARWIN_THREAD, 0, prev);
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    unsafe {
        
        let param: libc::sched_param = std::mem::zeroed();
        libc::pthread_setschedparam(libc::pthread_self(), prev, &param);
    }
    #[cfg(windows)]
    unsafe {
        extern "system" {
            fn GetCurrentThread() -> isize;
            fn SetThreadPriority(thread: isize, priority: i32) -> i32;
        }
        SetThreadPriority(GetCurrentThread(), prev);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = prev;
    }
}

/
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct Argon2SwfParams {
    /
    pub time_cost: u32,
    /
    pub memory_cost: u32,
    /
    pub parallelism: u32,
    /
    pub iterations: u64,
}

impl Default for Argon2SwfParams {
    /
    fn default() -> Self {
        Self {
            time_cost: 1,
            memory_cost: 65536, 
            parallelism: 1,
            iterations: 90,
        }
    }
}

/
pub fn enhanced_params() -> Argon2SwfParams {
    Argon2SwfParams {
        time_cost: 1,
        memory_cost: 65536, 
        parallelism: 1,
        iterations: 150,
    }
}

/
pub fn maximum_params() -> Argon2SwfParams {
    Argon2SwfParams {
        time_cost: 1,
        memory_cost: 65536, 
        parallelism: 1,
        iterations: 210,
    }
}

/
pub fn params_for_tier(content_tier: u8) -> Argon2SwfParams {
    match content_tier {
        3 => maximum_params(),
        2 => enhanced_params(),
        _ => Argon2SwfParams::default(), 
    }
}

/
pub fn test_params() -> Argon2SwfParams {
    Argon2SwfParams {
        time_cost: 1,
        memory_cost: 1024, 
        parallelism: 1,
        iterations: 3,
    }
}

/
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Argon2SwfProof {
    pub input: [u8; 32],
    pub merkle_root: [u8; 32],
    pub params: Argon2SwfParams,
    pub sampled_proofs: Vec<MerkleSampleProof>,
    pub claimed_duration: Duration,
    pub challenge: [u8; 32],
    /
    pub proof_algorithm: u16,
}

/
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MerkleSampleProof {
    pub leaf_index: u64,
    pub leaf_value: [u8; 32],
    pub sibling_path: Vec<[u8; 32]>,
    /
    /
    #[serde(default)]
    pub raw_output: [u8; 32],
}

/
/
const DEFAULT_SAMPLE_COUNT: usize = 20;

/
pub const PROOF_ALGORITHM_STANDARD: u16 = 20;
/
pub const PROOF_ALGORITHM_ENTANGLED: u16 = 21;

/
fn validate_iterations(iterations: u64) -> Result<(), String> {
    if iterations == 0 {
        return Err("iterations must be >= 1".into());
    }
    if iterations > u32::MAX as u64 {
        return Err(format!(
            "iterations {} exceeds u32::MAX ({})",
            iterations,
            u32::MAX
        ));
    }
    Ok(())
}

/
pub fn compute(input: [u8; 32], params: Argon2SwfParams) -> Result<Argon2SwfProof, String> {
    compute_with_algorithm(
        input,
        params,
        DEFAULT_SAMPLE_COUNT,
        PROOF_ALGORITHM_STANDARD,
    )
}

/
pub fn compute_with_algorithm(
    input: [u8; 32],
    params: Argon2SwfParams,
    sample_count: usize,
    proof_algorithm: u16,
) -> Result<Argon2SwfProof, String> {
    validate_iterations(params.iterations)?;

    let argon2 = build_argon2(&params)?;

    let start = Instant::now();
    let mut leaves = Vec::with_capacity(params.iterations as usize);
    let mut raw_outputs = Vec::with_capacity(params.iterations as usize);
    let mut current = input;

    let prev_priority = lower_thread_priority();
    for i in 0..params.iterations {
        
        
        
        let salt_hash = if i == 0 {
            let mut h = Sha256::new();
            h.update([0x00u8]);
            h.update(b"PoP-salt-v1");
            h.update(input);
            h.finalize()
        } else {
            let mut h = Sha256::new();
            h.update([0x01u8]);
            h.update(b"PoP-salt-v1");
            h.update((i as u32).to_be_bytes()); 
            h.finalize()
        };
        let salt = salt_hash.as_slice(); 

        let mut output = [0u8; 32];
        argon2
            .hash_password_into(&current, salt, &mut output)
            .map_err(|e| format!("Argon2id iteration {i}: {e}"))?;

        
        let leaf = {
            let mut h = Sha256::new();
            h.update([0x00u8]);
            h.update(output);
            h.finalize().into()
        };
        leaves.push(leaf);
        raw_outputs.push(output);
        current = output;
    }
    restore_thread_priority(prev_priority);

    let merkle_root = build_merkle_root(&leaves, params.iterations);

    let challenge = fiat_shamir_challenge(&merkle_root, &input, &params, proof_algorithm);

    let indices = select_indices(&challenge, params.iterations, sample_count);

    let tree = build_merkle_tree(&leaves, params.iterations);
    let sampled_proofs = indices
        .iter()
        .map(|&idx| {
            let path = merkle_proof(&tree, idx as usize, leaves.len());
            MerkleSampleProof {
                leaf_index: idx,
                leaf_value: leaves[idx as usize],
                sibling_path: path,
                raw_output: raw_outputs[idx as usize],
            }
        })
        .collect();

    Ok(Argon2SwfProof {
        input,
        merkle_root,
        params,
        sampled_proofs,
        claimed_duration: start.elapsed(),
        challenge,
        proof_algorithm,
    })
}

/
/
/
/
/
pub fn verify(proof: &Argon2SwfProof) -> Result<bool, String> {
    verify_with_samples(proof, proof.sampled_proofs.len())
}

/
pub fn verify_with_samples(proof: &Argon2SwfProof, sample_count: usize) -> Result<bool, String> {
    validate_iterations(proof.params.iterations)?;

    let expected_challenge = fiat_shamir_challenge(
        &proof.merkle_root,
        &proof.input,
        &proof.params,
        proof.proof_algorithm,
    );
    if proof.challenge.ct_eq(&expected_challenge).unwrap_u8() == 0 {
        return Ok(false);
    }

    let expected_indices = select_indices(&proof.challenge, proof.params.iterations, sample_count);
    for (sample, &expected_idx) in proof.sampled_proofs.iter().zip(expected_indices.iter()) {
        if sample.leaf_index != expected_idx {
            return Ok(false);
        }
    }

    
    if !proof.sampled_proofs.iter().any(|s| s.leaf_index == 0) {
        return Ok(false);
    }

    
    let argon2 = build_argon2(&proof.params)?;

    
    let mut sorted_samples: Vec<&MerkleSampleProof> = proof.sampled_proofs.iter().collect();
    sorted_samples.sort_by_key(|s| s.leaf_index);

    for sample in &proof.sampled_proofs {
        
        let expected_leaf: [u8; 32] = {
            let mut h = Sha256::new();
            h.update([0x00u8]);
            h.update(sample.raw_output);
            h.finalize().into()
        };
        if expected_leaf.ct_eq(&sample.leaf_value).unwrap_u8() == 0 {
            return Ok(false);
        }

        
        if !verify_merkle_proof(
            &proof.merkle_root,
            sample.leaf_index as usize,
            &sample.leaf_value,
            &sample.sibling_path,
        ) {
            return Ok(false);
        }

        
        if sample.leaf_index == 0 {
            let salt_hash = {
                let mut h = Sha256::new();
                h.update([0x00u8]);
                h.update(b"PoP-salt-v1");
                h.update(proof.input);
                h.finalize()
            };
            let mut expected_output = [0u8; 32];
            argon2
                .hash_password_into(&proof.input, salt_hash.as_slice(), &mut expected_output)
                .map_err(|e| format!("verify Argon2id index 0: {e}"))?;
            if expected_output.ct_eq(&sample.raw_output).unwrap_u8() == 0 {
                return Ok(false);
            }
        }
    }

    
    let has_index_0 = proof.sampled_proofs.iter().any(|s| s.leaf_index == 0);
    if !has_index_0 {
        return Ok(false);
    }

    
    for window in sorted_samples.windows(2) {
        let prev = window[0];
        let next = window[1];
        if next.leaf_index == prev.leaf_index + 1 {
            let salt_hash = {
                let mut h = Sha256::new();
                h.update([0x01u8]);
                h.update(b"PoP-salt-v1");
                h.update((next.leaf_index as u32).to_be_bytes());
                h.finalize()
            };
            let mut expected_output = [0u8; 32];
            argon2
                .hash_password_into(&prev.raw_output, salt_hash.as_slice(), &mut expected_output)
                .map_err(|e| {
                    format!(
                        "verify Argon2id transition {}->{}: {e}",
                        prev.leaf_index, next.leaf_index
                    )
                })?;
            if expected_output.ct_eq(&next.raw_output).unwrap_u8() == 0 {
                return Ok(false);
            }
        }
    }

    Ok(true)
}

/
pub fn calibrate(params: &Argon2SwfParams, duration: Duration) -> Result<u64, String> {
    let argon2 = build_argon2(params)?;

    let mut current = [0u8; 32];
    let salt = [0u8; 32];
    let mut iterations = 0u64;
    let start = Instant::now();

    let prev_priority = lower_thread_priority();
    while start.elapsed() < duration {
        let mut output = [0u8; 32];
        argon2
            .hash_password_into(&current, &salt, &mut output)
            .map_err(|e| format!("calibration: {e}"))?;
        current = output;
        iterations += 1;
    }
    restore_thread_priority(prev_priority);

    let elapsed_secs = start.elapsed().as_secs_f64();
    if elapsed_secs < 0.001 {
        return Err("calibration duration too short".into());
    }

    Ok((iterations as f64 / elapsed_secs) as u64)
}

fn build_argon2(params: &Argon2SwfParams) -> Result<Argon2<'static>, String> {
    let argon2_params = Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        Some(32),
    )
    .map_err(|e| format!("invalid Argon2id params: {e}"))?;

    Ok(Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        argon2_params,
    ))
}

/
/
/
fn fiat_shamir_challenge(
    merkle_root: &[u8; 32],
    input: &[u8; 32],
    params: &Argon2SwfParams,
    proof_algorithm: u16,
) -> [u8; 32] {
    let params_map = ciborium::Value::Map(vec![
        (1.into(), ciborium::Value::Integer(params.time_cost.into())),
        (
            2.into(),
            ciborium::Value::Integer(params.memory_cost.into()),
        ),
        (
            3.into(),
            ciborium::Value::Integer(params.parallelism.into()),
        ),
        (4.into(), ciborium::Value::Integer(params.iterations.into())),
    ]);
    let mut params_cbor = Vec::new();
    ciborium::into_writer(&params_map, &mut params_cbor)
        .unwrap_or_else(|e| panic!("CBOR encoding proof params: {e}"));

    let mut hasher = Sha256::new();
    hasher.update(b"PoP-Fiat-Shamir-v1");
    hasher.update(proof_algorithm.to_be_bytes());
    hasher.update(&params_cbor);
    hasher.update(input);
    hasher.update(merkle_root);
    hasher.finalize().into()
}

/
/
/
fn select_indices(sample_seed: &[u8; 32], num_leaves: u64, count: usize) -> Vec<u64> {
    use hkdf::Hkdf;

    use std::collections::HashSet;

    let hk = Hkdf::<Sha256>::from_prk(sample_seed).expect("sample seed is valid PRK length");
    let mut indices = Vec::with_capacity(count);
    let mut seen = HashSet::with_capacity(count);
    let mut j: u32 = 0;

    
    let n = num_leaves.min(u32::MAX as u64) as u32;
    let reject_above = u32::MAX - (u32::MAX % n);

    while indices.len() < count && indices.len() < num_leaves as usize {
        let mut okm = [0u8; 4];
        hk.expand(&j.to_be_bytes(), &mut okm)
            .expect("4 bytes is valid HKDF-Expand length");
        j += 1;
        let raw = u32::from_be_bytes(okm);
        if raw >= reject_above {
            continue;
        }
        let idx = (raw % n) as u64;
        if seen.insert(idx) {
            indices.push(idx);
        }
    }

    indices
}

/
fn padding_value(steps: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x02u8]);
    h.update(((steps + 1) as u32).to_be_bytes());
    h.finalize().into()
}

fn build_merkle_root(leaves: &[[u8; 32]], steps: u64) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let tree = build_merkle_tree(leaves, steps);
    tree[1]
}

/
/
fn build_merkle_tree(leaves: &[[u8; 32]], steps: u64) -> Vec<[u8; 32]> {
    let n = leaves.len().next_power_of_two();
    let mut tree = vec![[0u8; 32]; 2 * n];

    for (i, leaf) in leaves.iter().enumerate() {
        tree[n + i] = *leaf;
    }
    let pad = padding_value(steps);
    for i in leaves.len()..n {
        tree[n + i] = pad;
    }

    for i in (1..n).rev() {
        let mut hasher = Sha256::new();
        hasher.update([0x01u8]);
        hasher.update(tree[2 * i]);
        hasher.update(tree[2 * i + 1]);
        tree[i] = hasher.finalize().into();
    }

    tree
}

fn merkle_proof(tree: &[[u8; 32]], leaf_idx: usize, num_leaves: usize) -> Vec<[u8; 32]> {
    let n = num_leaves.next_power_of_two();
    let mut path = Vec::new();
    let mut idx = n + leaf_idx;

    while idx > 1 {
        let sibling = idx ^ 1;
        path.push(tree[sibling]);
        idx /= 2;
    }

    path
}

fn verify_merkle_proof(
    root: &[u8; 32],
    leaf_idx: usize,
    leaf_value: &[u8; 32],
    sibling_path: &[[u8; 32]],
) -> bool {
    let mut current = *leaf_value;
    let mut idx = leaf_idx;

    for sibling in sibling_path {
        
        let mut hasher = Sha256::new();
        hasher.update([0x01u8]);
        if idx % 2 == 0 {
            hasher.update(current);
            hasher.update(sibling);
        } else {
            hasher.update(sibling);
            hasher.update(current);
        }
        current = hasher.finalize().into();
        idx /= 2;
    }

    current.ct_eq(root).unwrap_u8() == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2_swf_compute_verify() {
        let input = [42u8; 32];
        let params = test_params();

        let proof = compute(input, params).expect("compute");
        assert_eq!(proof.input, input);
        assert_ne!(proof.merkle_root, [0u8; 32]);
        assert!(!proof.sampled_proofs.is_empty());

        let valid = verify(&proof).expect("verify");
        assert!(valid, "proof should verify");
    }

    #[test]
    fn test_deterministic_fiat_shamir() {
        let root = [1u8; 32];
        let input = [2u8; 32];
        let params = test_params();
        let c1 = fiat_shamir_challenge(&root, &input, &params, PROOF_ALGORITHM_STANDARD);
        let c2 = fiat_shamir_challenge(&root, &input, &params, PROOF_ALGORITHM_STANDARD);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_fiat_shamir_sensitive_to_root() {
        let input = [2u8; 32];
        let params = test_params();
        let c1 = fiat_shamir_challenge(&[1u8; 32], &input, &params, PROOF_ALGORITHM_STANDARD);
        let c2 = fiat_shamir_challenge(&[3u8; 32], &input, &params, PROOF_ALGORITHM_STANDARD);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_tampered_leaf_rejected() {
        let input = [42u8; 32];
        let params = test_params();

        let mut proof = compute(input, params).expect("compute");
        if let Some(sample) = proof.sampled_proofs.first_mut() {
            sample.leaf_value[0] ^= 0xFF;
        }

        let valid = verify(&proof).expect("verify");
        assert!(!valid, "tampered proof should not verify");
    }

    #[test]
    fn test_tampered_challenge_rejected() {
        let input = [42u8; 32];
        let params = test_params();

        let mut proof = compute(input, params).expect("compute");
        proof.challenge[0] ^= 0xFF;

        let valid = verify(&proof).expect("verify");
        assert!(!valid, "tampered challenge should not verify");
    }

    #[test]
    fn test_merkle_tree_roundtrip() {
        let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| [i; 32]).collect();
        let steps = 4u64;
        let root = build_merkle_root(&leaves, steps);
        let tree = build_merkle_tree(&leaves, steps);

        for (i, leaf) in leaves.iter().enumerate() {
            let path = merkle_proof(&tree, i, leaves.len());
            assert!(
                verify_merkle_proof(&root, i, leaf, &path),
                "proof for leaf {i} should verify"
            );
        }
    }

    #[test]
    fn test_different_inputs_different_roots() {
        let params = test_params();
        let p1 = compute([1u8; 32], params).expect("compute");
        let p2 = compute([2u8; 32], params).expect("compute");
        assert_ne!(p1.merkle_root, p2.merkle_root);
    }

    #[test]
    fn test_select_indices_unique() {
        let challenge = [0xAB; 32];
        let indices = select_indices(&challenge, 100, 8);
        let unique: std::collections::HashSet<_> = indices.iter().collect();
        assert_eq!(unique.len(), indices.len(), "indices should be unique");
    }

    #[test]
    fn test_core_default_params_match_spec() {
        let p = Argon2SwfParams::default();
        assert_eq!(p.time_cost, 1);
        assert_eq!(p.memory_cost, 65536);
        assert_eq!(p.parallelism, 1);
        assert_eq!(p.iterations, 90);
    }

    #[test]
    fn test_enhanced_params_match_spec() {
        let p = enhanced_params();
        assert_eq!(p.time_cost, 1);
        assert_eq!(p.memory_cost, 65536);
        assert_eq!(p.parallelism, 1);
        assert_eq!(p.iterations, 150);
    }

    #[test]
    fn test_maximum_params_match_spec() {
        let p = maximum_params();
        assert_eq!(p.time_cost, 1);
        assert_eq!(p.memory_cost, 65536);
        assert_eq!(p.parallelism, 1);
        assert_eq!(p.iterations, 210);
    }

    #[test]
    fn test_params_for_tier_selects_correctly() {
        assert_eq!(params_for_tier(1).iterations, 90);
        assert_eq!(params_for_tier(2).iterations, 150);
        assert_eq!(params_for_tier(3).iterations, 210);
        assert_eq!(params_for_tier(0).iterations, 90);
        assert_eq!(params_for_tier(255).iterations, 90);
    }

    #[test]
    fn test_select_indices_bounded() {
        let challenge = [0xAB; 32];
        let indices = select_indices(&challenge, 5, 8);
        assert!(indices.len() <= 5, "can't have more indices than leaves");
        for &idx in &indices {
            assert!(idx < 5, "index should be < num_leaves");
        }
    }

    #[test]
    fn test_zero_iterations_rejected() {
        let input = [42u8; 32];
        let params = Argon2SwfParams {
            iterations: 0,
            ..test_params()
        };
        let result = compute(input, params);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("iterations must be >= 1"));
    }

    #[test]
    fn test_overflow_iterations_rejected() {
        let input = [42u8; 32];
        let params = Argon2SwfParams {
            iterations: u64::MAX,
            ..test_params()
        };
        let result = compute(input, params);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds u32::MAX"));
    }

    #[test]
    fn test_verify_missing_index_zero_rejected() {
        let input = [42u8; 32];
        let params = test_params();
        let mut proof = compute(input, params).expect("compute");
        
        proof.sampled_proofs.retain(|s| s.leaf_index != 0);
        let valid = verify_with_samples(&proof, proof.sampled_proofs.len());
        
        assert!(
            valid.is_ok() && !valid.unwrap(),
            "proof without index 0 should not verify"
        );
    }
}
