// SPDX-License-Identifier: Apache-2.0

//! Single PoSME step function per draft-condrey-cfrg-posme Section 2.B.

use crate::block::{Block, LAMBDA};
use crate::hash::{addr_from, i2osp, posme_hash};
use crate::merkle::MerkleTree;

/// Log entry for a single step, used by the prover for proof generation.
pub struct StepLog {
    pub step_id: u32,
    /// Read addresses (length d).
    pub read_addrs: Vec<u32>,
    /// Block values at read time (length d).
    pub read_blocks: Vec<Block>,
    /// Write address.
    pub write_addr: u32,
    /// Block before write.
    pub old_block: Block,
    /// Block after write.
    pub new_block: Block,
    /// Final cursor after pointer-chase.
    pub cursor: [u8; LAMBDA],
    /// Arena Merkle root before this step's write.
    pub root_before: [u8; LAMBDA],
    /// Arena Merkle root after this step's write.
    pub root_after: [u8; LAMBDA],
    /// Transcript value produced by this step.
    pub transcript: [u8; LAMBDA],
}

/// Execute one PoSME step, mutating the arena and Merkle tree in place.
///
/// Returns a `StepLog` capturing all witness data needed for proof generation.
#[inline(never)]
pub fn posme_step(
    arena: &mut [Block],
    tree: &mut MerkleTree,
    t_prev: &[u8; LAMBDA],
    t: u32,
    d: u8,
) -> StepLog {
    let n = arena.len() as u32;
    let d_usize = d as usize;
    let mut cursor = *t_prev;
    let mut read_addrs = Vec::with_capacity(d_usize);
    let mut read_blocks = Vec::with_capacity(d_usize);

    // Phase 1: Pointer-chase reads (data-dependent addressing).
    for j in 0..d {
        let a = addr_from(&cursor, u32::from(j), n);
        read_addrs.push(a);
        let val = arena[a as usize];
        read_blocks.push(val);
        cursor = posme_hash(&[&cursor, &val.data, &val.causal]);
    }

    // Phase 2: Symbiotic write.
    let root_before = tree.root();
    let w = addr_from(&cursor, u32::from(d), n);
    let old_block = arena[w as usize];
    let new_data = posme_hash(&[&old_block.data, &cursor, &old_block.causal]);
    let new_causal = posme_hash(&[&old_block.causal, &cursor, &i2osp(t)]);
    let new_block = Block { data: new_data, causal: new_causal };
    arena[w as usize] = new_block;
    tree.update(w, &new_block);
    let root_after = tree.root();

    // Phase 3: Transcript chain.
    let transcript = posme_hash(&[t_prev, &i2osp(t), &cursor, &root_after]);

    StepLog {
        step_id: t,
        read_addrs,
        read_blocks,
        write_addr: w,
        old_block,
        new_block,
        cursor,
        root_before,
        root_after,
        transcript,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::initialize;

    #[test]
    fn step_mutates_arena() {
        let (mut arena, mut tree, _, t_0) = initialize(b"test", 1024);
        let log = posme_step(&mut arena, &mut tree, &t_0, 1, 8);
        assert_eq!(arena[log.write_addr as usize], log.new_block);
        assert_ne!(log.old_block, log.new_block);
    }

    #[test]
    fn step_advances_transcript() {
        let (mut arena, mut tree, _, t_0) = initialize(b"test", 1024);
        let log = posme_step(&mut arena, &mut tree, &t_0, 1, 8);
        assert_ne!(t_0, log.transcript);
    }

    #[test]
    fn step_deterministic() {
        let (mut a1, mut t1, _, t_0a) = initialize(b"det", 1024);
        let (mut a2, mut t2, _, t_0b) = initialize(b"det", 1024);
        let log1 = posme_step(&mut a1, &mut t1, &t_0a, 1, 8);
        let log2 = posme_step(&mut a2, &mut t2, &t_0b, 1, 8);
        assert_eq!(log1.transcript, log2.transcript);
        assert_eq!(log1.write_addr, log2.write_addr);
        assert_eq!(log1.read_addrs, log2.read_addrs);
    }

    #[test]
    fn step_root_changes() {
        let (mut arena, mut tree, _, t_0) = initialize(b"test", 1024);
        let log = posme_step(&mut arena, &mut tree, &t_0, 1, 8);
        assert_ne!(log.root_before, log.root_after);
    }

    #[test]
    fn step_transcript_includes_root() {
        let (mut arena, mut tree, _, t_0) = initialize(b"test", 1024);
        let log = posme_step(&mut arena, &mut tree, &t_0, 1, 8);
        let expected = posme_hash(&[&t_0, &i2osp(1), &log.cursor, &log.root_after]);
        assert_eq!(log.transcript, expected);
    }
}
