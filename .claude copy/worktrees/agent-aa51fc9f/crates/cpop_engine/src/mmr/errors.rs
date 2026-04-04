

use thiserror::Error;

/
#[derive(Debug, Error)]
pub enum MmrError {
    /
    #[error("empty")]
    Empty,
    /
    #[error("corrupted store")]
    CorruptedStore,
    /
    #[error("index out of range")]
    IndexOutOfRange,
    /
    #[error("invalid node data")]
    InvalidNodeData,
    /
    #[error("invalid proof")]
    InvalidProof,
    /
    #[error("hash mismatch")]
    HashMismatch,
    /
    #[error("node not found")]
    NodeNotFound,
    /
    #[error("proof component exceeds u16::MAX elements")]
    ProofTooLarge,
    /
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
