

//! Forensics error types.

/
#[derive(Debug, Clone, thiserror::Error)]
pub enum ForensicsError {
    #[error("insufficient data for analysis")]
    InsufficientData,
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("computation error: {0}")]
    ComputationError(String),
}
