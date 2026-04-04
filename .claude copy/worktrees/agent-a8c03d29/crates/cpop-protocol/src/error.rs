

use thiserror::Error;

/
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    /
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /
    #[error("serialization error: {0}")]
    Serialization(String),

    /
    #[error("cryptographic error: {0}")]
    Crypto(String),

    /
    #[error("protocol violation: {0}")]
    Protocol(String),

    #[error("validation failed: {0}")]
    Validation(String),

    #[error("unknown error: {0}")]
    Unknown(String),
}
