// crates/crypto/src/error.rs

#[cfg(feature = "serde_support")]
use serde::{Deserialize, Serialize};

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub enum CryptoError {
    #[error("unsupported operation")]
    Unsupported,
    #[error("invalid key")]
    InvalidKey,
    #[error("verification failed")]
    VerifyFailed,
    #[error("internal error: {0}")]
    Internal(&'static str),
}

pub type Result<T> = core::result::Result<T, CryptoError>;
