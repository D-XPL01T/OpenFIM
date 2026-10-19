use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum OpenFimError {
    #[error("I/O error at {path}: {source}")]
    IoError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("TOCTOU Inode/File Identity Substitution Detected for path: {path}. Expected {expected_identity}, but observed {actual_identity} post-read.")]
    ToctouSubstitutionDetected {
        path: PathBuf,
        expected_identity: String,
        actual_identity: String,
    },

    #[error("Unsupported or cryptographically deprecated hashing algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Rate limiter violation: requested {requested_bytes} bytes exceeds bucket size {capacity}")]
    RateLimiterExceeded {
        requested_bytes: usize,
        capacity: usize,
    },

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),

    #[error("General error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, OpenFimError>;
