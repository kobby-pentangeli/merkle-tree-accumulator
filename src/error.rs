//! Error types for Merkle tree accumulator operations.

/// Errors that can occur during Merkle tree accumulator operations.
#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum Error {
    /// Invalid proof: expected root does not match computed root.
    #[error("Invalid proof: expected root {expected}, got {actual}")]
    InvalidProof {
        /// Expected root hash (hex-encoded).
        expected: String,
        /// Actual computed root hash (hex-encoded).
        actual: String,
    },

    /// Index is out of bounds for the current accumulator state.
    #[error("Index {index} out of bounds (max: {max})")]
    IndexOutOfBounds {
        /// The requested index.
        index: u64,
        /// The maximum valid index.
        max: u64,
    },

    /// Operation requires a non-empty tree.
    #[error("Cannot operate on empty tree")]
    EmptyTree,

    /// Invalid witness at the specified height.
    #[error("Invalid witness at height {height}")]
    InvalidWitness {
        /// Height at which witness is invalid.
        height: u64,
    },

    /// Serialization or deserialization failed.
    #[error("Serialization error: {0}")]
    Serialization(String),
}

#[cfg(feature = "std")]
impl From<bincode::error::EncodeError> for Error {
    fn from(err: bincode::error::EncodeError) -> Self {
        Self::Serialization(err.to_string())
    }
}

#[cfg(feature = "std")]
impl From<bincode::error::DecodeError> for Error {
    fn from(err: bincode::error::DecodeError) -> Self {
        Self::Serialization(err.to_string())
    }
}

impl From<core::array::TryFromSliceError> for Error {
    fn from(err: core::array::TryFromSliceError) -> Self {
        Self::Serialization(format!("Invalid slice length: {err}"))
    }
}
