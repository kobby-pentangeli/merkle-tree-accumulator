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

    /// Height mismatch between tree and proof.
    #[error("Height mismatch: tree is at {tree_height}, proof is for {proof_height}")]
    HeightMismatch {
        /// Current tree height.
        tree_height: u64,
        /// Proof height.
        proof_height: u64,
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

    /// Newer witness not allowed for this accumulator configuration.
    #[error("Newer witness not allowed")]
    NewerWitnessNotAllowed,

    /// Root index is invalid or out of range.
    #[error("Invalid root index: {index}")]
    InvalidRootIndex {
        /// The invalid root index.
        index: usize,
    },
}

#[cfg(feature = "std")]
impl From<bincode::Error> for Error {
    fn from(err: bincode::Error) -> Self {
        Self::Serialization(err.to_string())
    }
}

impl From<core::array::TryFromSliceError> for Error {
    fn from(err: core::array::TryFromSliceError) -> Self {
        Self::Serialization(format!("Invalid slice length: {err}"))
    }
}
