//! Merkle Tree Accumulator implementation.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::{Error, Hash, Result};

/// A Merkle tree accumulator with append-only semantics and witness caching.
///
/// The accumulator maintains a set of Merkle tree roots and provides efficient
/// proof generation and verification for elements in the set. It is designed
/// for append-only workloads where elements are continuously added but never removed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleTreeAccumulator {
    /// Total number of elements added (accumulator height).
    pub height: u64,
    /// Merkle tree roots for each power of 2.
    pub roots: Vec<Hash>,
    /// Offset for tracking root rotations.
    pub offset: u64,
    /// Size of the roots array.
    pub roots_size: usize,
    /// Whether newer witnesses are allowed for verification.
    pub newer_witness_allowed: bool,
}

impl Default for MerkleTreeAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleTreeAccumulator {
    /// Creates a new empty accumulator.
    ///
    /// # Examples
    ///
    /// ```
    /// # use merkle_tree_accumulator::MerkleTreeAccumulator;
    ///
    /// let acc = MerkleTreeAccumulator::new();
    /// assert_eq!(acc.height(), 0);
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            height: 0,
            roots: Vec::new(),
            offset: 0,
            roots_size: 0,
            newer_witness_allowed: false,
        }
    }

    /// Returns the current height of the accumulator.
    ///
    /// The height represents the total number of elements that have been added
    /// to the accumulator since its creation.
    ///
    /// # Examples
    ///
    /// ```
    /// # use merkle_tree_accumulator::MerkleTreeAccumulator;
    ///
    /// let acc = MerkleTreeAccumulator::new();
    /// assert_eq!(acc.height(), 0);
    /// ```
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.height
    }

    /// Returns the root hash at the specified index.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidRootIndex` if the index is out of bounds.
    ///
    /// # Examples
    ///
    /// ```
    /// # use merkle_tree_accumulator::MerkleTreeAccumulator;
    ///
    /// let acc = MerkleTreeAccumulator::new();
    /// assert!(acc.get_root(0).is_err());
    /// ```
    pub fn get_root(&self, idx: usize) -> Result<&Hash> {
        self.roots
            .get(idx)
            .ok_or(Error::InvalidRootIndex { index: idx })
    }

    /// Serializes the accumulator to bytes using `bincode`.
    ///
    /// # Errors
    ///
    /// Returns `Error::Serialization` if serialization fails.
    #[cfg(feature = "std")]
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(Into::into)
    }

    /// Deserializes an accumulator from bytes.
    ///
    /// # Errors
    ///
    /// Returns `Error::Serialization` if deserialization fails.
    #[cfg(feature = "std")]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_accumulator() {
        let acc = MerkleTreeAccumulator::new();
        assert_eq!(acc.height(), 0);
        assert!(acc.get_root(0).is_err());
        assert!(acc.roots.is_empty());

        let acc = MerkleTreeAccumulator::default();
        assert_eq!(acc.height(), 0);
    }

    #[test]
    #[cfg(feature = "std")]
    fn serialization() {
        let acc = MerkleTreeAccumulator::new();
        let bytes = acc.to_bytes().unwrap();
        let deserialized = MerkleTreeAccumulator::from_bytes(&bytes).unwrap();
        assert_eq!(acc.height(), deserialized.height());
    }
}
