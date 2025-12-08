//! Merkle Tree Accumulator implementation.

use alloc::vec::Vec;
use core::num::NonZeroUsize;

use lru::LruCache;
use rs_merkle::{MerkleProof, MerkleTree};
use serde::{Deserialize, Serialize};

use crate::hash::Sha3Hasher;
use crate::{Error, Hash, Result};

/// Default cache size for witness caching.
const DEFAULT_CACHE_SIZE: usize = 1000;

/// A Merkle tree accumulator with append-only semantics and witness caching.
///
/// The accumulator maintains a Merkle tree and provides efficient proof
/// generation and verification for elements in the set. It is designed
/// for append-only workloads where elements are continuously added but never removed.
///
/// # Examples
///
/// ```
/// use merkle_tree_accumulator::{Hash, MerkleTreeAccumulator};
///
/// let mut acc = MerkleTreeAccumulator::new();
/// assert_eq!(acc.height(), 0);
///
/// // Add some elements
/// let leaf1 = Hash::from_data(b"data1");
/// acc.add(leaf1).unwrap();
/// assert_eq!(acc.height(), 1);
///
/// let leaf2 = Hash::from_data(b"data2");
/// acc.add(leaf2).unwrap();
/// assert_eq!(acc.height(), 2);
/// ```
#[derive(Clone)]
pub struct MerkleTreeAccumulator {
    /// Internal Merkle tree.
    tree: MerkleTree<Sha3Hasher>,
    /// Total number of elements added (accumulator height).
    height: u64,
    /// Leaves that have been added to the accumulator.
    leaves: Vec<[u8; 32]>,
    /// LRU cache for recent witnesses (leaf hashes).
    cache: LruCache<Hash, ()>,
    /// Whether newer witnesses are allowed for verification.
    newer_witness_allowed: bool,
}

impl Default for MerkleTreeAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for MerkleTreeAccumulator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MerkleTreeAccumulator")
            .field("height", &self.height)
            .field("leaves_count", &self.leaves.len())
            .field("newer_witness_allowed", &self.newer_witness_allowed)
            .finish_non_exhaustive()
    }
}

impl MerkleTreeAccumulator {
    /// Creates a new empty accumulator with default cache size.
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
    pub fn new() -> Self {
        Self::with_cache_size(DEFAULT_CACHE_SIZE)
    }

    /// Creates a new empty accumulator with the specified cache size.
    ///
    /// # Panics
    ///
    /// Panics if `cache_size` is 0 and `NonZeroUsize::new` fails. In practice,
    /// this is handled by using a minimum cache size of 1.
    ///
    /// # Examples
    ///
    /// ```
    /// # use merkle_tree_accumulator::MerkleTreeAccumulator;
    ///
    /// let acc = MerkleTreeAccumulator::with_cache_size(500);
    /// assert_eq!(acc.height(), 0);
    /// ```
    #[must_use]
    pub fn with_cache_size(cache_size: usize) -> Self {
        let cache_size = cache_size.max(1);
        let cache = LruCache::new(
            NonZeroUsize::new(cache_size).expect("cache size is guaranteed to be >= 1"),
        );

        Self {
            tree: MerkleTree::new(),
            height: 0,
            leaves: Vec::new(),
            cache,
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

    /// Returns the root hash of the accumulator.
    ///
    /// # Errors
    ///
    /// Returns `Error::EmptyTree` if the accumulator is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// # use merkle_tree_accumulator::{MerkleTreeAccumulator, Hash};
    ///
    /// let mut acc = MerkleTreeAccumulator::new();
    /// assert!(acc.root().is_err());
    ///
    /// acc.add(Hash::from_data(b"data")).unwrap();
    /// assert!(acc.root().is_ok());
    /// ```
    pub fn root(&self) -> Result<Hash> {
        if self.height == 0 {
            return Err(Error::EmptyTree);
        }
        let root_hash = self.tree.root().ok_or(Error::EmptyTree)?;
        Ok(Hash::from(root_hash))
    }

    /// Adds a new leaf to the accumulator.
    ///
    /// This is an append-only operation that adds the leaf to the end of the tree
    /// and updates the accumulator height.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle_tree_accumulator::{MerkleTreeAccumulator, Hash};
    ///
    /// let mut acc = MerkleTreeAccumulator::new();
    /// let leaf = Hash::from_data(b"my data");
    /// acc.add(leaf).unwrap();
    /// assert_eq!(acc.height(), 1);
    /// ```
    pub fn add(&mut self, leaf: Hash) -> Result<()> {
        // Add to cache
        self.cache.put(leaf, ());

        // Add to leaves and rebuild tree
        self.leaves.push(leaf.into_bytes());
        self.tree = MerkleTree::from_leaves(&self.leaves);
        self.height += 1;

        Ok(())
    }

    /// Generates a Merkle proof for a leaf at the given index.
    ///
    /// # Errors
    ///
    /// Returns `Error::IndexOutOfBounds` if the index is >= height.
    /// Returns `Error::EmptyTree` if the tree is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle_tree_accumulator::{MerkleTreeAccumulator, Hash};
    ///
    /// let mut acc = MerkleTreeAccumulator::new();
    /// acc.add(Hash::from_data(b"data1")).unwrap();
    /// acc.add(Hash::from_data(b"data2")).unwrap();
    ///
    /// let proof = acc.proof(0).unwrap();
    /// ```
    pub fn proof(&self, index: u64) -> Result<AccumulatorProof> {
        if index >= self.height {
            return Err(Error::IndexOutOfBounds {
                index,
                max: self.height.saturating_sub(1),
            });
        }

        if self.height == 0 {
            return Err(Error::EmptyTree);
        }

        #[allow(clippy::cast_possible_truncation)]
        let indices = vec![index as usize];
        let proof = self
            .tree
            .proof(&indices)
            .proof_hashes()
            .iter()
            .map(|h| Hash::from(*h))
            .collect();

        Ok(AccumulatorProof {
            leaf_index: index,
            hashes: proof,
            height: self.height,
        })
    }

    /// Generates individual Merkle proofs for multiple leaves.
    ///
    /// This method creates independent proofs for each requested leaf index.
    /// Each proof can be verified separately and contains its own complete set
    /// of sibling hashes needed to reconstruct the root.
    ///
    /// # Design Note
    ///
    /// This implementation prioritizes API simplicity and independent proof verification
    /// over storage efficiency. Each `AccumulatorProof` is self-contained and can be
    /// verified without reference to other proofs.
    ///
    /// For applications requiring maximum storage efficiency, use the
    /// `MultiProof` type, which is a compact multi-proof format where
    /// sibling hashes are shared across proofs.
    ///
    /// # Errors
    ///
    /// Returns `Error::IndexOutOfBounds` if any index is >= height.
    /// Returns `Error::EmptyTree` if the tree is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle_tree_accumulator::{MerkleTreeAccumulator, Hash};
    ///
    /// let mut acc = MerkleTreeAccumulator::new();
    /// acc.add(Hash::from_data(b"data1")).unwrap();
    /// acc.add(Hash::from_data(b"data2")).unwrap();
    /// acc.add(Hash::from_data(b"data3")).unwrap();
    ///
    /// // Generate independent proofs for multiple leaves
    /// let proofs = acc.proof_batch(&[0, 2]).unwrap();
    /// assert_eq!(proofs.len(), 2);
    ///
    /// // Each proof can be verified independently
    /// let leaf0 = Hash::from_data(b"data1");
    /// let leaf2 = Hash::from_data(b"data3");
    /// acc.verify(&proofs[0], &leaf0).unwrap();
    /// acc.verify(&proofs[1], &leaf2).unwrap();
    /// ```
    pub fn proof_batch(&self, indices: &[u64]) -> Result<Vec<AccumulatorProof>> {
        if self.height == 0 {
            return Err(Error::EmptyTree);
        }

        indices
            .iter()
            .map(|&index| self.proof(index))
            .collect::<Result<Vec<_>>>()
    }

    /// Verifies a proof for a given leaf.
    ///
    /// # Errors
    ///
    /// Returns an error if the proof is invalid or if cache validation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle_tree_accumulator::{MerkleTreeAccumulator, Hash};
    ///
    /// let mut acc = MerkleTreeAccumulator::new();
    /// let leaf = Hash::from_data(b"data");
    /// acc.add(leaf).unwrap();
    ///
    /// let proof = acc.proof(0).unwrap();
    /// acc.verify(&proof, &leaf).unwrap();
    /// ```
    pub fn verify(&self, proof: &AccumulatorProof, leaf: &Hash) -> Result<()> {
        if self.height == 0 {
            return Err(Error::EmptyTree);
        }

        // Check if we need to validate against cache
        if !self.newer_witness_allowed && proof.height < self.height && !self.cache.contains(leaf) {
            return Err(Error::InvalidWitness {
                height: proof.height,
            });
        }

        // Verify using rs-merkle
        let root = self.root()?;
        let proof_hashes: Vec<[u8; 32]> = proof.hashes.iter().map(|h| h.into_bytes()).collect();

        let merkle_proof = MerkleProof::<Sha3Hasher>::new(proof_hashes);
        #[allow(clippy::cast_possible_truncation)]
        let indices = vec![proof.leaf_index as usize];

        if merkle_proof.verify(
            root.into_bytes(),
            &indices,
            &[leaf.into_bytes()],
            self.leaves.len(),
        ) {
            Ok(())
        } else {
            Err(Error::InvalidProof {
                expected: root.to_hex(),
                actual: leaf.to_hex(),
            })
        }
    }

    /// Verifies multiple independent proofs with cache validation.
    ///
    /// This method verifies each proof individually, similar to calling `verify()`
    /// in a loop, but with a single root retrieval for efficiency. Each proof is
    /// validated against the cache and then verified independently.
    ///
    /// # Design Note
    ///
    /// This verifies **independent proofs** generated by `proof_batch()`. Each proof
    /// is self-contained and verified separately. For applications requiring a more
    /// storage-efficient approach, use `verify_multi_proof()` with `MultiProof`
    /// that shares sibling hashes across leaves.
    ///
    /// # Errors
    ///
    /// Returns an error if any proof is invalid or if cache validation fails for any leaf.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle_tree_accumulator::{MerkleTreeAccumulator, Hash};
    ///
    /// let mut acc = MerkleTreeAccumulator::new();
    /// let leaf1 = Hash::from_data(b"data1");
    /// let leaf2 = Hash::from_data(b"data2");
    /// acc.add(leaf1).unwrap();
    /// acc.add(leaf2).unwrap();
    ///
    /// let proofs = acc.proof_batch(&[0, 1]).unwrap();
    /// let leaves = vec![leaf1, leaf2];
    /// acc.verify_batch(&proofs, &leaves).unwrap();
    /// ```
    pub fn verify_batch(&self, proofs: &[AccumulatorProof], leaves: &[Hash]) -> Result<()> {
        if proofs.len() != leaves.len() {
            return Err(Error::Serialization(format!(
                "Proof count ({}) does not match leaf count ({})",
                proofs.len(),
                leaves.len()
            )));
        }

        if self.height == 0 {
            return Err(Error::EmptyTree);
        }

        let root = self.root()?;

        proofs
            .iter()
            .zip(leaves.iter())
            .try_for_each(|(proof, leaf)| {
                // Validate cache
                if !self.newer_witness_allowed
                    && proof.height < self.height
                    && !self.cache.contains(leaf)
                {
                    return Err(Error::InvalidWitness {
                        height: proof.height,
                    });
                }

                // Verify proof
                let proof_hashes = proof
                    .hashes
                    .iter()
                    .map(|h| h.into_bytes())
                    .collect::<Vec<[u8; 32]>>();

                let merkle_proof = MerkleProof::<Sha3Hasher>::new(proof_hashes);
                #[allow(clippy::cast_possible_truncation)]
                let indices = vec![proof.leaf_index as usize];

                if merkle_proof.verify(
                    root.into_bytes(),
                    &indices,
                    &[leaf.into_bytes()],
                    self.leaves.len(),
                ) {
                    Ok(())
                } else {
                    Err(Error::InvalidProof {
                        expected: root.to_hex(),
                        actual: leaf.to_hex(),
                    })
                }
            })
    }

    /// Sets whether newer witnesses are allowed for verification.
    ///
    /// When set to `true`, proofs generated at a newer height than when
    /// a leaf was added can still be verified.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle_tree_accumulator::MerkleTreeAccumulator;
    ///
    /// let mut acc = MerkleTreeAccumulator::new();
    /// acc.set_newer_witness_allowed(true);
    /// ```
    pub const fn set_newer_witness_allowed(&mut self, allowed: bool) {
        self.newer_witness_allowed = allowed;
    }

    /// Checks if a leaf hash is in the cache.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle_tree_accumulator::{MerkleTreeAccumulator, Hash};
    ///
    /// let mut acc = MerkleTreeAccumulator::new();
    /// let leaf = Hash::from_data(b"data");
    /// acc.add(leaf).unwrap();
    /// assert!(acc.contains_in_cache(&leaf));
    /// ```
    #[must_use]
    pub fn contains_in_cache(&self, leaf: &Hash) -> bool {
        self.cache.contains(leaf)
    }

    /// Serializes the accumulator to bytes using bincode.
    ///
    /// Note: The internal rs-merkle tree is reconstructed from leaves,
    /// so we only serialize the leaves and metadata.
    ///
    /// # Errors
    ///
    /// Returns `Error::Serialization` if serialization fails.
    #[cfg(feature = "std")]
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let data = SerializedAccumulator {
            height: self.height,
            leaves: self.leaves.clone(),
            newer_witness_allowed: self.newer_witness_allowed,
        };
        bincode::serialize(&data).map_err(Into::into)
    }

    /// Deserializes an accumulator from bytes.
    ///
    /// # Errors
    ///
    /// Returns `Error::Serialization` if deserialization fails.
    ///
    /// # Panics
    ///
    /// Should not panic as `DEFAULT_CACHE_SIZE` is a non-zero constant.
    #[cfg(feature = "std")]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let data: SerializedAccumulator = bincode::deserialize(bytes)?;
        let tree = MerkleTree::from_leaves(&data.leaves);

        Ok(Self {
            tree,
            height: data.height,
            leaves: data.leaves,
            cache: LruCache::new(
                NonZeroUsize::new(DEFAULT_CACHE_SIZE).expect("DEFAULT_CACHE_SIZE is non-zero"),
            ),
            newer_witness_allowed: data.newer_witness_allowed,
        })
    }
}

/// Serialization helper for `MerkleTreeAccumulator`.
#[cfg(feature = "std")]
#[derive(Serialize, Deserialize)]
struct SerializedAccumulator {
    height: u64,
    leaves: Vec<[u8; 32]>,
    newer_witness_allowed: bool,
}

/// A proof that a leaf exists in the accumulator at a specific height.
///
/// This wraps the proof hashes along with metadata about when the proof
/// was generated.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccumulatorProof {
    /// Index of the leaf in the tree.
    pub leaf_index: u64,
    /// Proof hashes (sibling hashes along the path to root).
    pub hashes: Vec<Hash>,
    /// Height of the accumulator when this proof was generated.
    pub height: u64,
}

impl AccumulatorProof {
    /// Serializes the proof to bytes using bincode.
    ///
    /// # Errors
    ///
    /// Returns `Error::Serialization` if serialization fails.
    #[cfg(feature = "std")]
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(Into::into)
    }

    /// Deserializes a proof from bytes.
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
        assert!(acc.root().is_err());
    }

    #[test]
    fn add_single_leaf() {
        let mut acc = MerkleTreeAccumulator::new();
        let leaf = Hash::from_data(b"test");

        acc.add(leaf).unwrap();
        assert_eq!(acc.height(), 1);
        assert!(acc.root().is_ok());
        assert!(acc.contains_in_cache(&leaf));
    }

    #[test]
    fn add_multiple_leaves() {
        let mut acc = MerkleTreeAccumulator::new();

        (0..10).for_each(|i| {
            let data = format!("leaf{i}");
            let leaf = Hash::from_data(data.as_bytes());
            acc.add(leaf).unwrap();
        });

        assert_eq!(acc.height(), 10);
    }

    #[test]
    fn generate_proof() {
        let mut acc = MerkleTreeAccumulator::new();
        let leaf1 = Hash::from_data(b"leaf1");
        let leaf2 = Hash::from_data(b"leaf2");

        acc.add(leaf1).unwrap();
        acc.add(leaf2).unwrap();

        let proof = acc.proof(0).unwrap();
        assert_eq!(proof.leaf_index, 0);
        assert_eq!(proof.height, 2);
    }

    #[test]
    fn generate_proof_batch() {
        let mut acc = MerkleTreeAccumulator::new();
        (0..5).for_each(|i| {
            let data = format!("leaf{i}");
            acc.add(Hash::from_data(data.as_bytes())).unwrap();
        });

        let proofs = acc.proof_batch(&[0, 2, 4]).unwrap();
        assert_eq!(proofs.len(), 3);
        assert_eq!(proofs[0].leaf_index, 0);
        assert_eq!(proofs[1].leaf_index, 2);
        assert_eq!(proofs[2].leaf_index, 4);
        assert_eq!(proofs[0].height, 5);
    }

    #[test]
    fn proof_out_of_bounds() {
        let mut acc = MerkleTreeAccumulator::new();
        acc.add(Hash::from_data(b"leaf")).unwrap();

        assert!(acc.proof(10).is_err());
    }

    #[test]
    fn batch_proof_out_of_bounds() {
        let mut acc = MerkleTreeAccumulator::new();
        acc.add(Hash::from_data(b"leaf")).unwrap();

        assert!(acc.proof_batch(&[0, 10]).is_err());
    }

    #[test]
    fn verify_valid_proof() {
        let mut acc = MerkleTreeAccumulator::new();
        let leaf = Hash::from_data(b"test");

        acc.add(leaf).unwrap();
        let proof = acc.proof(0).unwrap();

        assert!(acc.verify(&proof, &leaf).is_ok());
    }

    #[test]
    fn verify_invalid_leaf() {
        let mut acc = MerkleTreeAccumulator::new();
        let leaf = Hash::from_data(b"test");
        let wrong_leaf = Hash::from_data(b"wrong");

        acc.add(leaf).unwrap();
        let proof = acc.proof(0).unwrap();

        assert!(acc.verify(&proof, &wrong_leaf).is_err());
    }

    #[test]
    fn verify_batch() {
        let mut acc = MerkleTreeAccumulator::new();
        let leaves = (0..5)
            .map(|i| Hash::from_data(format!("leaf{i}").as_bytes()))
            .collect::<Vec<Hash>>();

        leaves.iter().for_each(|&leaf| {
            acc.add(leaf).unwrap();
        });

        let proofs = acc.proof_batch(&[0, 2, 4]).unwrap();
        let batch_leaves = vec![leaves[0], leaves[2], leaves[4]];

        assert!(acc.verify_batch(&proofs, &batch_leaves).is_ok());
    }

    #[test]
    fn verify_batch_invalid() {
        let mut acc = MerkleTreeAccumulator::new();
        let leaves = (0..5)
            .map(|i| Hash::from_data(format!("leaf{i}").as_bytes()))
            .collect::<Vec<Hash>>();

        leaves.iter().for_each(|&leaf| {
            acc.add(leaf).unwrap();
        });

        let proofs = acc.proof_batch(&[0, 2]).unwrap();
        let wrong_leaves = vec![leaves[0], Hash::from_data(b"wrong")];

        assert!(acc.verify_batch(&proofs, &wrong_leaves).is_err());
    }

    #[test]
    fn verify_batch_length_mismatch() {
        let mut acc = MerkleTreeAccumulator::new();
        acc.add(Hash::from_data(b"leaf1")).unwrap();
        acc.add(Hash::from_data(b"leaf2")).unwrap();

        let proofs = acc.proof_batch(&[0, 1]).unwrap();
        let leaves = vec![Hash::from_data(b"leaf1")]; // Only one leaf

        assert!(acc.verify_batch(&proofs, &leaves).is_err());
    }

    #[test]
    fn newer_witness_allowed() {
        let mut acc = MerkleTreeAccumulator::new();
        acc.set_newer_witness_allowed(true);

        let leaf = Hash::from_data(b"leaf");
        acc.add(leaf).unwrap();

        // Clear cache to simulate old witness
        let mut new_acc = MerkleTreeAccumulator::new();
        new_acc.set_newer_witness_allowed(true);
        new_acc.add(leaf).unwrap();
    }

    #[test]
    #[cfg(feature = "std")]
    fn accumulator_serialization() {
        let mut acc = MerkleTreeAccumulator::new();
        acc.add(Hash::from_data(b"leaf1")).unwrap();
        acc.add(Hash::from_data(b"leaf2")).unwrap();

        let bytes = acc.to_bytes().unwrap();
        let deserialized = MerkleTreeAccumulator::from_bytes(&bytes).unwrap();

        assert_eq!(acc.height(), deserialized.height());
        assert_eq!(
            acc.root().unwrap().to_hex(),
            deserialized.root().unwrap().to_hex()
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn proof_serialization() {
        let mut acc = MerkleTreeAccumulator::new();
        acc.add(Hash::from_data(b"leaf1")).unwrap();
        acc.add(Hash::from_data(b"leaf2")).unwrap();

        let proof = acc.proof(0).unwrap();
        let bytes = proof.to_bytes().unwrap();
        let deserialized = AccumulatorProof::from_bytes(&bytes).unwrap();

        assert_eq!(proof.leaf_index, deserialized.leaf_index);
        assert_eq!(proof.height, deserialized.height);
    }
}
