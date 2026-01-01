//! Merkle Tree Accumulator implementation.

use alloc::format;
use alloc::vec::Vec;

use rs_merkle::{Hasher, MerkleProof, MerkleTree};
use serde::{Deserialize, Serialize};

use crate::{Error, Hash, Result};

/// A Merkle tree accumulator with append-only semantics.
///
/// The accumulator is generic over the hash function, allowing you to choose
/// between different hashers like SHA3-256 (default) or Poseidon (algebraic hash).
///
/// # Type Parameters
///
/// - `H`: The hasher type implementing `rs_merkle::Hasher`. Use `Sha3H` for
///   general purposes or `PoseidonH` (with `poseidon` feature) for algebraic hashing.
///
/// # Examples
///
/// ```
/// use merkle_tree_accumulator::{Hash, Sha3Accumulator};
///
/// let mut acc = Sha3Accumulator::new();
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
pub struct MerkleTreeAccumulator<H: Hasher<Hash = [u8; 32]>> {
    /// Internal Merkle tree.
    tree: MerkleTree<H>,
    /// Leaves that have been added to the accumulator.
    leaves: Vec<[u8; 32]>,
}

impl<H: Hasher<Hash = [u8; 32]>> Default for MerkleTreeAccumulator<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: Hasher<Hash = [u8; 32]>> core::fmt::Debug for MerkleTreeAccumulator<H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MerkleTreeAccumulator")
            .field("height", &self.height())
            .finish_non_exhaustive()
    }
}

impl<H: Hasher<Hash = [u8; 32]>> PartialEq for MerkleTreeAccumulator<H> {
    fn eq(&self, other: &Self) -> bool {
        self.leaves == other.leaves
    }
}

impl<H: Hasher<Hash = [u8; 32]>> Eq for MerkleTreeAccumulator<H> {}

impl<H: Hasher<Hash = [u8; 32]>> MerkleTreeAccumulator<H> {
    /// Creates a new empty accumulator.
    ///
    /// # Examples
    ///
    /// ```
    /// # use merkle_tree_accumulator::Sha3Accumulator;
    ///
    /// let acc = Sha3Accumulator::new();
    /// assert_eq!(acc.height(), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            tree: MerkleTree::new(),
            leaves: Vec::new(),
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
    /// # use merkle_tree_accumulator::Sha3Accumulator;
    ///
    /// let acc = Sha3Accumulator::new();
    /// assert_eq!(acc.height(), 0);
    /// ```
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn height(&self) -> u64 {
        self.leaves.len() as u64
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
    /// # use merkle_tree_accumulator::{Sha3Accumulator, Hash};
    ///
    /// let mut acc = Sha3Accumulator::new();
    /// assert!(acc.root().is_err());
    ///
    /// acc.add(Hash::from_data(b"data")).unwrap();
    /// assert!(acc.root().is_ok());
    /// ```
    pub fn root(&self) -> Result<Hash> {
        if self.leaves.is_empty() {
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
    /// use merkle_tree_accumulator::{Sha3Accumulator, Hash};
    ///
    /// let mut acc = Sha3Accumulator::new();
    /// let leaf = Hash::from_data(b"my data");
    /// acc.add(leaf).unwrap();
    /// assert_eq!(acc.height(), 1);
    /// ```
    pub fn add(&mut self, leaf: Hash) -> Result<()> {
        self.leaves.push(leaf.into_bytes());
        self.tree = MerkleTree::from_leaves(&self.leaves);
        Ok(())
    }

    /// Generates a cryptographic proof for one or more leaf indices.
    ///
    /// This method handles both single-leaf and batch proofs:
    /// - **Single proof**: Pass a slice with one index, e.g., `&[0]`
    /// - **Batch proof**: Pass a slice with multiple indices, e.g., `&[0, 3, 7]`
    ///
    /// Batch proofs are more storage-efficient than generating individual proofs
    /// because sibling hashes are shared across all leaves.
    ///
    /// # Storage Efficiency
    ///
    /// For a tree with height H and N leaves to prove:
    /// - Single proof (N=1): ~H hashes
    /// - Batch proof (N>1): ~N + (H - `log_2` N) hashes (shared sibling hashes)
    ///
    /// # Errors
    ///
    /// Returns `Error::IndexOutOfBounds` if any index is >= height.
    /// Returns `Error::EmptyTree` if the tree is empty.
    ///
    /// # Examples
    ///
    /// Single leaf:
    /// ```
    /// use merkle_tree_accumulator::{Sha3Accumulator, Hash};
    ///
    /// let mut acc = Sha3Accumulator::new();
    /// acc.add(Hash::from_data(b"data")).unwrap();
    ///
    /// let proof = acc.prove(&[0]).unwrap();
    /// ```
    ///
    /// Multiple leaves:
    /// ```
    /// use merkle_tree_accumulator::{Sha3Accumulator, Hash};
    ///
    /// let mut acc = Sha3Accumulator::new();
    /// (0..10).for_each(|i| {
    ///     acc.add(Hash::from_data(format!("data{i}").as_bytes())).unwrap();
    /// });
    ///
    /// let proof = acc.prove(&[0, 3, 7]).unwrap();
    /// ```
    pub fn prove(&self, indices: &[u64]) -> Result<Proof> {
        let height = self.height();
        if height == 0 {
            return Err(Error::EmptyTree);
        }

        if indices.is_empty() {
            return Err(Error::Serialization(
                "Cannot generate proof for empty indices".to_string(),
            ));
        }

        indices.iter().try_for_each(|&index| {
            if index >= height {
                Err(Error::IndexOutOfBounds {
                    index,
                    max: height.saturating_sub(1),
                })
            } else {
                Ok(())
            }
        })?;

        #[allow(clippy::cast_possible_truncation)]
        let tree_indices = indices.iter().map(|&i| i as usize).collect::<Vec<usize>>();

        let proof_hashes = self
            .tree
            .proof(&tree_indices)
            .proof_hashes()
            .iter()
            .map(|h| Hash::from(*h))
            .collect::<Vec<Hash>>();

        Ok(Proof {
            indices: indices.to_vec(),
            hashes: proof_hashes,
            height,
        })
    }

    /// Verifies a proof for one or more leaves.
    ///
    /// This method handles both single-leaf and batch proofs. The number of leaves
    /// must match the number of indices in the proof.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The proof is invalid
    /// - The number of leaves doesn't match the proof indices
    /// - The tree is empty
    ///
    /// # Examples
    ///
    /// Single leaf:
    /// ```
    /// use merkle_tree_accumulator::{Sha3Accumulator, Hash};
    ///
    /// let mut acc = Sha3Accumulator::new();
    /// let leaf = Hash::from_data(b"data");
    /// acc.add(leaf).unwrap();
    ///
    /// let proof = acc.prove(&[0]).unwrap();
    /// acc.verify(&proof, &[leaf]).unwrap();
    /// ```
    ///
    /// Multiple leaves:
    /// ```
    /// use merkle_tree_accumulator::{Sha3Accumulator, Hash};
    ///
    /// let mut acc = Sha3Accumulator::new();
    /// (0..10).for_each(|i| {
    ///     acc.add(Hash::from_data(format!("data{i}").as_bytes())).unwrap();
    /// });
    ///
    /// let proof = acc.prove(&[0, 3, 7]).unwrap();
    /// let leaves = vec![
    ///     Hash::from_data(b"data0"),
    ///     Hash::from_data(b"data3"),
    ///     Hash::from_data(b"data7"),
    /// ];
    /// acc.verify(&proof, &leaves).unwrap();
    /// ```
    pub fn verify(&self, proof: &Proof, leaves: &[Hash]) -> Result<()> {
        if proof.indices.len() != leaves.len() {
            return Err(Error::Serialization(format!(
                "Proof index count ({}) does not match leaf count ({})",
                proof.indices.len(),
                leaves.len()
            )));
        }

        if self.leaves.is_empty() {
            return Err(Error::EmptyTree);
        }

        let root = self.root()?;
        let proof_hashes = proof
            .hashes
            .iter()
            .map(|h| h.into_bytes())
            .collect::<Vec<[u8; 32]>>();
        let merkle_proof = MerkleProof::<H>::new(proof_hashes);

        #[allow(clippy::cast_possible_truncation)]
        let indices = proof
            .indices
            .iter()
            .map(|&i| i as usize)
            .collect::<Vec<usize>>();
        let leaf_hashes = leaves
            .iter()
            .map(|h| h.into_bytes())
            .collect::<Vec<[u8; 32]>>();

        if merkle_proof.verify(root.into_bytes(), &indices, &leaf_hashes, self.leaves.len()) {
            Ok(())
        } else {
            let computed_root = merkle_proof
                .root(&indices, &leaf_hashes, self.leaves.len())
                .unwrap_or([0u8; 32]);
            Err(Error::InvalidProof {
                expected: root.to_string(),
                actual: Hash::from(computed_root).to_string(),
            })
        }
    }

    /// Serializes the accumulator to bytes using bincode.
    ///
    /// Note: The internal rs-merkle tree is reconstructed from leaves,
    /// so we only serialize the leaves.
    ///
    /// # Errors
    ///
    /// Returns `Error::Serialization` if serialization fails.
    #[cfg(feature = "std")]
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serde::encode_to_vec(&self.leaves, bincode::config::standard()).map_err(Into::into)
    }

    /// Deserializes an accumulator from bytes.
    ///
    /// # Errors
    ///
    /// Returns `Error::Serialization` if deserialization fails.
    #[cfg(feature = "std")]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (leaves, _): (Vec<[u8; 32]>, _) =
            bincode::serde::decode_from_slice(bytes, bincode::config::standard())?;
        let tree = MerkleTree::from_leaves(&leaves);
        Ok(Self { tree, leaves })
    }
}

/// A cryptographic proof that one or more leaves exist in the accumulator.
///
/// This struct handles both single-leaf and batch proofs efficiently:
/// - **Single proof**: `indices` contains one element, `hashes` contains sibling hashes for that path
/// - **Batch proof**: `indices` contains multiple elements, `hashes` are shared across all proofs
///
/// # Storage Efficiency
///
/// For a tree with height H and N leaves to prove:
/// - Single proof (N=1): ~H hashes
/// - Batch proof (N>1): ~N + (H - `log_2`N) hashes (shared sibling hashes)
///
/// # Examples
///
/// Single proof:
/// ```
/// use merkle_tree_accumulator::{Sha3Accumulator, Hash};
///
/// let mut acc = Sha3Accumulator::new();
/// let leaf = Hash::from_data(b"data");
/// acc.add(leaf).unwrap();
///
/// let proof = acc.prove(&[0]).unwrap();
/// acc.verify(&proof, &[leaf]).unwrap();
/// ```
///
/// Batch proof:
/// ```
/// use merkle_tree_accumulator::{Sha3Accumulator, Hash};
///
/// let mut acc = Sha3Accumulator::new();
/// (0..10).for_each(|i| {
///     acc.add(Hash::from_data(format!("data{i}").as_bytes())).unwrap();
/// });
///
/// let proof = acc.prove(&[0, 3, 7]).unwrap();
/// let leaves = vec![
///     Hash::from_data(b"data0"),
///     Hash::from_data(b"data3"),
///     Hash::from_data(b"data7"),
/// ];
/// acc.verify(&proof, &leaves).unwrap();
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    /// Indices of leaves being proven.
    pub indices: Vec<u64>,
    /// Proof hashes (sibling hashes, shared across all leaves).
    pub hashes: Vec<Hash>,
    /// Height of the accumulator when this proof was generated.
    pub height: u64,
}

impl Proof {
    /// Serializes the proof to bytes using bincode.
    ///
    /// # Errors
    ///
    /// Returns `Error::Serialization` if serialization fails.
    #[cfg(feature = "std")]
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serde::encode_to_vec(self, bincode::config::standard()).map_err(Into::into)
    }

    /// Deserializes a proof from bytes.
    ///
    /// # Errors
    ///
    /// Returns `Error::Serialization` if deserialization fails or if the
    /// proof data is malformed.
    #[cfg(feature = "std")]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (proof, _): (Self, _) =
            bincode::serde::decode_from_slice(bytes, bincode::config::standard())?;

        if proof.indices.is_empty() && !proof.hashes.is_empty() {
            return Err(Error::Serialization(
                "Invalid proof: has hashes but no indices".into(),
            ));
        }

        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Sha3Accumulator;

    #[test]
    fn new_accumulator() {
        let acc = Sha3Accumulator::new();
        assert_eq!(acc.height(), 0);
        assert!(acc.root().is_err());
    }

    #[test]
    fn add_single_leaf() {
        let mut acc = Sha3Accumulator::new();
        let leaf = Hash::from_data(b"test");

        acc.add(leaf).unwrap();
        assert_eq!(acc.height(), 1);
        assert!(acc.root().is_ok());
    }

    #[test]
    fn add_multiple_leaves() {
        let mut acc = Sha3Accumulator::new();

        (0..10).for_each(|i| {
            let data = format!("leaf{i}");
            let leaf = Hash::from_data(data.as_bytes());
            acc.add(leaf).unwrap();
        });

        assert_eq!(acc.height(), 10);
    }

    #[test]
    fn generate_proof() {
        let mut acc = Sha3Accumulator::new();
        let leaf1 = Hash::from_data(b"leaf1");
        let leaf2 = Hash::from_data(b"leaf2");

        acc.add(leaf1).unwrap();
        acc.add(leaf2).unwrap();

        let proof = acc.prove(&[0]).unwrap();
        assert_eq!(proof.indices[0], 0);
        assert_eq!(proof.height, 2);
    }

    #[test]
    fn prove_out_of_bounds() {
        let mut acc = Sha3Accumulator::new();
        acc.add(Hash::from_data(b"leaf")).unwrap();

        // Single index out of bounds
        assert!(acc.prove(&[10]).is_err());

        // Batch with one valid and one invalid index
        assert!(acc.prove(&[0, 10]).is_err());
    }

    #[test]
    fn verify_valid_proof() {
        let mut acc = Sha3Accumulator::new();
        let leaf = Hash::from_data(b"test");

        acc.add(leaf).unwrap();
        let proof = acc.prove(&[0]).unwrap();

        assert!(acc.verify(&proof, &[leaf]).is_ok());
    }

    #[test]
    fn verify_invalid_leaf() {
        let mut acc = Sha3Accumulator::new();
        let leaf = Hash::from_data(b"test");
        let wrong_leaf = Hash::from_data(b"wrong");

        acc.add(leaf).unwrap();
        let proof = acc.prove(&[0]).unwrap();

        assert!(acc.verify(&proof, &[wrong_leaf]).is_err());
    }

    #[test]
    fn verify_batch_proofs() {
        let mut acc = Sha3Accumulator::new();
        let leaves = (0..5)
            .map(|i| Hash::from_data(format!("leaf{i}").as_bytes()))
            .collect::<Vec<Hash>>();

        leaves.iter().for_each(|&leaf| {
            acc.add(leaf).unwrap();
        });

        // Valid batch proof
        let proof = acc.prove(&[0, 2, 4]).unwrap();
        let batch_leaves = vec![leaves[0], leaves[2], leaves[4]];
        assert!(acc.verify(&proof, &batch_leaves).is_ok());

        // Invalid: wrong leaf in batch
        let wrong_leaves = vec![leaves[0], Hash::from_data(b"wrong"), leaves[4]];
        assert!(acc.verify(&proof, &wrong_leaves).is_err());

        // Invalid: leaf count mismatch
        let too_few_leaves = vec![leaves[0]];
        assert!(acc.verify(&proof, &too_few_leaves).is_err());
    }

    #[test]
    #[cfg(feature = "std")]
    fn accumulator_serialization() {
        let mut acc = Sha3Accumulator::new();
        acc.add(Hash::from_data(b"leaf1")).unwrap();
        acc.add(Hash::from_data(b"leaf2")).unwrap();

        let bytes = acc.to_bytes().unwrap();
        let deserialized = Sha3Accumulator::from_bytes(&bytes).unwrap();

        assert_eq!(acc.height(), deserialized.height());
        assert_eq!(acc.root().unwrap(), deserialized.root().unwrap());
    }

    #[test]
    #[cfg(feature = "std")]
    fn proof_serialization() {
        let mut acc = Sha3Accumulator::new();
        (0..8).for_each(|i| {
            let data = format!("leaf{i}");
            acc.add(Hash::from_data(data.as_bytes())).unwrap();
        });

        // single proof serialization
        let single_proof = acc.prove(&[0]).unwrap();
        let bytes = single_proof.to_bytes().unwrap();
        let deserialized = Proof::from_bytes(&bytes).unwrap();
        assert_eq!(single_proof.indices, deserialized.indices);
        assert_eq!(single_proof.height, deserialized.height);
        assert_eq!(single_proof.hashes.len(), deserialized.hashes.len());

        // batch proof serialization
        let batch_proof = acc.prove(&[0, 3, 5]).unwrap();
        let bytes = batch_proof.to_bytes().unwrap();
        let deserialized = Proof::from_bytes(&bytes).unwrap();
        assert_eq!(batch_proof.indices, deserialized.indices);
        assert_eq!(batch_proof.height, deserialized.height);
        assert_eq!(batch_proof.hashes.len(), deserialized.hashes.len());
    }

    #[test]
    fn batch_proof_storage_efficiency() {
        let mut acc = Sha3Accumulator::new();
        (0..16).for_each(|i| {
            let data = format!("data{i}");
            acc.add(Hash::from_data(data.as_bytes())).unwrap();
        });

        let indices = [0, 4, 8, 12];
        let individual_proofs = indices
            .iter()
            .map(|&i| acc.prove(&[i]).unwrap())
            .collect::<Vec<Proof>>();
        let batch_proof = acc.prove(&indices).unwrap();

        let individual_hash_count = individual_proofs
            .iter()
            .map(|p| p.hashes.len())
            .sum::<usize>();

        // Batch proof should have fewer hashes (shared sibling hashes)
        assert!(
            batch_proof.hashes.len() < individual_hash_count,
            "Proof ({}) should be more compact than individual proofs ({})",
            batch_proof.hashes.len(),
            individual_hash_count
        );
    }

    #[test]
    fn prove_empty_tree() {
        let acc = Sha3Accumulator::new();
        assert!(acc.prove(&[0]).is_err());
    }

    #[cfg(any(feature = "blake3", feature = "poseidon"))]
    macro_rules! alt_hasher_tests {
        ($acc:ty) => {
            let mut alt_acc = <$acc>::new();
            let mut sha3_acc = Sha3Accumulator::new();

            let leaf1 = Hash::from_data(b"data1");
            let leaf2 = Hash::from_data(b"data2");

            alt_acc.add(leaf1).unwrap();
            alt_acc.add(leaf2).unwrap();
            sha3_acc.add(leaf1).unwrap();
            sha3_acc.add(leaf2).unwrap();

            assert_eq!(alt_acc.height(), 2);
            assert_eq!(sha3_acc.height(), 2);

            // Roots differ because of different hash functions
            assert_ne!(alt_acc.root().unwrap(), sha3_acc.root().unwrap());

            // Single proof
            let proof = alt_acc.prove(&[0]).unwrap();
            assert!(alt_acc.verify(&proof, &[leaf1]).is_ok());

            // Batch proof
            let leaf3 = Hash::from_data(b"data3");
            let leaf4 = Hash::from_data(b"data4");
            let leaf5 = Hash::from_data(b"data5");
            let leaf6 = Hash::from_data(b"data6");
            let leaf7 = Hash::from_data(b"data7");

            alt_acc.add(leaf3).unwrap();
            alt_acc.add(leaf4).unwrap();
            alt_acc.add(leaf5).unwrap();
            alt_acc.add(leaf6).unwrap();
            alt_acc.add(leaf7).unwrap();

            let batch_proof = alt_acc.prove(&[0, 3, 5]).unwrap();
            let leaves = vec![leaf1, leaf4, leaf6];
            assert!(alt_acc.verify(&batch_proof, &leaves).is_ok());
        };
    }

    #[test]
    #[cfg(feature = "blake3")]
    fn blake3_hasher_works() {
        use crate::Blake3Accumulator;
        alt_hasher_tests!(Blake3Accumulator);
    }

    #[test]
    #[cfg(feature = "poseidon")]
    fn poseidon_hasher_works() {
        use crate::PoseidonAccumulator;
        alt_hasher_tests!(PoseidonAccumulator);
    }

    #[test]
    fn prove_empty_indices() {
        let mut acc = Sha3Accumulator::new();
        acc.add(Hash::from_data(b"leaf")).unwrap();

        // Empty indices should fail
        let result = acc.prove(&[]);
        assert!(result.is_err());
    }
}
