//! BLAKE3 hasher implementation for high-performance applications.

use rs_merkle::Hasher;

use super::{INTERNAL_HASH_PREFIX, LEAF_HASH_PREFIX};

/// BLAKE3 hasher for high-performance applications.
///
/// BLAKE3 is a cryptographic hash function that is significantly faster than
/// SHA2 and SHA3, especially on modern hardware with SIMD instructions and
/// multi-core processors. It's designed with a binary tree structure that
/// supports practically unlimited parallelism.
///
/// # Security
///
/// This implementation uses domain separation prefixes as specified in
/// [RFC 9162 (Certificate Transparency)](https://datatracker.ietf.org/doc/html/rfc9162):
/// - Leaf nodes are prefixed with `0x00`
/// - Internal nodes are prefixed with `0x01`
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "blake3")]
/// # {
/// use merkle_tree_accumulator::hash::Blake3H;
/// use rs_merkle::Hasher;
///
/// let data = b"hello world";
/// let hash = Blake3H::hash(data);
/// assert_eq!(hash.len(), 32);
/// # }
/// ```
///
/// # Feature Flag
///
/// This hasher is only available with the `blake3` feature enabled:
/// ```toml
/// merkle-tree-accumulator = { version = "0.3", features = ["blake3"] }
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Blake3H;

impl Hasher for Blake3H {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[LEAF_HASH_PREFIX]);
        hasher.update(data);
        *hasher.finalize().as_bytes()
    }

    fn concat_and_hash(left: &Self::Hash, right: Option<&Self::Hash>) -> Self::Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[INTERNAL_HASH_PREFIX]);
        hasher.update(left);
        if let Some(right) = right {
            hasher.update(right);
        }
        *hasher.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_hasher_works() {
        let data = b"test data";
        let left = [1u8; 32];
        let right = [2u8; 32];

        let hash1 = Blake3H::hash(data);
        let hash2 = Blake3H::hash(data);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);

        // Concat and hash should work with two inputs
        let concat_hash1 = Blake3H::concat_and_hash(&left, Some(&right));
        let concat_hash2 = Blake3H::concat_and_hash(&left, Some(&right));
        assert_eq!(concat_hash1, concat_hash2);
        assert_ne!(concat_hash1, left);
        assert_ne!(concat_hash1, right);

        // Concat and hash should work with single input
        let single_hash1 = Blake3H::concat_and_hash(&left, None);
        let single_hash2 = Blake3H::concat_and_hash(&left, None);
        assert_eq!(single_hash1, single_hash2);

        // BLAKE3 and SHA3 should produce different outputs
        let blake3_hash = Blake3H::hash(data);
        let sha3_hash = crate::hash::Sha3H::hash(data);
        assert_ne!(blake3_hash, sha3_hash);
    }

    #[test]
    fn domain_separation_prevents_collision() {
        // Test that leaf hash and internal node hash are different.
        let left = [0xaa; 32];
        let right = [0xbb; 32];

        let internal_hash = Blake3H::concat_and_hash(&left, Some(&right));

        let mut fake_leaf = [0u8; 64];
        fake_leaf[..32].copy_from_slice(&left);
        fake_leaf[32..].copy_from_slice(&right);
        let fake_leaf_hash = Blake3H::hash(&fake_leaf);

        // These must be different due to domain separation
        assert_ne!(
            internal_hash, fake_leaf_hash,
            "Domain separation failed: leaf and internal node hashes collided"
        );
    }
}
