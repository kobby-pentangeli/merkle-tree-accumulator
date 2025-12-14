//! SHA3-256 hasher implementation for `rs-merkle` compatibility.

use digest::Digest;
use rs_merkle::Hasher;

use super::{INTERNAL_HASH_PREFIX, LEAF_HASH_PREFIX};

/// SHA3-256 hasher for `rs-merkle` compatibility.
///
/// This hasher implements the `rs_merkle::Hasher` trait using SHA3-256
/// as the underlying hash function. It serves as the default hash function
/// for the Merkle tree accumulator.
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
/// # use merkle_tree_accumulator::hash::Sha3H;
/// use rs_merkle::Hasher;
///
/// let data = b"hello world";
/// let hash = Sha3H::hash(data);
/// assert_eq!(hash.len(), 32);
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Sha3H;

impl Hasher for Sha3H {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        let mut hasher = sha3::Sha3_256::new();
        hasher.update([LEAF_HASH_PREFIX]);
        hasher.update(data);
        hasher.finalize().into()
    }

    fn concat_and_hash(left: &Self::Hash, right: Option<&Self::Hash>) -> Self::Hash {
        let mut hasher = sha3::Sha3_256::new();
        hasher.update([INTERNAL_HASH_PREFIX]);
        hasher.update(left);
        if let Some(right) = right {
            hasher.update(right);
        }
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha3_hasher_hash() {
        let data = b"test data";
        let hash1 = Sha3H::hash(data);
        let hash2 = Sha3H::hash(data);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn sha3_hasher_concat_and_hash() {
        let left = [1u8; 32];
        let right = [2u8; 32];
        let hash1 = Sha3H::concat_and_hash(&left, Some(&right));
        let hash2 = Sha3H::concat_and_hash(&left, Some(&right));
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, left);
        assert_ne!(hash1, right);
    }

    #[test]
    fn sha3_hasher_concat_single() {
        let left = [1u8; 32];
        let hash1 = Sha3H::concat_and_hash(&left, None);
        let hash2 = Sha3H::concat_and_hash(&left, None);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn domain_separation_prevents_collision() {
        // Test that leaf hash and internal node hash are different.
        let left = [0xaa; 32];
        let right = [0xbb; 32];

        let internal_hash = Sha3H::concat_and_hash(&left, Some(&right));

        let mut fake_leaf = [0u8; 64];
        fake_leaf[..32].copy_from_slice(&left);
        fake_leaf[32..].copy_from_slice(&right);
        let fake_leaf_hash = Sha3H::hash(&fake_leaf);

        assert_ne!(
            internal_hash, fake_leaf_hash,
            "Domain separation failed: leaf and internal node hashes collided"
        );
    }
}
