//! SHA3-256 hasher implementation for `rs-merkle` compatibility.

use digest::Digest;
use rs_merkle::Hasher;

/// SHA3-256 hasher for `rs-merkle` compatibility.
///
/// This hasher implements the `rs_merkle::Hasher` trait using SHA3-256
/// as the underlying hash function. It serves as the default hash function
/// for the Merkle tree accumulator.
///
/// # Examples
///
/// ```
/// # use merkle_tree_accumulator::hash::Sha3Hasher;
/// use rs_merkle::Hasher;
///
/// let data = b"hello world";
/// let hash = Sha3Hasher::hash(data);
/// assert_eq!(hash.len(), 32);
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Sha3Hasher;

impl Hasher for Sha3Hasher {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    fn concat_and_hash(left: &Self::Hash, right: Option<&Self::Hash>) -> Self::Hash {
        let mut hasher = sha3::Sha3_256::new();
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
        let hash1 = Sha3Hasher::hash(data);
        let hash2 = Sha3Hasher::hash(data);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn sha3_hasher_concat_and_hash() {
        let left = [1u8; 32];
        let right = [2u8; 32];
        let hash1 = Sha3Hasher::concat_and_hash(&left, Some(&right));
        let hash2 = Sha3Hasher::concat_and_hash(&left, Some(&right));
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, left);
        assert_ne!(hash1, right);
    }

    #[test]
    fn sha3_hasher_concat_single() {
        let left = [1u8; 32];
        let hash1 = Sha3Hasher::concat_and_hash(&left, None);
        let hash2 = Sha3Hasher::concat_and_hash(&left, None);
        assert_eq!(hash1, hash2);
    }
}
