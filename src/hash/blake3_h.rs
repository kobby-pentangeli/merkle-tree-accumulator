//! BLAKE3 hasher implementation for high-performance applications.

use rs_merkle::Hasher;

/// BLAKE3 hasher for high-performance applications.
///
/// BLAKE3 is a cryptographic hash function that is significantly faster than
/// SHA2 and SHA3, especially on modern hardware with SIMD instructions and
/// multi-core processors. It's designed with a binary tree structure that
/// supports practically unlimited parallelism.
///
/// # Performance
///
/// - **Speed**: 15-17× faster than SHA3-256 on modern CPUs
/// - **Parallelism**: Binary tree structure enables efficient multi-threading
/// - **Use case**: High-throughput systems, blockchains, distributed systems
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
        blake3::hash(data).into()
    }

    fn concat_and_hash(left: &Self::Hash, right: Option<&Self::Hash>) -> Self::Hash {
        let mut hasher = blake3::Hasher::new();
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
}
