//! Poseidon hasher implementation for arithmetic circuits.

use digest::Digest;
use rs_merkle::Hasher;

/// Poseidon hasher implementation.
///
/// This hasher uses the Poseidon hash function, an algebraic hash function
/// over prime fields. Poseidon is designed for arithmetic circuits and
/// can be useful in cryptographic applications that require efficient
/// hashing over field elements.
///
/// # Examples
///
/// ```ignore
/// # #[cfg(feature = "poseidon")]
/// # {
/// use merkle_tree_accumulator::hash::PoseidonH;
/// use rs_merkle::Hasher;
///
/// let data = b"hello world";
/// let hash = PoseidonH::hash(data);
/// assert_eq!(hash.len(), 32);
/// # }
/// ```
///
/// # Feature Flag
///
/// This hasher is only available with the `poseidon` feature enabled:
/// ```toml
/// merkle-tree-accumulator = { version = "0.3", features = ["poseidon"] }
/// ```
#[derive(Clone, Copy, Debug)]
pub struct PoseidonH;

impl Hasher for PoseidonH {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        use blstrs::Scalar;
        use ff::Field;
        use generic_array::GenericArray;
        use neptune::Poseidon;
        use neptune::poseidon::PoseidonConstants;

        // Create Poseidon hasher with arity 2 (binary tree)
        let constants = PoseidonConstants::<Scalar, typenum::U2>::new();

        let field_element = if data.len() <= 32 {
            let mut padded = [0u8; 32];
            padded[..data.len()].copy_from_slice(data);
            bytes_to_scalar(&padded)
        } else {
            // For longer data, use SHA3 first then convert to scalar
            let mut hasher = sha3::Sha3_256::new();
            hasher.update(data);
            let hash_bytes: [u8; 32] = hasher.finalize().into();
            bytes_to_scalar(&hash_bytes)
        };

        let preimage = GenericArray::from([field_element, Scalar::ZERO]);
        let hash_result = Poseidon::new_with_preimage(&preimage, &constants).hash();

        scalar_to_bytes(&hash_result)
    }

    fn concat_and_hash(left: &Self::Hash, right: Option<&Self::Hash>) -> Self::Hash {
        use blstrs::Scalar;
        use ff::Field;
        use generic_array::GenericArray;
        use neptune::Poseidon;
        use neptune::poseidon::PoseidonConstants;

        let constants = PoseidonConstants::<Scalar, typenum::U2>::new();
        let left_scalar = bytes_to_scalar(left);

        let hash_result = right.map_or_else(
            || {
                let preimage = GenericArray::from([left_scalar, Scalar::ZERO]);
                Poseidon::new_with_preimage(&preimage, &constants).hash()
            },
            |right| {
                let right_scalar = bytes_to_scalar(right);
                let preimage = GenericArray::from([left_scalar, right_scalar]);
                Poseidon::new_with_preimage(&preimage, &constants).hash()
            },
        );

        scalar_to_bytes(&hash_result)
    }
}

/// Converts a 32-byte array to a BLS12-381 scalar field element.
fn bytes_to_scalar(bytes: &[u8; 32]) -> blstrs::Scalar {
    use ff::{Field, PrimeField};
    // Take first 31 bytes to ensure we're within field modulus
    let mut repr = [0u8; 32];
    repr[..31].copy_from_slice(&bytes[..31]);
    blstrs::Scalar::from_repr(repr).unwrap_or(blstrs::Scalar::ZERO)
}

/// Converts a BLS12-381 scalar field element to a 32-byte array.
fn scalar_to_bytes(scalar: &blstrs::Scalar) -> [u8; 32] {
    use ff::PrimeField;
    scalar.to_repr()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poseidon_hasher_works() {
        let data = b"test data";
        let left = [1u8; 32];
        let right = [2u8; 32];

        let hash1 = PoseidonH::hash(data);
        let hash2 = PoseidonH::hash(data);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);

        // Concat and hash should work with two inputs
        let concat_hash1 = PoseidonH::concat_and_hash(&left, Some(&right));
        let concat_hash2 = PoseidonH::concat_and_hash(&left, Some(&right));
        assert_eq!(concat_hash1, concat_hash2);
        assert_ne!(concat_hash1, left);
        assert_ne!(concat_hash1, right);

        // Concat and hash should work with single input
        let single_hash1 = PoseidonH::concat_and_hash(&left, None);
        let single_hash2 = PoseidonH::concat_and_hash(&left, None);
        assert_eq!(single_hash1, single_hash2);

        // Poseidon and SHA3 should produce different outputs
        let poseidon_hash = PoseidonH::hash(data);
        let sha3_hash = crate::hash::Sha3H::hash(data);
        assert_ne!(poseidon_hash, sha3_hash);
    }
}
