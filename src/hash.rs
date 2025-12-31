//! Cryptographic hash types and hasher implementations.

use core::fmt;

use digest::Digest;
use rs_merkle::Hasher;
use serde::{Deserialize, Serialize};

use crate::Result;

const LEAF_HASH_PREFIX: u8 = 0x00;
const INTERNAL_HASH_PREFIX: u8 = 0x01;

/// SHA3-256 hasher for Merkle tree operations.
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

/// BLAKE3 hasher for high-performance Merkle tree operations.
#[cfg(feature = "blake3")]
#[derive(Clone, Copy, Debug)]
pub struct Blake3H;

#[cfg(feature = "blake3")]
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

/// Poseidon hasher for Merkle tree operations in algebraic circuits.
#[cfg(feature = "poseidon")]
#[derive(Clone, Copy, Debug)]
pub struct PoseidonH;

#[cfg(feature = "poseidon")]
impl Hasher for PoseidonH {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        use blstrs::Scalar;
        use ff::Field;
        use generic_array::GenericArray;
        use neptune::Poseidon;
        use neptune::poseidon::PoseidonConstants;

        let constants = PoseidonConstants::<Scalar, typenum::U4>::new();
        let domain_tag = Scalar::from(u64::from(LEAF_HASH_PREFIX));

        let field_element = if data.len() <= 32 {
            let mut padded = [0u8; 32];
            padded[..data.len()].copy_from_slice(data);
            poseidon_bytes_to_scalar(&padded)
        } else {
            let mut hasher = sha3::Sha3_256::new();
            hasher.update(data);
            let hash_bytes: [u8; 32] = hasher.finalize().into();
            poseidon_bytes_to_scalar(&hash_bytes)
        };

        let preimage = GenericArray::from([domain_tag, field_element, Scalar::ZERO, Scalar::ZERO]);
        let hash_result = Poseidon::new_with_preimage(&preimage, &constants).hash();
        poseidon_scalar_to_bytes(&hash_result)
    }

    fn concat_and_hash(left: &Self::Hash, right: Option<&Self::Hash>) -> Self::Hash {
        use blstrs::Scalar;
        use ff::Field;
        use generic_array::GenericArray;
        use neptune::Poseidon;
        use neptune::poseidon::PoseidonConstants;

        let constants = PoseidonConstants::<Scalar, typenum::U4>::new();
        let domain_tag = Scalar::from(u64::from(INTERNAL_HASH_PREFIX));
        let left_scalar = poseidon_bytes_to_scalar(left);

        let hash_result = right.map_or_else(
            || {
                let preimage =
                    GenericArray::from([domain_tag, left_scalar, Scalar::ZERO, Scalar::ZERO]);
                Poseidon::new_with_preimage(&preimage, &constants).hash()
            },
            |right| {
                let right_scalar = poseidon_bytes_to_scalar(right);
                let preimage =
                    GenericArray::from([domain_tag, left_scalar, right_scalar, Scalar::ZERO]);
                Poseidon::new_with_preimage(&preimage, &constants).hash()
            },
        );
        poseidon_scalar_to_bytes(&hash_result)
    }
}

#[cfg(feature = "poseidon")]
fn poseidon_bytes_to_scalar(bytes: &[u8; 32]) -> blstrs::Scalar {
    use ff::{Field, PrimeField};
    let mut repr = [0u8; 32];
    repr[..31].copy_from_slice(&bytes[..31]);
    blstrs::Scalar::from_repr(repr).unwrap_or(blstrs::Scalar::ZERO)
}

#[cfg(feature = "poseidon")]
fn poseidon_scalar_to_bytes(scalar: &blstrs::Scalar) -> [u8; 32] {
    use ff::PrimeField;
    scalar.to_repr()
}

/// A 256-bit (32-byte) cryptographic hash.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Hash([u8; 32]);

impl Hash {
    /// Creates a new hash from a 32-byte array.
    #[inline]
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Creates a hash by hashing the given data with SHA3-256.
    #[must_use]
    pub fn from_data(data: &[u8]) -> Self {
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(data);
        Self(hasher.finalize().into())
    }

    /// Creates a hash from a slice, returning an error if not exactly 32 bytes.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        let bytes: [u8; 32] = slice.try_into()?;
        Ok(Self(bytes))
    }

    /// Returns the hash as a byte slice.
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Converts the hash into a byte array.
    #[inline]
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Creates a zero hash (all bytes are 0).
    #[inline]
    #[must_use]
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Checks if this hash is zero (all bytes are 0) in constant time.
    #[inline]
    #[must_use]
    pub fn is_zero(&self) -> bool {
        let mut acc = 0u8;
        for &b in &self.0 {
            acc |= b;
        }
        acc == 0
    }
}

impl Default for Hash {
    fn default() -> Self {
        Self::zero()
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<Hash> for [u8; 32] {
    fn from(hash: Hash) -> Self {
        hash.0
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_from_data() {
        let hash1 = Hash::from_data(b"hello world");
        let hash2 = Hash::from_data(b"hello world");
        assert_eq!(hash1, hash2);
        assert!(!hash1.is_zero());
    }

    #[test]
    fn hash_from_slice() {
        let bytes = [42u8; 32];
        let hash = Hash::from_slice(&bytes[..]).unwrap();
        assert_eq!(hash.as_bytes(), &bytes);
        assert!(Hash::from_slice(&[0u8; 31][..]).is_err());
    }

    #[test]
    fn zero_hash() {
        let zero = Hash::zero();
        assert!(zero.is_zero());
        assert_eq!(zero, Hash::default());
        assert!(!Hash::from_data(b"x").is_zero());
    }

    #[test]
    fn hash_display() {
        let hash = Hash::new([0xab; 32]);
        let display = format!("{hash}");
        assert_eq!(display.len(), 64);
        assert!(display.starts_with("abab"));
    }

    #[test]
    fn bincode_serialization() {
        let hash = Hash::from_data(b"test");
        let bytes = bincode::serde::encode_to_vec(&hash, bincode::config::standard()).unwrap();
        let (decoded, _): (Hash, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(hash, decoded);
    }

    macro_rules! hasher_tests {
        ($hasher:ty) => {
            let data = b"test data";
            let h1 = <$hasher>::hash(data);
            let h2 = <$hasher>::hash(data);
            assert_eq!(h1, h2);
            assert_eq!(h1.len(), 32);

            let left = [1u8; 32];
            let right = [2u8; 32];
            let c1 = <$hasher>::concat_and_hash(&left, Some(&right));
            let c2 = <$hasher>::concat_and_hash(&left, Some(&right));
            assert_eq!(c1, c2);
            assert_ne!(c1, left);

            let s1 = <$hasher>::concat_and_hash(&left, None);
            let s2 = <$hasher>::concat_and_hash(&left, None);
            assert_eq!(s1, s2);

            let internal = <$hasher>::concat_and_hash(&left, Some(&right));
            let mut fake_leaf = [0u8; 64];
            fake_leaf[..32].copy_from_slice(&left);
            fake_leaf[32..].copy_from_slice(&right);
            let leaf = <$hasher>::hash(&fake_leaf);
            assert_ne!(internal, leaf, "domain separation failed");
        };
    }

    #[test]
    fn sha3_hasher() {
        hasher_tests!(Sha3H);
    }

    #[test]
    #[cfg(feature = "blake3")]
    fn blake3_hasher() {
        hasher_tests!(Blake3H);
    }

    #[test]
    #[cfg(feature = "poseidon")]
    fn poseidon_hasher() {
        hasher_tests!(PoseidonH);
    }
}
