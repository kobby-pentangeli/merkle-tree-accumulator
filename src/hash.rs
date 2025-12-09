//! Cryptographic hash types and operations for Merkle tree accumulators.
//!
//! This module provides a fixed-size hash type and integration with the `RustCrypto`
//! `digest` trait ecosystem. The default hash function is SHA3-256.
//!
//! It also provides the [`Sha3Hasher`] type which implements the `rs_merkle::Hasher`
//! trait, allowing SHA3-256 to be used with the `rs-merkle` library.

use core::fmt;

use digest::Digest;
use rs_merkle::Hasher;
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// A 256-bit (32-byte) cryptographic hash.
///
/// This type represents the output of cryptographic hash functions like SHA3-256,
/// Blake3, or other 256-bit hash functions. It is used throughout the library
/// for representing Merkle tree nodes, roots, and leaf values.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Hash([u8; 32]);

impl Hash {
    /// The size of a hash in bytes.
    pub const SIZE: usize = 32;

    /// The length of a hash expressed as a hexadecimal string
    pub const HEX_LEN: usize = 64;

    /// Creates a new hash from a 32-byte array.
    ///
    /// # Examples
    ///
    /// ```
    /// # use merkle_tree_accumulator::hash::Hash;
    ///
    /// let bytes = [0u8; 32];
    /// let hash = Hash::new(bytes);
    /// ```
    #[inline]
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Creates a hash by hashing the given data with SHA3-256.
    ///
    /// This is the default hash function used by the accumulator.
    ///
    /// # Examples
    ///
    /// ```
    /// # use merkle_tree_accumulator::hash::Hash;
    ///
    /// let data = b"some data";
    /// let hash = Hash::from_data(data);
    /// ```
    #[must_use]
    pub fn from_data(data: &[u8]) -> Self {
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        Self(result.into())
    }

    /// Creates a hash from a slice, returning an error if the slice is not exactly 32 bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use merkle_tree_accumulator::hash::Hash;
    ///
    /// let bytes = &[0u8; 32][..];
    /// let hash = Hash::from_slice(bytes).unwrap();
    /// ```
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        let bytes: [u8; 32] = slice.try_into()?;
        Ok(Self(bytes))
    }

    /// Returns the hash as a byte slice.
    ///
    /// # Examples
    ///
    /// ```
    /// # use merkle_tree_accumulator::hash::Hash;
    ///
    /// let hash = Hash::new([0u8; 32]);
    /// assert_eq!(hash.as_bytes().len(), 32);
    /// ```
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the hash as a mutable byte slice.
    #[inline]
    #[must_use]
    pub const fn as_bytes_mut(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }

    /// Converts the hash into a byte array.
    ///
    /// # Examples
    ///
    /// ```
    /// # use merkle_tree_accumulator::hash::Hash;
    ///
    /// let hash = Hash::new([1u8; 32]);
    /// let bytes = hash.into_bytes();
    /// assert_eq!(bytes[0], 1);
    /// ```
    #[inline]
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Returns a hexadecimal string representation of the hash.
    ///
    /// # Examples
    ///
    /// ```
    /// # use merkle_tree_accumulator::hash::Hash;
    ///
    /// let hash = Hash::new([0xab; 32]);
    /// let hex = hash.to_hex();
    /// assert!(hex.starts_with("abab"));
    /// ```
    #[must_use]
    pub fn to_hex(&self) -> String {
        use core::fmt::Write;
        self.0
            .iter()
            .fold(String::with_capacity(Self::HEX_LEN), |mut hex, b| {
                let _ = write!(hex, "{b:02x}");
                hex
            })
    }

    /// Creates a hash from a hexadecimal string.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not valid hexadecimal or not exactly 64 characters.
    ///
    /// # Examples
    ///
    /// ```
    /// # use merkle_tree_accumulator::hash::Hash;
    ///
    /// let hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    /// let hash = Hash::from_hex(hex).unwrap();
    /// assert_eq!(hash.to_hex(), hex);
    /// ```
    pub fn from_hex(hex: &str) -> Result<Self> {
        if hex.len() != Self::HEX_LEN {
            return Err(Error::Serialization(format!(
                "Invalid hex string length: expected {}, got {}",
                Self::HEX_LEN,
                hex.len()
            )));
        }

        let mut bytes = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let hex_byte = core::str::from_utf8(chunk)
                .map_err(|e| Error::Serialization(format!("Invalid UTF-8 in hex string: {e}")))?;

            bytes[i] = u8::from_str_radix(hex_byte, 16)
                .map_err(|e| Error::Serialization(format!("Invalid hex digit: {e}")))?;
        }

        Ok(Self(bytes))
    }

    /// Creates a zero hash (all bytes are 0).
    ///
    /// # Examples
    ///
    /// ```
    /// # use merkle_tree_accumulator::hash::Hash;
    ///
    /// let zero = Hash::zero();
    /// assert_eq!(zero.as_bytes(), &[0u8; 32]);
    /// ```
    #[inline]
    #[must_use]
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Checks if this hash is zero (all bytes are 0).
    ///
    /// # Examples
    ///
    /// ```
    /// # use merkle_tree_accumulator::hash::Hash;
    ///
    /// let hash = Hash::zero();
    /// assert!(hash.is_zero());
    ///
    /// let hash = Hash::from_data(b"data");
    /// assert!(!hash.is_zero());
    /// ```
    #[inline]
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
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

impl AsMut<[u8]> for Hash {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
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
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::LowerHex for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::UpperHex for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02X}"))
    }
}

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
/// use merkle_tree_accumulator::hash::PoseidonHasher;
/// use rs_merkle::Hasher;
///
/// let data = b"hello world";
/// let hash = PoseidonHasher::hash(data);
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
#[cfg(feature = "poseidon")]
#[derive(Clone, Copy, Debug)]
pub struct PoseidonHasher;

#[cfg(feature = "poseidon")]
impl Hasher for PoseidonHasher {
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
#[cfg(feature = "poseidon")]
fn bytes_to_scalar(bytes: &[u8; 32]) -> blstrs::Scalar {
    use ff::{Field, PrimeField};
    // Take first 31 bytes to ensure we're within field modulus
    let mut repr = [0u8; 32];
    repr[..31].copy_from_slice(&bytes[..31]);
    blstrs::Scalar::from_repr(repr).unwrap_or(blstrs::Scalar::ZERO)
}

/// Converts a BLS12-381 scalar field element to a 32-byte array.
#[cfg(feature = "poseidon")]
fn scalar_to_bytes(scalar: &blstrs::Scalar) -> [u8; 32] {
    use ff::PrimeField;
    scalar.to_repr()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_from_data() {
        let data = b"hello world";
        let hash1 = Hash::from_data(data);
        let hash2 = Hash::from_data(data);
        assert_eq!(hash1, hash2);
        assert!(!hash1.is_zero());
    }

    #[test]
    fn hash_from_slice() {
        let bytes = [42u8; 32];
        let hash = Hash::from_slice(&bytes[..]).unwrap();
        assert_eq!(hash.as_bytes(), &bytes);

        let invalid = [0u8; 31];
        assert!(Hash::from_slice(&invalid[..]).is_err());
    }

    #[test]
    fn hash_hex_conversion() {
        let hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let hash = Hash::from_hex(hex).unwrap();
        assert_eq!(hash.to_hex(), hex);

        let invalid_length = "0102";
        assert!(Hash::from_hex(invalid_length).is_err());

        let invalid_hex = "zzzz030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        assert!(Hash::from_hex(invalid_hex).is_err());
    }

    #[test]
    fn zero_hash() {
        let zero = Hash::zero();
        assert!(zero.is_zero());
        assert_eq!(zero, Hash::default());

        let nonzero = Hash::from_data(b"nonzero");
        assert!(!nonzero.is_zero());
    }

    #[test]
    fn hash_display() {
        let hash = Hash::new([0xab; 32]);
        let display = format!("{}", hash);
        assert_eq!(display.len(), Hash::HEX_LEN);
        assert!(display.starts_with("abab"));

        let upper = format!("{:X}", hash);
        assert!(upper.starts_with("ABAB"));
    }

    #[test]
    fn bincode_serialization() {
        let hash = Hash::from_data(b"test");
        let serialized = bincode::serde::encode_to_vec(&hash, bincode::config::standard()).unwrap();
        let (deserialized, _): (Hash, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard()).unwrap();
        assert_eq!(hash, deserialized);
    }

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

    #[test]
    #[cfg(feature = "poseidon")]
    fn poseidon_hasher_works() {
        use crate::hash::PoseidonHasher;

        let data = b"test data";
        let left = [1u8; 32];
        let right = [2u8; 32];

        let hash1 = PoseidonHasher::hash(data);
        let hash2 = PoseidonHasher::hash(data);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);

        // Concat and hash should work with two inputs
        let concat_hash1 = PoseidonHasher::concat_and_hash(&left, Some(&right));
        let concat_hash2 = PoseidonHasher::concat_and_hash(&left, Some(&right));
        assert_eq!(concat_hash1, concat_hash2);
        assert_ne!(concat_hash1, left);
        assert_ne!(concat_hash1, right);

        // Concat and hash should work with single input
        let single_hash1 = PoseidonHasher::concat_and_hash(&left, None);
        let single_hash2 = PoseidonHasher::concat_and_hash(&left, None);
        assert_eq!(single_hash1, single_hash2);

        // Poseidon and SHA3 should produce different outputs
        let poseidon_hash = PoseidonHasher::hash(data);
        let sha3_hash = Sha3Hasher::hash(data);
        assert_ne!(poseidon_hash, sha3_hash);
    }
}
