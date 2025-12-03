//! Cryptographic hash types and operations for Merkle tree accumulators.
//!
//! This module provides a fixed-size hash type and integration with the `RustCrypto`
//! `digest` trait ecosystem. The default hash function is SHA3-256.

use core::fmt;

use digest::Digest;
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
        let mut hex = String::with_capacity(Self::HEX_LEN);
        for b in &self.0 {
            use core::fmt::Write;
            let _ = write!(hex, "{b:02x}");
        }
        hex
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
        for b in &self.0 {
            write!(f, "{b:02X}")?;
        }
        Ok(())
    }
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
        let serialized = bincode::serialize(&hash).unwrap();
        let deserialized: Hash = bincode::deserialize(&serialized).unwrap();
        assert_eq!(hash, deserialized);
    }
}
