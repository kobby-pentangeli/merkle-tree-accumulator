use bytebuffer::ByteBuffer;
use rand::{thread_rng, Rng};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use to_vec::ToVec;

use super::{blake::Blake, error::Error};

const DISPLAY_HASH_LEN: usize = 4;
const RANDOM_HASH_BUFFER: usize = 4096;

/// Hash representation
/// It's most common type for crypto related types
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash, Copy)]
pub struct Hash(pub [u8; 32]);

/// Short Hash representation
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash, Copy)]
pub struct ShortHash(pub [u8; 20]);

impl Hash {
    /// Create Hash from bytes
    pub fn new(data: &[u8]) -> Self {
        Self(Blake::long(data))
    }

    /// Create Hash for any serializable data
    pub fn serialize<D: Serialize>(d: &D) -> Result<Self, Error> {
        let ser = bincode::serialize(d).map_err(|err| Error::HashSerialize(format!("{}", err)))?;
        Ok(Self(Blake::long(&ser[..])))
    }

    /// Generate random hash from random buffer
    pub fn generate_random() -> Self {
        let mut bytes: [u8; RANDOM_HASH_BUFFER] = [0; RANDOM_HASH_BUFFER];
        thread_rng().fill(&mut bytes);
        Self(Blake::long(&bytes.to_vec()))
    }

    /// Convert Hashto Hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Takes in byte arrays and outputs a Hash
    pub fn bytes_arrays_to_hash(byte_array: Vec<Vec<u8>>) -> Self {
        let mut buffer = ByteBuffer::new();
        for b in byte_array {
            buffer.write_bytes(&b);
        }
        Self(Blake::long(&buffer.to_bytes()[..]))
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl ToVec<u8> for Hash {
    fn to_vec(self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl Default for Hash {
    fn default() -> Self {
        Self { 0: [0; 32] }
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut formatted = String::new();
        for num in 1..DISPLAY_HASH_LEN {
            formatted.push_str(&format!("{:02X}", self.0[num - 1]));
        }
        formatted.push_str("...");
        for num in (1..DISPLAY_HASH_LEN).rev() {
            formatted.push_str(&format!("{:02X}", self.0[32 - num]));
        }
        write!(f, "{}", formatted)
    }
}

impl std::fmt::Debug for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut formatted = String::new();
        for num in 1..DISPLAY_HASH_LEN {
            formatted.push_str(&format!("{:02X}", self.0[num - 1]));
        }
        formatted.push_str("...");
        for num in (1..DISPLAY_HASH_LEN).rev() {
            formatted.push_str(&format!("{:02X}", self.0[32 - num]));
        }
        write!(f, "{}", formatted)
    }
}

impl ShortHash {
    /// Create Hash from bytes
    pub fn new(data: &[u8]) -> Self {
        Self(Blake::short(data))
    }

    /// Create Hash for any serializable data
    pub fn serialize<D: Serialize>(d: &D) -> Result<Self, Error> {
        let ser = bincode::serialize(d).map_err(|err| Error::HashSerialize(format!("{}", err)))?;
        Ok(Self(Blake::short(&ser[..])))
    }

    /// Generate random hash from random buffer
    pub fn generate_random() -> Self {
        let mut bytes: [u8; RANDOM_HASH_BUFFER] = [0; RANDOM_HASH_BUFFER];
        thread_rng().fill(&mut bytes);
        Self(Blake::short(&bytes.to_vec()))
    }

    /// Convert Hashto Hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Takes in byte arrays and outputs a Hash
    pub fn bytes_arrays_to_hash(byte_array: Vec<Vec<u8>>) -> Self {
        let mut buffer = ByteBuffer::new();
        for b in byte_array {
            buffer.write_bytes(&b);
        }
        Self(Blake::short(&buffer.to_bytes()[..]))
    }
}

impl AsRef<[u8]> for ShortHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl ToVec<u8> for ShortHash {
    fn to_vec(self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl Default for ShortHash {
    fn default() -> Self {
        Self { 0: [0; 20] }
    }
}

/// HashType representation. Used for common Hash relations
pub trait HashType:
    Eq
    + Ord
    + Clone
    + std::fmt::Debug
    + Send
    + Serialize
    + DeserializeOwned
    + Sync
    + std::hash::Hash
    + std::fmt::Display
    + Default
{
}

impl<N> HashType for N where
    N: Eq
        + Ord
        + Clone
        + Send
        + std::fmt::Debug
        + std::fmt::Display
        + std::hash::Hash
        + Serialize
        + DeserializeOwned
        + Sync
        + Default
{
}
