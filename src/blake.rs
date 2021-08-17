use blake2b_simd::Params;
use serde::{Deserialize, Serialize};

/// Blake hash representation
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash, Copy)]
pub enum Blake {}

const HASH_LENGTH: usize = 32;
const HASH_SHORT_LENGTH: usize = 20;

impl Blake {
    /// Take a bytes in and produce a long byte Hash array
    pub fn long(src: &[u8]) -> [u8; HASH_LENGTH] {
        let blake_hash = Params::new()
            .hash_length(HASH_LENGTH)
            .to_state()
            .update(src)
            .finalize();
        let mut hash: [u8; HASH_LENGTH] = [0; HASH_LENGTH];
        let a = blake_hash.as_ref().to_vec();
        hash.copy_from_slice(&a[0..HASH_LENGTH]);
        hash
    }

    /// Take short version of Hash of bytes array
    pub fn short(src: &[u8]) -> [u8; HASH_SHORT_LENGTH] {
        let h = Self::get_hash_by_length(src, HASH_SHORT_LENGTH);
        let mut hash: [u8; HASH_SHORT_LENGTH] = [0; HASH_SHORT_LENGTH];
        hash.copy_from_slice(&h[0..HASH_SHORT_LENGTH]);
        hash
    }

    /// Get Blake hash for specific length
    pub fn get_hash_by_length(src: &[u8], hash_length: usize) -> Vec<u8> {
        Params::new()
            .hash_length(hash_length)
            .to_state()
            .update(src)
            .finalize()
            .as_ref()
            .to_vec()
    }
}
