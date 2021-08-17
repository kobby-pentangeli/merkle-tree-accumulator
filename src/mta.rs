//! Merkle Tree Accumulator

use super::hash::Hash;
use borsh::{self, BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Struct for MTA
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Default, Deserialize, Serialize)]
#[serde(crate = "serde")]
pub struct MerkleTreeAccumulator {
    /// Height
    pub height: u64,
    /// Roots
    pub roots: Vec<Hash>,
    /// Offset
    pub offset: u64,
    /// Roots size
    pub roots_size: u64,
    /// Cache size
    pub cache_size: u64,
    /// Cache
    pub cache: Vec<Hash>,
    /// Is a newer witness allowed?
    pub newer_witness_allowed: bool,
}

impl MerkleTreeAccumulator {
    /// Initialize MTA from a serialized type
    pub fn init_from_serialized(&mut self, _rlp_bytes: &[u8]) {
        todo!()
    }

    /// Set offset
    pub fn set_offset(&mut self, _offset: u64) {
        todo!()
    }

    /// Get root
    pub fn get_root(&self, _idx: u64) -> &Hash {
        todo!()
    }

    /// Check if the MTA includes a cache
    pub fn includes_cache(&self, _hash: &Hash) -> bool {
        todo!()
    }

    /// Put cache
    pub fn put_cache(&mut self, _hash: &Hash) {
        todo!()
    }

    /// Add
    pub fn add(&mut self, _hash: &Hash) {
        todo!()
    }

    /// Get root index by height
    pub fn get_root_index_by_height(&self, _height: u64) -> u64 {
        todo!()
    }

    /// Verify
    pub fn verify(&mut self, _proof: &[&Hash], _leaf: &Hash, _height: u64, _at: u64) {
        todo!()
    }

    /// Convert MTA to bytes
    pub fn to_bytes(&mut self) -> Vec<u8> {
        todo!()
    }

    fn _verify(&mut self, _witness: &[&Hash], _root: &Hash, _leaf: &Hash, _index: u64) {
        todo!()
    }
}
