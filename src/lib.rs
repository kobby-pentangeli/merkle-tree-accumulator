//! # Merkle Tree Accumulator
//!
//! A simple, append-only Merkle tree-based cryptographic accumulator.
//!
//! # Features
//!
//! - **Multiple hashers**: SHA-3, BLAKE3, and Poseidon
//! - **Batch proofs**: Efficient multi-leaf proof generation and verification
//! - **no_std compatible**: Works without standard library
//!
//! # Example
//!
//! ```
//! use merkle_tree_accumulator::{Hash, Sha3Accumulator};
//!
//! let mut acc = Sha3Accumulator::new();
//! acc.add(Hash::from_data(b"leaf 1")).unwrap();
//! acc.add(Hash::from_data(b"leaf 2")).unwrap();
//!
//! let proof = acc.prove(&[0]).unwrap();
//! acc.verify(&proof, &[Hash::from_data(b"leaf 1")]).unwrap();
//! ```
//!
//! # Feature Flags
//!
//! - `std` (default): Standard library support
//! - `blake3`: BLAKE3 hasher
//! - `poseidon`: Poseidon hasher for algebraic circuits

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

extern crate alloc;

pub mod error;
pub mod hash;
pub mod mta;

pub use error::Error;
#[cfg(feature = "blake3")]
pub use hash::Blake3H;
#[cfg(feature = "poseidon")]
pub use hash::PoseidonH;
pub use hash::{Hash, Sha3H};
pub use mta::{MerkleTreeAccumulator, Proof};

/// Result type for accumulator operations.
pub type Result<T> = core::result::Result<T, Error>;

/// SHA3-256 accumulator (default).
pub type Sha3Accumulator = MerkleTreeAccumulator<Sha3H>;

/// BLAKE3 accumulator for high-performance applications.
///
/// Requires the `blake3` feature.
#[cfg(feature = "blake3")]
pub type Blake3Accumulator = MerkleTreeAccumulator<Blake3H>;

/// Poseidon accumulator for algebraic circuits.
///
/// Requires the `poseidon` feature.
#[cfg(feature = "poseidon")]
pub type PoseidonAccumulator = MerkleTreeAccumulator<PoseidonH>;
