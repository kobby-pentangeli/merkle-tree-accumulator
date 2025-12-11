//! # Merkle Tree Accumulator
//!
//! A simple, append-only Merkle tree-based cryptographic accumulator.
//!
//! # Features
//!
//! - **Multiple hashers**: Support for SHA-3, BLAKE3, and Poseidon hash functions
//! - **Height tracking**: Accumulator maintains height for historical verification
//! - **Witness caching**: LRU cache for efficient verification of old proofs
//! - **Chain-agnostic**: No blockchain-specific dependencies
//! - **Batch operations**: Optimized batch proof generation and verification
//! - **no-std/WASM compatible**: Works in constrained environments without standard library
//!
//! # Examples
//!
//! Basic usage:
//!
//! ```
//! use merkle_tree_accumulator::hash::Hash;
//!
//! let data = b"hello world";
//! let hash = Hash::from_data(data);
//! ```
//!
//! # Feature Flags
//!
//! - `std` (default): Enable standard library support
//! - `blake3`: Enable BLAKE3 hasher for high-performance applications
//! - `poseidon`: Enable Poseidon hasher for algebraic hash operations

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unstable_features,
    unused_import_braces,
    unused_qualifications
)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::cargo,
    clippy::nursery,
    rust_2018_idioms
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc
)]

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
#[cfg(feature = "blake3")]
pub use mta::Blake3Accumulator;
#[cfg(feature = "poseidon")]
pub use mta::PoseidonAccumulator;
pub use mta::{MerkleTreeAccumulator, Proof, Sha3Accumulator};

/// Result type for accumulator operations.
pub type Result<T> = core::result::Result<T, Error>;
