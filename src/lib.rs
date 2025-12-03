//! # Merkle Tree Accumulator
//!
//! This library provides a Merkle tree-based cryptographic accumulator with the following features:
//!
//! - **Append-only semantics**: Elements can only be added, never removed
//! - **Height tracking**: Accumulator maintains height for historical verification
//! - **Witness caching**: LRU cache for efficient verification of old proofs
//! - **Chain-agnostic**: No blockchain-specific dependencies
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
//! # Features
//!
//! - `std` (default): Enable standard library support

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
pub use hash::Hash;
pub use mta::MerkleTreeAccumulator;

/// Result type for accumulator operations.
pub type Result<T> = core::result::Result<T, Error>;
