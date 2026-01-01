# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2025-01-01

### Added

- **Multiple hash functions**: Support for SHA3-256 (default), BLAKE3, and Poseidon
  - `blake3` feature flag for high-performance hashing
  - `poseidon` feature flag for ZK-friendly algebraic hashing
- **Batch proofs**: Efficient multi-leaf proof generation and verification with shared sibling hashes
- **`PartialEq` and `Eq`** implementations for `MerkleTreeAccumulator`
- **Proof validation** on deserialization to catch malformed data
- Examples: `hello_world.rs` and `hasher_comparison.rs`
- CI workflows, contribution guidelines, and issue templates

### Changed

- **Complete rewrite** using `rs-merkle` for core Merkle tree operations
- **Simplified API**: `Hash::from_data()` for leaf creation, generic hasher via `MerkleTreeAccumulator<H>`
- **Consolidated hash module**: All hashers now in single `hash.rs` file
- **Rust 2024 edition** with MSRV 1.85
- **Improved Poseidon performance**: Constants cached with `LazyLock`
- **Fixed Poseidon entropy**: `bytes_to_scalar` now preserves all 256 bits instead of truncating to 248

### Removed

- Blockchain-specific dependencies (Parity RLP, NEAR Borsh)
- Witness caching (simplified accumulator semantics)
- Redundant `height` field (now derived from leaf count)
- `HashData` trait (replaced with direct `Hash::new(H::hash(data))` pattern)

## [0.2.0] - Previous Release

Initial public release with basic Merkle tree accumulator functionality.
