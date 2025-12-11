# Merkle Tree Accumulator

[![Crates.io](https://img.shields.io/crates/v/merkle-tree-accumulator.svg)](https://crates.io/crates/merkle-tree-accumulator)
[![Documentation](https://docs.rs/merkle-tree-accumulator/badge.svg)](https://docs.rs/merkle-tree-accumulator)
[![CI](https://github.com/kobby-pentangeli/merkle-tree-accumulator/workflows/CI/badge.svg)](https://github.com/kobby-pentangeli/merkle-tree-accumulator/actions)
[![License](https://img.shields.io/crates/l/merkle-tree-accumulator.svg)](https://github.com/kobby-pentangeli/merkle-tree-accumulator#license)

A simple, append-only Merkle tree-based cryptographic accumulator.

## Features

- ✅ **Multiple hashers**: Support for SHA-3, BLAKE3, and Poseidon hash functions
- ✅ **Height tracking**: Accumulator maintains height for proof verification
- ✅ **Chain-agnostic**: No blockchain-specific dependencies
- ✅ **Batch operations**: Optimized batch proof generation and verification
- ✅ **no-std/WASM compatible**: Works in constrained environments

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
merkle-tree-accumulator = "0.3"
```

### Basic Usage

```rust
use merkle_tree_accumulator::{Hash, Sha3Accumulator};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a new accumulator
    let mut acc = Sha3Accumulator::new();

    // Add some data
    let data = b"Hello, World!";
    let hash = Hash::from_data(data);
    acc.add(hash)?;

    // Generate a proof of membership
    let proof = acc.prove(&[0])?;

    // Verify the proof
    acc.verify(&proof, &[hash])?;

    println!("Proof verified!");
    Ok(())
}
```

### Batch Proofs

```rust
use merkle_tree_accumulator::{Hash, Sha3Accumulator};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut acc = Sha3Accumulator::new();

    // Add multiple items
    let items = vec![b"item1", b"item2", b"item3", b"item4"];
    let hashes: Vec<_> = items.iter()
        .map(|data| Hash::from_data(data))
        .collect();

    for hash in &hashes {
        acc.add(*hash)?;
    }

    // Generate a compact batch proof for indices [0, 2]
    let batch_proof = acc.prove(&[0, 2])?;

    // Verify the batch proof
    let batch_leaves = vec![hashes[0], hashes[2]];
    acc.verify(&batch_proof, &batch_leaves)?;

    println!("Batch proof verified!");
    Ok(())
}
```

## Hash Functions

The library supports three hash functions, each optimized for different use cases:

| Hasher                 | Domain              | Performance            | Use Case                                              |
| ---------------------- | ------------------- | ---------------------- | ----------------------------------------------------- |
| **SHA3-256** (default) | General Purpose     | Standard               | Compliance, broad compatibility, NIST standardized    |
| **BLAKE3**             | High Performance    | Faster than SHA3       | Blockchains, distributed systems, throughput-critical |
| **Poseidon**           | Arithmetic Circuits | Optimized for circuits | ZK proofs, field arithmetic operations                |

### Using BLAKE3

Enable the `blake3` feature:

```toml
[dependencies]
merkle-tree-accumulator = { version = "0.3", features = ["blake3"] }
```

```rust
use merkle_tree_accumulator::{Hash, Blake3Accumulator};

let mut acc = Blake3Accumulator::new();
acc.add(Hash::from_data(b"high-performance data"))?;
```

### Using Poseidon

Enable the `poseidon` feature:

```toml
[dependencies]
merkle-tree-accumulator = { version = "0.3", features = ["poseidon"] }
```

```rust
use merkle_tree_accumulator::{Hash, PoseidonAccumulator};

let mut acc = PoseidonAccumulator::new();
acc.add(Hash::from_data(b"zk-friendly data"))?;
```

## Examples

- **[hello_world.rs](examples/hello_world.rs)**: Core accumulator operations
- **[hasher_comparison.rs](examples/hasher_comparison.rs)**: Comparing different hash functions

Run examples with:

```bash
cargo run --example hello_world
cargo run --example hasher_comparison --all-features
```

## Feature Flags

- `std` (default): Enable standard library support
- `blake3`: Enable BLAKE3 hasher for high-performance applications
- `poseidon`: Enable Poseidon hasher for algebraic hash operations

## no-std Support

The library works in `no_std` environments:

```toml
[dependencies]
merkle-tree-accumulator = { version = "0.3", default-features = false }
```
