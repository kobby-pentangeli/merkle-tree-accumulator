//! Comparing different hash functions.
//!
//! This example demonstrates how to use different hash functions
//! (SHA3-256, BLAKE3, Poseidon) with the same accumulator API.
//!
//! Run with: cargo run --example hasher_comparison --all-features

#[cfg(feature = "blake3")]
use merkle_tree_accumulator::Blake3H;
#[cfg(feature = "poseidon")]
use merkle_tree_accumulator::PoseidonH;
use merkle_tree_accumulator::{Hash, MerkleTreeAccumulator, Sha3H};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Merkle Tree Accumulator: Hasher Comparison ===\n");

    let test_data: Vec<&[u8]> = vec![
        b"Transaction 1",
        b"Transaction 2",
        b"Transaction 3",
        b"Transaction 4",
        b"Transaction 5",
    ];

    println!("=== SHA3-256 Hasher (Default) ===");
    let mut sha3_acc = MerkleTreeAccumulator::<Sha3H>::new();

    for data in &test_data {
        let hash = Hash::from_data(data);
        sha3_acc.add(hash)?;
    }

    let sha3_root = sha3_acc.root()?;
    let sha3_proof = sha3_acc.prove(&[0, 2, 4])?;

    println!("Added {} items", sha3_acc.height());
    println!("Root: {}", sha3_root);
    println!("Batch proof size: {} hashes\n", sha3_proof.hashes.len());

    #[cfg(feature = "blake3")]
    {
        println!("=== BLAKE3 Hasher ===");
        let mut blake3_acc = MerkleTreeAccumulator::<Blake3H>::new();

        for data in &test_data {
            let hash = Hash::from_data(data);
            blake3_acc.add(hash)?;
        }

        let blake3_root = blake3_acc.root()?;
        let blake3_proof = blake3_acc.prove(&[0, 2, 4])?;

        println!("Added {} items", blake3_acc.height());
        println!("Root: {}", blake3_root);
        println!("Batch proof size: {} hashes", blake3_proof.hashes.len());

        if sha3_root == blake3_root {
            println!("Unexpected: Roots should differ with different hash functions");
        } else {
            println!("Roots differ as expected (different hash functions)");
        }
        println!();
    }

    #[cfg(not(feature = "blake3"))]
    {
        println!("=== BLAKE3 Hasher ===");
        println!("Not available (enable with --features blake3)\n");
    }

    #[cfg(feature = "poseidon")]
    {
        println!("=== Poseidon Hasher ===");
        let mut poseidon_acc = MerkleTreeAccumulator::<PoseidonH>::new();

        for data in &test_data {
            let hash = Hash::from_data(data);
            poseidon_acc.add(hash)?;
        }

        let poseidon_root = poseidon_acc.root()?;
        let poseidon_proof = poseidon_acc.prove(&[0, 2, 4])?;

        println!("Added {} items", poseidon_acc.height());
        println!("Root: {}", poseidon_root);
        println!("Batch proof size: {} hashes", poseidon_proof.hashes.len());

        if sha3_root == poseidon_root {
            println!("Unexpected: Roots should differ with different hash functions");
        } else {
            println!("Roots differ as expected (different hash functions)");
        }
        println!();
    }

    #[cfg(not(feature = "poseidon"))]
    {
        println!("=== Poseidon Hasher ===");
        println!("Not available (enable with --features poseidon)\n");
    }

    Ok(())
}
