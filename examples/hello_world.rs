//! Basic usage example demonstrating core accumulator operations.
//!
//! This example shows how to:
//! - Create a new accumulator
//! - Add elements to it
//! - Generate proofs of membership
//! - Verify proofs
//!
//! Run with: cargo run --example hello_world

use merkle_tree_accumulator::{Hash, Sha3Accumulator};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Merkle Tree Accumulator: Hello World Example ===\n");

    // Create a new accumulator using SHA3-256 (default)
    let mut acc = Sha3Accumulator::new();
    println!("Created new accumulator");
    println!("Initial height: {}\n", acc.height());

    let data_items: Vec<&[u8]> = vec![
        b"Alice's transaction",
        b"Bob's transaction",
        b"Charlie's transaction",
        b"Dave's transaction",
    ];

    println!("Adding {} items to the accumulator:", data_items.len());
    for (i, data) in data_items.iter().enumerate() {
        let hash = Hash::from_data(data);
        acc.add(hash)?;
        println!("  [{}] Added: {} bytes -> {}", i, data.len(), hash);
    }

    println!("\nAccumulator height: {}", acc.height());
    println!("Accumulator root: {}\n", acc.root()?);

    println!("=== Proof Generation ===");
    let alice_hash = Hash::from_data(b"Alice's transaction");
    let proof = acc.prove(&[0])?;

    println!("Generated proof for index 0");
    println!("  Proof indices: {:?}", proof.indices);
    println!("  Proof hashes: {}", proof.hashes.len());
    println!("  Proof height: {}\n", proof.height);

    println!("=== Proof Verification ===");
    match acc.verify(&proof, &[alice_hash]) {
        Ok(()) => println!("Proof verified successfully!"),
        Err(e) => println!("Proof verification failed: {e}"),
    }

    println!("\nTrying to verify with incorrect data:");
    let wrong_hash = Hash::from_data(b"Eve's fraudulent transaction");
    match acc.verify(&proof, &[wrong_hash]) {
        Ok(()) => println!("This should not happen!"),
        Err(e) => println!("Correctly rejected invalid proof: {e}"),
    }

    println!("\n=== Batch Proof ===");
    let batch_proof = acc.prove(&[0, 2])?;
    let batch_leaves = vec![
        Hash::from_data(b"Alice's transaction"),
        Hash::from_data(b"Charlie's transaction"),
    ];

    println!("Generated batch proof for indices [0, 2]");
    println!("  Batch proof hashes: {}", batch_proof.hashes.len());

    match acc.verify(&batch_proof, &batch_leaves) {
        Ok(()) => println!("Batch proof verified successfully!"),
        Err(e) => println!("Batch proof verification failed: {e}"),
    }

    Ok(())
}
