//! Basic usage example demonstrating core accumulator operations.
//!
//! Run with: cargo run --example hello_world

use merkle_tree_accumulator::{Hash, Sha3Accumulator};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Merkle Tree Accumulator ===\n");

    let mut acc = Sha3Accumulator::new();

    let data_items: Vec<&[u8]> = vec![
        b"Alice's transaction",
        b"Bob's transaction",
        b"Charlie's transaction",
        b"Dave's transaction",
    ];

    println!("Adding {} items:", data_items.len());
    for (i, data) in data_items.iter().enumerate() {
        let hash = Hash::from_data(data);
        acc.add(hash)?;
        println!("  [{}] {} -> {}", i, String::from_utf8_lossy(data), hash);
    }

    println!("\nHeight: {}", acc.height());
    println!("Root: {}\n", acc.root()?);

    let alice_hash = Hash::from_data(b"Alice's transaction");
    let proof = acc.prove(&[0])?;
    println!("Proof for index 0: {} hashes", proof.hashes.len());

    match acc.verify(&proof, &[alice_hash]) {
        Ok(()) => println!("Verification: PASS"),
        Err(e) => println!("Verification: FAIL ({e})"),
    }

    let wrong_hash = Hash::from_data(b"Eve's fraudulent transaction");
    match acc.verify(&proof, &[wrong_hash]) {
        Ok(()) => println!("This should not happen!"),
        Err(_) => println!("Invalid proof correctly rejected"),
    }

    println!("\n=== Batch Proof ===");
    let batch_proof = acc.prove(&[0, 2])?;
    let batch_leaves = vec![
        Hash::from_data(b"Alice's transaction"),
        Hash::from_data(b"Charlie's transaction"),
    ];
    println!(
        "Batch proof for [0, 2]: {} hashes",
        batch_proof.hashes.len()
    );

    match acc.verify(&batch_proof, &batch_leaves) {
        Ok(()) => println!("Batch verification: PASS"),
        Err(e) => println!("Batch verification: FAIL ({e})"),
    }

    Ok(())
}
