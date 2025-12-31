//! Comparing different hash functions.
//!
//! Run with: cargo run --example hasher_comparison --all-features

#[cfg(feature = "blake3")]
use merkle_tree_accumulator::Blake3H;
#[cfg(feature = "poseidon")]
use merkle_tree_accumulator::PoseidonH;
use merkle_tree_accumulator::{Hash, MerkleTreeAccumulator, Sha3H};
#[cfg(any(feature = "blake3", feature = "poseidon"))]
use rs_merkle::Hasher;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Hasher Comparison ===\n");

    let test_data: Vec<&[u8]> = vec![
        b"Transaction 1",
        b"Transaction 2",
        b"Transaction 3",
        b"Transaction 4",
        b"Transaction 5",
    ];

    println!("SHA3-256:");
    let mut sha3_acc = MerkleTreeAccumulator::<Sha3H>::new();
    for data in &test_data {
        sha3_acc.add(Hash::from_data(data))?;
    }
    let sha3_root = sha3_acc.root()?;
    println!("  Root: {}\n", sha3_root);

    #[cfg(feature = "blake3")]
    {
        println!("BLAKE3:");
        let mut blake3_acc = MerkleTreeAccumulator::<Blake3H>::new();
        for data in &test_data {
            blake3_acc.add(Hash::new(Blake3H::hash(data)))?;
        }
        let blake3_root = blake3_acc.root()?;
        println!("  Root: {}", blake3_root);
        println!("  Differs from SHA3: {}\n", sha3_root != blake3_root);
    }

    #[cfg(not(feature = "blake3"))]
    println!("BLAKE3: not available (--features blake3)\n");

    #[cfg(feature = "poseidon")]
    {
        println!("Poseidon:");
        let mut poseidon_acc = MerkleTreeAccumulator::<PoseidonH>::new();
        for data in &test_data {
            poseidon_acc.add(Hash::new(PoseidonH::hash(data)))?;
        }
        let poseidon_root = poseidon_acc.root()?;
        println!("  Root: {}", poseidon_root);
        println!("  Differs from SHA3: {}\n", sha3_root != poseidon_root);
    }

    #[cfg(not(feature = "poseidon"))]
    println!("Poseidon: not available (--features poseidon)\n");

    Ok(())
}
