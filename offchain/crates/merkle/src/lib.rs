//! Poseidon merkle tree implementation compatible with circomlib.
//!
//! This crate provides:
//! - Poseidon hash functions (2, 3, 4 inputs) matching circomlib constants
//! - Incremental merkle tree with efficient updates
//! - Zero-hash precomputation for sparse trees

pub mod poseidon;
pub mod tree;

#[cfg(test)]
mod test_vectors;

pub use poseidon::*;
pub use tree::*;
