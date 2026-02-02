//! Poseidon merkle tree implementation compatible with circomlib.
//!
//! This crate provides:
//! - Poseidon hash functions (2, 3, 4 inputs) matching circomlib constants
//! - Incremental merkle tree with efficient updates
//! - Zero-hash precomputation for sparse trees
//! - Hierarchical tree types for 4-level structure

pub mod hierarchy;
pub mod poseidon;
pub mod tree;

#[cfg(test)]
mod test_vectors;

pub use hierarchy::*;
pub use poseidon::*;
pub use tree::*;
