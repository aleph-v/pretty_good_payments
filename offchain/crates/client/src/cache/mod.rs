//! Local proof cache for storing merkle tree roots.
//!
//! The cache stores roots and computes merkle paths dynamically.

pub mod proof_cache;

pub use proof_cache::{CachedBlockRoots, ProofCache, SyncPoint};
