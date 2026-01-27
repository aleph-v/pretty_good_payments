//! Incremental Poseidon merkle tree implementation.
//!
//! Supports:
//! - Efficient incremental updates
//! - Sparse tree representation with precomputed zero hashes
//! - Proof generation and verification

use crate::poseidon::poseidon2;
use alloy_primitives::B256;
use thiserror::Error;

/// Errors that can occur during merkle tree operations
#[derive(Debug, Error)]
pub enum MerkleError {
    #[error("Tree is full (max leaves: {0})")]
    TreeFull(usize),

    #[error("Index {0} out of bounds (max: {1})")]
    IndexOutOfBounds(usize, usize),

    #[error("Invalid proof length: expected {expected}, got {actual}")]
    InvalidProofLength { expected: usize, actual: usize },

    #[error("Proof verification failed")]
    VerificationFailed,
}

/// Precompute zero hashes for a tree of given depth
/// zero_hashes[i] = hash of two children that are both zero_hashes[i-1]
/// zero_hashes[0] = 0 (the leaf value)
pub fn compute_zero_hashes(depth: usize) -> Vec<B256> {
    let mut zero_hashes = Vec::with_capacity(depth + 1);
    zero_hashes.push(B256::ZERO);

    for i in 1..=depth {
        let prev = zero_hashes[i - 1];
        zero_hashes.push(poseidon2(prev, prev));
    }

    zero_hashes
}

/// A sparse incremental Poseidon merkle tree
#[derive(Debug, Clone)]
pub struct IncrementalMerkleTree {
    /// Tree depth
    depth: usize,
    /// Precomputed zero hashes for each level
    zero_hashes: Vec<B256>,
    /// Non-zero nodes stored by level and index
    /// Level 0 = leaves, Level depth = root
    nodes: Vec<std::collections::HashMap<usize, B256>>,
    /// Next leaf index to insert at
    next_index: usize,
}

impl IncrementalMerkleTree {
    /// Create a new empty merkle tree with the given depth
    pub fn new(depth: usize) -> Self {
        let zero_hashes = compute_zero_hashes(depth);
        let nodes = (0..=depth)
            .map(|_| std::collections::HashMap::new())
            .collect();

        Self {
            depth,
            zero_hashes,
            nodes,
            next_index: 0,
        }
    }

    /// Get the tree depth
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Get the current root of the tree
    pub fn root(&self) -> B256 {
        self.get_node(self.depth, 0)
    }

    /// Get the number of leaves inserted
    pub fn size(&self) -> usize {
        self.next_index
    }

    /// Get the maximum number of leaves
    pub fn capacity(&self) -> usize {
        1 << self.depth
    }

    /// Check if the tree is full
    pub fn is_full(&self) -> bool {
        self.next_index >= self.capacity()
    }

    /// Get a node at a specific level and index
    pub fn get_node(&self, level: usize, index: usize) -> B256 {
        self.nodes
            .get(level)
            .and_then(|level_nodes| level_nodes.get(&index))
            .copied()
            .unwrap_or_else(|| self.zero_hashes[level])
    }

    /// Set a node at a specific level and index
    fn set_node(&mut self, level: usize, index: usize, value: B256) {
        if value == self.zero_hashes[level] {
            // Don't store zero hashes explicitly
            self.nodes[level].remove(&index);
        } else {
            self.nodes[level].insert(index, value);
        }
    }

    /// Insert a leaf and return the new root
    pub fn insert(&mut self, leaf: B256) -> Result<B256, MerkleError> {
        if self.is_full() {
            return Err(MerkleError::TreeFull(self.capacity()));
        }

        let index = self.next_index;
        self.set_leaf(index, leaf);
        self.next_index += 1;

        Ok(self.root())
    }

    /// Set a leaf at a specific index and update all parent nodes
    pub fn set_leaf(&mut self, index: usize, value: B256) {
        let mut current_index = index;
        let mut current_value = value;

        // Set the leaf
        self.set_node(0, index, value);

        // Update all parents up to the root
        for level in 0..self.depth {
            let parent_index = current_index / 2;
            let is_left = current_index % 2 == 0;
            let sibling_index = if is_left {
                current_index + 1
            } else {
                current_index - 1
            };
            let sibling = self.get_node(level, sibling_index);

            let parent_value = if is_left {
                poseidon2(current_value, sibling)
            } else {
                poseidon2(sibling, current_value)
            };

            self.set_node(level + 1, parent_index, parent_value);
            current_value = parent_value;
            current_index = parent_index;
        }
    }

    /// Get the merkle proof for a leaf at the given index
    pub fn get_proof(&self, index: usize) -> Result<MerkleProof, MerkleError> {
        if index >= self.capacity() {
            return Err(MerkleError::IndexOutOfBounds(index, self.capacity()));
        }

        let mut siblings = Vec::with_capacity(self.depth);
        let mut current_index = index;

        for level in 0..self.depth {
            let sibling_index = current_index ^ 1; // Toggle last bit
            siblings.push(self.get_node(level, sibling_index));
            current_index /= 2;
        }

        Ok(MerkleProof {
            leaf_index: index,
            siblings,
        })
    }

    /// Verify a merkle proof
    pub fn verify_proof(&self, leaf: B256, proof: &MerkleProof) -> bool {
        let computed_root = proof.compute_root(leaf);
        computed_root == self.root()
    }

    /// Compute the root that would result from inserting a leaf at the given index
    pub fn compute_root_with_leaf(&self, index: usize, leaf: B256) -> Result<B256, MerkleError> {
        let proof = self.get_proof(index)?;
        Ok(proof.compute_root(leaf))
    }
}

/// A merkle proof for a specific leaf
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    /// Index of the leaf in the tree
    pub leaf_index: usize,
    /// Sibling nodes from leaf to root
    pub siblings: Vec<B256>,
}

impl MerkleProof {
    /// Compute the root from this proof and a leaf value
    pub fn compute_root(&self, leaf: B256) -> B256 {
        let mut current = leaf;
        let mut index = self.leaf_index;

        for sibling in &self.siblings {
            let is_left = index % 2 == 0;
            current = if is_left {
                poseidon2(current, *sibling)
            } else {
                poseidon2(*sibling, current)
            };
            index /= 2;
        }

        current
    }

    /// Get the depth of this proof
    pub fn depth(&self) -> usize {
        self.siblings.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_hashes() {
        let hashes = compute_zero_hashes(4);
        assert_eq!(hashes.len(), 5);
        assert_eq!(hashes[0], B256::ZERO);

        // Each level should be hash of two copies of previous level
        for i in 1..hashes.len() {
            let expected = poseidon2(hashes[i - 1], hashes[i - 1]);
            assert_eq!(hashes[i], expected);
        }
    }

    #[test]
    fn test_empty_tree_root() {
        let tree = IncrementalMerkleTree::new(4);
        let zero_hashes = compute_zero_hashes(4);

        // Empty tree root should be the zero hash at depth
        assert_eq!(tree.root(), zero_hashes[4]);
    }

    #[test]
    fn test_insert_single_leaf() {
        let mut tree = IncrementalMerkleTree::new(4);
        let leaf = B256::from([1u8; 32]);

        let root1 = tree.insert(leaf).unwrap();
        let root2 = tree.root();

        assert_eq!(root1, root2);
        assert_ne!(root1, compute_zero_hashes(4)[4]);
    }

    #[test]
    fn test_insert_multiple_leaves() {
        let mut tree = IncrementalMerkleTree::new(4);

        let leaf1 = B256::from([1u8; 32]);
        let leaf2 = B256::from([2u8; 32]);

        let root1 = tree.insert(leaf1).unwrap();
        let root2 = tree.insert(leaf2).unwrap();

        assert_ne!(root1, root2);
        assert_eq!(tree.size(), 2);
    }

    #[test]
    fn test_tree_full() {
        let mut tree = IncrementalMerkleTree::new(2); // Capacity = 4

        for i in 0..4 {
            let leaf = B256::from([i as u8; 32]);
            tree.insert(leaf).unwrap();
        }

        assert!(tree.is_full());

        let result = tree.insert(B256::from([5u8; 32]));
        assert!(matches!(result, Err(MerkleError::TreeFull(4))));
    }

    #[test]
    fn test_proof_generation() {
        let mut tree = IncrementalMerkleTree::new(4);
        let leaf = B256::from([1u8; 32]);

        tree.insert(leaf).unwrap();

        let proof = tree.get_proof(0).unwrap();
        assert_eq!(proof.leaf_index, 0);
        assert_eq!(proof.siblings.len(), 4);
    }

    #[test]
    fn test_proof_verification() {
        let mut tree = IncrementalMerkleTree::new(4);
        let leaf = B256::from([1u8; 32]);

        tree.insert(leaf).unwrap();

        let proof = tree.get_proof(0).unwrap();
        assert!(tree.verify_proof(leaf, &proof));

        // Wrong leaf should fail
        let wrong_leaf = B256::from([2u8; 32]);
        assert!(!tree.verify_proof(wrong_leaf, &proof));
    }

    #[test]
    fn test_compute_root_with_leaf() {
        let mut tree = IncrementalMerkleTree::new(4);
        let leaf = B256::from([1u8; 32]);

        // Compute what root would be without actually inserting
        let expected_root = tree.compute_root_with_leaf(0, leaf).unwrap();

        // Now actually insert and verify
        let actual_root = tree.insert(leaf).unwrap();
        assert_eq!(expected_root, actual_root);
    }

    #[test]
    fn test_set_leaf_updates_correctly() {
        let mut tree = IncrementalMerkleTree::new(4);

        let leaf1 = B256::from([1u8; 32]);
        let leaf2 = B256::from([2u8; 32]);

        tree.set_leaf(0, leaf1);
        let root1 = tree.root();

        tree.set_leaf(0, leaf2);
        let root2 = tree.root();

        assert_ne!(root1, root2);
    }
}
