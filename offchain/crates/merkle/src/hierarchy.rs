//! Hierarchical merkle tree types for the four-level PGP tree structure.
//!
//! The merkle tree has four distinct levels:
//!
//! ```text
//! Level 1: Day Tree (15 bits)
//!          - 2^15 = 32,768 days (~89 years)
//!          - Each leaf is a day subtree root
//!          - Root of this tree is the global anchor
//!          |
//!          v
//! Level 2: Block-in-Day Tree (13 bits)
//!          - 2^13 = 8,192 blocks per day
//!          - Each leaf is a block root
//!          - Subtree root becomes leaf in day tree
//!          |
//!          v
//! Level 3: Block Tree (16 bits)
//!          - 2^16 = 65,536 leaves per block
//!          - Each leaf is a note commitment
//!          - Block root becomes leaf in block-in-day tree
//!          |
//!          v
//! Level 4: Leaves (note commitments)
//!          - Poseidon(asset, amount, blinding, publicKey)
//!
//! Total: 44 bits = 15 (days) + 13 (blocks/day) + 16 (leaves/block)
//! ```

use crate::poseidon::poseidon2;
use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

/// Depth of the day tree (15 levels, supports ~89 years)
pub const DAY_TREE_DEPTH: usize = 15;

/// Depth of the block-in-day tree (13 levels, 8192 blocks per day)
pub const BLOCK_IN_DAY_DEPTH: usize = 13;

/// Depth of the block tree (16 levels, 65536 leaves per block)
pub const BLOCK_TREE_DEPTH: usize = 16;

/// Total tree depth (44 levels)
pub const TOTAL_DEPTH: usize = DAY_TREE_DEPTH + BLOCK_IN_DAY_DEPTH + BLOCK_TREE_DEPTH;

/// Number of blocks per day (2^13 = 8192)
pub const BLOCKS_PER_DAY: u64 = 1 << BLOCK_IN_DAY_DEPTH;

/// Maximum days supported (2^15 = 32768)
pub const MAX_DAYS: u64 = 1 << DAY_TREE_DEPTH;

/// Maximum leaves per block (2^16 = 65536)
pub const MAX_LEAVES_PER_BLOCK: u64 = 1 << BLOCK_TREE_DEPTH;

/// Position in the 4-level hierarchy.
///
/// Uniquely identifies a leaf in the full 44-level tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TreePosition {
    /// Day index (15 bits, 0..32768)
    pub day: u16,
    /// Block index within the day (13 bits, 0..8192)
    pub block_in_day: u16,
    /// Leaf index within the block (16 bits, 0..65536)
    pub leaf_in_block: u16,
}

impl TreePosition {
    /// Create a new tree position.
    ///
    /// # Panics
    /// Panics if any component is out of range.
    pub fn new(day: u16, block_in_day: u16, leaf_in_block: u16) -> Self {
        assert!(
            (day as u64) < MAX_DAYS,
            "day {} exceeds max {}",
            day,
            MAX_DAYS - 1
        );
        assert!(
            (block_in_day as u64) < BLOCKS_PER_DAY,
            "block_in_day {} exceeds max {}",
            block_in_day,
            BLOCKS_PER_DAY - 1
        );
        assert!(
            (leaf_in_block as u64) < MAX_LEAVES_PER_BLOCK,
            "leaf_in_block {} exceeds max {}",
            leaf_in_block,
            MAX_LEAVES_PER_BLOCK - 1
        );
        Self {
            day,
            block_in_day,
            leaf_in_block,
        }
    }

    /// Create from a flat 44-bit leaf index.
    ///
    /// The index is decomposed as:
    /// - Bits 43:29 = day (15 bits)
    /// - Bits 28:16 = block_in_day (13 bits)
    /// - Bits 15:0 = leaf_in_block (16 bits)
    pub fn from_flat_index(index: u64) -> Self {
        let leaf_in_block = (index & 0xFFFF) as u16;
        let block_in_day = ((index >> 16) & 0x1FFF) as u16;
        let day = ((index >> 29) & 0x7FFF) as u16;
        Self {
            day,
            block_in_day,
            leaf_in_block,
        }
    }

    /// Convert to a flat 44-bit leaf index.
    pub fn to_flat_index(&self) -> u64 {
        ((self.day as u64) << 29) | ((self.block_in_day as u64) << 16) | (self.leaf_in_block as u64)
    }

    /// Get the tree index for the root tree (28 levels).
    ///
    /// This is the position of the block root in the combined day+block-in-day tree.
    /// tree_index = day * 8192 + block_in_day
    pub fn root_tree_index(&self) -> u64 {
        (self.day as u64) * BLOCKS_PER_DAY + (self.block_in_day as u64)
    }

    /// Create from block number and leaf index.
    ///
    /// Block number is global, leaf index is within the block.
    pub fn from_block_nr_and_leaf(block_nr: u64, leaf_index: u32, genesis_day: u64) -> Self {
        // Convert block_nr to day and block_in_day
        // This depends on how blocks are assigned to days in the system
        // For now, assume block_nr maps directly to tree_index
        let tree_index = block_nr;
        let day = (tree_index / BLOCKS_PER_DAY + genesis_day) as u16;
        let block_in_day = (tree_index % BLOCKS_PER_DAY) as u16;
        let leaf_in_block = leaf_index as u16;

        Self {
            day,
            block_in_day,
            leaf_in_block,
        }
    }
}

/// Day root (root of the 13-level block-in-day subtree).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DayRoot {
    /// Day index
    pub day: u16,
    /// Root hash of the day's block-in-day subtree
    pub root: B256,
}

/// Block root (root of the 16-level block tree).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRoot {
    /// Day index
    pub day: u16,
    /// Block index within the day
    pub block_in_day: u16,
    /// Root hash of the block tree
    pub root: B256,
}

impl BlockRoot {
    /// Get the tree index for this block in the root tree.
    pub fn tree_index(&self) -> u64 {
        (self.day as u64) * BLOCKS_PER_DAY + (self.block_in_day as u64)
    }
}

/// Hierarchical merkle proof separated by level.
///
/// This structure makes the tree hierarchy explicit, unlike a flat 44-level proof.
/// It allows efficient partial verification and incremental syncing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HierarchicalProof {
    /// Position of the leaf in the tree
    pub position: TreePosition,
    /// The leaf value (note commitment)
    pub leaf: B256,
    /// Block tree siblings (16 levels, from leaf to block root)
    pub block_siblings: [B256; BLOCK_TREE_DEPTH],
    /// Block-in-day tree siblings (13 levels, from block root to day root)
    pub day_siblings: [B256; BLOCK_IN_DAY_DEPTH],
    /// Day tree siblings (15 levels, from day root to global anchor)
    pub global_siblings: [B256; DAY_TREE_DEPTH],
}

impl HierarchicalProof {
    /// Create a new hierarchical proof.
    pub fn new(
        position: TreePosition,
        leaf: B256,
        block_siblings: [B256; BLOCK_TREE_DEPTH],
        day_siblings: [B256; BLOCK_IN_DAY_DEPTH],
        global_siblings: [B256; DAY_TREE_DEPTH],
    ) -> Self {
        Self {
            position,
            leaf,
            block_siblings,
            day_siblings,
            global_siblings,
        }
    }

    /// Create from a flat 44-level proof.
    ///
    /// # Arguments
    /// * `position` - The leaf position
    /// * `leaf` - The leaf value
    /// * `flat_siblings` - All 44 siblings from leaf to root
    pub fn from_flat(
        position: TreePosition,
        leaf: B256,
        flat_siblings: &[B256; TOTAL_DEPTH],
    ) -> Self {
        let mut block_siblings = [B256::ZERO; BLOCK_TREE_DEPTH];
        let mut day_siblings = [B256::ZERO; BLOCK_IN_DAY_DEPTH];
        let mut global_siblings = [B256::ZERO; DAY_TREE_DEPTH];

        // First 16 levels are block tree
        block_siblings.copy_from_slice(&flat_siblings[0..BLOCK_TREE_DEPTH]);

        // Next 13 levels are block-in-day tree
        day_siblings.copy_from_slice(
            &flat_siblings[BLOCK_TREE_DEPTH..BLOCK_TREE_DEPTH + BLOCK_IN_DAY_DEPTH],
        );

        // Last 15 levels are day tree
        global_siblings.copy_from_slice(&flat_siblings[BLOCK_TREE_DEPTH + BLOCK_IN_DAY_DEPTH..]);

        Self {
            position,
            leaf,
            block_siblings,
            day_siblings,
            global_siblings,
        }
    }

    /// Flatten to 44-level circuit format.
    ///
    /// Returns (siblings, flat_index) for use in ZK circuits.
    pub fn to_circuit_format(&self) -> ([B256; TOTAL_DEPTH], u64) {
        let mut siblings = [B256::ZERO; TOTAL_DEPTH];

        // First 16 levels are block tree
        siblings[0..BLOCK_TREE_DEPTH].copy_from_slice(&self.block_siblings);

        // Next 13 levels are block-in-day tree
        siblings[BLOCK_TREE_DEPTH..BLOCK_TREE_DEPTH + BLOCK_IN_DAY_DEPTH]
            .copy_from_slice(&self.day_siblings);

        // Last 15 levels are day tree
        siblings[BLOCK_TREE_DEPTH + BLOCK_IN_DAY_DEPTH..].copy_from_slice(&self.global_siblings);

        (siblings, self.position.to_flat_index())
    }

    /// Compute the block root from the leaf and block siblings.
    pub fn compute_block_root(&self) -> B256 {
        let mut current = self.leaf;
        let mut index = self.position.leaf_in_block as usize;

        for sibling in &self.block_siblings {
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

    /// Compute the day root from the block root and day siblings.
    pub fn compute_day_root(&self) -> B256 {
        let block_root = self.compute_block_root();
        let mut current = block_root;
        let mut index = self.position.block_in_day as usize;

        for sibling in &self.day_siblings {
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

    /// Compute the global anchor from the day root and global siblings.
    pub fn compute_global_root(&self) -> B256 {
        let day_root = self.compute_day_root();
        let mut current = day_root;
        let mut index = self.position.day as usize;

        for sibling in &self.global_siblings {
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

    /// Verify the proof against an expected global root.
    pub fn verify(&self, expected_root: B256) -> bool {
        self.compute_global_root() == expected_root
    }
}

/// Proof components that can be shared between notes in the same block.
///
/// When syncing multiple notes from the same block, only the block tree proof
/// is unique per note. The day and global siblings can be shared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedBlockProof {
    /// Day index
    pub day: u16,
    /// Block index within the day
    pub block_in_day: u16,
    /// Block root
    pub block_root: B256,
    /// Block-in-day tree siblings (13 levels)
    pub day_siblings: [B256; BLOCK_IN_DAY_DEPTH],
    /// Day tree siblings (15 levels)
    pub global_siblings: [B256; DAY_TREE_DEPTH],
}

impl SharedBlockProof {
    /// Compute the day root.
    pub fn compute_day_root(&self) -> B256 {
        let mut current = self.block_root;
        let mut index = self.block_in_day as usize;

        for sibling in &self.day_siblings {
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

    /// Compute the global anchor.
    pub fn compute_global_root(&self) -> B256 {
        let day_root = self.compute_day_root();
        let mut current = day_root;
        let mut index = self.day as usize;

        for sibling in &self.global_siblings {
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
}

/// Leaf-level proof within a block (the unique part per note).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafProof {
    /// Leaf index within the block
    pub leaf_index: u16,
    /// The leaf value
    pub leaf: B256,
    /// Block tree siblings (16 levels)
    pub siblings: [B256; BLOCK_TREE_DEPTH],
}

impl LeafProof {
    /// Compute the block root.
    pub fn compute_block_root(&self) -> B256 {
        let mut current = self.leaf;
        let mut index = self.leaf_index as usize;

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

    /// Combine with a shared block proof to create a full hierarchical proof.
    pub fn with_shared_proof(&self, shared: &SharedBlockProof) -> HierarchicalProof {
        HierarchicalProof {
            position: TreePosition {
                day: shared.day,
                block_in_day: shared.block_in_day,
                leaf_in_block: self.leaf_index,
            },
            leaf: self.leaf,
            block_siblings: self.siblings,
            day_siblings: shared.day_siblings,
            global_siblings: shared.global_siblings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tree_position_new() {
        let pos = TreePosition::new(100, 500, 1000);
        assert_eq!(pos.day, 100);
        assert_eq!(pos.block_in_day, 500);
        assert_eq!(pos.leaf_in_block, 1000);
    }

    #[test]
    fn test_tree_position_flat_index_roundtrip() {
        let pos = TreePosition::new(100, 500, 1000);
        let flat = pos.to_flat_index();
        let recovered = TreePosition::from_flat_index(flat);
        assert_eq!(pos, recovered);
    }

    #[test]
    fn test_tree_position_root_tree_index() {
        let pos = TreePosition::new(1, 100, 0);
        // tree_index = day * 8192 + block_in_day = 1 * 8192 + 100 = 8292
        assert_eq!(pos.root_tree_index(), 8292);
    }

    #[test]
    fn test_tree_position_max_values() {
        // Test with maximum valid values
        let pos = TreePosition::new(
            (MAX_DAYS - 1) as u16,
            (BLOCKS_PER_DAY - 1) as u16,
            (MAX_LEAVES_PER_BLOCK - 1) as u16,
        );
        let flat = pos.to_flat_index();
        let recovered = TreePosition::from_flat_index(flat);
        assert_eq!(pos, recovered);
    }

    #[test]
    fn test_hierarchical_proof_compute_block_root() {
        // Simple test with zero siblings (empty tree)
        let proof = HierarchicalProof {
            position: TreePosition::new(0, 0, 0),
            leaf: B256::repeat_byte(0x11),
            block_siblings: [B256::ZERO; BLOCK_TREE_DEPTH],
            day_siblings: [B256::ZERO; BLOCK_IN_DAY_DEPTH],
            global_siblings: [B256::ZERO; DAY_TREE_DEPTH],
        };

        let block_root = proof.compute_block_root();
        // Should hash leaf up through 16 levels of zero siblings
        assert_ne!(block_root, B256::ZERO);
    }

    #[test]
    fn test_hierarchical_proof_to_circuit_format() {
        let mut block_siblings = [B256::ZERO; BLOCK_TREE_DEPTH];
        block_siblings[0] = B256::repeat_byte(0x01);

        let mut day_siblings = [B256::ZERO; BLOCK_IN_DAY_DEPTH];
        day_siblings[0] = B256::repeat_byte(0x02);

        let mut global_siblings = [B256::ZERO; DAY_TREE_DEPTH];
        global_siblings[0] = B256::repeat_byte(0x03);

        let proof = HierarchicalProof {
            position: TreePosition::new(1, 2, 3),
            leaf: B256::repeat_byte(0x11),
            block_siblings,
            day_siblings,
            global_siblings,
        };

        let (flat_siblings, flat_index) = proof.to_circuit_format();

        // Check siblings are in correct positions
        assert_eq!(flat_siblings[0], B256::repeat_byte(0x01)); // First block sibling
        assert_eq!(flat_siblings[BLOCK_TREE_DEPTH], B256::repeat_byte(0x02)); // First day sibling
        assert_eq!(
            flat_siblings[BLOCK_TREE_DEPTH + BLOCK_IN_DAY_DEPTH],
            B256::repeat_byte(0x03)
        ); // First global sibling

        // Check flat index
        let expected_flat = (1u64 << 29) | (2u64 << 16) | 3u64;
        assert_eq!(flat_index, expected_flat);
    }

    #[test]
    fn test_hierarchical_proof_from_flat() {
        let mut flat_siblings = [B256::ZERO; TOTAL_DEPTH];
        flat_siblings[0] = B256::repeat_byte(0x01);
        flat_siblings[BLOCK_TREE_DEPTH] = B256::repeat_byte(0x02);
        flat_siblings[BLOCK_TREE_DEPTH + BLOCK_IN_DAY_DEPTH] = B256::repeat_byte(0x03);

        let position = TreePosition::new(1, 2, 3);
        let leaf = B256::repeat_byte(0x11);

        let proof = HierarchicalProof::from_flat(position, leaf, &flat_siblings);

        assert_eq!(proof.block_siblings[0], B256::repeat_byte(0x01));
        assert_eq!(proof.day_siblings[0], B256::repeat_byte(0x02));
        assert_eq!(proof.global_siblings[0], B256::repeat_byte(0x03));
    }

    #[test]
    fn test_leaf_proof_with_shared_proof() {
        let leaf_proof = LeafProof {
            leaf_index: 42,
            leaf: B256::repeat_byte(0x11),
            siblings: [B256::ZERO; BLOCK_TREE_DEPTH],
        };

        let shared = SharedBlockProof {
            day: 1,
            block_in_day: 2,
            block_root: B256::repeat_byte(0x22),
            day_siblings: [B256::ZERO; BLOCK_IN_DAY_DEPTH],
            global_siblings: [B256::ZERO; DAY_TREE_DEPTH],
        };

        let full_proof = leaf_proof.with_shared_proof(&shared);

        assert_eq!(full_proof.position.day, 1);
        assert_eq!(full_proof.position.block_in_day, 2);
        assert_eq!(full_proof.position.leaf_in_block, 42);
        assert_eq!(full_proof.leaf, leaf_proof.leaf);
    }

    #[test]
    fn test_block_root_tree_index() {
        let root = BlockRoot {
            day: 10,
            block_in_day: 100,
            root: B256::ZERO,
        };
        // tree_index = 10 * 8192 + 100 = 82020
        assert_eq!(root.tree_index(), 82020);
    }
}
