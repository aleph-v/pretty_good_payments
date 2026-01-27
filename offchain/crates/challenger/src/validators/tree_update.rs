//! Tree update validation.
//!
//! This validator checks that merkle root updates after deposit groups and
//! transactions are computed correctly. Each update inserts 3 leaves and
//! produces a new root.

use alloy::primitives::B256;
use pgp_merkle::{poseidon2, IncrementalMerkleTree};
use tracing::{debug, warn};

use crate::validators::{FraudEvidence, TreeUpdateMerkleData};
use pgp_common::blob::ParsedBlock;
use pgp_common::contracts::BlockData;
use pgp_common::types::constants::{BLOCK_DEPTH, ROOT_DEPTH};

/// Tree update validator for merkle root correctness
pub struct TreeUpdateValidator {
    // Uses pgp_merkle for root computation
}

impl TreeUpdateValidator {
    /// Create a new tree update validator
    pub fn new() -> Self {
        Self {}
    }

    /// Validate all tree updates in a block
    ///
    /// This checks that each deposit group and transaction produces the correct
    /// new merkle root when applying their 3 leaves.
    ///
    /// # Arguments
    /// * `block_data` - The block's metadata including initial anchor
    /// * `block` - Parsed block with deposit groups and transactions
    /// * `prior_anchor` - The anchor before this block (from previous block or genesis)
    /// * `prior_block_nr` - Block number of the prior anchor (None if genesis)
    /// * `block_index` - The block's position in the root tree
    /// * `start_in_block_index` - Starting leaf index within the block tree
    /// * `root_path` - Sibling hashes for the block's position in the root tree (28 levels)
    ///
    /// # Returns
    /// Tuple of (fraud_evidence, final_block_tree_root)
    /// - fraud_evidence: Vector of fraud evidence for any incorrect tree updates
    /// - final_block_tree_root: The root of the 12-level block tree after all updates
    ///   (needed for root tree tracking - this is what gets inserted as a leaf in the root tree)
    pub fn validate_block(
        &self,
        block_data: &BlockData,
        block: &ParsedBlock,
        prior_anchor: B256,
        prior_block_nr: Option<u64>,
        block_index: u64,
        start_in_block_index: usize,
        root_path: &[B256],
    ) -> (Vec<FraudEvidence>, B256) {
        let mut fraud = Vec::new();
        let mut in_block_index = start_in_block_index;
        let mut update_nr: u64 = 0;

        // Track the current anchor as we process updates
        let mut current_anchor = prior_anchor;
        // Track where the prior anchor came from
        let mut current_prior_block_nr = prior_block_nr;
        let mut current_prior_update_nr: Option<u64> = None;

        // Initialize a tree tracker for computing expected roots
        let mut tree = BlockTreeTracker::new(block_index as usize, root_path);

        debug!(
            "Validating tree updates for block {}: {} deposit groups, {} transactions",
            block_data.blockNr,
            block.deposit_groups.len(),
            block.transactions.len()
        );

        // Validate deposit group updates
        for (group_idx, group) in block.deposit_groups.iter().enumerate() {
            let leaves = [group.leaf0, group.leaf1, group.leaf2];
            let submitted_root = group.new_root;

            // Capture merkle data BEFORE applying update (needed for ZK proof if fraud detected)
            let merkle_data = tree.get_merkle_data_before_update(in_block_index, leaves);

            // Compute expected root
            let expected_root = tree.apply_update_at(leaves, in_block_index);

            if expected_root != submitted_root {
                warn!(
                    "Incorrect tree update at deposit group {}: expected {:?}, got {:?}",
                    group_idx, expected_root, submitted_root
                );
                fraud.push(FraudEvidence::IncorrectTreeUpdate {
                    block_data: block_data.clone(),
                    update_nr,
                    is_tx: false,
                    expected_anchor: expected_root,
                    submitted_anchor: submitted_root,
                    prior_anchor: current_anchor,
                    leaves,
                    prior_anchor_block_nr: current_prior_block_nr,
                    prior_update_nr: current_prior_update_nr,
                    merkle_data: Some(merkle_data),
                });
            }

            // Update tracking state for next update
            current_anchor = submitted_root;
            current_prior_block_nr = None; // Now from this block
            current_prior_update_nr = Some(update_nr);
            in_block_index += 3;
            update_nr += 1;
        }

        // Validate transaction updates
        let num_transactions = block.transactions.len();
        for (tx_idx, tx) in block.transactions.iter().enumerate() {
            let leaves = [tx.leaf0, tx.leaf1, tx.leaf2];
            let submitted_root = tx.new_root;

            // Capture merkle data BEFORE applying update (needed for ZK proof if fraud detected)
            let merkle_data = tree.get_merkle_data_before_update(in_block_index, leaves);

            // Compute expected root
            let expected_root = tree.apply_update_at(leaves, in_block_index);

            if expected_root != submitted_root {
                warn!(
                    "Incorrect tree update at tx {}: expected {:?}, got {:?}",
                    tx_idx, expected_root, submitted_root
                );
                fraud.push(FraudEvidence::IncorrectTreeUpdate {
                    block_data: block_data.clone(),
                    update_nr,
                    is_tx: true,
                    expected_anchor: expected_root,
                    submitted_anchor: submitted_root,
                    prior_anchor: current_anchor,
                    leaves,
                    prior_anchor_block_nr: current_prior_block_nr,
                    prior_update_nr: current_prior_update_nr,
                    merkle_data: Some(merkle_data),
                });
            }

            // Update tracking state for next update
            current_anchor = submitted_root;
            current_prior_block_nr = None; // Now from this block
            current_prior_update_nr = Some(update_nr);
            in_block_index += 3;
            update_nr += 1;
        }

        // Get the final block tree root (this is what gets inserted into the root tree)
        let final_block_tree_root = tree.block_root();

        // Check for wrong final anchor in BlockData
        // This fraud case is when all blob roots are correct, but the final anchor
        // in BlockData doesn't match the computed true anchor
        // The contract checks: if (isLast && trueAnchor != data.anchor) revert NoFraud()
        let final_expected_anchor = tree.current_anchor();
        if final_expected_anchor != block_data.anchor {
            // Determine which update was the last one
            let num_deposit_groups = block.deposit_groups.len();
            let is_last_tx = num_transactions > 0;
            let last_update_nr = if is_last_tx {
                (num_deposit_groups + num_transactions - 1) as u64
            } else if num_deposit_groups > 0 {
                (num_deposit_groups - 1) as u64
            } else {
                // No updates at all - shouldn't happen, but handle gracefully
                return (fraud, final_block_tree_root);
            };

            // Get leaves from the last update
            let last_leaves = if is_last_tx {
                let tx = &block.transactions[num_transactions - 1];
                [tx.leaf0, tx.leaf1, tx.leaf2]
            } else {
                let group = &block.deposit_groups[num_deposit_groups - 1];
                [group.leaf0, group.leaf1, group.leaf2]
            };

            // For final anchor mismatch, the merkle data is from the last update
            // The in_block_index was already advanced, so subtract 3 to get the correct position
            let last_in_block_index = in_block_index.saturating_sub(3);
            let merkle_data = TreeUpdateMerkleData {
                block_root_before: tree.block_root(),
                block_index: tree.block_index(),
                in_block_index: last_in_block_index,
                nonzero_field: tree.get_nonzero_field(last_in_block_index),
                block_proofs: tree.get_block_proofs_for_update(last_in_block_index, last_leaves),
                root_path: tree.root_path_array(),
            };

            warn!(
                "Incorrect final anchor in BlockData: expected {:?}, got {:?}",
                final_expected_anchor, block_data.anchor
            );
            fraud.push(FraudEvidence::IncorrectTreeUpdate {
                block_data: block_data.clone(),
                update_nr: last_update_nr,
                is_tx: is_last_tx,
                expected_anchor: final_expected_anchor,
                submitted_anchor: block_data.anchor,
                prior_anchor: current_anchor,
                leaves: last_leaves,
                prior_anchor_block_nr: current_prior_block_nr,
                prior_update_nr: current_prior_update_nr,
                merkle_data: Some(merkle_data),
            });
        }

        (fraud, final_block_tree_root)
    }

    /// Compute expected root for a single update
    ///
    /// This is useful for testing individual updates.
    ///
    /// # Arguments
    /// * `prior_anchor` - The anchor before this update
    /// * `leaves` - The 3 leaves being inserted
    /// * `block_index` - The block's position in the root tree
    /// * `in_block_index` - Starting leaf index within the block tree
    /// * `root_path` - Sibling hashes for the block's position in the root tree
    pub fn compute_expected_root(
        _prior_anchor: B256,
        leaves: [B256; 3],
        block_index: usize,
        in_block_index: usize,
        root_path: &[B256],
    ) -> B256 {
        let mut tree = BlockTreeTracker::new(block_index, root_path);
        tree.apply_update_at(leaves, in_block_index)
    }
}

impl Default for TreeUpdateValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Blocks per day in the tree structure (2^13 = 8192)
/// The tree is split such that each day starts in a new subtree.
/// treeIndex = day * BLOCKS_PER_DAY + block_index_in_day
pub const BLOCKS_PER_DAY: u64 = 8192; // 2^13

/// Root tree tracker for maintaining the 28-level tree of block roots
///
/// This tracks the root tree state across blocks, providing:
/// - `tree_index`: The block's position in the root tree (day * 8192 + index_in_day)
/// - `root_path`: The 28 sibling hashes for the block's position
/// - `current_anchor`: The root of the root tree (global anchor)
///
/// Each L2 block inserts its final block root at its treeIndex position.
/// The treeIndex is computed as: day * 8192 + block_index_in_day
pub struct RootTreeTracker {
    /// The root tree (28 levels) storing block roots at sparse positions
    root_tree: IncrementalMerkleTree,
    /// The current anchor (root tree's root)
    current_anchor: B256,
    /// Block roots indexed by treeIndex (for persistence/recovery)
    /// Stored as (treeIndex, block_root) pairs
    block_roots: std::collections::HashMap<u64, B256>,
}

impl RootTreeTracker {
    /// Create a new root tree tracker starting from genesis
    pub fn new() -> Self {
        let root_tree = IncrementalMerkleTree::new(ROOT_DEPTH);
        let current_anchor = root_tree.root();

        Self {
            root_tree,
            current_anchor,
            block_roots: std::collections::HashMap::new(),
        }
    }

    /// Restore root tree state from persisted block roots
    ///
    /// This rebuilds the root tree by inserting block roots at their treeIndex positions.
    /// The input is a vector of (treeIndex, block_root) pairs.
    pub fn from_block_roots(block_roots: &[(u64, B256)]) -> Self {
        let mut root_tree = IncrementalMerkleTree::new(ROOT_DEPTH);
        let mut roots_map = std::collections::HashMap::new();

        for (tree_index, root) in block_roots {
            root_tree.set_leaf(*tree_index as usize, *root);
            roots_map.insert(*tree_index, *root);
        }

        let current_anchor = root_tree.root();

        Self {
            root_tree,
            current_anchor,
            block_roots: roots_map,
        }
    }

    /// Maximum tree index supported by the root tree (2^28 - 1)
    pub const MAX_TREE_INDEX: u64 = (1 << ROOT_DEPTH) - 1;

    /// Compute the tree index from day and block index within day
    ///
    /// treeIndex = day * 8192 + block_index_in_day
    ///
    /// # Panics
    /// Panics if block_index_in_day >= BLOCKS_PER_DAY or if the result exceeds MAX_TREE_INDEX
    pub fn compute_tree_index(day: u64, block_index_in_day: u64) -> u64 {
        assert!(
            block_index_in_day < BLOCKS_PER_DAY,
            "block_index_in_day {block_index_in_day} must be < BLOCKS_PER_DAY {BLOCKS_PER_DAY}"
        );

        let tree_index = day
            .checked_mul(BLOCKS_PER_DAY)
            .and_then(|d| d.checked_add(block_index_in_day))
            .expect("Tree index overflow");

        assert!(
            tree_index <= Self::MAX_TREE_INDEX,
            "Tree index {} exceeds maximum {} (day={}, block_index={})",
            tree_index,
            Self::MAX_TREE_INDEX,
            day,
            block_index_in_day
        );

        tree_index
    }

    /// Get the root path (28 sibling hashes) for a specific tree index
    ///
    /// This provides the sibling hashes needed to compute the anchor
    /// after inserting a block root at the given position.
    ///
    /// # Panics
    /// Panics if the proof doesn't have exactly ROOT_DEPTH siblings
    pub fn get_root_path_for_index(&self, tree_index: u64) -> [B256; ROOT_DEPTH] {
        let proof = self
            .root_tree
            .get_proof(tree_index as usize)
            .expect("Tree index should be valid");

        // Validate that the proof has exactly ROOT_DEPTH siblings
        assert_eq!(
            proof.siblings.len(),
            ROOT_DEPTH,
            "Merkle proof has {} siblings, expected {}",
            proof.siblings.len(),
            ROOT_DEPTH
        );

        let mut path = [B256::ZERO; ROOT_DEPTH];
        for (i, sibling) in proof.siblings.iter().enumerate() {
            path[i] = *sibling;
        }
        path
    }

    /// Get the current anchor (root of the root tree)
    pub fn current_anchor(&self) -> B256 {
        self.current_anchor
    }

    /// Insert a block root at a specific tree index
    ///
    /// Call this after validating a block, passing the treeIndex and final block root.
    /// This updates the root tree and returns the new anchor.
    ///
    /// # Arguments
    /// * `tree_index` - The position in the root tree (day * 8192 + block_index_in_day)
    /// * `block_root` - The root of the 12-level block tree
    pub fn insert_block_root(&mut self, tree_index: u64, block_root: B256) -> B256 {
        // Insert the block root at the specific tree index
        self.root_tree.set_leaf(tree_index as usize, block_root);

        // Update state
        self.current_anchor = self.root_tree.root();
        self.block_roots.insert(tree_index, block_root);

        self.current_anchor
    }

    /// Remove a block root at a specific tree index (for rollback)
    ///
    /// This sets the position back to zero and updates the anchor.
    pub fn remove_block_root(&mut self, tree_index: u64) {
        if self.block_roots.remove(&tree_index).is_some() {
            // Set the leaf back to zero
            self.root_tree.set_leaf(tree_index as usize, B256::ZERO);
            self.current_anchor = self.root_tree.root();
        }
    }

    /// Get all block roots as (treeIndex, block_root) pairs (for persistence)
    pub fn block_roots(&self) -> Vec<(u64, B256)> {
        self.block_roots.iter().map(|(&k, &v)| (k, v)).collect()
    }

    /// Get the number of blocks tracked
    pub fn block_count(&self) -> usize {
        self.block_roots.len()
    }

    /// Compute what the anchor would be if a block root were inserted at a tree index.
    ///
    /// This does NOT modify the tree state - it's a read-only computation.
    /// Use this when building blocks to compute the expected anchor before submission.
    ///
    /// # Arguments
    /// * `tree_index` - The position in the root tree (day * 8192 + block_index_in_day)
    /// * `block_root` - The root of the 12-level block tree
    ///
    /// # Returns
    /// The anchor that would result from inserting this block root
    pub fn compute_anchor_for_block(&self, tree_index: u64, block_root: B256) -> B256 {
        // Get the root path for this position
        let root_path = self.get_root_path_for_index(tree_index);

        // Compute anchor by hashing up the tree
        compute_anchor_from_path(block_root, tree_index, &root_path)
    }
}

/// Compute an anchor from a block root and root tree path.
///
/// This is the core anchor computation: hash the block root up through
/// the 28-level root tree using the sibling path.
///
/// # Arguments
/// * `block_root` - The root of the 12-level block tree
/// * `tree_index` - The position in the root tree
/// * `root_path` - The 28 sibling hashes for this position
pub fn compute_anchor_from_path(
    block_root: B256,
    tree_index: u64,
    root_path: &[B256; ROOT_DEPTH],
) -> B256 {
    let mut current = block_root;
    let mut index = tree_index as usize;

    for sibling in root_path.iter().take(ROOT_DEPTH) {
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

impl Default for RootTreeTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracker for building a single block's tree state and computing anchors.
///
/// The PGP merkle tree has a two-level structure:
/// - Root tree (28 levels): Contains block roots
/// - Block tree (12 levels): Contains leaves within a block
///
/// Each update inserts 3 leaves into the block tree, then computes the anchor
/// by hashing the block root up through the root tree path.
///
/// This struct is Clone, allowing you to snapshot state before applying updates
/// and restore if needed (e.g., if block submission fails).
#[derive(Clone)]
pub struct BlockTreeTracker {
    /// Current block tree (12 levels)
    block_tree: IncrementalMerkleTree,
    /// Root tree path (28 levels) - stored as sibling hashes for the block position
    root_path: Vec<B256>,
    /// Block index in the root tree
    block_index: usize,
    /// Precomputed zero hashes for root tree
    root_zero_hashes: Vec<B256>,
    /// Current in-block leaf index (tracks where next leaves will be inserted)
    in_block_index: usize,
}

impl BlockTreeTracker {
    /// Create a new block tree tracker.
    ///
    /// # Arguments
    /// * `block_index` - The block's position in the root tree (tree_index)
    /// * `root_path` - Sibling hashes for the block's position in the root tree.
    ///   Should have ROOT_DEPTH (28) elements. Missing elements will
    ///   be filled with zero hashes.
    pub fn new(block_index: usize, root_path: &[B256]) -> Self {
        // Initialize block tree
        let block_tree = IncrementalMerkleTree::new(BLOCK_DEPTH);

        // Compute zero hashes for root tree (used to fill missing path elements)
        let root_zero_hashes = pgp_merkle::compute_zero_hashes(ROOT_DEPTH);

        // Use provided root path, padding with zero hashes if needed
        let mut full_root_path = root_path.to_vec();
        while full_root_path.len() < ROOT_DEPTH {
            full_root_path.push(root_zero_hashes[full_root_path.len()]);
        }

        Self {
            block_tree,
            root_path: full_root_path,
            block_index,
            root_zero_hashes,
            in_block_index: 0,
        }
    }

    /// Create from a fixed-size root path array.
    pub fn from_root_path_array(block_index: usize, root_path: [B256; ROOT_DEPTH]) -> Self {
        Self::new(block_index, &root_path)
    }

    /// Apply a 3-leaf update and return the new anchor.
    ///
    /// Inserts the 3 leaves at the current in-block index, advances the index by 3,
    /// and returns the new anchor.
    pub fn apply_update(&mut self, leaves: [B256; 3]) -> B256 {
        // Insert the 3 leaves into the block tree
        for (i, leaf) in leaves.iter().enumerate() {
            let leaf_index = self.in_block_index + i;
            self.block_tree.set_leaf(leaf_index, *leaf);
        }
        self.in_block_index += 3;

        // Get the updated block root
        let block_root = self.block_tree.root();

        // Compute the anchor (root of root tree with updated block root)
        self.compute_anchor(block_root)
    }

    /// Apply a 3-leaf update at a specific in-block index.
    ///
    /// This is used by the challenger for validation where the index is known.
    /// Does NOT advance the internal in_block_index counter.
    pub fn apply_update_at(&mut self, leaves: [B256; 3], in_block_index: usize) -> B256 {
        // Insert the 3 leaves into the block tree
        for (i, leaf) in leaves.iter().enumerate() {
            let leaf_index = in_block_index + i;
            self.block_tree.set_leaf(leaf_index, *leaf);
        }

        // Get the updated block root
        let block_root = self.block_tree.root();

        // Compute the anchor (root of root tree with updated block root)
        self.compute_anchor(block_root)
    }

    /// Compute the anchor given a block root
    pub fn compute_anchor(&self, block_root: B256) -> B256 {
        let mut current = block_root;
        let mut index = self.block_index;

        // Traverse up the root tree
        for level in 0..ROOT_DEPTH {
            let sibling = if level < self.root_path.len() {
                self.root_path[level]
            } else {
                self.root_zero_hashes[level]
            };

            let is_left = index % 2 == 0;
            current = if is_left {
                poseidon2(current, sibling)
            } else {
                poseidon2(sibling, current)
            };
            index /= 2;
        }

        current
    }

    /// Get the current anchor based on the current block tree state.
    pub fn current_anchor(&self) -> B256 {
        let block_root = self.block_tree.root();
        self.compute_anchor(block_root)
    }

    /// Get the current block tree root.
    pub fn block_root(&self) -> B256 {
        self.block_tree.root()
    }

    /// Get the block index (position in root tree).
    pub fn block_index(&self) -> u64 {
        self.block_index as u64
    }

    /// Get the current in-block leaf index.
    pub fn in_block_index(&self) -> usize {
        self.in_block_index
    }

    /// Get the root path as a fixed-size array.
    pub fn root_path_array(&self) -> [B256; 28] {
        let mut arr = [B256::ZERO; 28];
        for (i, hash) in self.root_path.iter().take(28).enumerate() {
            arr[i] = *hash;
        }
        arr
    }

    /// Get merkle proofs for the predictableUpdate circuit, properly generating
    /// proofs at the correct tree states as leaves are inserted.
    ///
    /// The circuit requires:
    /// - blockProofs[0]: Proof for position `inBlockIndex - 1` (or 0) from INITIAL tree
    /// - blockProofs[1]: Proof for position `inBlockIndex` from INITIAL tree
    /// - blockProofs[2]: Proof for position `inBlockIndex + 1` AFTER updates[0] inserted
    /// - blockProofs[3]: Proof for position `inBlockIndex + 2` AFTER updates[0] AND updates[1] inserted
    pub fn get_block_proofs_for_update(
        &self,
        in_block_index: usize,
        leaves: [B256; 3],
    ) -> [[B256; 12]; 4] {
        let mut proofs = [[B256::ZERO; 12]; 4];

        // Clone the block tree so we can modify it to generate proofs at different states
        let mut tree = self.block_tree.clone();

        // Proof 0: position inBlockIndex - 1 (or 0 if index is 0) from INITIAL tree
        let pos0 = if in_block_index > 0 {
            in_block_index - 1
        } else {
            0
        };
        if let Ok(proof) = tree.get_proof(pos0) {
            for (j, sibling) in proof.siblings.iter().take(12).enumerate() {
                proofs[0][j] = *sibling;
            }
        }

        // Proof 1: position inBlockIndex from INITIAL tree
        if let Ok(proof) = tree.get_proof(in_block_index) {
            for (j, sibling) in proof.siblings.iter().take(12).enumerate() {
                proofs[1][j] = *sibling;
            }
        }

        // Insert updates[0] at inBlockIndex
        tree.set_leaf(in_block_index, leaves[0]);

        // Proof 2: position inBlockIndex + 1 from tree AFTER updates[0] inserted
        if let Ok(proof) = tree.get_proof(in_block_index + 1) {
            for (j, sibling) in proof.siblings.iter().take(12).enumerate() {
                proofs[2][j] = *sibling;
            }
        }

        // Insert updates[1] at inBlockIndex + 1
        tree.set_leaf(in_block_index + 1, leaves[1]);

        // Proof 3: position inBlockIndex + 2 from tree AFTER updates[0] AND updates[1] inserted
        if let Ok(proof) = tree.get_proof(in_block_index + 2) {
            for (j, sibling) in proof.siblings.iter().take(12).enumerate() {
                proofs[3][j] = *sibling;
            }
        }

        proofs
    }

    /// Get the previous non-zero field value for bounds checking.
    /// This is the last non-zero leaf before in_block_index.
    pub fn get_nonzero_field(&self, in_block_index: usize) -> B256 {
        // Look for the last non-zero leaf before in_block_index
        if in_block_index == 0 {
            return B256::ZERO;
        }

        for i in (0..in_block_index).rev() {
            let leaf = self.block_tree.get_node(0, i);
            if leaf != B256::ZERO {
                return leaf;
            }
        }

        B256::ZERO
    }

    /// Get complete merkle data for ZK proof generation BEFORE applying an update.
    ///
    /// Must be called BEFORE apply_update to capture the pre-update state.
    /// The leaves parameter is needed to generate proofs at the correct tree states
    /// as required by the predictableUpdate circuit.
    pub fn get_merkle_data_before_update(
        &self,
        in_block_index: usize,
        leaves: [B256; 3],
    ) -> TreeUpdateMerkleData {
        TreeUpdateMerkleData {
            block_root_before: self.block_root(),
            block_index: self.block_index(),
            in_block_index,
            nonzero_field: self.get_nonzero_field(in_block_index),
            block_proofs: self.get_block_proofs_for_update(in_block_index, leaves),
            root_path: self.root_path_array(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::Address;
    use alloy::primitives::U256;
    use pgp_common::contracts::TimestampAndIndex;

    #[allow(dead_code)]
    fn make_block_data(block_nr: u64, num_deposits: u64, num_txs: u64) -> BlockData {
        BlockData {
            anchor: B256::ZERO,
            timestamp: U256::ZERO,
            numTransactions: U256::from(num_txs),
            numDeposits: U256::from(num_deposits),
            blockNr: U256::from(block_nr),
            blockIndex: TimestampAndIndex { day: 0, index: 0 },
            sequencer: Address::ZERO,
            blobhashes: vec![],
        }
    }

    #[test]
    fn test_tree_update_validator_new() {
        let validator = TreeUpdateValidator::new();
        // Just test it can be created
        let _ = validator;
    }

    #[test]
    fn test_incremental_tree_updates() {
        use pgp_merkle::IncrementalMerkleTree;

        // Create a simple tree and verify it produces deterministic results
        let mut tree = IncrementalMerkleTree::new(12);

        // Use values that fit within the BN254 scalar field (first byte < 0x30)
        let leaf1 = B256::from([
            0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0x11,
        ]);
        let leaf2 = B256::from([
            0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0x22,
        ]);
        let leaf3 = B256::from([
            0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0x33,
        ]);

        tree.insert(leaf1).unwrap();
        let root1 = tree.root();

        tree.insert(leaf2).unwrap();
        let root2 = tree.root();

        tree.insert(leaf3).unwrap();
        let root3 = tree.root();

        // Roots should be different
        assert_ne!(root1, root2);
        assert_ne!(root2, root3);

        // Roots should be deterministic (create same tree again)
        let mut tree2 = IncrementalMerkleTree::new(12);
        tree2.insert(leaf1).unwrap();
        tree2.insert(leaf2).unwrap();
        tree2.insert(leaf3).unwrap();

        assert_eq!(tree.root(), tree2.root());
    }

    #[test]
    fn test_zero_hashes() {
        let zero_hashes = pgp_merkle::compute_zero_hashes(12);
        assert_eq!(zero_hashes.len(), 13); // depth + 1

        // First zero hash is just zero
        assert_eq!(zero_hashes[0], B256::ZERO);

        // Subsequent hashes are Poseidon of previous
        for i in 1..zero_hashes.len() {
            let expected = poseidon2(zero_hashes[i - 1], zero_hashes[i - 1]);
            assert_eq!(zero_hashes[i], expected);
        }
    }

    #[test]
    fn test_poseidon2_consistency() {
        let a = B256::repeat_byte(0x11);
        let b = B256::repeat_byte(0x22);

        let hash1 = poseidon2(a, b);
        let hash2 = poseidon2(a, b);

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, B256::ZERO);
    }
}
