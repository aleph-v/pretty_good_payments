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
    /// - final_block_tree_root: The root of the 16-level block tree after all updates
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

    /// Restore root tree state from persisted block roots (legacy format)
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

    /// Restore root tree state from hierarchical block roots
    ///
    /// This rebuilds the root tree from the new hierarchical format:
    /// (day, block_in_day, block_nr, block_root, leaf_count)
    pub fn from_hierarchical_block_roots(block_roots: &[(u16, u16, u64, B256, u32)]) -> Self {
        let mut root_tree = IncrementalMerkleTree::new(ROOT_DEPTH);
        let mut roots_map = std::collections::HashMap::new();

        for (day, block_in_day, _block_nr, root, _leaf_count) in block_roots {
            let tree_index = Self::compute_tree_index(*day as u64, *block_in_day as u64);
            root_tree.set_leaf(tree_index as usize, *root);
            roots_map.insert(tree_index, *root);
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
    /// * `block_root` - The root of the 16-level block tree
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
    /// * `block_root` - The root of the 16-level block tree
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
/// * `block_root` - The root of the 16-level block tree
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
        let is_left = index.is_multiple_of(2);
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

/// Depth of the day tree (15 levels)
pub const DAY_DEPTH: usize = 15;

/// Depth of the block-in-day tree (13 levels)
pub const BLOCK_IN_DAY_DEPTH: usize = 13;

/// Hierarchical root tree tracker with explicit day/block-in-day structure.
///
/// This models the 4-level merkle tree hierarchy:
/// - Day Tree (15 levels): 32,768 days
/// - Block-in-Day Tree (13 levels): 8,192 blocks per day
/// - Block Tree (16 levels): 65,536 leaves per block
/// - Leaves (note commitments)
///
/// Key benefits over the flat RootTreeTracker:
/// - Explicit hierarchy enables efficient sync APIs
/// - Day roots can be persisted and queried independently
/// - Lazy loading of day subtrees reduces memory usage
pub struct HierarchicalRootTracker {
    /// 15-level day tree (leaves are day subtree roots)
    day_tree: IncrementalMerkleTree,
    /// 13-level block-in-day subtrees, keyed by day (lazy loaded)
    day_subtrees: std::collections::HashMap<u16, IncrementalMerkleTree>,
    /// Cached day roots (root of each day's 13-level subtree)
    day_roots: std::collections::HashMap<u16, B256>,
    /// Block roots by (day, block_in_day) -> (block_root, leaf_count)
    block_roots: std::collections::HashMap<(u16, u16), (B256, u32)>,
    /// Current global anchor (root of the 15-level day tree)
    current_anchor: B256,
    /// Last day that was modified (for detecting day transitions)
    last_day: Option<u16>,
}

impl HierarchicalRootTracker {
    /// Create a new hierarchical root tracker starting from genesis
    pub fn new() -> Self {
        let day_tree = IncrementalMerkleTree::new(DAY_DEPTH);
        let current_anchor = day_tree.root();

        Self {
            day_tree,
            day_subtrees: std::collections::HashMap::new(),
            day_roots: std::collections::HashMap::new(),
            block_roots: std::collections::HashMap::new(),
            current_anchor,
            last_day: None,
        }
    }

    /// Initialize from database with explicit hierarchy.
    ///
    /// # Arguments
    /// * `day_roots` - Vec of (day, day_root, block_count, last_block_nr)
    /// * `block_roots` - Vec of (day, block_in_day, block_nr, block_root, leaf_count)
    pub fn from_database(
        day_roots_data: &[(u16, B256, u32, u64)],
        block_roots_data: &[(u16, u16, u64, B256, u32)],
    ) -> Self {
        let mut tracker = Self::new();

        // First, load day roots into the day tree
        for (day, day_root, _block_count, _last_block_nr) in day_roots_data {
            tracker.day_tree.set_leaf(*day as usize, *day_root);
            tracker.day_roots.insert(*day, *day_root);
        }

        // Load block roots and build day subtrees as needed
        for (day, block_in_day, _block_nr, block_root, leaf_count) in block_roots_data {
            tracker
                .block_roots
                .insert((*day, *block_in_day), (*block_root, *leaf_count));

            // Get or create the day subtree
            let subtree = tracker
                .day_subtrees
                .entry(*day)
                .or_insert_with(|| IncrementalMerkleTree::new(BLOCK_IN_DAY_DEPTH));

            subtree.set_leaf(*block_in_day as usize, *block_root);
        }

        // Recompute day roots for any days that have subtrees but weren't in day_roots_data
        // This handles the case where we have block roots but day root wasn't persisted yet
        for (&day, subtree) in &tracker.day_subtrees {
            if !tracker.day_roots.contains_key(&day) {
                let computed_root = subtree.root();
                tracker.day_tree.set_leaf(day as usize, computed_root);
                tracker.day_roots.insert(day, computed_root);
            }
        }

        tracker.current_anchor = tracker.day_tree.root();
        tracker.last_day = block_roots_data.iter().map(|(day, _, _, _, _)| *day).max();

        tracker
    }

    /// Insert a block root at a hierarchical position.
    ///
    /// Returns (new_anchor, day_changed, new_day_root if day_changed)
    pub fn insert_block_root(
        &mut self,
        day: u16,
        block_in_day: u16,
        block_root: B256,
        leaf_count: u32,
    ) -> (B256, bool, Option<B256>) {
        // Store the block root
        self.block_roots
            .insert((day, block_in_day), (block_root, leaf_count));

        // Get or create the day subtree
        let subtree = self
            .day_subtrees
            .entry(day)
            .or_insert_with(|| IncrementalMerkleTree::new(BLOCK_IN_DAY_DEPTH));

        // Insert block root into the day subtree
        subtree.set_leaf(block_in_day as usize, block_root);

        // Compute new day root
        let new_day_root = subtree.root();
        let old_day_root = self.day_roots.insert(day, new_day_root);

        // Update day tree
        self.day_tree.set_leaf(day as usize, new_day_root);
        self.current_anchor = self.day_tree.root();

        // Check if this is a day transition
        let day_changed = match self.last_day {
            Some(last) => day != last,
            None => true,
        };
        self.last_day = Some(day);

        // Return old day root if day changed (for persisting previous day)
        let previous_day_root = if day_changed { old_day_root } else { None };

        (self.current_anchor, day_changed, previous_day_root)
    }

    /// Get the current global anchor (root of day tree)
    pub fn current_anchor(&self) -> B256 {
        self.current_anchor
    }

    /// Get a day root
    pub fn get_day_root(&self, day: u16) -> Option<B256> {
        self.day_roots.get(&day).copied()
    }

    /// Get all day roots as (day, root) pairs
    pub fn get_all_day_roots(&self) -> Vec<(u16, B256)> {
        let mut roots: Vec<_> = self.day_roots.iter().map(|(&d, &r)| (d, r)).collect();
        roots.sort_by_key(|(d, _)| *d);
        roots
    }

    /// Get day roots in a range
    pub fn get_day_roots_range(&self, from_day: u16, to_day: u16) -> Vec<(u16, B256)> {
        let mut roots: Vec<_> = self
            .day_roots
            .iter()
            .filter(|(&d, _)| d >= from_day && d <= to_day)
            .map(|(&d, &r)| (d, r))
            .collect();
        roots.sort_by_key(|(d, _)| *d);
        roots
    }

    /// Get all block roots for a specific day
    pub fn get_block_roots_for_day(&self, day: u16) -> Vec<(u16, B256, u32)> {
        let mut roots: Vec<_> = self
            .block_roots
            .iter()
            .filter(|((d, _), _)| *d == day)
            .map(|((_, bid), (root, lc))| (*bid, *root, *lc))
            .collect();
        roots.sort_by_key(|(bid, _, _)| *bid);
        roots
    }

    /// Get the 15-level sibling path for a day position (day tree proof)
    pub fn get_day_path(&self, day: u16) -> [B256; DAY_DEPTH] {
        let proof = self
            .day_tree
            .get_proof(day as usize)
            .expect("Day index should be valid");

        let mut path = [B256::ZERO; DAY_DEPTH];
        for (i, sibling) in proof.siblings.iter().take(DAY_DEPTH).enumerate() {
            path[i] = *sibling;
        }
        path
    }

    /// Get the 13-level sibling path for a block within a day (block-in-day tree proof)
    pub fn get_block_in_day_path(&self, day: u16, block_in_day: u16) -> [B256; BLOCK_IN_DAY_DEPTH] {
        let subtree = self
            .day_subtrees
            .get(&day)
            .expect("Day subtree should exist");

        let proof = subtree
            .get_proof(block_in_day as usize)
            .expect("Block index should be valid");

        let mut path = [B256::ZERO; BLOCK_IN_DAY_DEPTH];
        for (i, sibling) in proof.siblings.iter().take(BLOCK_IN_DAY_DEPTH).enumerate() {
            path[i] = *sibling;
        }
        path
    }

    /// Get the full 28-level root path for a position (combined block-in-day + day path)
    ///
    /// This is compatible with the flat ROOT_DEPTH structure used by BlockTreeTracker
    pub fn get_root_path_for_position(&self, day: u16, block_in_day: u16) -> [B256; ROOT_DEPTH] {
        let mut path = [B256::ZERO; ROOT_DEPTH];

        // First 13 levels: block-in-day path
        if let Some(subtree) = self.day_subtrees.get(&day) {
            if let Ok(proof) = subtree.get_proof(block_in_day as usize) {
                for (i, sibling) in proof.siblings.iter().take(BLOCK_IN_DAY_DEPTH).enumerate() {
                    path[i] = *sibling;
                }
            }
        } else {
            // No subtree yet - use zero hashes for block-in-day path
            let zero_hashes = pgp_merkle::compute_zero_hashes(BLOCK_IN_DAY_DEPTH);
            for (i, hash) in zero_hashes.iter().take(BLOCK_IN_DAY_DEPTH).enumerate() {
                path[i] = *hash;
            }
        }

        // Next 15 levels: day path
        let day_proof = self
            .day_tree
            .get_proof(day as usize)
            .expect("Day index should be valid");
        for (i, sibling) in day_proof.siblings.iter().take(DAY_DEPTH).enumerate() {
            path[BLOCK_IN_DAY_DEPTH + i] = *sibling;
        }

        path
    }

    /// Get the tree index from (day, block_in_day) - for compatibility with flat format
    pub fn compute_tree_index(day: u16, block_in_day: u16) -> u64 {
        (day as u64) * BLOCKS_PER_DAY + (block_in_day as u64)
    }

    /// Get the number of blocks tracked
    pub fn block_count(&self) -> usize {
        self.block_roots.len()
    }

    /// Get the number of days tracked
    pub fn day_count(&self) -> usize {
        self.day_roots.len()
    }

    /// Get block count for a specific day
    pub fn get_block_count_for_day(&self, day: u16) -> u32 {
        self.block_roots.keys().filter(|(d, _)| *d == day).count() as u32
    }

    /// Get the last day that was modified
    pub fn last_day(&self) -> Option<u16> {
        self.last_day
    }

    /// Remove block roots from a specific block onwards (for rollback)
    ///
    /// Takes a predicate function that receives (day, block_in_day) and returns
    /// the block_nr for that position, allowing filtering by block_nr.
    pub fn remove_blocks_from<F>(&mut self, from_block_nr: u64, get_block_nr: F)
    where
        F: Fn(u16, u16) -> Option<u64>,
    {
        // Collect positions to remove
        let to_remove: Vec<_> = self
            .block_roots
            .keys()
            .filter(|(day, block_in_day)| {
                get_block_nr(*day, *block_in_day)
                    .map(|nr| nr >= from_block_nr)
                    .unwrap_or(false)
            })
            .copied()
            .collect();

        // Track affected days
        let mut affected_days: std::collections::HashSet<u16> = std::collections::HashSet::new();

        // Remove the block roots
        for (day, block_in_day) in to_remove {
            self.block_roots.remove(&(day, block_in_day));
            affected_days.insert(day);

            // Update the day subtree
            if let Some(subtree) = self.day_subtrees.get_mut(&day) {
                subtree.set_leaf(block_in_day as usize, B256::ZERO);
            }
        }

        // Recompute day roots for affected days
        for day in affected_days {
            if let Some(subtree) = self.day_subtrees.get(&day) {
                let new_root = subtree.root();
                self.day_roots.insert(day, new_root);
                self.day_tree.set_leaf(day as usize, new_root);
            }
        }

        // Update anchor
        self.current_anchor = self.day_tree.root();

        // Update last_day
        self.last_day = self.block_roots.keys().map(|(d, _)| *d).max();
    }

    /// Compute what the anchor would be for a new block (read-only)
    pub fn compute_anchor_for_block(&self, day: u16, block_in_day: u16, block_root: B256) -> B256 {
        let root_path = self.get_root_path_for_position(day, block_in_day);
        let tree_index = Self::compute_tree_index(day, block_in_day);
        compute_anchor_from_path(block_root, tree_index, &root_path)
    }
}

impl Default for HierarchicalRootTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracker for building a single block's tree state and computing anchors.
///
/// The PGP merkle tree has a two-level structure:
/// - Root tree (28 levels): Contains block roots
/// - Block tree (16 levels): Contains leaves within a block
///
/// Each update inserts 3 leaves into the block tree, then computes the anchor
/// by hashing the block root up through the root tree path.
///
/// This struct is Clone, allowing you to snapshot state before applying updates
/// and restore if needed (e.g., if block submission fails).
#[derive(Clone)]
pub struct BlockTreeTracker {
    /// Current block tree (16 levels)
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

            let is_left = index.is_multiple_of(2);
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
    ) -> [[B256; 16]; 4] {
        let mut proofs = [[B256::ZERO; 16]; 4];

        // Clone the block tree so we can modify it to generate proofs at different states
        let mut tree = self.block_tree.clone();

        // Proof 0: position inBlockIndex - 1 (or 0 if index is 0) from INITIAL tree
        let pos0 = if in_block_index > 0 {
            in_block_index - 1
        } else {
            0
        };
        if let Ok(proof) = tree.get_proof(pos0) {
            for (j, sibling) in proof.siblings.iter().take(16).enumerate() {
                proofs[0][j] = *sibling;
            }
        }

        // Proof 1: position inBlockIndex from INITIAL tree
        if let Ok(proof) = tree.get_proof(in_block_index) {
            for (j, sibling) in proof.siblings.iter().take(16).enumerate() {
                proofs[1][j] = *sibling;
            }
        }

        // Insert updates[0] at inBlockIndex
        tree.set_leaf(in_block_index, leaves[0]);

        // Proof 2: position inBlockIndex + 1 from tree AFTER updates[0] inserted
        if let Ok(proof) = tree.get_proof(in_block_index + 1) {
            for (j, sibling) in proof.siblings.iter().take(16).enumerate() {
                proofs[2][j] = *sibling;
            }
        }

        // Insert updates[1] at inBlockIndex + 1
        tree.set_leaf(in_block_index + 1, leaves[1]);

        // Proof 3: position inBlockIndex + 2 from tree AFTER updates[0] AND updates[1] inserted
        if let Ok(proof) = tree.get_proof(in_block_index + 2) {
            for (j, sibling) in proof.siblings.iter().take(16).enumerate() {
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

    // Helper to create valid field elements (first byte < 0x30 to stay in BN254 field)
    fn valid_block_root(byte: u8) -> B256 {
        B256::from([
            0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, byte,
        ])
    }

    #[test]
    fn test_hierarchical_root_tracker_new() {
        let tracker = HierarchicalRootTracker::new();
        assert_eq!(tracker.block_count(), 0);
        assert_eq!(tracker.day_count(), 0);
        assert!(tracker.last_day().is_none());
        // Initial anchor should be the empty tree root
        assert_ne!(tracker.current_anchor(), B256::ZERO);
    }

    #[test]
    fn test_hierarchical_root_tracker_insert() {
        let mut tracker = HierarchicalRootTracker::new();
        let initial_anchor = tracker.current_anchor();

        let block_root = valid_block_root(0x11);
        let (new_anchor, day_changed, _) = tracker.insert_block_root(0, 0, block_root, 30);

        assert_ne!(new_anchor, initial_anchor);
        assert!(day_changed); // First insert is always a day change
        assert_eq!(tracker.block_count(), 1);
        assert_eq!(tracker.day_count(), 1);
        assert_eq!(tracker.last_day(), Some(0));

        // Insert another block in same day
        let block_root2 = valid_block_root(0x22);
        let (_, day_changed2, _) = tracker.insert_block_root(0, 1, block_root2, 45);
        assert!(!day_changed2); // Same day
        assert_eq!(tracker.block_count(), 2);

        // Insert block in new day - day_changed should be true, and we get the OLD
        // value of day 1's root (which was None since it's new)
        let block_root3 = valid_block_root(0x33);
        let (_, day_changed3, _prev_day_root) = tracker.insert_block_root(1, 0, block_root3, 15);
        assert!(day_changed3);
        // prev_day_root is the OLD root of day 1 (the new day), not day 0
        // Since day 1 didn't exist before, this is None - that's the correct behavior
        assert_eq!(tracker.day_count(), 2);

        // Verify day 0's root is tracked correctly
        assert!(tracker.get_day_root(0).is_some());
        assert!(tracker.get_day_root(1).is_some());
    }

    #[test]
    fn test_hierarchical_root_tracker_paths() {
        let mut tracker = HierarchicalRootTracker::new();

        // Insert some blocks
        tracker.insert_block_root(0, 0, valid_block_root(0x11), 30);
        tracker.insert_block_root(0, 1, valid_block_root(0x22), 30);
        tracker.insert_block_root(1, 0, valid_block_root(0x33), 30);

        // Get day path (15 levels)
        let day_path = tracker.get_day_path(0);
        assert_eq!(day_path.len(), DAY_DEPTH);

        // Get block-in-day path (13 levels)
        let bid_path = tracker.get_block_in_day_path(0, 0);
        assert_eq!(bid_path.len(), BLOCK_IN_DAY_DEPTH);

        // Get full root path (28 levels)
        let root_path = tracker.get_root_path_for_position(0, 1);
        assert_eq!(root_path.len(), ROOT_DEPTH);
    }

    #[test]
    fn test_hierarchical_root_tracker_compute_tree_index() {
        // day=0, block_in_day=0 => tree_index=0
        assert_eq!(HierarchicalRootTracker::compute_tree_index(0, 0), 0);

        // day=0, block_in_day=100 => tree_index=100
        assert_eq!(HierarchicalRootTracker::compute_tree_index(0, 100), 100);

        // day=1, block_in_day=0 => tree_index=8192
        assert_eq!(HierarchicalRootTracker::compute_tree_index(1, 0), 8192);

        // day=1, block_in_day=100 => tree_index=8292
        assert_eq!(HierarchicalRootTracker::compute_tree_index(1, 100), 8292);
    }

    #[test]
    fn test_hierarchical_root_tracker_from_database() {
        // Simulate loading from database with valid field elements
        let day_roots = vec![
            (0u16, valid_block_root(0xAA), 100u32, 99u64),
            (1u16, valid_block_root(0xBB), 50u32, 149u64),
        ];
        let block_roots = vec![
            (0u16, 0u16, 0u64, valid_block_root(0x11), 30u32),
            (0u16, 1u16, 1u64, valid_block_root(0x22), 30u32),
            (1u16, 0u16, 100u64, valid_block_root(0x33), 30u32),
        ];

        let tracker = HierarchicalRootTracker::from_database(&day_roots, &block_roots);

        assert_eq!(tracker.block_count(), 3);
        assert_eq!(tracker.day_count(), 2);
        assert_eq!(tracker.last_day(), Some(1));

        // Verify day roots are loaded
        assert!(tracker.get_day_root(0).is_some());
        assert!(tracker.get_day_root(1).is_some());

        // Verify block roots for day
        let day0_blocks = tracker.get_block_roots_for_day(0);
        assert_eq!(day0_blocks.len(), 2);
    }

    #[test]
    fn test_hierarchical_root_tracker_block_queries() {
        let mut tracker = HierarchicalRootTracker::new();

        // Insert blocks across multiple days
        tracker.insert_block_root(0, 0, valid_block_root(0x11), 30);
        tracker.insert_block_root(0, 1, valid_block_root(0x22), 45);
        tracker.insert_block_root(0, 2, valid_block_root(0x33), 60);
        tracker.insert_block_root(1, 0, valid_block_root(0x44), 15);

        // Query block count per day
        assert_eq!(tracker.get_block_count_for_day(0), 3);
        assert_eq!(tracker.get_block_count_for_day(1), 1);
        assert_eq!(tracker.get_block_count_for_day(2), 0);

        // Query all blocks for a day
        let day0_blocks = tracker.get_block_roots_for_day(0);
        assert_eq!(day0_blocks.len(), 3);
        assert_eq!(day0_blocks[0].0, 0); // block_in_day
        assert_eq!(day0_blocks[1].0, 1);
        assert_eq!(day0_blocks[2].0, 2);

        // Query day roots
        let all_days = tracker.get_all_day_roots();
        assert_eq!(all_days.len(), 2);

        let day_range = tracker.get_day_roots_range(0, 0);
        assert_eq!(day_range.len(), 1);
    }

    #[test]
    fn test_root_tree_tracker_new() {
        let tracker = RootTreeTracker::new();
        assert_eq!(tracker.block_count(), 0);
        // Initial anchor should be the empty tree root (not zero)
        assert_ne!(tracker.current_anchor(), B256::ZERO);
    }

    #[test]
    fn test_root_tree_tracker_insert_and_remove() {
        let mut tracker = RootTreeTracker::new();
        let initial_anchor = tracker.current_anchor();

        // Insert a block root
        let tree_index = 0;
        let block_root = valid_block_root(0x11);
        let new_anchor = tracker.insert_block_root(tree_index, block_root);

        assert_ne!(new_anchor, initial_anchor);
        assert_eq!(tracker.block_count(), 1);
        assert_eq!(tracker.current_anchor(), new_anchor);

        // Remove the block root
        tracker.remove_block_root(tree_index);
        assert_eq!(tracker.block_count(), 0);
        assert_eq!(tracker.current_anchor(), initial_anchor);
    }

    #[test]
    fn test_root_tree_tracker_compute_tree_index() {
        // Basic cases
        assert_eq!(RootTreeTracker::compute_tree_index(0, 0), 0);
        assert_eq!(RootTreeTracker::compute_tree_index(0, 100), 100);
        assert_eq!(RootTreeTracker::compute_tree_index(1, 0), BLOCKS_PER_DAY);
        assert_eq!(
            RootTreeTracker::compute_tree_index(2, 500),
            2 * BLOCKS_PER_DAY + 500
        );
    }

    #[test]
    #[should_panic(expected = "block_index_in_day")]
    fn test_root_tree_tracker_compute_tree_index_invalid_block() {
        // block_index_in_day >= BLOCKS_PER_DAY should panic
        RootTreeTracker::compute_tree_index(0, BLOCKS_PER_DAY);
    }

    #[test]
    fn test_root_tree_tracker_from_block_roots() {
        let block_roots = vec![
            (0, valid_block_root(0x11)),
            (100, valid_block_root(0x22)),
            (8192, valid_block_root(0x33)), // day 1, block 0
        ];

        let tracker = RootTreeTracker::from_block_roots(&block_roots);
        assert_eq!(tracker.block_count(), 3);

        // Verify anchor is computed correctly
        let anchor = tracker.current_anchor();
        assert_ne!(anchor, B256::ZERO);
    }

    #[test]
    fn test_root_tree_tracker_root_path() {
        let mut tracker = RootTreeTracker::new();

        // Insert some blocks
        tracker.insert_block_root(0, valid_block_root(0x11));
        tracker.insert_block_root(1, valid_block_root(0x22));

        // Get root path for a position
        let path = tracker.get_root_path_for_index(0);
        assert_eq!(path.len(), ROOT_DEPTH);
    }

    #[test]
    fn test_root_tree_tracker_compute_anchor_for_block() {
        let mut tracker = RootTreeTracker::new();

        let block_root = valid_block_root(0x11);
        let tree_index = 42;

        // Compute what anchor would be WITHOUT modifying state
        let computed_anchor = tracker.compute_anchor_for_block(tree_index, block_root);

        // State should not have changed
        assert_eq!(tracker.block_count(), 0);

        // Now actually insert and verify it matches
        let actual_anchor = tracker.insert_block_root(tree_index, block_root);
        assert_eq!(computed_anchor, actual_anchor);
    }

    #[test]
    fn test_block_tree_tracker_new() {
        let root_path = [B256::ZERO; ROOT_DEPTH];
        let tracker = BlockTreeTracker::from_root_path_array(0, root_path);

        assert_eq!(tracker.block_index(), 0);
        assert_eq!(tracker.in_block_index(), 0);
        // Block root should be the empty tree root
        assert_ne!(tracker.block_root(), B256::ZERO);
    }

    #[test]
    fn test_block_tree_tracker_apply_update() {
        let root_path = [B256::ZERO; ROOT_DEPTH];
        let mut tracker = BlockTreeTracker::from_root_path_array(0, root_path);

        let initial_anchor = tracker.current_anchor();

        let leaves = [
            valid_block_root(0x11),
            valid_block_root(0x22),
            valid_block_root(0x33),
        ];

        let new_anchor = tracker.apply_update(leaves);
        assert_ne!(new_anchor, initial_anchor);
        assert_eq!(tracker.in_block_index(), 3);

        // Apply another update
        let leaves2 = [
            valid_block_root(0x44),
            valid_block_root(0x55),
            valid_block_root(0x66),
        ];
        let newer_anchor = tracker.apply_update(leaves2);
        assert_ne!(newer_anchor, new_anchor);
        assert_eq!(tracker.in_block_index(), 6);
    }

    #[test]
    fn test_block_tree_tracker_apply_update_at() {
        let root_path = [B256::ZERO; ROOT_DEPTH];
        let mut tracker = BlockTreeTracker::from_root_path_array(0, root_path);

        let leaves = [
            valid_block_root(0x11),
            valid_block_root(0x22),
            valid_block_root(0x33),
        ];

        // apply_update_at does NOT advance in_block_index
        let _anchor = tracker.apply_update_at(leaves, 0);
        assert_eq!(tracker.in_block_index(), 0); // Should stay at 0
    }

    #[test]
    fn test_block_tree_tracker_merkle_data() {
        let root_path = [B256::ZERO; ROOT_DEPTH];
        let tracker = BlockTreeTracker::from_root_path_array(0, root_path);

        let leaves = [
            valid_block_root(0x11),
            valid_block_root(0x22),
            valid_block_root(0x33),
        ];

        let merkle_data = tracker.get_merkle_data_before_update(0, leaves);

        assert_eq!(merkle_data.block_index, 0);
        assert_eq!(merkle_data.in_block_index, 0);
        assert_eq!(merkle_data.block_proofs.len(), 4);
        assert_eq!(merkle_data.root_path.len(), ROOT_DEPTH);
    }

    #[test]
    fn test_block_tree_tracker_nonzero_field() {
        let root_path = [B256::ZERO; ROOT_DEPTH];
        let mut tracker = BlockTreeTracker::from_root_path_array(0, root_path);

        // Initially empty - nonzero_field should be ZERO
        assert_eq!(tracker.get_nonzero_field(0), B256::ZERO);
        assert_eq!(tracker.get_nonzero_field(3), B256::ZERO);

        // Insert some leaves
        let leaves = [
            valid_block_root(0x11),
            valid_block_root(0x22),
            valid_block_root(0x33),
        ];
        tracker.apply_update(leaves);

        // Now check nonzero_field at various positions
        assert_eq!(tracker.get_nonzero_field(0), B256::ZERO); // Nothing before index 0
        assert_eq!(tracker.get_nonzero_field(3), valid_block_root(0x33)); // Last leaf before index 3
        assert_eq!(tracker.get_nonzero_field(2), valid_block_root(0x22)); // Last leaf before index 2
    }

    #[test]
    fn test_block_tree_tracker_clone() {
        let root_path = [B256::ZERO; ROOT_DEPTH];
        let mut tracker = BlockTreeTracker::from_root_path_array(0, root_path);

        let leaves = [
            valid_block_root(0x11),
            valid_block_root(0x22),
            valid_block_root(0x33),
        ];
        tracker.apply_update(leaves);

        let snapshot = tracker.clone();

        // Apply more updates to original
        let leaves2 = [
            valid_block_root(0x44),
            valid_block_root(0x55),
            valid_block_root(0x66),
        ];
        tracker.apply_update(leaves2);

        // Snapshot should still have original state
        assert_eq!(snapshot.in_block_index(), 3);
        assert_eq!(tracker.in_block_index(), 6);
        assert_ne!(snapshot.current_anchor(), tracker.current_anchor());
    }

    #[test]
    fn test_hierarchical_remove_blocks_from() {
        let mut tracker = HierarchicalRootTracker::new();

        // Insert blocks with known block numbers
        // We'll simulate: block_nr 0 at (day=0, bid=0), block_nr 1 at (day=0, bid=1), etc.
        tracker.insert_block_root(0, 0, valid_block_root(0x11), 30);
        tracker.insert_block_root(0, 1, valid_block_root(0x22), 30);
        tracker.insert_block_root(0, 2, valid_block_root(0x33), 30);
        tracker.insert_block_root(1, 0, valid_block_root(0x44), 30);

        assert_eq!(tracker.block_count(), 4);

        // Remove blocks from block_nr 2 onwards
        // We need to provide a mapping function that returns block_nr for (day, bid)
        tracker.remove_blocks_from(2, |day, bid| {
            // Simple mapping: block_nr = day * 1000 + bid
            // So (0,0)=0, (0,1)=1, (0,2)=2, (1,0)=1000
            Some(day as u64 * 1000 + bid as u64)
        });

        // Should remove (0,2) with block_nr=2 and (1,0) with block_nr=1000
        assert_eq!(tracker.block_count(), 2);
        assert_eq!(tracker.get_block_count_for_day(0), 2);
        assert_eq!(tracker.get_block_count_for_day(1), 0);
    }

    #[test]
    fn test_compute_anchor_from_path() {
        let block_root = valid_block_root(0x11);
        let tree_index = 0;
        let root_path = [B256::ZERO; ROOT_DEPTH];

        // Compute anchor
        let anchor = compute_anchor_from_path(block_root, tree_index, &root_path);

        // With all-zero path, the anchor should be computed by hashing up
        // This is a deterministic operation
        assert_ne!(anchor, B256::ZERO);
        assert_ne!(anchor, block_root); // Should be different from input

        // Same inputs should give same output
        let anchor2 = compute_anchor_from_path(block_root, tree_index, &root_path);
        assert_eq!(anchor, anchor2);

        // Different tree_index should give different anchor (even with same path)
        let anchor3 = compute_anchor_from_path(block_root, 1, &root_path);
        assert_ne!(anchor, anchor3);
    }
}
