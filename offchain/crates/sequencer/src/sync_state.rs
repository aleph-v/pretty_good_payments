//! State for serving sync API endpoints.
//!
//! This module provides the server-side logic for the hierarchical merkle sync API.
//! It uses database lookups via StateManager for data persistence, combined with
//! HierarchicalRootTracker for computing merkle paths.

use alloy::primitives::B256;
use pgp_challenger::validators::tree_update::HierarchicalRootTracker;
use pgp_challenger::StateManager;
use pgp_common::blob::ParsedBlock;
use pgp_merkle::{BlockRoot, DayRoot, IncrementalMerkleTree, TreePosition};
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;
use tracing::warn;

/// Depth constants
pub const DAY_TREE_DEPTH: usize = 15;
pub const BLOCK_IN_DAY_DEPTH: usize = 13;
pub const BLOCK_TREE_DEPTH: usize = 16;

/// Response for GET /sync/status
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SyncStatusResponse {
    pub latest_block_nr: u64,
    pub latest_day: u16,
    pub latest_block_in_day: u16,
    pub current_anchor: B256,
    pub genesis_anchor: B256,
}

/// Response for GET /sync/day-roots
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DayRootsResponse {
    pub day_roots: Vec<DayRoot>,
    pub current_anchor: B256,
}

/// Response for GET /sync/block-roots
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlockRootsResponse {
    pub day: u16,
    pub block_roots: Vec<BlockRoot>,
    pub day_root: B256,
}

/// Response for GET /sync/day-path
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DayPathResponse {
    pub day: u16,
    pub day_path: [B256; DAY_TREE_DEPTH],
    pub day_root: B256,
    pub current_anchor: B256,
}

/// Response for GET /sync/block-path
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlockInDayPathResponse {
    pub day: u16,
    pub block_in_day: u16,
    pub block_path: [B256; BLOCK_IN_DAY_DEPTH],
    pub block_root: B256,
    pub day_root: B256,
}

/// Response for GET /sync/block-tree-proof
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlockTreeProofResponse {
    pub block_nr: u64,
    pub leaf_index: u32,
    pub leaf: B256,
    pub block_siblings: [B256; BLOCK_TREE_DEPTH],
    pub block_root: B256,
    pub position: TreePosition,
}

/// Response for GET /sync/full-proof
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FullProofResponse {
    pub block_nr: u64,
    pub leaf_index: u32,
    pub position: TreePosition,
    pub leaf: B256,
    pub block_siblings: [B256; BLOCK_TREE_DEPTH],
    pub block_in_day_siblings: [B256; BLOCK_IN_DAY_DEPTH],
    pub day_siblings: [B256; DAY_TREE_DEPTH],
    pub current_anchor: B256,
}

/// State for serving sync API endpoints.
///
/// This combines database access (StateManager) for persistent data lookups
/// with HierarchicalRootTracker for computing merkle paths.
pub struct SyncState {
    state_manager: Arc<Mutex<StateManager>>,
    root_tree_tracker: Arc<RwLock<HierarchicalRootTracker>>,
}

impl SyncState {
    /// Create a new SyncState.
    pub fn new(
        state_manager: Arc<Mutex<StateManager>>,
        root_tree_tracker: Arc<RwLock<HierarchicalRootTracker>>,
    ) -> Self {
        Self {
            state_manager,
            root_tree_tracker,
        }
    }

    /// Get the genesis anchor (empty tree root).
    fn genesis_anchor() -> B256 {
        HierarchicalRootTracker::new().current_anchor()
    }

    /// Serve GET /sync/status
    pub async fn get_sync_status(&self) -> SyncStatusResponse {
        // Use database for latest block info
        let (latest_block_nr, latest_day, latest_block_in_day) = {
            let state = self.state_manager.lock().unwrap();

            let block_nr = match state.get_latest_block_nr() {
                Ok(Some(nr)) => nr,
                Ok(None) => 0, // No blocks yet - this is valid initial state
                Err(e) => {
                    warn!("Failed to get latest block number: {}", e);
                    0
                }
            };

            let day = match state.get_latest_day() {
                Ok(Some(d)) => d,
                Ok(None) => 0, // No days yet - valid initial state
                Err(e) => {
                    warn!("Failed to get latest day: {}", e);
                    0
                }
            };

            let block_in_day = match state.get_latest_block_in_day(day) {
                Ok(Some(bid)) => bid,
                Ok(None) => 0, // No blocks in day yet - valid initial state
                Err(e) => {
                    warn!("Failed to get latest block in day {}: {}", day, e);
                    0
                }
            };

            (block_nr, day, block_in_day)
        };

        // Use tracker for current anchor (it's kept in sync with database)
        let current_anchor = {
            let tracker = self.root_tree_tracker.read().await;
            tracker.current_anchor()
        };

        SyncStatusResponse {
            latest_block_nr,
            latest_day,
            latest_block_in_day,
            current_anchor,
            genesis_anchor: Self::genesis_anchor(),
        }
    }

    /// Serve GET /sync/day-roots
    pub async fn get_day_roots(&self, from_day: u16, to_day: u16) -> DayRootsResponse {
        // Use database for day roots (ensures we have all persisted data)
        let day_roots = {
            let state = self.state_manager.lock().unwrap();
            match state.get_day_roots_range(from_day, to_day) {
                Ok(roots) => roots
                    .into_iter()
                    .map(|(day, root)| DayRoot { day, root })
                    .collect(),
                Err(e) => {
                    warn!(
                        "Failed to get day roots range [{}, {}]: {}",
                        from_day, to_day, e
                    );
                    Vec::new()
                }
            }
        };

        // Use tracker for current anchor
        let current_anchor = {
            let tracker = self.root_tree_tracker.read().await;
            tracker.current_anchor()
        };

        DayRootsResponse {
            day_roots,
            current_anchor,
        }
    }

    /// Serve GET /sync/block-roots
    pub async fn get_block_roots(&self, day: u16) -> BlockRootsResponse {
        // Use database for block roots (ensures we have all persisted data)
        let (block_roots, day_root) = {
            let state = self.state_manager.lock().unwrap();

            // Get block roots for the day: (block_in_day, block_nr, block_root, leaf_count)
            let roots = match state.get_block_roots_for_day(day) {
                Ok(roots) => roots
                    .into_iter()
                    .map(|(block_in_day, _block_nr, root, _leaf_count)| BlockRoot {
                        day,
                        block_in_day,
                        root,
                    })
                    .collect(),
                Err(e) => {
                    warn!("Failed to get block roots for day {}: {}", day, e);
                    Vec::new()
                }
            };

            // Get day root from database
            let day_root = match state.load_day_root(day) {
                Ok(Some((root, _, _))) => root,
                Ok(None) => {
                    // Day root not yet computed - this is valid for current day
                    B256::ZERO
                }
                Err(e) => {
                    warn!("Failed to load day root for day {}: {}", day, e);
                    B256::ZERO
                }
            };

            (roots, day_root)
        };

        BlockRootsResponse {
            day,
            block_roots,
            day_root,
        }
    }

    /// Serve GET /sync/day-path
    pub async fn get_day_path(&self, day: u16) -> DayPathResponse {
        // Use tracker for path computation (it has the tree structure)
        let tracker = self.root_tree_tracker.read().await;

        let day_path = tracker.get_day_path(day);
        let day_root = tracker.get_day_root(day).unwrap_or(B256::ZERO);
        let current_anchor = tracker.current_anchor();

        DayPathResponse {
            day,
            day_path,
            day_root,
            current_anchor,
        }
    }

    /// Serve GET /sync/block-path
    pub async fn get_block_path(&self, day: u16, block_in_day: u16) -> BlockInDayPathResponse {
        // Use tracker for path computation (it has the tree structure)
        let tracker = self.root_tree_tracker.read().await;

        let block_path = tracker.get_block_in_day_path(day, block_in_day);

        // Get block root from tracker's block_roots
        let block_roots = tracker.get_block_roots_for_day(day);
        let block_root = block_roots
            .iter()
            .find(|(bid, _, _)| *bid == block_in_day)
            .map(|(_, root, _)| *root)
            .unwrap_or(B256::ZERO);

        let day_root = tracker.get_day_root(day).unwrap_or(B256::ZERO);

        BlockInDayPathResponse {
            day,
            block_in_day,
            block_path,
            block_root,
            day_root,
        }
    }

    /// Serve GET /sync/block-tree-proof
    ///
    /// Reconstructs the block tree from stored blob data and computes the merkle
    /// proof for a specific leaf.
    pub async fn get_block_tree_proof(
        &self,
        block_nr: u64,
        leaf_index: u32,
    ) -> Option<BlockTreeProofResponse> {
        // Load block data and reconstruct tree
        let (block_tree, parsed_block, position) = self.reconstruct_block_tree(block_nr).await?;

        // Validate leaf index
        let total_leaves = self.count_block_leaves(&parsed_block);
        if leaf_index as usize >= total_leaves {
            warn!(
                "Leaf index {} out of bounds for block {} (has {} leaves)",
                leaf_index, block_nr, total_leaves
            );
            return None;
        }

        // Get the leaf value at this index
        let leaf = self.get_leaf_at_index(&parsed_block, leaf_index as usize)?;

        // Get the merkle proof for this leaf
        let proof = block_tree.get_proof(leaf_index as usize).ok()?;

        // Convert siblings to fixed-size array
        let mut block_siblings = [B256::ZERO; BLOCK_TREE_DEPTH];
        for (i, sibling) in proof.siblings.iter().take(BLOCK_TREE_DEPTH).enumerate() {
            block_siblings[i] = *sibling;
        }

        // Get block root
        let block_root = block_tree.root();

        // Update position with leaf index
        let full_position =
            TreePosition::new(position.day, position.block_in_day, leaf_index as u16);

        Some(BlockTreeProofResponse {
            block_nr,
            leaf_index,
            leaf,
            block_siblings,
            block_root,
            position: full_position,
        })
    }

    /// Serve GET /sync/full-proof
    ///
    /// Combines block tree proof with day/block-in-day paths for a complete
    /// 44-level proof from leaf to global anchor.
    pub async fn get_full_proof(
        &self,
        block_nr: u64,
        leaf_index: u32,
    ) -> Option<FullProofResponse> {
        // Get block tree proof first
        let block_proof = self.get_block_tree_proof(block_nr, leaf_index).await?;

        // Get the day and block-in-day paths from the tracker
        let (block_in_day_siblings, day_siblings, current_anchor) = {
            let tracker = self.root_tree_tracker.read().await;

            let block_in_day_path = tracker
                .get_block_in_day_path(block_proof.position.day, block_proof.position.block_in_day);
            let day_path = tracker.get_day_path(block_proof.position.day);
            let anchor = tracker.current_anchor();

            (block_in_day_path, day_path, anchor)
        };

        Some(FullProofResponse {
            block_nr,
            leaf_index,
            position: block_proof.position,
            leaf: block_proof.leaf,
            block_siblings: block_proof.block_siblings,
            block_in_day_siblings,
            day_siblings,
            current_anchor,
        })
    }

    /// Reconstruct the block tree from stored blob data.
    ///
    /// Returns the reconstructed tree, parsed block, and the block's position.
    async fn reconstruct_block_tree(
        &self,
        block_nr: u64,
    ) -> Option<(IncrementalMerkleTree, ParsedBlock, TreePosition)> {
        // Load block data from database
        let (block_data, position) = {
            let state = self.state_manager.lock().unwrap();

            let (block_data, _l1_block) = state.load_block_data(block_nr).ok()??;

            // Get block position
            let (day, block_in_day) = state.get_block_position(block_nr).ok()??;

            (block_data, TreePosition::new(day, block_in_day, 0))
        };

        // Load blobs from database
        let blob_data_vec = self.load_blobs_for_block(&block_data.blobhashes)?;

        // Parse blob data into B256 arrays
        let blobs_b256: Vec<Vec<B256>> = blob_data_vec
            .iter()
            .map(|blob_bytes| {
                blob_bytes
                    .chunks(32)
                    .map(|chunk| {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(chunk);
                        B256::from(arr)
                    })
                    .collect()
            })
            .collect();

        // Parse the block
        let num_deposits: usize = block_data.numDeposits.try_into().unwrap_or(0);
        let num_transactions: usize = block_data.numTransactions.try_into().unwrap_or(0);

        let parsed_block =
            ParsedBlock::from_blob_vecs(&blobs_b256, num_deposits, num_transactions).ok()?;

        // Reconstruct the block tree by inserting all leaves
        let block_tree = self.build_block_tree(&parsed_block);

        Some((block_tree, parsed_block, position))
    }

    /// Load blob data for a block's blob hashes.
    fn load_blobs_for_block(&self, blobhashes: &[B256]) -> Option<Vec<Vec<u8>>> {
        let state = self.state_manager.lock().unwrap();

        let mut blob_data_vec = Vec::new();
        for blobhash in blobhashes {
            match state.load_blob(*blobhash) {
                Ok(Some(data)) => blob_data_vec.push(data),
                Ok(None) => {
                    warn!("Blob {} not found", blobhash);
                    return None;
                }
                Err(e) => {
                    warn!("Failed to load blob {}: {}", blobhash, e);
                    return None;
                }
            }
        }

        if blob_data_vec.is_empty() {
            return None;
        }

        Some(blob_data_vec)
    }

    /// Build a block tree from a parsed block by inserting all leaves.
    fn build_block_tree(&self, parsed_block: &ParsedBlock) -> IncrementalMerkleTree {
        let mut tree = IncrementalMerkleTree::new(BLOCK_TREE_DEPTH);
        let mut leaf_index = 0;

        // Insert deposit leaves (3 per group)
        for group in &parsed_block.deposit_groups {
            tree.set_leaf(leaf_index, group.leaf0);
            tree.set_leaf(leaf_index + 1, group.leaf1);
            tree.set_leaf(leaf_index + 2, group.leaf2);
            leaf_index += 3;
        }

        // Insert transaction leaves (3 per transaction)
        for tx in &parsed_block.transactions {
            tree.set_leaf(leaf_index, tx.leaf0);
            tree.set_leaf(leaf_index + 1, tx.leaf1);
            tree.set_leaf(leaf_index + 2, tx.leaf2);
            leaf_index += 3;
        }

        tree
    }

    /// Count the total number of leaves in a parsed block.
    fn count_block_leaves(&self, parsed_block: &ParsedBlock) -> usize {
        // Each deposit group has 3 leaves, each transaction has 3 leaves
        parsed_block.deposit_groups.len() * 3 + parsed_block.transactions.len() * 3
    }

    /// Get the leaf value at a specific index in the block.
    fn get_leaf_at_index(&self, parsed_block: &ParsedBlock, index: usize) -> Option<B256> {
        let deposit_leaves = parsed_block.deposit_groups.len() * 3;

        if index < deposit_leaves {
            // It's a deposit leaf
            let group_idx = index / 3;
            let leaf_in_group = index % 3;
            let group = parsed_block.deposit_groups.get(group_idx)?;
            Some(match leaf_in_group {
                0 => group.leaf0,
                1 => group.leaf1,
                2 => group.leaf2,
                _ => unreachable!(),
            })
        } else {
            // It's a transaction leaf
            let tx_index = (index - deposit_leaves) / 3;
            let leaf_in_tx = (index - deposit_leaves) % 3;
            let tx = parsed_block.transactions.get(tx_index)?;
            Some(match leaf_in_tx {
                0 => tx.leaf0,
                1 => tx.leaf1,
                2 => tx.leaf2,
                _ => unreachable!(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp_common::types::{Groth16Proof, ParsedDepositGroup, ParsedTransaction};

    #[tokio::test]
    async fn test_sync_state_genesis() {
        let state_manager = Arc::new(Mutex::new(StateManager::in_memory().unwrap()));
        let root_tree = Arc::new(RwLock::new(HierarchicalRootTracker::new()));
        let sync_state = SyncState::new(state_manager, root_tree);

        let status = sync_state.get_sync_status().await;

        assert_eq!(status.latest_block_nr, 0);
        assert_eq!(status.latest_day, 0);
        assert_eq!(status.current_anchor, status.genesis_anchor);
    }

    /// Create a valid BN254 field element (first byte must be < 0x30)
    fn valid_field_element(byte: u8) -> B256 {
        B256::from([
            0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, byte,
        ])
    }

    #[test]
    fn test_build_block_tree() {
        let state_manager = Arc::new(Mutex::new(StateManager::in_memory().unwrap()));
        let root_tree_tracker = Arc::new(RwLock::new(HierarchicalRootTracker::new()));
        let sync_state = SyncState::new(state_manager, root_tree_tracker);

        // Create a simple parsed block with one deposit group using valid field elements
        let parsed_block = ParsedBlock {
            deposit_groups: vec![ParsedDepositGroup {
                leaf0: valid_field_element(0x11),
                leaf1: valid_field_element(0x22),
                leaf2: valid_field_element(0x33),
                new_root: B256::ZERO,
            }],
            transactions: vec![],
            num_deposits: 3,
        };

        let tree = sync_state.build_block_tree(&parsed_block);

        // Verify tree was built correctly
        assert_eq!(tree.get_node(0, 0), valid_field_element(0x11));
        assert_eq!(tree.get_node(0, 1), valid_field_element(0x22));
        assert_eq!(tree.get_node(0, 2), valid_field_element(0x33));

        // Verify root is computed
        assert_ne!(tree.root(), B256::ZERO);
    }

    #[test]
    fn test_count_block_leaves() {
        let state_manager = Arc::new(Mutex::new(StateManager::in_memory().unwrap()));
        let root_tree_tracker = Arc::new(RwLock::new(HierarchicalRootTracker::new()));
        let sync_state = SyncState::new(state_manager, root_tree_tracker);

        // Block with 2 deposit groups and 1 transaction = 9 leaves
        let parsed_block = ParsedBlock {
            deposit_groups: vec![
                ParsedDepositGroup {
                    leaf0: B256::ZERO,
                    leaf1: B256::ZERO,
                    leaf2: B256::ZERO,
                    new_root: B256::ZERO,
                },
                ParsedDepositGroup {
                    leaf0: B256::ZERO,
                    leaf1: B256::ZERO,
                    leaf2: B256::ZERO,
                    new_root: B256::ZERO,
                },
            ],
            transactions: vec![ParsedTransaction {
                proof: Groth16Proof::default(),
                anchor_info: B256::ZERO,
                nullifier0: B256::ZERO,
                nullifier1: B256::ZERO,
                leaf0: B256::ZERO,
                leaf1: B256::ZERO,
                leaf2: B256::ZERO,
                new_root: B256::ZERO,
            }],
            num_deposits: 6,
        };

        assert_eq!(sync_state.count_block_leaves(&parsed_block), 9);
    }

    #[test]
    fn test_get_leaf_at_index() {
        let state_manager = Arc::new(Mutex::new(StateManager::in_memory().unwrap()));
        let root_tree_tracker = Arc::new(RwLock::new(HierarchicalRootTracker::new()));
        let sync_state = SyncState::new(state_manager, root_tree_tracker);

        let parsed_block = ParsedBlock {
            deposit_groups: vec![ParsedDepositGroup {
                leaf0: B256::repeat_byte(0x11),
                leaf1: B256::repeat_byte(0x22),
                leaf2: B256::repeat_byte(0x33),
                new_root: B256::ZERO,
            }],
            transactions: vec![ParsedTransaction {
                proof: Groth16Proof::default(),
                anchor_info: B256::ZERO,
                nullifier0: B256::ZERO,
                nullifier1: B256::ZERO,
                leaf0: B256::repeat_byte(0x44),
                leaf1: B256::repeat_byte(0x55),
                leaf2: B256::repeat_byte(0x66),
                new_root: B256::ZERO,
            }],
            num_deposits: 3,
        };

        // Deposit leaves
        assert_eq!(
            sync_state.get_leaf_at_index(&parsed_block, 0),
            Some(B256::repeat_byte(0x11))
        );
        assert_eq!(
            sync_state.get_leaf_at_index(&parsed_block, 1),
            Some(B256::repeat_byte(0x22))
        );
        assert_eq!(
            sync_state.get_leaf_at_index(&parsed_block, 2),
            Some(B256::repeat_byte(0x33))
        );

        // Transaction leaves
        assert_eq!(
            sync_state.get_leaf_at_index(&parsed_block, 3),
            Some(B256::repeat_byte(0x44))
        );
        assert_eq!(
            sync_state.get_leaf_at_index(&parsed_block, 4),
            Some(B256::repeat_byte(0x55))
        );
        assert_eq!(
            sync_state.get_leaf_at_index(&parsed_block, 5),
            Some(B256::repeat_byte(0x66))
        );

        // Out of bounds
        assert_eq!(sync_state.get_leaf_at_index(&parsed_block, 6), None);
    }

    #[test]
    fn test_block_tree_proof_consistency() {
        let state_manager = Arc::new(Mutex::new(StateManager::in_memory().unwrap()));
        let root_tree_tracker = Arc::new(RwLock::new(HierarchicalRootTracker::new()));
        let sync_state = SyncState::new(state_manager, root_tree_tracker);

        // Create a block with known leaves using valid field elements
        let parsed_block = ParsedBlock {
            deposit_groups: vec![ParsedDepositGroup {
                leaf0: valid_field_element(0x11),
                leaf1: valid_field_element(0x22),
                leaf2: valid_field_element(0x33),
                new_root: B256::ZERO,
            }],
            transactions: vec![],
            num_deposits: 3,
        };

        let tree = sync_state.build_block_tree(&parsed_block);
        let expected_root = tree.root();

        // Get proof for leaf 0 and verify it computes to the same root
        let proof = tree.get_proof(0).unwrap();
        let computed_root = proof.compute_root(valid_field_element(0x11));

        assert_eq!(computed_root, expected_root);
    }
}
