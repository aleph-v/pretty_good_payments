//! State for serving sync API endpoints.
//!
//! This module provides the server-side logic for the hierarchical merkle sync API.

use alloy::primitives::B256;
use pgp_challenger::validators::tree_update::RootTreeTracker;
use pgp_challenger::StateManager;
use pgp_merkle::{BlockRoot, DayRoot, TreePosition};
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;

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
/// This is a thin wrapper that provides read-only access to the tree state
/// for sync clients.
pub struct SyncState {
    state_manager: Arc<Mutex<StateManager>>,
    root_tree_tracker: Arc<RwLock<RootTreeTracker>>,
}

impl SyncState {
    /// Create a new SyncState.
    pub fn new(
        state_manager: Arc<Mutex<StateManager>>,
        root_tree_tracker: Arc<RwLock<RootTreeTracker>>,
    ) -> Self {
        Self {
            state_manager,
            root_tree_tracker,
        }
    }

    /// Get the genesis anchor (empty tree root).
    fn genesis_anchor() -> B256 {
        RootTreeTracker::new().current_anchor()
    }

    /// Serve GET /sync/status
    pub async fn get_sync_status(&self) -> SyncStatusResponse {
        let tracker = self.root_tree_tracker.read().await;

        let latest_block_nr = {
            let state = self.state_manager.lock().unwrap();
            state.get_latest_block_nr().ok().flatten().unwrap_or(0)
        };
        let latest_day = tracker.latest_day().unwrap_or(0);
        let latest_block_in_day = tracker.latest_block_in_day(latest_day).unwrap_or(0);

        SyncStatusResponse {
            latest_block_nr,
            latest_day,
            latest_block_in_day,
            current_anchor: tracker.current_anchor(),
            genesis_anchor: Self::genesis_anchor(),
        }
    }

    /// Serve GET /sync/day-roots
    pub async fn get_day_roots(&self, from_day: u16, to_day: u16) -> DayRootsResponse {
        let tracker = self.root_tree_tracker.read().await;

        let day_roots = tracker.get_day_roots_range(from_day, to_day);

        DayRootsResponse {
            day_roots,
            current_anchor: tracker.current_anchor(),
        }
    }

    /// Serve GET /sync/block-roots
    pub async fn get_block_roots(&self, day: u16) -> BlockRootsResponse {
        let tracker = self.root_tree_tracker.read().await;

        let block_roots = tracker.get_block_roots_for_day(day);
        let day_root = tracker.get_day_root(day);

        BlockRootsResponse {
            day,
            block_roots,
            day_root,
        }
    }

    /// Serve GET /sync/day-path
    pub async fn get_day_path(&self, day: u16) -> DayPathResponse {
        let tracker = self.root_tree_tracker.read().await;

        let day_path = tracker.get_day_path(day);
        let day_root = tracker.get_day_root(day);

        DayPathResponse {
            day,
            day_path,
            day_root,
            current_anchor: tracker.current_anchor(),
        }
    }

    /// Serve GET /sync/block-path
    pub async fn get_block_path(&self, day: u16, block_in_day: u16) -> BlockInDayPathResponse {
        let tracker = self.root_tree_tracker.read().await;

        let block_path = tracker.get_block_in_day_path(day, block_in_day);
        let block_root = tracker
            .get_block_root_at(day, block_in_day)
            .unwrap_or(B256::ZERO);
        let day_root = tracker.get_day_root(day);

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
    /// This requires access to the block tree state which is stored in the StateManager.
    /// For now, return a placeholder - full implementation would store block tree state.
    pub async fn get_block_tree_proof(
        &self,
        block_nr: u64,
        leaf_index: u32,
    ) -> Option<BlockTreeProofResponse> {
        // This would require storing block tree state in the database
        // For now, return None to indicate this endpoint isn't fully implemented
        let _ = (block_nr, leaf_index);
        None
    }

    /// Serve GET /sync/full-proof
    ///
    /// This combines block tree proof with day/block-in-day paths.
    /// Requires block tree state storage for full implementation.
    pub async fn get_full_proof(
        &self,
        block_nr: u64,
        leaf_index: u32,
    ) -> Option<FullProofResponse> {
        // This would require storing block tree state in the database
        // For now, return None to indicate this endpoint isn't fully implemented
        let _ = (block_nr, leaf_index);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sync_state_genesis() {
        let state_manager = Arc::new(Mutex::new(StateManager::in_memory().unwrap()));
        let root_tree = Arc::new(RwLock::new(RootTreeTracker::new()));
        let sync_state = SyncState::new(state_manager, root_tree);

        let status = sync_state.get_sync_status().await;

        assert_eq!(status.latest_block_nr, 0);
        assert_eq!(status.latest_day, 0);
        assert_eq!(status.current_anchor, status.genesis_anchor);
    }
}
