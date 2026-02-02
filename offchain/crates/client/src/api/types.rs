//! API request/response types for the sequencer sync API.

use alloy_primitives::B256;
use pgp_merkle::{BlockRoot, DayRoot, TreePosition};
use serde::{Deserialize, Serialize};

/// Response for GET /sync/status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatusResponse {
    /// Latest committed block number
    pub latest_block_nr: u64,
    /// Latest day with blocks
    pub latest_day: u16,
    /// Latest block index within the latest day
    pub latest_block_in_day: u16,
    /// Current global anchor (root tree root)
    pub current_anchor: B256,
    /// Genesis anchor (empty tree root)
    pub genesis_anchor: B256,
}

/// Response for GET /sync/day-roots
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DayRootsResponse {
    /// Day roots in the requested range
    pub day_roots: Vec<DayRoot>,
    /// Current anchor at time of response
    pub current_anchor: B256,
}

/// Response for GET /sync/block-roots
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRootsResponse {
    /// Day for which block roots are returned
    pub day: u16,
    /// Block roots for the day (only non-zero entries)
    pub block_roots: Vec<BlockRoot>,
    /// Day root for verification
    pub day_root: B256,
}

/// Response for GET /sync/day-path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DayPathResponse {
    /// Day for which the path is returned
    pub day: u16,
    /// 15-level path from day position to global root
    pub day_path: [B256; 15],
    /// Day subtree root
    pub day_root: B256,
    /// Current anchor at time of response
    pub current_anchor: B256,
}

/// Response for GET /sync/block-path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockInDayPathResponse {
    /// Day index
    pub day: u16,
    /// Block index within the day
    pub block_in_day: u16,
    /// 13-level path from block position to day root
    pub block_path: [B256; 13],
    /// Block tree root
    pub block_root: B256,
    /// Day subtree root
    pub day_root: B256,
}

/// Response for GET /sync/block-tree-proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockTreeProofResponse {
    /// Block number
    pub block_nr: u64,
    /// Leaf index within the block
    pub leaf_index: u32,
    /// The leaf value at this position
    pub leaf: B256,
    /// 16-level block tree proof
    pub block_siblings: [B256; 16],
    /// Block tree root
    pub block_root: B256,
    /// Full hierarchical position
    pub position: TreePosition,
}

/// Response for GET /sync/full-proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullProofResponse {
    /// Block number
    pub block_nr: u64,
    /// Leaf index within the block
    pub leaf_index: u32,
    /// Full hierarchical position
    pub position: TreePosition,
    /// The leaf value
    pub leaf: B256,
    /// 16-level block tree siblings
    pub block_siblings: [B256; 16],
    /// 13-level block-in-day siblings
    pub block_in_day_siblings: [B256; 13],
    /// 15-level day siblings
    pub day_siblings: [B256; 15],
    /// Current anchor at time of response
    pub current_anchor: B256,
}

/// Request for POST /tx (transaction submission)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTxRequest {
    /// The transaction to submit
    pub transaction: pgp_common::types::ParsedTransaction,
}

/// Response for POST /tx
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTxResponse {
    /// Whether the transaction was accepted
    pub accepted: bool,
    /// Human-readable status message
    pub message: String,
    /// Current mempool size
    pub mempool_size: usize,
}
