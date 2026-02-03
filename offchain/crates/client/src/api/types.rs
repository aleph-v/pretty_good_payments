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

/// Request for POST /withdrawal-proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalProofRequest {
    /// The leaf commitment to find
    pub leaf_commitment: B256,
    /// The block number to search in
    pub block_nr: u64,
}

/// Block data response (from sequencer)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockDataResponse {
    /// Anchor hash
    pub anchor: B256,
    /// Block timestamp (as string)
    pub timestamp: String,
    /// Number of transactions
    pub num_transactions: u64,
    /// Number of deposits
    pub num_deposits: u64,
    /// Block number
    pub block_nr: u64,
    /// Day index
    pub day: u64,
    /// Block index within day
    pub block_in_day: u64,
    /// Sequencer address (as hex string)
    pub sequencer: String,
    /// Blob hashes
    pub blobhashes: Vec<B256>,
}

/// Response for POST /withdrawal-proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalProofResponse {
    /// Whether the proof was found
    pub found: bool,
    /// Human-readable message
    pub message: String,
    /// Block data needed for L1 withdrawal
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_data: Option<BlockDataResponse>,
    /// Transaction index within the block
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_nr: Option<u64>,
    /// Output index within the transaction (0, 1, or 2)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub which: Option<u8>,
    /// 48-byte KZG commitment (hex encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    /// 48-byte KZG proof (hex encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
}
