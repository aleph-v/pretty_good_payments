//! REST API for the sequencer.
//!
//! Provides endpoints for:
//! - Submitting transactions to the mempool
//! - Syncing merkle proofs for clients
//! - Generating withdrawal proofs

use crate::mempool::{AddResult, Mempool, MempoolStats, ValidationError};
use crate::sync_state::SyncState;
use alloy_primitives::B256;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use pgp_challenger::{memory, KzgProver};
use pgp_common::blob::ParsedBlock;
use pgp_common::contracts::BlockData;
use pgp_common::types::ParsedTransaction;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Shared state for the API handlers.
pub struct ApiState {
    /// The transaction mempool.
    pub mempool: Arc<Mempool>,
    /// Sync state for merkle proof endpoints (optional - not available in all test contexts).
    pub sync_state: Option<Arc<SyncState>>,
}

impl ApiState {
    /// Create new API state with the given mempool.
    pub fn new(mempool: Arc<Mempool>) -> Self {
        Self {
            mempool,
            sync_state: None,
        }
    }

    /// Create new API state with mempool and sync state.
    pub fn with_sync(mempool: Arc<Mempool>, sync_state: Arc<SyncState>) -> Self {
        Self {
            mempool,
            sync_state: Some(sync_state),
        }
    }
}

/// Request body for transaction submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTxRequest {
    /// The transaction to submit.
    pub transaction: ParsedTransaction,
}

/// Response for transaction submission.
#[derive(Debug, Clone, Serialize)]
pub struct SubmitTxResponse {
    /// Whether the transaction was accepted.
    pub accepted: bool,
    /// Human-readable status message.
    pub message: String,
    /// Current mempool size after this operation.
    pub mempool_size: usize,
}

/// Response for mempool status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolStatusResponse {
    /// Number of pending transactions.
    pub pending: usize,
    /// Maximum allowed pending transactions.
    pub max_pending: usize,
    /// Age of the oldest transaction in milliseconds.
    pub oldest_age_ms: Option<u64>,
    /// Number of full blobs worth of transactions.
    pub blobs_worth: usize,
    /// Whether there are enough transactions for at least one blob.
    pub ready_for_block: bool,
}

impl From<MempoolStats> for MempoolStatusResponse {
    fn from(stats: MempoolStats) -> Self {
        Self {
            pending: stats.pending,
            max_pending: stats.max_pending,
            oldest_age_ms: stats.oldest_age_ms,
            blobs_worth: stats.blobs_worth,
            ready_for_block: stats.blobs_worth > 0,
        }
    }
}

/// Health check response.
#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    /// Service status.
    pub status: String,
}

/// Response for poke (trigger block submission).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PokeResponse {
    /// Whether the trigger was accepted.
    pub triggered: bool,
    /// Human-readable status message.
    pub message: String,
    /// Current mempool size.
    pub mempool_size: usize,
}

/// Request body for withdrawal proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalProofRequest {
    /// The leaf commitment to find.
    pub leaf_commitment: B256,
    /// The block number containing the transaction.
    pub block_nr: u64,
}

/// Response for withdrawal proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalProofResponse {
    /// Whether the proof was found.
    pub found: bool,
    /// Human-readable message.
    pub message: String,
    /// Block data needed for L1 withdrawal (serialized).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_data: Option<BlockDataResponse>,
    /// Transaction index within the block.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_nr: Option<u64>,
    /// Output index within the transaction (0, 1, or 2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub which: Option<u8>,
    /// 48-byte KZG commitment (hex encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    /// 48-byte KZG proof (hex encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
}

/// Serializable representation of BlockData for the API response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockDataResponse {
    /// Anchor hash.
    pub anchor: B256,
    /// Block timestamp.
    pub timestamp: String,
    /// Number of transactions.
    pub num_transactions: u64,
    /// Number of deposits.
    pub num_deposits: u64,
    /// Block number.
    pub block_nr: u64,
    /// Day index.
    pub day: u64,
    /// Block index within day.
    pub block_in_day: u64,
    /// Sequencer address.
    pub sequencer: String,
    /// Blob hashes.
    pub blobhashes: Vec<B256>,
}

impl From<BlockData> for BlockDataResponse {
    fn from(data: BlockData) -> Self {
        Self {
            anchor: data.anchor,
            timestamp: data.timestamp.to_string(),
            num_transactions: data.numTransactions.try_into().unwrap_or(0),
            num_deposits: data.numDeposits.try_into().unwrap_or(0),
            block_nr: data.blockNr.try_into().unwrap_or(0),
            day: data.blockIndex.day as u64,
            block_in_day: data.blockIndex.index as u64,
            sequencer: format!("0x{}", hex::encode(data.sequencer)),
            blobhashes: data.blobhashes,
        }
    }
}

/// Create the API router.
pub fn create_router(state: Arc<ApiState>) -> Router {
    Router::new()
        // Transaction endpoints
        .route("/tx", post(submit_tx))
        .route("/mempool", get(mempool_status))
        .route("/health", get(health_check))
        .route("/poke", post(poke))
        .route("/withdrawal-proof", post(withdrawal_proof))
        // Sync endpoints
        .route("/sync/status", get(sync_status))
        .route("/sync/day-roots", get(sync_day_roots))
        .route("/sync/block-roots", get(sync_block_roots))
        .route("/sync/day-path", get(sync_day_path))
        .route("/sync/block-path", get(sync_block_path))
        .route("/sync/block-tree-proof", get(sync_block_tree_proof))
        .route("/sync/full-proof", get(sync_full_proof))
        .with_state(state)
}

/// POST /tx - Submit a transaction to the mempool.
async fn submit_tx(
    State(state): State<Arc<ApiState>>,
    Json(request): Json<SubmitTxRequest>,
) -> impl IntoResponse {
    debug!("Received transaction submission");

    let result = state.mempool.add(request.transaction).await;
    let mempool_size = state.mempool.len().await;

    match result {
        AddResult::Accepted => {
            debug!("Transaction accepted, mempool size: {}", mempool_size);
            (
                StatusCode::OK,
                Json(SubmitTxResponse {
                    accepted: true,
                    message: "Transaction accepted".to_string(),
                    mempool_size,
                }),
            )
        }
        AddResult::MempoolFull => {
            warn!(
                "Transaction rejected: mempool full (size: {})",
                mempool_size
            );
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(SubmitTxResponse {
                    accepted: false,
                    message: "Mempool is full, try again later".to_string(),
                    mempool_size,
                }),
            )
        }
        AddResult::ValidationFailed(error) => {
            let message = match &error {
                ValidationError::NullifierAlreadySpent {
                    nullifier,
                    block_nr,
                    tx_index,
                } => {
                    warn!(
                        "Transaction rejected: nullifier {} already spent in block {} tx {}",
                        nullifier, block_nr, tx_index
                    );
                    format!(
                        "Nullifier {nullifier} already spent in block {block_nr} transaction {tx_index}"
                    )
                }
                ValidationError::NullifierPending { nullifier } => {
                    warn!(
                        "Transaction rejected: nullifier {} already pending",
                        nullifier
                    );
                    format!("Nullifier {nullifier} already pending in mempool")
                }
                ValidationError::DuplicateNullifiersInTx { nullifier } => {
                    warn!(
                        "Transaction rejected: duplicate nullifier {} in tx",
                        nullifier
                    );
                    format!("Transaction contains duplicate nullifier {nullifier}")
                }
                ValidationError::AnchorBlockInFuture {
                    referenced_block,
                    latest_block,
                } => {
                    warn!(
                        "Transaction rejected: anchor references block {} but latest is {}",
                        referenced_block, latest_block
                    );
                    format!(
                        "Anchor references future block {referenced_block} (latest: {latest_block})"
                    )
                }
                ValidationError::AnchorUpdateOutOfBounds {
                    block_nr,
                    update_nr,
                    is_deposit,
                    max_update_nr,
                } => {
                    warn!(
                        "Transaction rejected: anchor update_nr {} out of bounds for block {} is_deposit={} (max: {:?})",
                        update_nr, block_nr, is_deposit, max_update_nr
                    );
                    format!(
                        "Anchor update_nr {update_nr} out of bounds for block {block_nr} (max: {max_update_nr:?})"
                    )
                }
                ValidationError::AnchorNotFound {
                    block_nr,
                    update_nr,
                    is_deposit,
                } => {
                    warn!(
                        "Transaction rejected: anchor not found for block={} update={} is_deposit={}",
                        block_nr, update_nr, is_deposit
                    );
                    format!(
                        "Anchor not found: block={block_nr}, update={update_nr}, is_deposit={is_deposit}"
                    )
                }
                ValidationError::InvalidZkProof { reason } => {
                    warn!("Transaction rejected: invalid ZK proof - {}", reason);
                    format!("Invalid ZK proof: {reason}")
                }
            };
            (
                StatusCode::BAD_REQUEST,
                Json(SubmitTxResponse {
                    accepted: false,
                    message,
                    mempool_size,
                }),
            )
        }
        AddResult::DatabaseError(error) => {
            tracing::error!("Database error during validation: {}", error);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SubmitTxResponse {
                    accepted: false,
                    message: "Internal error during validation".to_string(),
                    mempool_size,
                }),
            )
        }
    }
}

/// GET /mempool - Get mempool status.
async fn mempool_status(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let stats = state.mempool.stats().await;
    (StatusCode::OK, Json(MempoolStatusResponse::from(stats)))
}

/// GET /health - Health check endpoint.
async fn health_check() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "ok".to_string(),
        }),
    )
}

/// POST /poke - Trigger immediate block submission.
///
/// This endpoint signals the block builder to attempt submission with whatever
/// transactions are currently in the mempool, regardless of the minimum threshold.
/// The actual block building and submission happens asynchronously in the block
/// builder loop - this endpoint just sets a flag and returns immediately.
async fn poke(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    info!("Poke endpoint called - triggering block submission");

    let mempool_size = state.mempool.len().await;

    if mempool_size == 0 {
        return (
            StatusCode::OK,
            Json(PokeResponse {
                triggered: false,
                message: "Mempool is empty, nothing to submit".to_string(),
                mempool_size,
            }),
        );
    }

    // Set the trigger flag - block builder loop will pick this up
    state.mempool.trigger_submit();

    (
        StatusCode::OK,
        Json(PokeResponse {
            triggered: true,
            message: format!("Block submission triggered with {mempool_size} pending transactions"),
            mempool_size,
        }),
    )
}

/// POST /withdrawal-proof - Generate KZG proof for L1 withdrawal.
///
/// Given a leaf commitment and block number, this endpoint finds the transaction
/// output containing that commitment and generates the KZG proof needed for
/// the Withdraw.sol contract on L1.
///
/// Returns the BlockData, transaction index, output index, KZG commitment, and KZG proof.
async fn withdrawal_proof(
    State(state): State<Arc<ApiState>>,
    Json(request): Json<WithdrawalProofRequest>,
) -> impl IntoResponse {
    info!(
        "Withdrawal proof requested for leaf {} in block {}",
        request.leaf_commitment, request.block_nr
    );

    // Load block data
    let block_data = match state.mempool.load_block_data(request.block_nr).await {
        Ok(Some((data, _l1_block))) => data,
        Ok(None) => {
            warn!("Block {} not found", request.block_nr);
            return (
                StatusCode::NOT_FOUND,
                Json(WithdrawalProofResponse {
                    found: false,
                    message: format!("Block {} not found", request.block_nr),
                    block_data: None,
                    tx_nr: None,
                    which: None,
                    commitment: None,
                    proof: None,
                }),
            );
        }
        Err(e) => {
            warn!("Failed to load block {}: {}", request.block_nr, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(WithdrawalProofResponse {
                    found: false,
                    message: format!("Failed to load block: {}", e),
                    block_data: None,
                    tx_nr: None,
                    which: None,
                    commitment: None,
                    proof: None,
                }),
            );
        }
    };

    // Load blobs for this block
    let mut blob_data_vec: Vec<Vec<u8>> = Vec::new();
    for blobhash in &block_data.blobhashes {
        match state.mempool.load_blob(*blobhash).await {
            Ok(Some(data)) => blob_data_vec.push(data),
            Ok(None) => {
                warn!("Blob {} not found for block {}", blobhash, request.block_nr);
                return (
                    StatusCode::NOT_FOUND,
                    Json(WithdrawalProofResponse {
                        found: false,
                        message: format!("Blob {} not found", blobhash),
                        block_data: None,
                        tx_nr: None,
                        which: None,
                        commitment: None,
                        proof: None,
                    }),
                );
            }
            Err(e) => {
                warn!("Failed to load blob {}: {}", blobhash, e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(WithdrawalProofResponse {
                        found: false,
                        message: format!("Failed to load blob: {}", e),
                        block_data: None,
                        tx_nr: None,
                        which: None,
                        commitment: None,
                        proof: None,
                    }),
                );
            }
        }
    }

    if blob_data_vec.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            Json(WithdrawalProofResponse {
                found: false,
                message: "No blobs found for block".to_string(),
                block_data: None,
                tx_nr: None,
                which: None,
                commitment: None,
                proof: None,
            }),
        );
    }

    // Parse the blob data to find transactions
    // Convert raw bytes to B256 arrays for parsing
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

    let num_deposits: usize = block_data.numDeposits.try_into().unwrap_or(0);
    let num_transactions: usize = block_data.numTransactions.try_into().unwrap_or(0);

    let parsed_block =
        match ParsedBlock::from_blob_vecs(&blobs_b256, num_deposits, num_transactions) {
            Ok(block) => block,
            Err(e) => {
                warn!("Failed to parse block blob: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(WithdrawalProofResponse {
                        found: false,
                        message: format!("Failed to parse blob: {}", e),
                        block_data: None,
                        tx_nr: None,
                        which: None,
                        commitment: None,
                        proof: None,
                    }),
                );
            }
        };

    // Search for the leaf commitment in transaction outputs
    let mut found_tx_nr: Option<usize> = None;
    let mut found_which: Option<u8> = None;

    for (tx_idx, tx) in parsed_block.transactions.iter().enumerate() {
        if tx.leaf0 == request.leaf_commitment {
            found_tx_nr = Some(tx_idx);
            found_which = Some(0);
            break;
        }
        if tx.leaf1 == request.leaf_commitment {
            found_tx_nr = Some(tx_idx);
            found_which = Some(1);
            break;
        }
        if tx.leaf2 == request.leaf_commitment {
            found_tx_nr = Some(tx_idx);
            found_which = Some(2);
            break;
        }
    }

    let (tx_nr, which) = match (found_tx_nr, found_which) {
        (Some(t), Some(w)) => (t, w),
        _ => {
            warn!(
                "Leaf commitment {} not found in block {}",
                request.leaf_commitment, request.block_nr
            );
            return (
                StatusCode::NOT_FOUND,
                Json(WithdrawalProofResponse {
                    found: false,
                    message: format!(
                        "Leaf commitment {} not found in block {}",
                        request.leaf_commitment, request.block_nr
                    ),
                    block_data: None,
                    tx_nr: None,
                    which: None,
                    commitment: None,
                    proof: None,
                }),
            );
        }
    };

    // Calculate the memory address for this leaf
    let memory_address =
        memory::leaf_memory_address(tx_nr as u64, num_deposits as u64, false, which as u64);

    // Determine which blob contains this field
    let blob_index = memory_address as usize / 4096;
    let field_index = memory_address as usize % 4096;

    if blob_index >= blob_data_vec.len() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(WithdrawalProofResponse {
                found: false,
                message: format!(
                    "Memory address {} requires blob {} but only {} blobs available",
                    memory_address,
                    blob_index,
                    blob_data_vec.len()
                ),
                block_data: None,
                tx_nr: None,
                which: None,
                commitment: None,
                proof: None,
            }),
        );
    }

    // Generate KZG proof
    let kzg_prover = match KzgProver::new() {
        Ok(prover) => prover,
        Err(e) => {
            warn!("Failed to create KZG prover: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(WithdrawalProofResponse {
                    found: false,
                    message: format!("Failed to create KZG prover: {}", e),
                    block_data: None,
                    tx_nr: None,
                    which: None,
                    commitment: None,
                    proof: None,
                }),
            );
        }
    };

    let kzg_result = match kzg_prover.generate_proof(&blob_data_vec[blob_index], field_index) {
        Ok(proof) => proof,
        Err(e) => {
            warn!("Failed to generate KZG proof: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(WithdrawalProofResponse {
                    found: false,
                    message: format!("Failed to generate KZG proof: {}", e),
                    block_data: None,
                    tx_nr: None,
                    which: None,
                    commitment: None,
                    proof: None,
                }),
            );
        }
    };

    info!(
        "Generated withdrawal proof for tx {} output {} in block {}",
        tx_nr, which, request.block_nr
    );

    (
        StatusCode::OK,
        Json(WithdrawalProofResponse {
            found: true,
            message: "Withdrawal proof generated successfully".to_string(),
            block_data: Some(BlockDataResponse::from(block_data)),
            tx_nr: Some(tx_nr as u64),
            which: Some(which),
            commitment: Some(format!("0x{}", hex::encode(&kzg_result.commitment))),
            proof: Some(format!("0x{}", hex::encode(&kzg_result.proof))),
        }),
    )
}

// ============================================================================
// Sync API Handlers
// ============================================================================

/// Query params for day roots endpoint
#[derive(Debug, Deserialize)]
pub struct DayRootsQuery {
    pub from: u16,
    pub to: u16,
}

/// Query params for block roots endpoint
#[derive(Debug, Deserialize)]
pub struct BlockRootsQuery {
    pub day: u16,
}

/// Query params for day path endpoint
#[derive(Debug, Deserialize)]
pub struct DayPathQuery {
    pub day: u16,
}

/// Query params for block path endpoint
#[derive(Debug, Deserialize)]
pub struct BlockPathQuery {
    pub day: u16,
    pub block: u16,
}

/// Query params for block tree proof endpoint
#[derive(Debug, Deserialize)]
pub struct BlockTreeProofQuery {
    pub block_nr: u64,
    pub leaf_index: u32,
}

/// Query params for full proof endpoint
#[derive(Debug, Deserialize)]
pub struct FullProofQuery {
    pub block_nr: u64,
    pub leaf_index: u32,
}

/// GET /sync/status - Get current sync status
async fn sync_status(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let Some(sync_state) = &state.sync_state else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Sync state not available"})),
        );
    };

    let response = sync_state.get_sync_status().await;
    match serde_json::to_value(response) {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(e) => {
            warn!("Failed to serialize sync status response: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to serialize response"})),
            )
        }
    }
}

/// GET /sync/day-roots - Get day roots for a range
async fn sync_day_roots(
    State(state): State<Arc<ApiState>>,
    Query(params): Query<DayRootsQuery>,
) -> impl IntoResponse {
    let Some(sync_state) = &state.sync_state else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Sync state not available"})),
        );
    };

    let response = sync_state.get_day_roots(params.from, params.to).await;
    match serde_json::to_value(response) {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(e) => {
            warn!("Failed to serialize day roots response: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to serialize response"})),
            )
        }
    }
}

/// GET /sync/block-roots - Get block roots for a day
async fn sync_block_roots(
    State(state): State<Arc<ApiState>>,
    Query(params): Query<BlockRootsQuery>,
) -> impl IntoResponse {
    let Some(sync_state) = &state.sync_state else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Sync state not available"})),
        );
    };

    let response = sync_state.get_block_roots(params.day).await;
    match serde_json::to_value(response) {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(e) => {
            warn!("Failed to serialize block roots response: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to serialize response"})),
            )
        }
    }
}

/// GET /sync/day-path - Get day path for merkle proof
async fn sync_day_path(
    State(state): State<Arc<ApiState>>,
    Query(params): Query<DayPathQuery>,
) -> impl IntoResponse {
    let Some(sync_state) = &state.sync_state else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Sync state not available"})),
        );
    };

    let response = sync_state.get_day_path(params.day).await;
    match serde_json::to_value(response) {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(e) => {
            warn!("Failed to serialize day path response: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to serialize response"})),
            )
        }
    }
}

/// GET /sync/block-path - Get block-in-day path for merkle proof
async fn sync_block_path(
    State(state): State<Arc<ApiState>>,
    Query(params): Query<BlockPathQuery>,
) -> impl IntoResponse {
    let Some(sync_state) = &state.sync_state else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Sync state not available"})),
        );
    };

    let response = sync_state.get_block_path(params.day, params.block).await;
    match serde_json::to_value(response) {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(e) => {
            warn!("Failed to serialize block path response: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to serialize response"})),
            )
        }
    }
}

/// GET /sync/block-tree-proof - Get block tree proof for a leaf
async fn sync_block_tree_proof(
    State(state): State<Arc<ApiState>>,
    Query(params): Query<BlockTreeProofQuery>,
) -> impl IntoResponse {
    let Some(sync_state) = &state.sync_state else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Sync state not available"})),
        );
    };

    match sync_state
        .get_block_tree_proof(params.block_nr, params.leaf_index)
        .await
    {
        Some(response) => match serde_json::to_value(response) {
            Ok(value) => (StatusCode::OK, Json(value)),
            Err(e) => {
                warn!("Failed to serialize block tree proof response: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "Failed to serialize response"})),
                )
            }
        },
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Block tree proof not found"})),
        ),
    }
}

/// GET /sync/full-proof - Get full 44-level proof for a leaf
async fn sync_full_proof(
    State(state): State<Arc<ApiState>>,
    Query(params): Query<FullProofQuery>,
) -> impl IntoResponse {
    let Some(sync_state) = &state.sync_state else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Sync state not available"})),
        );
    };

    match sync_state
        .get_full_proof(params.block_nr, params.leaf_index)
        .await
    {
        Some(response) => match serde_json::to_value(response) {
            Ok(value) => (StatusCode::OK, Json(value)),
            Err(e) => {
                warn!("Failed to serialize full proof response: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "Failed to serialize response"})),
                )
            }
        },
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Full proof not found"})),
        ),
    }
}

/// Result of the API server task.
///
/// This is returned when the API server terminates, either normally or with an error.
#[derive(Debug)]
pub enum ApiServerResult {
    /// Server shut down gracefully
    Shutdown,
    /// Server encountered an error
    Error(String),
}

/// Start the API server without sync support.
///
/// This function spawns a Tokio task that runs the HTTP server.
/// It returns the task handle so it can be monitored or cancelled.
/// Note: Sync endpoints will return 503 Service Unavailable.
pub async fn start_api_server(
    listen_addr: &str,
    mempool: Arc<Mempool>,
) -> eyre::Result<tokio::task::JoinHandle<ApiServerResult>> {
    let state = Arc::new(ApiState::new(mempool));
    let router = create_router(state);

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    info!("API server listening on {}", listen_addr);

    let handle = tokio::spawn(async move {
        match axum::serve(listener, router).await {
            Ok(()) => {
                info!("API server shut down gracefully");
                ApiServerResult::Shutdown
            }
            Err(e) => {
                tracing::error!("API server error: {}", e);
                ApiServerResult::Error(e.to_string())
            }
        }
    });

    Ok(handle)
}

/// Start the API server with full sync support.
///
/// This version includes the SyncState for serving merkle proof endpoints.
pub async fn start_api_server_with_sync(
    listen_addr: &str,
    mempool: Arc<Mempool>,
    sync_state: Arc<SyncState>,
) -> eyre::Result<tokio::task::JoinHandle<ApiServerResult>> {
    let state = Arc::new(ApiState::with_sync(mempool, sync_state));
    let router = create_router(state);

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    info!(
        "API server listening on {} (with sync support)",
        listen_addr
    );

    let handle = tokio::spawn(async move {
        match axum::serve(listener, router).await {
            Ok(()) => {
                info!("API server (with sync) shut down gracefully");
                ApiServerResult::Shutdown
            }
            Err(e) => {
                tracing::error!("API server error: {}", e);
                ApiServerResult::Error(e.to_string())
            }
        }
    });

    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mempool::MempoolConfig;
    use alloy_primitives::B256;
    use axum::body::Body;
    use axum::http::Request;
    use pgp_challenger::{Groth16Verifier, StateManager};
    use std::path::PathBuf;
    use tower::ServiceExt;

    /// Path to the circuits directory from the project root
    fn circuits_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../circuits/outputs")
    }

    /// Create a test verifier using the real verification keys.
    fn create_test_verifier() -> Option<Groth16Verifier> {
        let circuits = circuits_path();
        let transfer_vk = circuits.join("transfer/transferVKey.json");
        let update_vk = circuits.join("predictableUpdate/predictableUpdateVKey.json");

        if !transfer_vk.exists() || !update_vk.exists() {
            return None;
        }

        Groth16Verifier::new(&transfer_vk, &update_vk).ok()
    }

    fn create_test_mempool() -> Option<Arc<Mempool>> {
        let verifier = create_test_verifier()?;
        let state = StateManager::in_memory().ok()?;
        Some(Arc::new(Mempool::new(
            MempoolConfig::default(),
            state,
            verifier,
        )))
    }

    fn create_test_mempool_with_config(config: MempoolConfig) -> Option<Arc<Mempool>> {
        let verifier = create_test_verifier()?;
        let state = StateManager::in_memory().ok()?;
        Some(Arc::new(Mempool::new(config, state, verifier)))
    }

    /// Create a test transaction with unique nullifiers.
    fn make_test_tx(id: u8) -> ParsedTransaction {
        let base = (id as u16) * 10;
        ParsedTransaction {
            nullifier0: B256::from_slice(
                &[0u8; 31]
                    .into_iter()
                    .chain(std::iter::once(base as u8))
                    .collect::<Vec<_>>(),
            ),
            nullifier1: B256::from_slice(
                &[0u8; 31]
                    .into_iter()
                    .chain(std::iter::once((base + 1) as u8))
                    .collect::<Vec<_>>(),
            ),
            leaf0: B256::repeat_byte(id.wrapping_add(2)),
            leaf1: B256::repeat_byte(id.wrapping_add(3)),
            leaf2: B256::repeat_byte(id.wrapping_add(4)),
            ..Default::default()
        }
    }

    fn create_test_router() -> Option<(Router, Arc<Mempool>)> {
        let mempool = create_test_mempool()?;
        let state = Arc::new(ApiState::new(mempool.clone()));
        let router = create_router(state);
        Some((router, mempool))
    }

    #[tokio::test]
    async fn test_health_check() {
        let Some((router, _)) = create_test_router() else {
            eprintln!("Skipping test: verification keys not found");
            return;
        };

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_mempool_status() {
        let Some(mempool) = create_test_mempool() else {
            eprintln!("Skipping test: verification keys not found");
            return;
        };

        // Add transactions bypassing validation
        mempool.insert_unchecked(make_test_tx(1)).await;
        mempool.insert_unchecked(make_test_tx(2)).await;

        let state = Arc::new(ApiState::new(mempool));
        let router = create_router(state);

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/mempool")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let status: MempoolStatusResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(status.pending, 2);
    }

    #[tokio::test]
    async fn test_submit_tx_mempool_full() {
        let Some(mempool) = create_test_mempool_with_config(MempoolConfig { max_pending: 1 })
        else {
            eprintln!("Skipping test: verification keys not found");
            return;
        };

        // Fill the mempool bypassing validation
        mempool.insert_unchecked(make_test_tx(1)).await;

        let state = Arc::new(ApiState::new(mempool));
        let router = create_router(state);

        let tx = make_test_tx(2);
        let request = SubmitTxRequest { transaction: tx };
        let body = serde_json::to_string(&request).unwrap();

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tx")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_submit_tx_validation_error() {
        let Some((router, _mempool)) = create_test_router() else {
            eprintln!("Skipping test: verification keys not found");
            return;
        };

        // Create a transaction with duplicate nullifiers (fails early validation)
        let duplicate_null = B256::repeat_byte(0xAA);
        let tx = ParsedTransaction {
            nullifier0: duplicate_null,
            nullifier1: duplicate_null,
            ..Default::default()
        };
        let request = SubmitTxRequest { transaction: tx };
        let body = serde_json::to_string(&request).unwrap();

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tx")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_poke_endpoint() {
        let Some(mempool) = create_test_mempool() else {
            eprintln!("Skipping test: verification keys not found");
            return;
        };

        // Add a transaction so the mempool isn't empty (poke returns early if empty)
        mempool.insert_unchecked(make_test_tx(1)).await;

        let state = Arc::new(ApiState::new(mempool.clone()));
        let router = create_router(state);

        // Force flag should be false initially
        assert!(!mempool.check_and_clear_force_submit());

        // Poke the endpoint
        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/poke")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Force flag should now be true
        assert!(mempool.check_and_clear_force_submit());
    }

    #[tokio::test]
    async fn test_poke_empty_mempool() {
        let Some((router, mempool)) = create_test_router() else {
            eprintln!("Skipping test: verification keys not found");
            return;
        };

        // Mempool is empty, so poke should return early without setting flag
        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/poke")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify the response indicates nothing was triggered
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let poke_response: PokeResponse = serde_json::from_slice(&body).unwrap();
        assert!(!poke_response.triggered);
        assert_eq!(poke_response.mempool_size, 0);

        // Force flag should NOT be set for empty mempool
        assert!(!mempool.check_and_clear_force_submit());
    }
}
