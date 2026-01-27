//! REST API for the sequencer.
//!
//! Provides endpoints for submitting transactions to the mempool.

use crate::mempool::{AddResult, Mempool, MempoolStats, ValidationError};
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use pgp_common::types::ParsedTransaction;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Shared state for the API handlers.
pub struct ApiState {
    /// The transaction mempool.
    pub mempool: Arc<Mempool>,
}

impl ApiState {
    /// Create new API state with the given mempool.
    pub fn new(mempool: Arc<Mempool>) -> Self {
        Self { mempool }
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

/// Create the API router.
pub fn create_router(state: Arc<ApiState>) -> Router {
    Router::new()
        .route("/tx", post(submit_tx))
        .route("/mempool", get(mempool_status))
        .route("/health", get(health_check))
        .route("/poke", post(poke))
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
            message: format!(
                "Block submission triggered with {mempool_size} pending transactions"
            ),
            mempool_size,
        }),
    )
}

/// Start the API server.
///
/// This function spawns a Tokio task that runs the HTTP server.
/// It returns the task handle so it can be monitored or cancelled.
pub async fn start_api_server(
    listen_addr: &str,
    mempool: Arc<Mempool>,
) -> eyre::Result<tokio::task::JoinHandle<()>> {
    let state = Arc::new(ApiState::new(mempool));
    let router = create_router(state);

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    info!("API server listening on {}", listen_addr);

    let handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, router).await {
            tracing::error!("API server error: {}", e);
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
