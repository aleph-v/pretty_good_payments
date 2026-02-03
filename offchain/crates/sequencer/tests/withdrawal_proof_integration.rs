//! Integration test for the withdrawal proof API endpoint.
//!
//! This test verifies:
//! 1. The /withdrawal-proof endpoint can find a leaf commitment in a stored block
//! 2. The KZG proof generated is valid and has the correct format
//!
//! Note: This test requires the circuit files to be compiled.

use alloy::primitives::{Address, B256, U256};
use eyre::Result;
use std::path::PathBuf;
use std::sync::Arc;

use pgp_challenger::StateManager;
use pgp_common::contracts::{BlockData, TimestampAndIndex};
use pgp_sequencer::api::{
    create_router, ApiState, WithdrawalProofRequest, WithdrawalProofResponse,
};
use pgp_sequencer::{Mempool, MempoolConfig};

use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

// ============================================================================
// Test Helpers
// ============================================================================

fn find_project_root() -> PathBuf {
    // Navigate from offchain/crates/sequencer/tests to project root
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn circuits_path() -> PathBuf {
    find_project_root().join("circuits/outputs")
}

/// Create a test verifier using the real verification keys.
/// Returns None if the verification key files are not found.
fn create_test_verifier() -> Option<pgp_challenger::Groth16Verifier> {
    let circuits = circuits_path();
    let transfer_vk = circuits.join("transfer/transferVKey.json");
    let update_vk = circuits.join("predictableUpdate/predictableUpdateVKey.json");

    if !transfer_vk.exists() || !update_vk.exists() {
        return None;
    }

    pgp_challenger::Groth16Verifier::new(&transfer_vk, &update_vk).ok()
}

/// Create a test mempool with the given StateManager.
fn create_test_mempool(state: StateManager) -> Option<Arc<Mempool>> {
    let verifier = create_test_verifier()?;
    Some(Arc::new(Mempool::new(
        MempoolConfig::default(),
        state,
        verifier,
    )))
}

// ============================================================================
// Tests
// ============================================================================

/// Test the withdrawal proof endpoint returns not found for missing block.
#[tokio::test]
async fn test_withdrawal_proof_block_not_found() -> Result<()> {
    let state = StateManager::in_memory()?;
    let Some(mempool) = create_test_mempool(state) else {
        eprintln!("Skipping test: verification keys not found");
        return Ok(());
    };

    let api_state = Arc::new(ApiState::new(mempool));
    let router = create_router(api_state);

    // Request for a block that doesn't exist
    let request = WithdrawalProofRequest {
        leaf_commitment: B256::repeat_byte(0x42),
        block_nr: 999,
    };
    let body = serde_json::to_string(&request)?;

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/withdrawal-proof")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await?;

    let status = response.status();
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    let proof_response: WithdrawalProofResponse = serde_json::from_slice(&body_bytes)?;

    assert_eq!(status.as_u16(), 404, "Should return 404 for missing block");
    assert!(!proof_response.found, "Should not find the leaf");
    assert!(
        proof_response.message.contains("not found"),
        "Message should indicate not found"
    );

    println!("Block not found test passed!");
    Ok(())
}

/// Test the withdrawal proof endpoint with properly stored blob data.
///
/// This test manually stores blob and block data to verify the full flow.
#[tokio::test]
async fn test_withdrawal_proof_with_stored_data() -> Result<()> {
    let state = StateManager::in_memory()?;

    // Create a simple blob with 131072 bytes (4096 * 32 byte fields)
    let mut blob_data = vec![0u8; 131072];

    // Put a known leaf value at field 11 (position of leaf0 for tx 0 with 0 deposits)
    // Transaction layout: 8 proof fields + 1 anchor_info + 2 nullifiers + 3 leaves + 1 new_root = 15 fields
    // leaf0 is at position 11 (8+1+2=11)
    let test_leaf = B256::repeat_byte(0x42);
    let leaf_position = 11 * 32; // Field 11
    blob_data[leaf_position..leaf_position + 32].copy_from_slice(test_leaf.as_slice());

    // Create a versioned hash for the blob
    let versioned_hash = B256::repeat_byte(0x01);

    // Save the blob to state
    state.save_blob(versioned_hash, &blob_data, 100)?;

    // Create block data
    let block_data = BlockData {
        anchor: B256::repeat_byte(0xAA),
        timestamp: U256::from(1234567890u64),
        numTransactions: U256::from(1u64),
        numDeposits: U256::ZERO,
        blockNr: U256::from(1u64),
        blockIndex: TimestampAndIndex {
            day: 0u128,
            index: 0u128,
        },
        sequencer: Address::repeat_byte(0xBB),
        blobhashes: vec![versioned_hash],
    };

    // Save block data to state
    state.save_block_data(&block_data, 100)?;

    // Create mempool with this state
    let Some(mempool) = create_test_mempool(state) else {
        eprintln!("Skipping test: verification keys not found");
        return Ok(());
    };

    // Create API router
    let api_state = Arc::new(ApiState::new(mempool));
    let router = create_router(api_state);

    // Request withdrawal proof for the known leaf
    let request = WithdrawalProofRequest {
        leaf_commitment: test_leaf,
        block_nr: 1,
    };
    let body = serde_json::to_string(&request)?;

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/withdrawal-proof")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await?;

    let status = response.status();
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    let response_text = String::from_utf8_lossy(&body_bytes);
    println!("Response status: {status}");
    println!("Response body: {response_text}");

    let proof_response: WithdrawalProofResponse = serde_json::from_slice(&body_bytes)?;

    // Verify the response
    assert!(proof_response.found, "Should find the leaf commitment");
    assert_eq!(proof_response.tx_nr, Some(0), "Should be tx 0");
    assert_eq!(proof_response.which, Some(0), "Should be output 0 (leaf0)");
    assert!(
        proof_response.commitment.is_some(),
        "Should have KZG commitment"
    );
    assert!(proof_response.proof.is_some(), "Should have KZG proof");

    // Verify commitment and proof are properly formatted
    let commitment = proof_response.commitment.unwrap();
    let proof = proof_response.proof.unwrap();
    assert!(
        commitment.starts_with("0x"),
        "Commitment should be hex encoded"
    );
    assert!(proof.starts_with("0x"), "Proof should be hex encoded");

    // Commitment is 48 bytes = 96 hex chars + "0x"
    assert_eq!(
        commitment.len(),
        98,
        "Commitment should be 48 bytes (98 chars with 0x)"
    );
    // Proof is 48 bytes = 96 hex chars + "0x"
    assert_eq!(
        proof.len(),
        98,
        "Proof should be 48 bytes (98 chars with 0x)"
    );

    println!("Withdrawal proof generated successfully!");
    println!("  tx_nr: {}", proof_response.tx_nr.unwrap());
    println!("  which: {}", proof_response.which.unwrap());
    println!("  commitment: {}", commitment);
    println!("  proof: {}", proof);

    Ok(())
}

/// Test withdrawal proof for leaf1 (second output of a transaction).
#[tokio::test]
async fn test_withdrawal_proof_leaf1() -> Result<()> {
    let state = StateManager::in_memory()?;

    let mut blob_data = vec![0u8; 131072];

    // Put leaf1 at field 12 (leaf0 at 11, leaf1 at 12)
    let test_leaf = B256::repeat_byte(0x55);
    let leaf_position = 12 * 32; // Field 12
    blob_data[leaf_position..leaf_position + 32].copy_from_slice(test_leaf.as_slice());

    let versioned_hash = B256::repeat_byte(0x02);
    state.save_blob(versioned_hash, &blob_data, 100)?;

    let block_data = BlockData {
        anchor: B256::repeat_byte(0xAA),
        timestamp: U256::from(1234567890u64),
        numTransactions: U256::from(1u64),
        numDeposits: U256::ZERO,
        blockNr: U256::from(2u64),
        blockIndex: TimestampAndIndex {
            day: 0u128,
            index: 1u128,
        },
        sequencer: Address::repeat_byte(0xBB),
        blobhashes: vec![versioned_hash],
    };

    state.save_block_data(&block_data, 100)?;

    let Some(mempool) = create_test_mempool(state) else {
        eprintln!("Skipping test: verification keys not found");
        return Ok(());
    };

    let api_state = Arc::new(ApiState::new(mempool));
    let router = create_router(api_state);

    let request = WithdrawalProofRequest {
        leaf_commitment: test_leaf,
        block_nr: 2,
    };
    let body = serde_json::to_string(&request)?;

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/withdrawal-proof")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await?;

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    let proof_response: WithdrawalProofResponse = serde_json::from_slice(&body_bytes)?;

    assert!(proof_response.found, "Should find the leaf commitment");
    assert_eq!(proof_response.tx_nr, Some(0), "Should be tx 0");
    assert_eq!(proof_response.which, Some(1), "Should be output 1 (leaf1)");

    println!("Leaf1 withdrawal proof test passed!");
    Ok(())
}

/// Test withdrawal proof for a leaf not in the block.
#[tokio::test]
async fn test_withdrawal_proof_leaf_not_found() -> Result<()> {
    let state = StateManager::in_memory()?;

    let blob_data = vec![0u8; 131072]; // All zeros, no matching leaf

    let versioned_hash = B256::repeat_byte(0x03);
    state.save_blob(versioned_hash, &blob_data, 100)?;

    let block_data = BlockData {
        anchor: B256::repeat_byte(0xAA),
        timestamp: U256::from(1234567890u64),
        numTransactions: U256::from(1u64),
        numDeposits: U256::ZERO,
        blockNr: U256::from(3u64),
        blockIndex: TimestampAndIndex {
            day: 0u128,
            index: 2u128,
        },
        sequencer: Address::repeat_byte(0xBB),
        blobhashes: vec![versioned_hash],
    };

    state.save_block_data(&block_data, 100)?;

    let Some(mempool) = create_test_mempool(state) else {
        eprintln!("Skipping test: verification keys not found");
        return Ok(());
    };

    let api_state = Arc::new(ApiState::new(mempool));
    let router = create_router(api_state);

    // Request a leaf that doesn't exist in the block
    let request = WithdrawalProofRequest {
        leaf_commitment: B256::repeat_byte(0xFF),
        block_nr: 3,
    };
    let body = serde_json::to_string(&request)?;

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/withdrawal-proof")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await?;

    let status = response.status();
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    let proof_response: WithdrawalProofResponse = serde_json::from_slice(&body_bytes)?;

    assert_eq!(status.as_u16(), 404, "Should return 404 for missing leaf");
    assert!(!proof_response.found, "Should not find the leaf");
    assert!(
        proof_response.message.contains("not found"),
        "Message should indicate not found"
    );

    println!("Leaf not found test passed!");
    Ok(())
}

/// Test withdrawal proof with multiple transactions.
#[tokio::test]
async fn test_withdrawal_proof_second_transaction() -> Result<()> {
    let state = StateManager::in_memory()?;

    let mut blob_data = vec![0u8; 131072];

    // First transaction uses fields 0-14, second starts at 15
    // Second tx leaf0 is at position 15 + 11 = 26
    // Note: Use byte < 0x73 to stay within BLS12-381 field element bounds
    let test_leaf = B256::repeat_byte(0x66);
    let leaf_position = 26 * 32; // Field 26 = second tx's leaf0
    blob_data[leaf_position..leaf_position + 32].copy_from_slice(test_leaf.as_slice());

    // Debug: verify the data is in the right place
    println!("Test leaf: {test_leaf}");
    println!("Leaf position (bytes): {leaf_position}");
    println!("Leaf position (field): {}", leaf_position / 32);

    let versioned_hash = B256::repeat_byte(0x04);
    state.save_blob(versioned_hash, &blob_data, 100)?;

    let block_data = BlockData {
        anchor: B256::repeat_byte(0xAA),
        timestamp: U256::from(1234567890u64),
        numTransactions: U256::from(2u64), // Two transactions
        numDeposits: U256::ZERO,
        blockNr: U256::from(4u64),
        blockIndex: TimestampAndIndex {
            day: 0u128,
            index: 3u128,
        },
        sequencer: Address::repeat_byte(0xBB),
        blobhashes: vec![versioned_hash],
    };

    state.save_block_data(&block_data, 100)?;

    // Debug: verify blob retrieval
    let retrieved_blob = state.load_blob(versioned_hash)?;
    assert!(retrieved_blob.is_some(), "Blob should be retrievable");
    let retrieved_blob = retrieved_blob.unwrap();
    let field_26_bytes = &retrieved_blob[leaf_position..leaf_position + 32];
    let field_26 = B256::from_slice(field_26_bytes);
    println!("Retrieved field 26: {field_26}");
    assert_eq!(field_26, test_leaf, "Field 26 should contain test leaf");

    let Some(mempool) = create_test_mempool(state) else {
        eprintln!("Skipping test: verification keys not found");
        return Ok(());
    };

    let api_state = Arc::new(ApiState::new(mempool));
    let router = create_router(api_state);

    let request = WithdrawalProofRequest {
        leaf_commitment: test_leaf,
        block_nr: 4,
    };
    let body = serde_json::to_string(&request)?;

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/withdrawal-proof")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await?;

    let status = response.status();
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    let response_text = String::from_utf8_lossy(&body_bytes);
    println!("Response status: {status}");
    println!("Response body: {response_text}");

    let proof_response: WithdrawalProofResponse = serde_json::from_slice(&body_bytes)?;

    assert!(proof_response.found, "Should find the leaf commitment");
    assert_eq!(proof_response.tx_nr, Some(1), "Should be tx 1 (second tx)");
    assert_eq!(proof_response.which, Some(0), "Should be output 0 (leaf0)");

    println!("Second transaction withdrawal proof test passed!");
    Ok(())
}
