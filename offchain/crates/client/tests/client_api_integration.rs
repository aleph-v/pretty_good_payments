//! Integration tests for client API interactions.
//!
//! These tests verify the ACTUAL API endpoints used by the client:
//! 1. Sync API endpoints return correct data
//! 2. Transaction submission with ZK proof validation
//! 3. Full flow from proof generation to mempool acceptance
//!
//! Note: These tests use the real API handler functions (not HTTP),
//! but call them through the router to ensure the full API path is tested.

use alloy_primitives::{Address, B256, U256};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use eyre::Result;
use pgp_challenger::validators::tree_update::HierarchicalRootTracker;
use pgp_challenger::{Groth16Verifier, StateManager};
use pgp_client::cache::{CachedBlockRoots, ProofCache};
use pgp_client::commands::transfer::build_transfer;
use pgp_client::wallet::keys::{derive_public_key, derive_spending_key};
use pgp_client::wallet::notes::StoredProof;
use pgp_client::wallet::{TrackedNote, Wallet};
use pgp_common::types::ParsedTransaction;
use pgp_merkle::{
    hierarchy::{BLOCK_IN_DAY_DEPTH, BLOCK_TREE_DEPTH, DAY_TREE_DEPTH},
    BlockRoot, DayRoot, IncrementalMerkleTree, TreePosition,
};
use pgp_sequencer::api::{ApiState, SubmitTxRequest};
use pgp_sequencer::mempool::MempoolConfig;
use pgp_sequencer::sync_state::{
    BlockRootsResponse, DayRootsResponse, SyncState, SyncStatusResponse,
};
use pgp_sequencer::{create_router, Mempool};
use sha2::Digest;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tokio::sync::RwLock;
use tower::ServiceExt;

// ============================================================================
// Test Utilities
// ============================================================================

fn find_project_root() -> PathBuf {
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let mut path = PathBuf::from(manifest_dir);
        for _ in 0..3 {
            if path.join("foundry.toml").exists() {
                return path;
            }
            path = path.parent().unwrap_or(&path).to_path_buf();
        }
    }

    if let Ok(cwd) = std::env::current_dir() {
        let mut path = cwd;
        for _ in 0..5 {
            if path.join("foundry.toml").exists() {
                return path;
            }
            if let Some(parent) = path.parent() {
                path = parent.to_path_buf();
            } else {
                break;
            }
        }
    }

    PathBuf::from("/Users/pvienhage/dev/pretty_good_payments")
}

fn transfer_zkey_path() -> PathBuf {
    find_project_root().join("circuits/outputs/transfer/transfer.zkey")
}

fn transfer_vkey_path() -> PathBuf {
    find_project_root().join("circuits/outputs/transfer/transferVKey.json")
}

fn update_vkey_path() -> PathBuf {
    find_project_root().join("circuits/outputs/predictableUpdate/predictableUpdateVKey.json")
}

fn circuits_available() -> bool {
    transfer_zkey_path().exists()
}

fn vkeys_available() -> bool {
    transfer_vkey_path().exists() && update_vkey_path().exists()
}

fn snarkjs_available() -> bool {
    Command::new("npx")
        .args(["snarkjs", "--version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Ensure a B256 value is a valid BN254 field element
fn ensure_field_valid(value: B256) -> B256 {
    let mut bytes = value.0;
    bytes[0] &= 0x1F;
    B256::from(bytes)
}

/// Compute leaf hash: Poseidon4(asset, amount, blinding, publicKey)
fn compute_leaf_hash(asset: Address, amount: U256, blinding: B256, public_key: B256) -> B256 {
    pgp_merkle::compute_leaf_hash(asset, amount, blinding, public_key)
}

/// Create a test wallet with a deterministic seed
fn create_test_wallet(temp_dir: &TempDir, seed: &str) -> Wallet {
    let spending_key = derive_spending_key(seed);
    let wallet_path = temp_dir.path().join("wallet.json");
    let wallet = Wallet::from_spending_key(spending_key);
    wallet.save(&wallet_path).expect("Failed to save wallet");
    Wallet::load(&wallet_path).expect("Failed to load wallet")
}

/// Create a Groth16 verifier for test
fn create_test_verifier() -> Option<Groth16Verifier> {
    if !vkeys_available() {
        return None;
    }
    Groth16Verifier::new(&transfer_vkey_path(), &update_vkey_path()).ok()
}

// ============================================================================
// Test Setup Structures
// ============================================================================

/// Test setup with a merkle tree and notes
struct TestSetup {
    tree: IncrementalMerkleTree,
    anchor: B256,
    notes: Vec<NoteData>,
}

struct NoteData {
    asset: Address,
    amount: U256,
    blinding: B256,
    #[allow(dead_code)]
    public_key: B256,
    index: u64,
    leaf: B256,
}

impl TestSetup {
    fn new(public_key: B256, asset: Address, amounts: &[U256]) -> Self {
        let mut tree = IncrementalMerkleTree::new(BLOCK_TREE_DEPTH);
        let mut notes = Vec::new();

        for (i, &amount) in amounts.iter().enumerate() {
            let blinding =
                ensure_field_valid(B256::from(U256::from(0x100 + i as u64).to_be_bytes()));
            let leaf = compute_leaf_hash(asset, amount, blinding, public_key);
            tree.insert(leaf).expect("Tree insert failed");

            notes.push(NoteData {
                asset,
                amount,
                blinding,
                public_key,
                index: i as u64,
                leaf,
            });
        }

        let anchor = tree.root();
        Self {
            tree,
            anchor,
            notes,
        }
    }

    fn get_block_siblings(&self, index: usize) -> [B256; BLOCK_TREE_DEPTH] {
        let proof = self.tree.get_proof(index).expect("Failed to get proof");
        let mut siblings = [B256::ZERO; BLOCK_TREE_DEPTH];
        for (i, h) in proof.siblings.iter().enumerate() {
            if i < BLOCK_TREE_DEPTH {
                siblings[i] = *h;
            }
        }
        siblings
    }
}

/// Add notes to a wallet and create a matching proof cache
fn setup_wallet_and_cache(wallet: &mut Wallet, setup: &TestSetup, cache: &mut ProofCache) {
    for note in &setup.notes {
        let position = TreePosition::new(0, 0, note.index as u16);
        let block_siblings = setup.get_block_siblings(note.index as usize);

        let stored_proof = StoredProof::new_complete(
            block_siblings,
            setup.anchor,
            [B256::ZERO; BLOCK_IN_DAY_DEPTH],
            setup.anchor,
        );

        let tracked = TrackedNote {
            commitment: note.leaf,
            asset: note.asset,
            amount: note.amount,
            blinding: note.blinding,
            block_nr: 0,
            leaf_index: note.index as u32,
            position,
            spent: false,
            nullifier: None,
            stored_proof: Some(stored_proof),
        };
        wallet.add_note(tracked);
    }

    cache.set_last_sync(setup.anchor, 0, 0);
    cache.update_day_roots(&[DayRoot {
        day: 0,
        root: setup.anchor,
    }]);
    cache.set_current_day_block_roots(CachedBlockRoots {
        day: 0,
        block_roots: vec![BlockRoot {
            day: 0,
            block_in_day: 0,
            root: setup.anchor,
        }],
        day_root: setup.anchor,
        fetched_at_block_nr: 0,
        fetched_at_anchor: setup.anchor,
    });
}

/// Create a full API test context with all components
struct ApiTestContext {
    router: axum::Router,
    mempool: Arc<Mempool>,
    #[allow(dead_code)]
    sync_state: Arc<SyncState>,
    #[allow(dead_code)]
    state_manager: Arc<Mutex<StateManager>>,
    root_tree_tracker: Arc<RwLock<HierarchicalRootTracker>>,
}

impl ApiTestContext {
    fn new() -> Option<Self> {
        let verifier = create_test_verifier()?;
        let state_manager = Arc::new(Mutex::new(StateManager::in_memory().ok()?));
        let root_tree_tracker = Arc::new(RwLock::new(HierarchicalRootTracker::new()));
        let sync_state = Arc::new(SyncState::new(
            state_manager.clone(),
            root_tree_tracker.clone(),
        ));
        let mempool = Arc::new(Mempool::new(
            MempoolConfig::default(),
            StateManager::in_memory().ok()?,
            verifier,
        ));

        let api_state = Arc::new(ApiState::with_sync(mempool.clone(), sync_state.clone()));
        let router = create_router(api_state);

        Some(Self {
            router,
            mempool,
            sync_state,
            state_manager,
            root_tree_tracker,
        })
    }

    /// Register an anchor in the mempool
    async fn register_anchor(&self, block_nr: u32, update_nr: u32, is_deposit: bool, anchor: B256) {
        self.mempool
            .register_anchor(block_nr, update_nr, is_deposit, anchor)
            .await;
    }

    /// Update the hierarchical root tracker with block data
    async fn update_root_tracker(
        &self,
        day: u16,
        block_in_day: u16,
        block_root: B256,
        leaf_count: u32,
    ) {
        let mut tracker = self.root_tree_tracker.write().await;
        tracker.insert_block_root(day, block_in_day, block_root, leaf_count);
    }
}

// ============================================================================
// Sync API Tests
// ============================================================================

#[tokio::test]
async fn test_sync_status_endpoint() {
    let Some(ctx) = ApiTestContext::new() else {
        eprintln!("Skipping test: verification keys not found");
        return;
    };

    let response = ctx
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/sync/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let status: SyncStatusResponse = serde_json::from_slice(&body).unwrap();

    // Genesis state should show block 0, day 0
    assert_eq!(status.latest_block_nr, 0);
    assert_eq!(status.latest_day, 0);
    // Genesis anchor should match current anchor (empty tree)
    assert_eq!(status.current_anchor, status.genesis_anchor);
}

#[tokio::test]
async fn test_sync_day_roots_endpoint() {
    let Some(ctx) = ApiTestContext::new() else {
        eprintln!("Skipping test: verification keys not found");
        return;
    };

    let response = ctx
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/sync/day-roots?from=0&to=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let roots: DayRootsResponse = serde_json::from_slice(&body).unwrap();

    // No day roots in empty state (day 0 is not finalized)
    // This is expected - day roots are only populated when days are finalized
    assert!(roots.day_roots.is_empty() || roots.day_roots.len() <= 1);
}

#[tokio::test]
async fn test_sync_block_roots_endpoint() {
    let Some(ctx) = ApiTestContext::new() else {
        eprintln!("Skipping test: verification keys not found");
        return;
    };

    // Update root tracker with a test block
    let test_root = ensure_field_valid(B256::from(U256::from(0x1234).to_be_bytes()));
    ctx.update_root_tracker(0, 0, test_root, 0).await;

    let response = ctx
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/sync/block-roots?day=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let roots: BlockRootsResponse = serde_json::from_slice(&body).unwrap();

    assert_eq!(roots.day, 0);
    // Block roots come from database, which is empty in this test
    // The root tracker update above doesn't persist to database
}

#[tokio::test]
async fn test_sync_day_path_endpoint() {
    let Some(ctx) = ApiTestContext::new() else {
        eprintln!("Skipping test: verification keys not found");
        return;
    };

    let response = ctx
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/sync/day-path?day=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let path_response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Should have day_path array of DAY_TREE_DEPTH elements
    let day_path = path_response["day_path"].as_array().unwrap();
    assert_eq!(day_path.len(), DAY_TREE_DEPTH);
}

#[tokio::test]
async fn test_sync_block_path_endpoint() {
    let Some(ctx) = ApiTestContext::new() else {
        eprintln!("Skipping test: verification keys not found");
        return;
    };

    // First, add a block to the tracker so the day subtree exists
    let test_root = ensure_field_valid(B256::from(U256::from(0x5678).to_be_bytes()));
    ctx.update_root_tracker(0, 0, test_root, 3).await;

    let response = ctx
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/sync/block-path?day=0&block=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let path_response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Should have block_path array of BLOCK_IN_DAY_DEPTH elements
    let block_path = path_response["block_path"].as_array().unwrap();
    assert_eq!(block_path.len(), BLOCK_IN_DAY_DEPTH);
}

// ============================================================================
// Transaction Submission Tests
// ============================================================================

#[tokio::test]
async fn test_submit_tx_with_zk_validation() -> Result<()> {
    if !snarkjs_available() {
        eprintln!("Skipping test: npx snarkjs not found");
        return Ok(());
    }

    if !circuits_available() {
        eprintln!("Skipping test: transfer circuit files not found");
        return Ok(());
    }

    let Some(ctx) = ApiTestContext::new() else {
        eprintln!("Skipping test: verification keys not found");
        return Ok(());
    };

    let temp_dir = TempDir::new()?;

    // Create sender wallet
    let mut wallet = create_test_wallet(&temp_dir, "sender for api test");
    let sender_pubkey = wallet.public_key();

    // Create recipient
    let recipient_key = derive_spending_key("recipient for api test");
    let recipient_pubkey = derive_public_key(recipient_key);

    // Create test tree with notes owned by sender
    let asset = Address::ZERO;
    let setup = TestSetup::new(sender_pubkey, asset, &[U256::from(1000)]);

    // Set up wallet and cache
    let mut cache = ProofCache::new();
    setup_wallet_and_cache(&mut wallet, &setup, &mut cache);

    // Register the test anchor in the mempool
    ctx.register_anchor(0, 0, false, setup.anchor).await;

    // Build the transfer using the ACTUAL client code
    let built = build_transfer(
        &mut wallet,
        &cache,
        &transfer_zkey_path(),
        recipient_pubkey,
        U256::from(600),
        asset,
    )
    .await?;

    // Submit via API endpoint
    let request = SubmitTxRequest {
        transaction: built.transaction.clone(),
    };
    let body = serde_json::to_string(&request).unwrap();

    let response = ctx
        .router
        .clone()
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

    assert_eq!(response.status(), StatusCode::OK);

    let response_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let tx_response: serde_json::Value = serde_json::from_slice(&response_body).unwrap();

    assert!(
        tx_response["accepted"].as_bool().unwrap(),
        "Transaction should be accepted: {}",
        tx_response["message"]
    );
    assert_eq!(tx_response["mempool_size"].as_u64().unwrap(), 1);

    // Verify mempool state
    assert_eq!(ctx.mempool.len().await, 1);

    println!("Transaction submitted successfully via API!");
    println!("  Nullifier 0: 0x{}", hex::encode(built.nullifiers[0]));
    println!("  Output leaf 0: 0x{}", hex::encode(built.output_leaves[0]));

    Ok(())
}

#[tokio::test]
async fn test_submit_tx_duplicate_nullifier_rejected() {
    let Some(ctx) = ApiTestContext::new() else {
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

    let response = ctx
        .router
        .clone()
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

    let response_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let tx_response: serde_json::Value = serde_json::from_slice(&response_body).unwrap();

    assert!(!tx_response["accepted"].as_bool().unwrap());
    assert!(tx_response["message"]
        .as_str()
        .unwrap()
        .contains("duplicate nullifier"));
}

#[tokio::test]
async fn test_submit_tx_invalid_anchor_rejected() {
    let Some(ctx) = ApiTestContext::new() else {
        eprintln!("Skipping test: verification keys not found");
        return;
    };

    // Create a transaction with a non-zero anchor_info (references non-existent block)
    let tx = ParsedTransaction {
        nullifier0: B256::repeat_byte(0x01),
        nullifier1: B256::repeat_byte(0x02),
        // anchor_info with block_nr > 0 but no such block exists
        anchor_info: B256::from(U256::from(1).to_be_bytes()),
        ..Default::default()
    };

    let request = SubmitTxRequest { transaction: tx };
    let body = serde_json::to_string(&request).unwrap();

    let response = ctx
        .router
        .clone()
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

    // Should fail anchor validation (no block registered)
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let tx_response: serde_json::Value = serde_json::from_slice(&response_body).unwrap();

    assert!(!tx_response["accepted"].as_bool().unwrap());
}

// ============================================================================
// Mempool Status Tests
// ============================================================================

#[tokio::test]
async fn test_mempool_status_endpoint() {
    let Some(ctx) = ApiTestContext::new() else {
        eprintln!("Skipping test: verification keys not found");
        return;
    };

    let response = ctx
        .router
        .clone()
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
    let status: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(status["pending"], 0);
    assert!(!status["ready_for_block"].as_bool().unwrap());
}

// ============================================================================
// Full Integration Flow Tests
// ============================================================================

#[tokio::test]
async fn test_full_flow_sync_then_transfer() -> Result<()> {
    if !snarkjs_available() {
        eprintln!("Skipping test: npx snarkjs not found");
        return Ok(());
    }

    if !circuits_available() {
        eprintln!("Skipping test: transfer circuit files not found");
        return Ok(());
    }

    let Some(ctx) = ApiTestContext::new() else {
        eprintln!("Skipping test: verification keys not found");
        return Ok(());
    };

    let temp_dir = TempDir::new()?;

    // Step 1: Check sync status
    let status_response = ctx
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/sync/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(status_response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(status_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let status: SyncStatusResponse = serde_json::from_slice(&body).unwrap();

    println!("Sync Status:");
    println!("  Latest block: {}", status.latest_block_nr);
    println!("  Latest day: {}", status.latest_day);
    println!("  Current anchor: 0x{}", hex::encode(status.current_anchor));

    // Step 2: Create wallet and setup test state
    let mut wallet = create_test_wallet(&temp_dir, "full flow sender");
    let sender_pubkey = wallet.public_key();

    let recipient_key = derive_spending_key("full flow recipient");
    let recipient_pubkey = derive_public_key(recipient_key);

    let asset = Address::ZERO;
    let setup = TestSetup::new(sender_pubkey, asset, &[U256::from(500), U256::from(500)]);

    let mut cache = ProofCache::new();
    setup_wallet_and_cache(&mut wallet, &setup, &mut cache);

    // Register anchor
    ctx.register_anchor(0, 0, false, setup.anchor).await;

    // Step 3: Build and submit transfer
    let built = build_transfer(
        &mut wallet,
        &cache,
        &transfer_zkey_path(),
        recipient_pubkey,
        U256::from(750), // Requires both notes
        asset,
    )
    .await?;

    let request = SubmitTxRequest {
        transaction: built.transaction.clone(),
    };
    let body = serde_json::to_string(&request).unwrap();

    let response = ctx
        .router
        .clone()
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

    assert_eq!(response.status(), StatusCode::OK);

    let response_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let tx_response: serde_json::Value = serde_json::from_slice(&response_body).unwrap();

    assert!(
        tx_response["accepted"].as_bool().unwrap(),
        "Full flow transaction should be accepted"
    );

    // Step 4: Verify mempool status
    let mempool_response = ctx
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/mempool")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let mempool_body = axum::body::to_bytes(mempool_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let mempool_status: serde_json::Value = serde_json::from_slice(&mempool_body).unwrap();

    assert_eq!(mempool_status["pending"], 1);

    println!("Full flow completed successfully!");
    println!("  Transfer amount: 750");
    println!("  Change amount: 250");
    println!("  Mempool size: {}", mempool_status["pending"]);

    Ok(())
}

#[tokio::test]
async fn test_multiple_transfers_same_mempool() -> Result<()> {
    if !snarkjs_available() {
        eprintln!("Skipping test: npx snarkjs not found");
        return Ok(());
    }

    if !circuits_available() {
        eprintln!("Skipping test: transfer circuit files not found");
        return Ok(());
    }

    let Some(ctx) = ApiTestContext::new() else {
        eprintln!("Skipping test: verification keys not found");
        return Ok(());
    };

    let temp_dir1 = TempDir::new()?;
    let temp_dir2 = TempDir::new()?;

    // Create two separate wallets with their own notes
    let mut wallet1 = create_test_wallet(&temp_dir1, "sender 1");
    let sender1_pubkey = wallet1.public_key();

    let mut wallet2 = create_test_wallet(&temp_dir2, "sender 2");
    let sender2_pubkey = wallet2.public_key();

    let recipient_key = derive_spending_key("shared recipient");
    let recipient_pubkey = derive_public_key(recipient_key);

    let asset = Address::ZERO;

    // Different test setups = different anchors
    let setup1 = TestSetup::new(sender1_pubkey, asset, &[U256::from(1000)]);
    let setup2 = TestSetup::new(sender2_pubkey, asset, &[U256::from(2000)]);

    let mut cache1 = ProofCache::new();
    let mut cache2 = ProofCache::new();

    setup_wallet_and_cache(&mut wallet1, &setup1, &mut cache1);
    setup_wallet_and_cache(&mut wallet2, &setup2, &mut cache2);

    // Register both anchors
    ctx.register_anchor(0, 0, false, setup1.anchor).await;
    ctx.register_anchor(0, 1, false, setup2.anchor).await;

    // Build first transfer
    let built1 = build_transfer(
        &mut wallet1,
        &cache1,
        &transfer_zkey_path(),
        recipient_pubkey,
        U256::from(500),
        asset,
    )
    .await?;

    // Build second transfer
    let built2 = build_transfer(
        &mut wallet2,
        &cache2,
        &transfer_zkey_path(),
        recipient_pubkey,
        U256::from(1500),
        asset,
    )
    .await?;

    // Submit first
    let request1 = SubmitTxRequest {
        transaction: built1.transaction.clone(),
    };
    let body1 = serde_json::to_string(&request1).unwrap();

    let response1 = ctx
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/tx")
                .header("content-type", "application/json")
                .body(Body::from(body1))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response1.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response1.into_body(), usize::MAX)
        .await
        .unwrap();
    let tx_response1: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        tx_response1["accepted"].as_bool().unwrap(),
        "First transfer should be accepted"
    );

    // Submit second
    let request2 = SubmitTxRequest {
        transaction: built2.transaction.clone(),
    };
    let body2 = serde_json::to_string(&request2).unwrap();

    let response2 = ctx
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/tx")
                .header("content-type", "application/json")
                .body(Body::from(body2))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response2.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response2.into_body(), usize::MAX)
        .await
        .unwrap();
    let tx_response2: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        tx_response2["accepted"].as_bool().unwrap(),
        "Second transfer should be accepted"
    );

    // Verify both are in mempool
    assert_eq!(ctx.mempool.len().await, 2);

    println!("Multiple transfers submitted successfully!");
    println!("  Transfer 1: 500 tokens");
    println!("  Transfer 2: 1500 tokens");
    println!("  Mempool size: {}", ctx.mempool.len().await);

    Ok(())
}

// ============================================================================
// Health Check Test
// ============================================================================

#[tokio::test]
async fn test_health_endpoint() {
    let Some(ctx) = ApiTestContext::new() else {
        eprintln!("Skipping test: verification keys not found");
        return;
    };

    let response = ctx
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let health: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(health["status"], "ok");
}

// ============================================================================
// Comprehensive Hierarchical Tree Tests
// ============================================================================

/// Helper to create valid BN254 field elements for blob data
fn make_valid_leaf(index: usize) -> B256 {
    // Ensure first byte is < 0x30 for BN254 field validity
    let mut bytes = [0u8; 32];
    bytes[0] = 0x01;
    bytes[31] = (index & 0xFF) as u8;
    bytes[30] = ((index >> 8) & 0xFF) as u8;
    B256::from(bytes)
}

/// Create a test blob with deposit data
/// Blob layout: [deposits range][transactions range]
/// Each deposit group: [leaf0, leaf1, leaf2, new_root] (4 fields)
fn create_test_blob_with_deposits(num_deposits: usize) -> Vec<u8> {
    use pgp_common::types::constants::DEPOSIT_GROUP_SIZE;

    let num_groups = num_deposits.div_ceil(3);
    let mut blob_data = vec![0u8; 131072]; // 4096 fields * 32 bytes

    for group_idx in 0..num_groups {
        let base_offset = group_idx * DEPOSIT_GROUP_SIZE * 32;

        // leaf0
        let leaf0 = make_valid_leaf(group_idx * 3);
        blob_data[base_offset..base_offset + 32].copy_from_slice(leaf0.as_slice());

        // leaf1
        let leaf1 = make_valid_leaf(group_idx * 3 + 1);
        blob_data[base_offset + 32..base_offset + 64].copy_from_slice(leaf1.as_slice());

        // leaf2
        let leaf2 = make_valid_leaf(group_idx * 3 + 2);
        blob_data[base_offset + 64..base_offset + 96].copy_from_slice(leaf2.as_slice());

        // new_root (just use a placeholder)
        let new_root = make_valid_leaf(1000 + group_idx);
        blob_data[base_offset + 96..base_offset + 128].copy_from_slice(new_root.as_slice());
    }

    blob_data
}

/// Compute versioned hash (simplified for testing - uses first 32 bytes with version prefix)
fn compute_test_versioned_hash(blob_data: &[u8]) -> B256 {
    let mut hasher = sha2::Sha256::new();
    hasher.update(blob_data);
    let hash = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes[0] = 0x01; // KZG versioned hash prefix
    bytes[1..].copy_from_slice(&hash[1..]);
    B256::from(bytes)
}

/// Full API test context with database population support
struct FullApiTestContext {
    router: axum::Router,
    mempool: Arc<Mempool>,
    #[allow(dead_code)]
    sync_state: Arc<SyncState>,
    state_manager: Arc<Mutex<StateManager>>,
    root_tree_tracker: Arc<RwLock<HierarchicalRootTracker>>,
}

impl FullApiTestContext {
    fn new() -> Option<Self> {
        let verifier = create_test_verifier()?;
        let state_manager = Arc::new(Mutex::new(StateManager::in_memory().ok()?));
        let root_tree_tracker = Arc::new(RwLock::new(HierarchicalRootTracker::new()));
        let sync_state = Arc::new(SyncState::new(
            state_manager.clone(),
            root_tree_tracker.clone(),
        ));

        // Use separate StateManager for mempool
        let mempool = Arc::new(Mempool::new(
            MempoolConfig::default(),
            StateManager::in_memory().ok()?,
            verifier,
        ));

        let api_state = Arc::new(ApiState::with_sync(mempool.clone(), sync_state.clone()));
        let router = create_router(api_state);

        Some(Self {
            router,
            mempool,
            sync_state,
            state_manager,
            root_tree_tracker,
        })
    }

    /// Add a block with deposits to the database and tracker
    async fn add_block_with_deposits(
        &self,
        block_nr: u64,
        day: u16,
        block_in_day: u16,
        num_deposits: usize,
    ) -> (B256, B256) {
        use pgp_common::contracts::{BlockData, TimestampAndIndex};

        // Create blob data
        let blob_data = create_test_blob_with_deposits(num_deposits);
        let versioned_hash = compute_test_versioned_hash(&blob_data);

        // Build block tree to compute block root
        let mut block_tree = IncrementalMerkleTree::new(BLOCK_TREE_DEPTH);
        let num_groups = num_deposits.div_ceil(3);
        for group_idx in 0..num_groups {
            block_tree.insert(make_valid_leaf(group_idx * 3)).unwrap();
            block_tree
                .insert(make_valid_leaf(group_idx * 3 + 1))
                .unwrap();
            block_tree
                .insert(make_valid_leaf(group_idx * 3 + 2))
                .unwrap();
        }
        let block_root = block_tree.root();

        // Save to database
        {
            let state = self.state_manager.lock().unwrap();

            // Save blob
            state
                .save_blob(versioned_hash, &blob_data, block_nr)
                .unwrap();

            // Create and save block data
            let block_data = BlockData {
                anchor: B256::ZERO, // Will be computed
                timestamp: U256::from(1700000000u64 + block_nr * 12),
                numTransactions: U256::ZERO,
                numDeposits: U256::from(num_deposits as u64),
                blockNr: U256::from(block_nr),
                blockIndex: TimestampAndIndex {
                    day: day as u128,
                    index: block_in_day as u128,
                },
                sequencer: Address::ZERO,
                blobhashes: vec![versioned_hash],
            };
            state.save_block_data(&block_data, block_nr).unwrap();

            // Save block root
            state
                .save_block_root(
                    day,
                    block_in_day,
                    block_nr,
                    block_root,
                    (num_deposits * 3) as u32,
                )
                .unwrap();
        }

        // Update tracker
        let anchor = {
            let mut tracker = self.root_tree_tracker.write().await;
            let (anchor, _is_new_day, _) =
                tracker.insert_block_root(day, block_in_day, block_root, (num_groups * 3) as u32);
            anchor
        };

        // Register anchor in mempool
        self.mempool
            .register_anchor(block_nr as u32, 0, false, anchor)
            .await;

        (block_root, anchor)
    }

    /// Finalize a day in the database
    fn finalize_day(&self, day: u16, day_root: B256, block_count: u32, last_block_nr: u64) {
        let state = self.state_manager.lock().unwrap();
        state
            .save_day_root(day, day_root, block_count, last_block_nr)
            .unwrap();
    }
}

#[tokio::test]
async fn test_sync_block_tree_proof_with_real_data() {
    let Some(ctx) = FullApiTestContext::new() else {
        eprintln!("Skipping test: verification keys not found");
        return;
    };

    // Add a block with 6 deposits (2 groups = 6 leaves)
    let (block_root, _anchor) = ctx.add_block_with_deposits(1, 0, 0, 6).await;

    // Test getting block tree proof for leaf 0
    let response = ctx
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/sync/block-tree-proof?block_nr=1&leaf_index=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let proof_response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Verify response structure
    assert_eq!(proof_response["block_nr"], 1);
    assert_eq!(proof_response["leaf_index"], 0);

    // Verify block_siblings has BLOCK_TREE_DEPTH elements
    let block_siblings = proof_response["block_siblings"].as_array().unwrap();
    assert_eq!(block_siblings.len(), BLOCK_TREE_DEPTH);

    // Verify block root matches
    let returned_root = proof_response["block_root"].as_str().unwrap();
    assert_eq!(returned_root, format!("0x{}", hex::encode(block_root)));

    // Verify position
    assert_eq!(proof_response["position"]["day"], 0);
    assert_eq!(proof_response["position"]["block_in_day"], 0);
    assert_eq!(proof_response["position"]["leaf_in_block"], 0);

    println!("Block tree proof test passed!");
    println!("  Block root: {}", returned_root);
    println!("  Leaf: {}", proof_response["leaf"]);
}

#[tokio::test]
async fn test_sync_full_proof_with_real_data() {
    let Some(ctx) = FullApiTestContext::new() else {
        eprintln!("Skipping test: verification keys not found");
        return;
    };

    // Add a block with 3 deposits (1 group = 3 leaves)
    let (_block_root, anchor) = ctx.add_block_with_deposits(1, 0, 0, 3).await;

    // Test getting full proof for leaf 0
    let response = ctx
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/sync/full-proof?block_nr=1&leaf_index=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let proof_response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Verify response structure - should have all 3 levels of siblings
    let block_siblings = proof_response["block_siblings"].as_array().unwrap();
    assert_eq!(
        block_siblings.len(),
        BLOCK_TREE_DEPTH,
        "Should have 16 block siblings"
    );

    let block_in_day_siblings = proof_response["block_in_day_siblings"].as_array().unwrap();
    assert_eq!(
        block_in_day_siblings.len(),
        BLOCK_IN_DAY_DEPTH,
        "Should have 13 block-in-day siblings"
    );

    let day_siblings = proof_response["day_siblings"].as_array().unwrap();
    assert_eq!(
        day_siblings.len(),
        DAY_TREE_DEPTH,
        "Should have 15 day siblings"
    );

    // Verify anchor matches
    let returned_anchor = proof_response["current_anchor"].as_str().unwrap();
    assert_eq!(returned_anchor, format!("0x{}", hex::encode(anchor)));

    println!("Full proof test passed!");
    println!("  Anchor: {}", returned_anchor);
    println!("  Block siblings: {} levels", block_siblings.len());
    println!(
        "  Block-in-day siblings: {} levels",
        block_in_day_siblings.len()
    );
    println!("  Day siblings: {} levels", day_siblings.len());
    println!(
        "  Total proof depth: {} levels",
        BLOCK_TREE_DEPTH + BLOCK_IN_DAY_DEPTH + DAY_TREE_DEPTH
    );
}

#[tokio::test]
async fn test_multi_block_day_structure() {
    let Some(ctx) = FullApiTestContext::new() else {
        eprintln!("Skipping test: verification keys not found");
        return;
    };

    // Add multiple blocks in day 0
    let (_root1, _anchor1) = ctx.add_block_with_deposits(1, 0, 0, 3).await;
    let (_root2, _anchor2) = ctx.add_block_with_deposits(2, 0, 1, 6).await;
    let (_root3, anchor3) = ctx.add_block_with_deposits(3, 0, 2, 9).await;

    // Verify sync status shows correct state
    let response = ctx
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/sync/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let status: SyncStatusResponse = serde_json::from_slice(&body).unwrap();

    // Latest block should be 3 (from database it will be 0 since we don't update last_processed)
    // But current anchor should reflect all 3 blocks
    assert_eq!(
        status.current_anchor, anchor3,
        "Anchor should reflect all 3 blocks"
    );

    // Get block-in-day path for block 1 (should have non-zero siblings now)
    let response = ctx
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/sync/block-path?day=0&block=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let path_response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let block_path = path_response["block_path"].as_array().unwrap();
    assert_eq!(block_path.len(), BLOCK_IN_DAY_DEPTH);

    // First sibling should be non-zero (block 0's root is the sibling of block 1)
    let first_sibling = block_path[0].as_str().unwrap();
    assert_ne!(
        first_sibling,
        format!("0x{}", hex::encode(B256::ZERO)),
        "First sibling should be non-zero (block 0's root)"
    );

    println!("Multi-block day structure test passed!");
    println!("  3 blocks in day 0");
    println!("  Block 1's first sibling: {}", first_sibling);
}

#[tokio::test]
async fn test_multi_day_structure() {
    let Some(ctx) = FullApiTestContext::new() else {
        eprintln!("Skipping test: verification keys not found");
        return;
    };

    // Add blocks in day 0
    let (_root1, _) = ctx.add_block_with_deposits(1, 0, 0, 3).await;

    // "Finalize" day 0 by computing day root and saving
    let day0_root = {
        let tracker = ctx.root_tree_tracker.read().await;
        tracker.get_day_root(0).unwrap_or(B256::ZERO)
    };
    ctx.finalize_day(0, day0_root, 1, 1);

    // Add blocks in day 1
    let (_, anchor_day1) = ctx.add_block_with_deposits(2, 1, 0, 6).await;

    // Verify day roots endpoint returns day 0
    let response = ctx
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/sync/day-roots?from=0&to=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let roots: DayRootsResponse = serde_json::from_slice(&body).unwrap();

    assert_eq!(roots.day_roots.len(), 1, "Should have day 0 root");
    assert_eq!(roots.day_roots[0].day, 0);
    assert_eq!(roots.day_roots[0].root, day0_root);

    // Verify day path for day 0 has non-zero siblings now (day 1 exists)
    let response = ctx
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/sync/day-path?day=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let path_response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let day_path = path_response["day_path"].as_array().unwrap();
    assert_eq!(day_path.len(), DAY_TREE_DEPTH);

    // First sibling should be non-zero (day 1's root)
    let first_sibling = day_path[0].as_str().unwrap();
    assert_ne!(
        first_sibling,
        format!("0x{}", hex::encode(B256::ZERO)),
        "First sibling should be non-zero (day 1's root)"
    );

    println!("Multi-day structure test passed!");
    println!("  Day 0 root: 0x{}", hex::encode(day0_root));
    println!("  Day 0's first sibling (day 1): {}", first_sibling);
    println!("  Final anchor: 0x{}", hex::encode(anchor_day1));
}

#[tokio::test]
async fn test_proof_verification_round_trip() {
    let Some(ctx) = FullApiTestContext::new() else {
        eprintln!("Skipping test: verification keys not found");
        return;
    };

    // Add a block with deposits
    let (block_root, _anchor) = ctx.add_block_with_deposits(1, 0, 0, 3).await;

    // Get full proof for leaf 0
    let response = ctx
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/sync/full-proof?block_nr=1&leaf_index=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let proof_response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Extract proof components
    let leaf_str = proof_response["leaf"].as_str().unwrap();
    let leaf = B256::from_slice(&hex::decode(leaf_str.trim_start_matches("0x")).unwrap());

    let block_siblings: Vec<B256> = proof_response["block_siblings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            B256::from_slice(&hex::decode(s.as_str().unwrap().trim_start_matches("0x")).unwrap())
        })
        .collect();

    // Verify block tree proof computes to block root
    let mut current = leaf;
    let leaf_index = 0u32;
    for (level, sibling) in block_siblings.iter().enumerate() {
        let bit = (leaf_index >> level) & 1;
        current = if bit == 0 {
            pgp_merkle::poseidon2(current, *sibling)
        } else {
            pgp_merkle::poseidon2(*sibling, current)
        };
    }

    assert_eq!(
        current, block_root,
        "Block proof should compute to block root"
    );

    println!("Proof verification round-trip test passed!");
    println!("  Leaf: {}", leaf_str);
    println!("  Computed block root: 0x{}", hex::encode(current));
    println!("  Expected block root: 0x{}", hex::encode(block_root));
}
