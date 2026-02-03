//! Integration tests for client transfer proof generation.
//!
//! These tests verify the ACTUAL transfer command code paths:
//! 1. `build_transfer` generates valid ZK proofs
//! 2. Blinding derivation matches circuit expectations
//! 3. Generated proofs pass mempool validation (Rust verifier)
//! 4. Anchor info is correctly computed from cached data
//!
//! Note: These tests require:
//! - snarkjs and npx installed
//! - circuits compiled (circuits/outputs/transfer/)

use alloy_primitives::{Address, B256, U256};
use eyre::Result;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use tempfile::TempDir;

use pgp_client::cache::{CachedBlockRoots, ProofCache};
use pgp_client::commands::transfer::build_transfer;
use pgp_client::wallet::keys::{
    compute_transfer_blinding, derive_blinding, derive_public_key, derive_spending_key,
};
use pgp_client::wallet::notes::StoredProof;
use pgp_client::wallet::{TrackedNote, Wallet};
use pgp_common::types::DecodedAnchorInfo;
use pgp_merkle::{
    hierarchy::{BLOCK_IN_DAY_DEPTH, BLOCK_TREE_DEPTH},
    poseidon2, BlockRoot, DayRoot, IncrementalMerkleTree, TreePosition,
};

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

/// Compute nullifier: Poseidon3(privateKey, blinding, index)
fn compute_nullifier(private_key: B256, blinding: B256, index: u64) -> B256 {
    pgp_merkle::compute_nullifier(private_key, blinding, index)
}

/// Create a test wallet with a deterministic seed
fn create_test_wallet(temp_dir: &TempDir, seed: &str) -> Wallet {
    let spending_key = derive_spending_key(seed);

    // Create wallet with the spending key
    let wallet_path = temp_dir.path().join("wallet.json");
    let wallet = Wallet::from_spending_key(spending_key);
    wallet.save(&wallet_path).expect("Failed to save wallet");

    Wallet::load(&wallet_path).expect("Failed to load wallet")
}

/// Create a test tree with notes and return (tree, anchor, notes)
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
    // Add notes to wallet WITH stored proofs
    // In the new architecture, notes store their own proofs (block siblings + block-in-day siblings)
    for note in &setup.notes {
        let position = TreePosition::new(0, 0, note.index as u16);
        let block_siblings = setup.get_block_siblings(note.index as usize);

        // For testing, we treat this as a "finalized" day with complete proofs
        // The block-in-day siblings are all zeros since there's only one block
        let stored_proof = StoredProof::new_complete(
            block_siblings,
            setup.anchor, // block_root = tree root for single-block test
            [B256::ZERO; BLOCK_IN_DAY_DEPTH], // block_in_day_siblings
            setup.anchor, // day_root = tree root for single-day test
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

    // Set up proof cache with day roots (for computing day paths)
    // The cache stores day roots and computes day paths dynamically
    cache.set_last_sync(setup.anchor, 0, 0);

    // Add day root for day 0 (the anchor is the day root in this test setup)
    cache.update_day_roots(&[DayRoot {
        day: 0,
        root: setup.anchor,
    }]);

    // Also set up current day block roots (for computing block-in-day paths if needed)
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

// ============================================================================
// Unit Tests - Blinding Derivation
// ============================================================================

#[test]
fn test_derive_blinding_deterministic() {
    let spending_key = derive_spending_key("test seed phrase");

    let b1 = derive_blinding(spending_key, "transfer", 0);
    let b2 = derive_blinding(spending_key, "transfer", 0);

    assert_eq!(b1, b2, "Same inputs should produce same blinding");
}

#[test]
fn test_derive_blinding_different_indices() {
    let spending_key = derive_spending_key("test seed phrase");

    let b1 = derive_blinding(spending_key, "transfer", 0);
    let b2 = derive_blinding(spending_key, "transfer", 1);

    assert_ne!(
        b1, b2,
        "Different indices should produce different blindings"
    );
}

#[test]
fn test_derive_blinding_different_keys() {
    let key1 = derive_spending_key("seed one");
    let key2 = derive_spending_key("seed two");

    let b1 = derive_blinding(key1, "transfer", 0);
    let b2 = derive_blinding(key2, "transfer", 0);

    assert_ne!(b1, b2, "Different keys should produce different blindings");
}

#[test]
fn test_derive_blinding_within_field() {
    let spending_key = derive_spending_key("test seed");
    let blinding = derive_blinding(spending_key, "transfer", 12345);

    // Top 3 bits should be cleared (0x1F mask in derive_blinding)
    assert!(
        blinding.0[0] <= 0x1F,
        "Blinding should be within BN254 field"
    );
}

#[test]
fn test_compute_transfer_blinding_matches_poseidon() {
    // The circuit enforces: blinding = Poseidon(random, hashLeavesIn)
    let random = ensure_field_valid(B256::from(U256::from(0x42).to_be_bytes()));
    let leaves_hash = ensure_field_valid(B256::from(U256::from(0x123).to_be_bytes()));

    let blinding = compute_transfer_blinding(random, leaves_hash);
    let expected = poseidon2(random, leaves_hash);

    assert_eq!(
        blinding, expected,
        "compute_transfer_blinding should match Poseidon(random, hashLeavesIn)"
    );
}

// ============================================================================
// Integration Tests - Actual build_transfer Function
// ============================================================================

#[tokio::test]
async fn test_build_transfer_generates_valid_proof() -> Result<()> {
    if !snarkjs_available() {
        eprintln!("Skipping test: npx snarkjs not found");
        return Ok(());
    }

    if !circuits_available() {
        eprintln!("Skipping test: transfer circuit files not found");
        return Ok(());
    }

    // Create temp directory for wallet
    let temp_dir = TempDir::new()?;

    // Create sender wallet
    let mut wallet = create_test_wallet(&temp_dir, "sender wallet seed");
    let sender_pubkey = wallet.public_key();

    // Create recipient
    let recipient_key = derive_spending_key("recipient seed");
    let recipient_pubkey = derive_public_key(recipient_key);

    // Create test tree with notes owned by sender
    let asset = Address::ZERO;
    let setup = TestSetup::new(sender_pubkey, asset, &[U256::from(500), U256::from(500)]);

    // Set up wallet and cache
    let mut cache = ProofCache::new();
    setup_wallet_and_cache(&mut wallet, &setup, &mut cache);

    // Call the ACTUAL build_transfer function
    let built = build_transfer(
        &mut wallet,
        &cache,
        &transfer_zkey_path(),
        recipient_pubkey,
        U256::from(700), // Transfer 700, change 300
        asset,
    )
    .await?;

    // Verify the proof was generated
    assert_ne!(built.proof.a_x, B256::ZERO, "Proof a_x should not be zero");
    assert_ne!(built.proof.a_y, B256::ZERO, "Proof a_y should not be zero");

    // Verify nullifiers are not zero (spent notes)
    assert_ne!(
        built.nullifiers[0],
        B256::ZERO,
        "Nullifier 0 should not be zero"
    );
    // Second nullifier may or may not be zero depending on how many inputs were used

    // Verify output leaves
    assert_ne!(
        built.output_leaves[0],
        B256::ZERO,
        "Output leaf 0 (recipient) should not be zero"
    );
    // Output leaf 1 is change (300), should not be zero
    assert_ne!(
        built.output_leaves[1],
        B256::ZERO,
        "Output leaf 1 (change) should not be zero"
    );

    // Verify the transaction has the correct anchor info
    let decoded_anchor = DecodedAnchorInfo::decode(built.transaction.anchor_info);
    assert_eq!(
        decoded_anchor.block_nr, 0,
        "Anchor should reference block 0"
    );
    assert!(!decoded_anchor.is_deposit, "Should not be a deposit tx");

    // Verify the anchor matches
    assert_eq!(
        built.anchor, setup.anchor,
        "Built anchor should match test anchor"
    );

    println!("build_transfer generated valid proof!");
    println!("  Nullifier 0: 0x{}", hex::encode(built.nullifiers[0]));
    println!("  Nullifier 1: 0x{}", hex::encode(built.nullifiers[1]));
    println!("  Output leaf 0: 0x{}", hex::encode(built.output_leaves[0]));
    println!("  Output leaf 1: 0x{}", hex::encode(built.output_leaves[1]));
    println!("  Anchor: 0x{}", hex::encode(built.anchor));

    Ok(())
}

#[tokio::test]
async fn test_build_transfer_proof_passes_rust_verifier() -> Result<()> {
    if !snarkjs_available() {
        eprintln!("Skipping test: npx snarkjs not found");
        return Ok(());
    }

    if !circuits_available() {
        eprintln!("Skipping test: transfer circuit files not found");
        return Ok(());
    }

    if !transfer_vkey_path().exists() || !update_vkey_path().exists() {
        eprintln!("Skipping test: verification key files not found");
        return Ok(());
    }

    // Create temp directory
    let temp_dir = TempDir::new()?;

    // Create wallets
    let mut wallet = create_test_wallet(&temp_dir, "sender for verifier test");
    let sender_pubkey = wallet.public_key();

    let recipient_key = derive_spending_key("recipient for verifier test");
    let recipient_pubkey = derive_public_key(recipient_key);

    // Create test tree
    let asset = Address::ZERO;
    let setup = TestSetup::new(sender_pubkey, asset, &[U256::from(1000)]);

    // Set up wallet and cache
    let mut cache = ProofCache::new();
    setup_wallet_and_cache(&mut wallet, &setup, &mut cache);

    // Call build_transfer
    let built = build_transfer(
        &mut wallet,
        &cache,
        &transfer_zkey_path(),
        recipient_pubkey,
        U256::from(600), // Transfer 600, change 400
        asset,
    )
    .await?;

    // Create Groth16 verifier
    let verifier =
        pgp_challenger::Groth16Verifier::new(&transfer_vkey_path(), &update_vkey_path())?;

    // Build public inputs from the built transaction
    let public_inputs = pgp_challenger::TransferPublicInputs {
        anchor: built.anchor,
        eth_key: Address::ZERO,
        nullifier0: built.nullifiers[0],
        nullifier1: built.nullifiers[1],
        leaf0: built.output_leaves[0],
        leaf1: built.output_leaves[1],
        leaf2: built.output_leaves[2],
    };

    // Verify the proof
    let is_valid = verifier.verify_transfer_proof(&built.proof, &public_inputs)?;

    assert!(is_valid, "Proof generated by build_transfer should verify");

    println!("build_transfer proof verified by Rust Groth16 verifier!");

    Ok(())
}

#[tokio::test]
async fn test_build_transfer_accepted_by_mempool() -> Result<()> {
    if !snarkjs_available() {
        eprintln!("Skipping test: npx snarkjs not found");
        return Ok(());
    }

    if !circuits_available() {
        eprintln!("Skipping test: transfer circuit files not found");
        return Ok(());
    }

    if !transfer_vkey_path().exists() || !update_vkey_path().exists() {
        eprintln!("Skipping test: verification key files not found");
        return Ok(());
    }

    // Create temp directory
    let temp_dir = TempDir::new()?;

    // Create wallet
    let mut wallet = create_test_wallet(&temp_dir, "sender for mempool test");
    let sender_pubkey = wallet.public_key();

    let recipient_key = derive_spending_key("recipient for mempool test");
    let recipient_pubkey = derive_public_key(recipient_key);

    // Create test tree
    let asset = Address::ZERO;
    let setup = TestSetup::new(sender_pubkey, asset, &[U256::from(500), U256::from(500)]);

    // Set up wallet and cache
    let mut cache = ProofCache::new();
    setup_wallet_and_cache(&mut wallet, &setup, &mut cache);

    // Call build_transfer
    let built = build_transfer(
        &mut wallet,
        &cache,
        &transfer_zkey_path(),
        recipient_pubkey,
        U256::from(800), // Transfer 800, change 200
        asset,
    )
    .await?;

    // Create mempool with the test anchor
    let state = pgp_challenger::StateManager::in_memory()?;
    let verifier =
        pgp_challenger::Groth16Verifier::new(&transfer_vkey_path(), &update_vkey_path())?;
    let mempool = Arc::new(pgp_sequencer::Mempool::new(
        pgp_sequencer::MempoolConfig::default(),
        state,
        verifier,
    ));

    // Register the test anchor at block 0
    mempool.register_anchor(0, 0, false, setup.anchor).await;

    // Submit the transaction built by build_transfer
    let result = mempool.add(built.transaction.clone()).await;

    assert_eq!(
        result,
        pgp_sequencer::mempool::AddResult::Accepted,
        "Mempool should accept transaction built by build_transfer"
    );

    assert_eq!(mempool.len().await, 1, "Mempool should have 1 transaction");

    println!("build_transfer transaction accepted by mempool!");

    Ok(())
}

#[tokio::test]
async fn test_build_transfer_nullifiers_match_expected() -> Result<()> {
    if !snarkjs_available() {
        eprintln!("Skipping test: npx snarkjs not found");
        return Ok(());
    }

    if !circuits_available() {
        eprintln!("Skipping test: transfer circuit files not found");
        return Ok(());
    }

    // Create temp directory
    let temp_dir = TempDir::new()?;

    // Create wallet
    let mut wallet = create_test_wallet(&temp_dir, "sender for nullifier test");
    let sender_pubkey = wallet.public_key();
    let spending_key = wallet.spending_key();

    let recipient_key = derive_spending_key("recipient for nullifier test");
    let recipient_pubkey = derive_public_key(recipient_key);

    // Create test tree
    let asset = Address::ZERO;
    let setup = TestSetup::new(sender_pubkey, asset, &[U256::from(1000)]);

    // Set up wallet and cache
    let mut cache = ProofCache::new();
    setup_wallet_and_cache(&mut wallet, &setup, &mut cache);

    // Call build_transfer
    let built = build_transfer(
        &mut wallet,
        &cache,
        &transfer_zkey_path(),
        recipient_pubkey,
        U256::from(1000), // Transfer all
        asset,
    )
    .await?;

    // Compute expected nullifier for the first note
    // nullifier = Poseidon3(spending_key, blinding, flat_index)
    let note = &setup.notes[0];
    let flat_index = TreePosition::new(0, 0, note.index as u16).to_flat_index();
    let expected_nullifier = compute_nullifier(spending_key, note.blinding, flat_index);

    assert_eq!(
        built.nullifiers[0], expected_nullifier,
        "Nullifier from build_transfer should match expected computation"
    );

    println!("build_transfer nullifier matches expected!");
    println!("  Expected: 0x{}", hex::encode(expected_nullifier));
    println!("  Actual:   0x{}", hex::encode(built.nullifiers[0]));

    Ok(())
}

#[tokio::test]
async fn test_build_transfer_output_leaves_match_expected() -> Result<()> {
    if !snarkjs_available() {
        eprintln!("Skipping test: npx snarkjs not found");
        return Ok(());
    }

    if !circuits_available() {
        eprintln!("Skipping test: transfer circuit files not found");
        return Ok(());
    }

    // Create temp directory
    let temp_dir = TempDir::new()?;

    // Create wallet
    let mut wallet = create_test_wallet(&temp_dir, "sender for leaf test");
    let sender_pubkey = wallet.public_key();
    let spending_key = wallet.spending_key();

    let recipient_key = derive_spending_key("recipient for leaf test");
    let recipient_pubkey = derive_public_key(recipient_key);

    // Create test tree with a single note
    let asset = Address::ZERO;
    let setup = TestSetup::new(sender_pubkey, asset, &[U256::from(1000)]);

    // Set up wallet and cache
    let mut cache = ProofCache::new();
    setup_wallet_and_cache(&mut wallet, &setup, &mut cache);

    // Get the tx_counter before the transfer (should be 0)
    let tx_counter = wallet.tx_counter;

    // Call build_transfer
    let built = build_transfer(
        &mut wallet,
        &cache,
        &transfer_zkey_path(),
        recipient_pubkey,
        U256::from(700), // Transfer 700, change 300
        asset,
    )
    .await?;

    // Compute expected output leaf for recipient
    // First, compute leaves_in_hash
    let input_note = &setup.notes[0];
    let leaf0 = compute_leaf_hash(asset, input_note.amount, input_note.blinding, sender_pubkey);
    let leaf1 = B256::ZERO; // Single input
    let leaves_in_hash = poseidon2(leaf0, leaf1);

    // Derive the blinding for the recipient output (index 0)
    let recipient_random = derive_blinding(spending_key, "transfer", tx_counter << 8);
    let recipient_blinding = compute_transfer_blinding(recipient_random, leaves_in_hash);

    // Compute expected recipient leaf
    let expected_recipient_leaf =
        compute_leaf_hash(asset, U256::from(700), recipient_blinding, recipient_pubkey);

    assert_eq!(
        built.output_leaves[0], expected_recipient_leaf,
        "Recipient output leaf should match expected computation"
    );

    // Compute expected change leaf (index 1)
    let change_random = derive_blinding(spending_key, "transfer", (tx_counter << 8) | 1);
    let change_blinding = compute_transfer_blinding(change_random, leaves_in_hash);
    let expected_change_leaf =
        compute_leaf_hash(asset, U256::from(300), change_blinding, sender_pubkey);

    assert_eq!(
        built.output_leaves[1], expected_change_leaf,
        "Change output leaf should match expected computation"
    );

    println!("build_transfer output leaves match expected!");
    println!(
        "  Recipient leaf: 0x{}",
        hex::encode(built.output_leaves[0])
    );
    println!(
        "  Change leaf:    0x{}",
        hex::encode(built.output_leaves[1])
    );

    Ok(())
}

#[tokio::test]
async fn test_build_transfer_increments_tx_counter() -> Result<()> {
    if !snarkjs_available() {
        eprintln!("Skipping test: npx snarkjs not found");
        return Ok(());
    }

    if !circuits_available() {
        eprintln!("Skipping test: transfer circuit files not found");
        return Ok(());
    }

    // Create temp directory
    let temp_dir = TempDir::new()?;

    // Create wallet
    let mut wallet = create_test_wallet(&temp_dir, "sender for counter test");
    let sender_pubkey = wallet.public_key();

    let recipient_key = derive_spending_key("recipient for counter test");
    let recipient_pubkey = derive_public_key(recipient_key);

    // Create test tree with enough for multiple transfers
    let asset = Address::ZERO;
    let setup = TestSetup::new(sender_pubkey, asset, &[U256::from(1000), U256::from(1000)]);

    // Set up wallet and cache
    let mut cache = ProofCache::new();
    setup_wallet_and_cache(&mut wallet, &setup, &mut cache);

    let counter_before = wallet.tx_counter;

    // Call build_transfer
    let _built = build_transfer(
        &mut wallet,
        &cache,
        &transfer_zkey_path(),
        recipient_pubkey,
        U256::from(500),
        asset,
    )
    .await?;

    let counter_after = wallet.tx_counter;

    assert_eq!(
        counter_after,
        counter_before + 1,
        "build_transfer should increment tx_counter"
    );

    println!("build_transfer correctly increments tx_counter: {counter_before} -> {counter_after}");

    Ok(())
}

#[tokio::test]
async fn test_build_transfer_fails_with_insufficient_balance() -> Result<()> {
    // Create temp directory
    let temp_dir = TempDir::new()?;

    // Create wallet
    let mut wallet = create_test_wallet(&temp_dir, "sender for balance test");
    let sender_pubkey = wallet.public_key();

    let recipient_key = derive_spending_key("recipient for balance test");
    let recipient_pubkey = derive_public_key(recipient_key);

    // Create test tree with limited funds
    let asset = Address::ZERO;
    let setup = TestSetup::new(sender_pubkey, asset, &[U256::from(100)]);

    // Set up wallet and cache
    let mut cache = ProofCache::new();
    setup_wallet_and_cache(&mut wallet, &setup, &mut cache);

    // Try to transfer more than available
    let result = build_transfer(
        &mut wallet,
        &cache,
        &transfer_zkey_path(),
        recipient_pubkey,
        U256::from(500), // Only have 100
        asset,
    )
    .await;

    assert!(
        result.is_err(),
        "build_transfer should fail with insufficient balance"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Insufficient balance"),
        "Error should mention insufficient balance"
    );

    println!("build_transfer correctly rejects insufficient balance");

    Ok(())
}

#[tokio::test]
async fn test_build_transfer_fails_with_missing_cache() -> Result<()> {
    // Create temp directory
    let temp_dir = TempDir::new()?;

    // Create wallet with notes but NO cache
    let mut wallet = create_test_wallet(&temp_dir, "sender for cache test");
    let sender_pubkey = wallet.public_key();

    let recipient_key = derive_spending_key("recipient for cache test");
    let recipient_pubkey = derive_public_key(recipient_key);

    // Create test tree
    let asset = Address::ZERO;
    let setup = TestSetup::new(sender_pubkey, asset, &[U256::from(1000)]);

    // Add notes to wallet but DON'T set up cache properly
    for note in &setup.notes {
        let position = TreePosition::new(0, 0, note.index as u16);
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
            stored_proof: None,
        };
        wallet.add_note(tracked);
    }

    // Empty cache (no anchor set)
    let cache = ProofCache::new();

    // Try to transfer
    let result = build_transfer(
        &mut wallet,
        &cache,
        &transfer_zkey_path(),
        recipient_pubkey,
        U256::from(500),
        asset,
    )
    .await;

    assert!(
        result.is_err(),
        "build_transfer should fail with empty cache"
    );

    println!("build_transfer correctly rejects missing cache");

    Ok(())
}
