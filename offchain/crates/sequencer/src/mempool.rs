//! Transaction mempool with FIFO queue for the sequencer.
//!
//! The mempool holds pending transactions until they can be batched into blobs.
//! Batching is triggered when the mempool has enough transactions to fill a blob
//! (~273 transactions = 4096 fields / 15 fields per tx).
//!
//! Transactions are validated before being added:
//! - Nullifiers are checked against historical records (via StateManager database)
//! - Nullifiers are checked against pending transactions (via in-memory HashSet)

use alloy::primitives::B256;
use pgp_challenger::{Groth16Verifier, StateManager, TransferPublicInputs};
use pgp_common::types::constants::{BLOB_SIZE, TX_SIZE};
use pgp_common::types::{DecodedAnchorInfo, ParsedTransaction};
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tokio::sync::Mutex;
use tracing::warn;

/// Number of transactions that fill one blob.
/// Each transaction uses 15 fields, and a blob has 4096 fields.
/// We use strict less-than for validation, so 273 transactions (4095 fields) fit.
pub const TRANSACTIONS_PER_BLOB: usize = BLOB_SIZE / TX_SIZE;

/// Configuration for the mempool.
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    /// Maximum transactions to hold (backpressure limit).
    /// When reached, new transactions are rejected.
    pub max_pending: usize,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_pending: 10000, // Allow ~10k pending transactions
        }
    }
}

/// Reason a transaction was rejected during validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// A nullifier was already used in a confirmed block.
    NullifierAlreadySpent {
        nullifier: B256,
        block_nr: u64,
        tx_index: u32,
    },
    /// A nullifier is already pending in the mempool.
    NullifierPending { nullifier: B256 },
    /// Both nullifiers in the transaction are the same.
    DuplicateNullifiersInTx { nullifier: B256 },
    /// The anchor reference block is in the future (not yet committed).
    AnchorBlockInFuture {
        referenced_block: u32,
        latest_block: u64,
    },
    /// The anchor reference update_nr is out of bounds.
    AnchorUpdateOutOfBounds {
        block_nr: u32,
        update_nr: u32,
        is_deposit: bool,
        max_update_nr: Option<u32>,
    },
    /// The anchor value could not be found in the database.
    AnchorNotFound {
        block_nr: u32,
        update_nr: u32,
        is_deposit: bool,
    },
    /// The ZK proof is invalid.
    InvalidZkProof { reason: String },
}

/// A transaction in the mempool with metadata.
#[derive(Debug, Clone)]
pub struct MempoolTransaction {
    /// The parsed transaction data (15 fields).
    pub transaction: ParsedTransaction,
    /// Submission timestamp (for FIFO ordering and metrics).
    pub received_at: Instant,
}

impl MempoolTransaction {
    /// Create a new mempool transaction.
    pub fn new(transaction: ParsedTransaction) -> Self {
        Self {
            transaction,
            received_at: Instant::now(),
        }
    }
}

/// Result of adding a transaction to the mempool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddResult {
    /// Transaction accepted into the mempool.
    Accepted,
    /// Mempool is full, transaction rejected.
    MempoolFull,
    /// Transaction failed validation.
    ValidationFailed(ValidationError),
    /// Database error during validation.
    DatabaseError(String),
}

/// Thread-safe transaction mempool with FIFO queue, nullifier validation, and ZK verification.
pub struct Mempool {
    /// FIFO queue of pending transactions.
    transactions: Mutex<VecDeque<MempoolTransaction>>,
    /// Pending nullifiers from transactions in the mempool (for fast duplicate detection).
    pending_nullifiers: Mutex<HashSet<B256>>,
    /// State manager for historical nullifier lookups and anchor validation.
    /// SQLite Connection is not Sync, so we need a mutex for concurrent access.
    state: Mutex<StateManager>,
    /// ZK proof verifier for validating Groth16 proofs.
    zk_verifier: Groth16Verifier,
    /// Configuration.
    config: MempoolConfig,
    /// Flag to trigger immediate block submission (set by /poke endpoint).
    /// When true, the block builder loop will attempt to submit a block
    /// regardless of how many transactions are in the mempool.
    force_submit: AtomicBool,
}

impl Mempool {
    /// Create a new mempool with the given configuration, state manager, and ZK verifier.
    ///
    /// The state manager is used to check historical nullifiers and anchor validity.
    /// It should use the same database file as the challenger for consistency.
    ///
    /// The ZK verifier is used to validate Groth16 proofs for each transaction.
    pub fn new(config: MempoolConfig, state: StateManager, verifier: Groth16Verifier) -> Self {
        Self {
            transactions: Mutex::new(VecDeque::new()),
            pending_nullifiers: Mutex::new(HashSet::new()),
            state: Mutex::new(state),
            zk_verifier: verifier,
            config,
            force_submit: AtomicBool::new(false),
        }
    }

    /// Add a transaction to the mempool after validation.
    ///
    /// Validates:
    /// 1. Mempool is not full
    /// 2. Nullifiers are not duplicates within the transaction
    /// 3. Nullifiers are not already pending in the mempool
    /// 4. Nullifiers are not already spent (checked against database)
    /// 5. Anchor reference is valid (block exists, update_nr in bounds)
    /// 6. ZK proof is valid (if verifier is configured)
    ///
    /// Returns `AddResult::Accepted` if the transaction was added,
    /// or an appropriate error variant if validation failed.
    pub async fn add(&self, tx: ParsedTransaction) -> AddResult {
        // Check capacity first (cheap)
        let queue_len = self.transactions.lock().await.len();
        if queue_len >= self.config.max_pending {
            return AddResult::MempoolFull;
        }

        // Collect nullifiers from this transaction
        let nullifiers = [tx.nullifier0, tx.nullifier1];

        // Check for duplicate nullifiers within the same transaction
        if nullifiers[0] == nullifiers[1] {
            return AddResult::ValidationFailed(ValidationError::DuplicateNullifiersInTx {
                nullifier: nullifiers[0],
            });
        }

        // Check against pending nullifiers in mempool
        {
            let pending = self.pending_nullifiers.lock().await;
            for nullifier in nullifiers {
                if pending.contains(&nullifier) {
                    return AddResult::ValidationFailed(ValidationError::NullifierPending {
                        nullifier,
                    });
                }
            }
        }

        // Decode anchor info from the transaction
        let anchor_info = DecodedAnchorInfo::decode(tx.anchor_info);

        // All database operations in one lock acquisition
        let anchor = {
            let state = self.state.lock().await;

            // Check nullifiers against historical records
            match state.get_nullifiers_batch(&nullifiers) {
                Ok(existing) => {
                    for nullifier in nullifiers {
                        if let Some(record) = existing.get(&nullifier) {
                            return AddResult::ValidationFailed(
                                ValidationError::NullifierAlreadySpent {
                                    nullifier,
                                    block_nr: record.block_nr,
                                    tx_index: record.tx_index,
                                },
                            );
                        }
                    }
                }
                Err(e) => {
                    return AddResult::DatabaseError(format!("Failed to check nullifiers: {}", e));
                }
            }

            // Validate anchor reference - check block is not in the future
            let latest_block = match state.get_latest_block_nr() {
                Ok(Some(bn)) => bn,
                Ok(None) => {
                    // No blocks yet - only block 0 (genesis) is valid
                    if anchor_info.block_nr > 0 {
                        return AddResult::ValidationFailed(ValidationError::AnchorBlockInFuture {
                            referenced_block: anchor_info.block_nr,
                            latest_block: 0,
                        });
                    }
                    0
                }
                Err(e) => {
                    return AddResult::DatabaseError(format!("Failed to get latest block: {}", e));
                }
            };

            if (anchor_info.block_nr as u64) > latest_block {
                return AddResult::ValidationFailed(ValidationError::AnchorBlockInFuture {
                    referenced_block: anchor_info.block_nr,
                    latest_block,
                });
            }

            // Check update_nr bounds
            let max_update = match state
                .get_max_update_nr(anchor_info.block_nr, anchor_info.is_deposit)
            {
                Ok(max) => max,
                Err(e) => {
                    return AddResult::DatabaseError(format!("Failed to get max update_nr: {}", e));
                }
            };

            if let Some(max) = max_update {
                if anchor_info.update_nr > max {
                    warn!(
                        "Anchor update_nr {} > max {} for block {} is_deposit={}",
                        anchor_info.update_nr, max, anchor_info.block_nr, anchor_info.is_deposit
                    );
                    return AddResult::ValidationFailed(ValidationError::AnchorUpdateOutOfBounds {
                        block_nr: anchor_info.block_nr,
                        update_nr: anchor_info.update_nr,
                        is_deposit: anchor_info.is_deposit,
                        max_update_nr: Some(max),
                    });
                }
            } else if anchor_info.update_nr > 0 {
                // No anchors exist for this (block, is_deposit) combination
                warn!(
                    "No anchors found for block {} is_deposit={}, but update_nr={}",
                    anchor_info.block_nr, anchor_info.is_deposit, anchor_info.update_nr
                );
                return AddResult::ValidationFailed(ValidationError::AnchorUpdateOutOfBounds {
                    block_nr: anchor_info.block_nr,
                    update_nr: anchor_info.update_nr,
                    is_deposit: anchor_info.is_deposit,
                    max_update_nr: None,
                });
            }

            // Load the actual anchor value for ZK proof verification
            match state.load_anchor(
                anchor_info.block_nr,
                anchor_info.update_nr,
                anchor_info.is_deposit,
            ) {
                Ok(Some(a)) => a,
                Ok(None) => {
                    warn!(
                        "Anchor not found: block={}, update={}, is_deposit={}",
                        anchor_info.block_nr, anchor_info.update_nr, anchor_info.is_deposit
                    );
                    return AddResult::ValidationFailed(ValidationError::AnchorNotFound {
                        block_nr: anchor_info.block_nr,
                        update_nr: anchor_info.update_nr,
                        is_deposit: anchor_info.is_deposit,
                    });
                }
                Err(e) => {
                    return AddResult::DatabaseError(format!("Failed to load anchor: {}", e));
                }
            }
        };

        // Validate ZK proof
        let public_inputs = TransferPublicInputs {
            anchor,
            eth_key: anchor_info.eth_key,
            nullifier0: tx.nullifier0,
            nullifier1: tx.nullifier1,
            leaf0: tx.leaf0,
            leaf1: tx.leaf1,
            leaf2: tx.leaf2,
        };

        match self
            .zk_verifier
            .verify_transfer_proof(&tx.proof, &public_inputs)
        {
            Ok(true) => {
                // Proof is valid, continue
            }
            Ok(false) => {
                warn!("Invalid ZK proof for transaction");
                return AddResult::ValidationFailed(ValidationError::InvalidZkProof {
                    reason: "Groth16 verification returned false".to_string(),
                });
            }
            Err(e) => {
                warn!("ZK proof verification error: {}", e);
                return AddResult::ValidationFailed(ValidationError::InvalidZkProof {
                    reason: format!("Verification error: {}", e),
                });
            }
        }

        // Validation passed - add to mempool and track nullifiers
        {
            let mut pending = self.pending_nullifiers.lock().await;
            for nullifier in nullifiers {
                pending.insert(nullifier);
            }
        }

        let mut queue = self.transactions.lock().await;
        // Re-check capacity after acquiring lock (race condition protection)
        if queue.len() >= self.config.max_pending {
            // Rollback nullifier tracking
            let mut pending = self.pending_nullifiers.lock().await;
            for nullifier in nullifiers {
                pending.remove(&nullifier);
            }
            return AddResult::MempoolFull;
        }
        queue.push_back(MempoolTransaction::new(tx));
        AddResult::Accepted
    }

    /// Get the number of pending transactions.
    pub async fn len(&self) -> usize {
        self.transactions.lock().await.len()
    }

    /// Check if the mempool is empty.
    pub async fn is_empty(&self) -> bool {
        self.transactions.lock().await.is_empty()
    }

    /// Check if the mempool has enough transactions for a full blob.
    pub async fn has_full_blob(&self) -> bool {
        self.len().await >= TRANSACTIONS_PER_BLOB
    }

    /// Take up to `count` transactions from the front of the queue (FIFO).
    ///
    /// This removes the transactions from the mempool and removes their
    /// nullifiers from the pending set.
    pub async fn take(&self, count: usize) -> Vec<ParsedTransaction> {
        let mut queue = self.transactions.lock().await;
        let take_count = count.min(queue.len());
        let mut result = Vec::with_capacity(take_count);

        for _ in 0..take_count {
            if let Some(mtx) = queue.pop_front() {
                result.push(mtx.transaction);
            }
        }

        // Remove nullifiers from pending set
        if !result.is_empty() {
            let mut pending = self.pending_nullifiers.lock().await;
            for tx in &result {
                pending.remove(&tx.nullifier0);
                pending.remove(&tx.nullifier1);
            }
        }

        result
    }

    /// Take transactions for one full blob (up to TRANSACTIONS_PER_BLOB).
    ///
    /// This removes the transactions from the mempool.
    pub async fn take_blob_batch(&self) -> Vec<ParsedTransaction> {
        self.take(TRANSACTIONS_PER_BLOB).await
    }

    /// Return transactions to the front of the mempool.
    ///
    /// Used when block submission fails and we need to retry.
    /// Transactions are returned in order, so the first in the vec
    /// will be at the front of the queue. Their nullifiers are added
    /// back to the pending set.
    pub async fn return_to_front(&self, txs: Vec<ParsedTransaction>) {
        // Add nullifiers back to pending set
        if !txs.is_empty() {
            let mut pending = self.pending_nullifiers.lock().await;
            for tx in &txs {
                pending.insert(tx.nullifier0);
                pending.insert(tx.nullifier1);
            }
        }

        let mut queue = self.transactions.lock().await;
        for tx in txs.into_iter().rev() {
            queue.push_front(MempoolTransaction::new(tx));
        }
    }

    /// Clear all pending transactions and their nullifiers.
    pub async fn clear(&self) {
        self.transactions.lock().await.clear();
        self.pending_nullifiers.lock().await.clear();
    }

    /// Get mempool statistics.
    pub async fn stats(&self) -> MempoolStats {
        let queue = self.transactions.lock().await;
        let pending = queue.len();
        let oldest_age_ms = queue
            .front()
            .map(|tx| tx.received_at.elapsed().as_millis() as u64);
        let pending_nullifiers = self.pending_nullifiers.lock().await.len();
        MempoolStats {
            pending,
            max_pending: self.config.max_pending,
            oldest_age_ms,
            blobs_worth: pending / TRANSACTIONS_PER_BLOB,
            pending_nullifiers,
        }
    }

    /// Get the count of pending nullifiers (for testing/monitoring).
    pub async fn pending_nullifier_count(&self) -> usize {
        self.pending_nullifiers.lock().await.len()
    }

    /// Trigger immediate block submission.
    ///
    /// This sets a flag that the block builder loop checks. When the flag is set,
    /// the block builder will attempt to submit a block with whatever transactions
    /// are available, regardless of the minimum threshold.
    ///
    /// This is called by the `/poke` API endpoint.
    pub fn trigger_submit(&self) {
        self.force_submit.store(true, Ordering::SeqCst);
    }

    /// Check if forced submission was requested and clear the flag.
    ///
    /// Returns `true` if `trigger_submit()` was called since the last check.
    /// The flag is atomically cleared, so subsequent calls will return `false`
    /// until `trigger_submit()` is called again.
    ///
    /// This is called by the block builder loop.
    pub fn check_and_clear_force_submit(&self) -> bool {
        self.force_submit.swap(false, Ordering::SeqCst)
    }

    /// Insert a transaction directly without validation (for testing only).
    ///
    /// This bypasses all validation checks and adds the transaction directly
    /// to the queue. The nullifiers are also added to the pending set.
    #[cfg(test)]
    pub async fn insert_unchecked(&self, tx: ParsedTransaction) {
        // Track nullifiers
        {
            let mut pending = self.pending_nullifiers.lock().await;
            pending.insert(tx.nullifier0);
            pending.insert(tx.nullifier1);
        }
        // Add to queue
        let mut queue = self.transactions.lock().await;
        queue.push_back(MempoolTransaction::new(tx));
    }
}

/// Mempool statistics for monitoring.
#[derive(Debug, Clone)]
pub struct MempoolStats {
    /// Number of pending transactions.
    pub pending: usize,
    /// Maximum allowed pending transactions.
    pub max_pending: usize,
    /// Age of the oldest transaction in milliseconds.
    pub oldest_age_ms: Option<u64>,
    /// Number of full blobs worth of transactions.
    pub blobs_worth: usize,
    /// Number of nullifiers tracked from pending transactions.
    pub pending_nullifiers: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Path to the circuits directory from the project root
    fn circuits_path() -> PathBuf {
        // Navigate from offchain/crates/sequencer/src to project root, then to circuits
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../circuits/outputs")
    }

    /// Create a test verifier using the real verification keys.
    /// Returns None if the verification key files are not found.
    fn create_test_verifier() -> Option<Groth16Verifier> {
        let circuits = circuits_path();
        let transfer_vk = circuits.join("transfer/transferVKey.json");
        let update_vk = circuits.join("predictableUpdate/predictableUpdateVKey.json");

        if !transfer_vk.exists() || !update_vk.exists() {
            return None;
        }

        Groth16Verifier::new(&transfer_vk, &update_vk).ok()
    }

    /// Create a test mempool with real ZK verification.
    /// Returns None if verification keys are not available.
    fn create_test_mempool() -> Option<Mempool> {
        let verifier = create_test_verifier()?;
        let state = StateManager::in_memory().ok()?;
        Some(Mempool::new(MempoolConfig::default(), state, verifier))
    }

    /// Create a test mempool with custom config.
    fn create_test_mempool_with_config(config: MempoolConfig) -> Option<Mempool> {
        let verifier = create_test_verifier()?;
        let state = StateManager::in_memory().ok()?;
        Some(Mempool::new(config, state, verifier))
    }

    /// Create a test mempool with pre-configured state.
    fn create_test_mempool_with_state(state: StateManager) -> Option<Mempool> {
        let verifier = create_test_verifier()?;
        Some(Mempool::new(MempoolConfig::default(), state, verifier))
    }

    /// Create a test transaction with unique nullifiers.
    /// Note: These have invalid ZK proofs, so they will fail ZK validation.
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

    // ========================================================================
    // Tests for validation that happens BEFORE ZK verification
    // These tests check validation stages 1-4 which don't require valid ZK proofs
    // ========================================================================

    #[tokio::test]
    async fn test_reject_duplicate_nullifier_in_tx() {
        let Some(mempool) = create_test_mempool() else {
            eprintln!("Skipping test: verification keys not found");
            return;
        };

        // Create a transaction with the same nullifier in both slots
        // This fails at step 2 (duplicate nullifier check) before ZK verification
        let duplicate_null = B256::repeat_byte(0xAA);
        let tx = ParsedTransaction {
            nullifier0: duplicate_null,
            nullifier1: duplicate_null,
            ..Default::default()
        };

        let result = mempool.add(tx).await;
        assert!(matches!(
            result,
            AddResult::ValidationFailed(ValidationError::DuplicateNullifiersInTx { .. })
        ));
        assert_eq!(mempool.len().await, 0);
    }

    #[tokio::test]
    async fn test_reject_pending_nullifier() {
        let Some(mempool) = create_test_mempool() else {
            eprintln!("Skipping test: verification keys not found");
            return;
        };

        // Insert a transaction with a specific nullifier (bypasses validation)
        let tx1 = ParsedTransaction {
            nullifier0: B256::repeat_byte(0x10),
            nullifier1: B256::repeat_byte(0x11),
            ..Default::default()
        };
        mempool.insert_unchecked(tx1.clone()).await;

        // Try to add a transaction that reuses the pending nullifier
        // This fails at step 3 (pending nullifier check) before anchor/ZK validation
        let tx2 = ParsedTransaction {
            nullifier0: tx1.nullifier0, // Reuse nullifier from tx1
            nullifier1: B256::repeat_byte(0xFF),
            ..Default::default()
        };

        let result = mempool.add(tx2).await;
        assert!(matches!(
            result,
            AddResult::ValidationFailed(ValidationError::NullifierPending { .. })
        ));
    }

    #[tokio::test]
    async fn test_reject_historical_nullifier() {
        let state = StateManager::in_memory().unwrap();

        // Pre-populate database with a spent nullifier AND a valid anchor
        let spent_nullifier = B256::repeat_byte(0xBB);
        let record = pgp_challenger::validators::nullifier::NullifierRecord {
            block_nr: 100,
            tx_index: 5,
            which: 0,
        };
        state.save_nullifier(&spent_nullifier, &record).unwrap();

        // Add a genesis anchor so anchor validation passes
        let genesis_anchor = B256::repeat_byte(0x01);
        state.save_anchor(0, 0, false, genesis_anchor).unwrap();

        let Some(mempool) = create_test_mempool_with_state(state) else {
            eprintln!("Skipping test: verification keys not found");
            return;
        };

        // Create a transaction with a valid anchor reference (block 0, update 0)
        // but with a spent nullifier
        let anchor_info = DecodedAnchorInfo {
            block_nr: 0,
            update_nr: 0,
            is_deposit: false,
            eth_key: alloy::primitives::Address::ZERO,
        };

        let tx = ParsedTransaction {
            anchor_info: anchor_info.encode(),
            nullifier0: spent_nullifier,
            nullifier1: B256::repeat_byte(0xCC),
            ..Default::default()
        };

        let result = mempool.add(tx).await;
        match result {
            AddResult::ValidationFailed(ValidationError::NullifierAlreadySpent {
                nullifier,
                block_nr,
                tx_index,
            }) => {
                assert_eq!(nullifier, spent_nullifier);
                assert_eq!(block_nr, 100);
                assert_eq!(tx_index, 5);
            }
            other => panic!("Expected NullifierAlreadySpent, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_reject_anchor_block_in_future() {
        let Some(mempool) = create_test_mempool() else {
            eprintln!("Skipping test: verification keys not found");
            return;
        };

        // Create a transaction referencing a future block (block 100 when no blocks exist)
        let anchor_info = DecodedAnchorInfo {
            block_nr: 100,
            update_nr: 0,
            is_deposit: false,
            eth_key: alloy::primitives::Address::ZERO,
        };

        let tx = ParsedTransaction {
            anchor_info: anchor_info.encode(),
            nullifier0: B256::repeat_byte(0x01),
            nullifier1: B256::repeat_byte(0x02),
            ..Default::default()
        };

        let result = mempool.add(tx).await;
        assert!(matches!(
            result,
            AddResult::ValidationFailed(ValidationError::AnchorBlockInFuture { .. })
        ));
    }

    #[tokio::test]
    async fn test_reject_anchor_update_out_of_bounds() {
        let state = StateManager::in_memory().unwrap();

        // Add an anchor for block 0, update 0 only
        let genesis_anchor = B256::repeat_byte(0x01);
        state.save_anchor(0, 0, false, genesis_anchor).unwrap();

        let Some(mempool) = create_test_mempool_with_state(state) else {
            eprintln!("Skipping test: verification keys not found");
            return;
        };

        // Create a transaction referencing block 0, update 5 (out of bounds)
        let anchor_info = DecodedAnchorInfo {
            block_nr: 0,
            update_nr: 5, // Only update 0 exists
            is_deposit: false,
            eth_key: alloy::primitives::Address::ZERO,
        };

        let tx = ParsedTransaction {
            anchor_info: anchor_info.encode(),
            nullifier0: B256::repeat_byte(0x01),
            nullifier1: B256::repeat_byte(0x02),
            ..Default::default()
        };

        let result = mempool.add(tx).await;
        assert!(matches!(
            result,
            AddResult::ValidationFailed(ValidationError::AnchorUpdateOutOfBounds { .. })
        ));
    }

    #[tokio::test]
    async fn test_reject_anchor_not_found() {
        let state = StateManager::in_memory().unwrap();

        // Add block data but no anchors
        use alloy::primitives::{Address, U256};
        use pgp_common::contracts::{BlockData, TimestampAndIndex};

        let block_data = BlockData {
            anchor: B256::ZERO,
            timestamp: U256::ZERO,
            numTransactions: U256::ZERO,
            numDeposits: U256::ZERO,
            blockNr: U256::ZERO,
            blockIndex: TimestampAndIndex {
                day: 0u128,
                index: 0u128,
            },
            sequencer: Address::ZERO,
            blobhashes: vec![],
        };
        state.save_block_data(&block_data, 1).unwrap();

        let Some(mempool) = create_test_mempool_with_state(state) else {
            eprintln!("Skipping test: verification keys not found");
            return;
        };

        // Create a transaction referencing block 0, update 0 (block exists but no anchor)
        let anchor_info = DecodedAnchorInfo {
            block_nr: 0,
            update_nr: 0,
            is_deposit: false,
            eth_key: alloy::primitives::Address::ZERO,
        };

        let tx = ParsedTransaction {
            anchor_info: anchor_info.encode(),
            nullifier0: B256::repeat_byte(0x01),
            nullifier1: B256::repeat_byte(0x02),
            ..Default::default()
        };

        let result = mempool.add(tx).await;
        // This should fail at anchor bounds check (no anchors exist for this block/is_deposit)
        assert!(matches!(
            result,
            AddResult::ValidationFailed(
                ValidationError::AnchorUpdateOutOfBounds { .. }
                    | ValidationError::AnchorNotFound { .. }
            )
        ));
    }

    #[tokio::test]
    async fn test_reject_invalid_zk_proof() {
        let state = StateManager::in_memory().unwrap();

        // Add a valid anchor
        let genesis_anchor = B256::repeat_byte(0x01);
        state.save_anchor(0, 0, false, genesis_anchor).unwrap();

        let Some(mempool) = create_test_mempool_with_state(state) else {
            eprintln!("Skipping test: verification keys not found");
            return;
        };

        // Create a transaction with valid anchor reference but invalid ZK proof
        let anchor_info = DecodedAnchorInfo {
            block_nr: 0,
            update_nr: 0,
            is_deposit: false,
            eth_key: alloy::primitives::Address::ZERO,
        };

        let tx = ParsedTransaction {
            anchor_info: anchor_info.encode(),
            nullifier0: B256::repeat_byte(0x01),
            nullifier1: B256::repeat_byte(0x02),
            // proof is default (all zeros) which is invalid
            ..Default::default()
        };

        let result = mempool.add(tx).await;
        assert!(matches!(
            result,
            AddResult::ValidationFailed(ValidationError::InvalidZkProof { .. })
        ));
    }

    // ========================================================================
    // Tests for mempool operations (take, return, clear, stats)
    // These don't require transactions to pass validation
    // ========================================================================

    #[tokio::test]
    async fn test_mempool_take_and_return() {
        let Some(mempool) = create_test_mempool() else {
            eprintln!("Skipping test: verification keys not found");
            return;
        };

        // Insert transactions using helper (bypasses validation)
        mempool.insert_unchecked(make_test_tx(1)).await;
        mempool.insert_unchecked(make_test_tx(2)).await;

        assert_eq!(mempool.len().await, 2);
        assert_eq!(mempool.pending_nullifier_count().await, 4);

        // Take both - nullifiers should be removed
        let taken = mempool.take(2).await;
        assert_eq!(taken.len(), 2);
        assert!(mempool.is_empty().await);
        assert_eq!(mempool.pending_nullifier_count().await, 0);

        // Return them - nullifiers should be re-added
        mempool.return_to_front(taken).await;
        assert_eq!(mempool.len().await, 2);
        assert_eq!(mempool.pending_nullifier_count().await, 4);
    }

    #[tokio::test]
    async fn test_nullifiers_cleared_on_clear() {
        let Some(mempool) = create_test_mempool() else {
            eprintln!("Skipping test: verification keys not found");
            return;
        };

        // Insert transaction using helper
        mempool.insert_unchecked(make_test_tx(1)).await;

        assert_eq!(mempool.pending_nullifier_count().await, 2);
        assert_eq!(mempool.len().await, 1);

        mempool.clear().await;

        assert_eq!(mempool.len().await, 0);
        assert_eq!(mempool.pending_nullifier_count().await, 0);
    }

    #[tokio::test]
    async fn test_mempool_stats() {
        let Some(mempool) = create_test_mempool() else {
            eprintln!("Skipping test: verification keys not found");
            return;
        };

        // Insert transactions using helper
        mempool.insert_unchecked(make_test_tx(1)).await;
        mempool.insert_unchecked(make_test_tx(2)).await;

        let stats = mempool.stats().await;
        assert_eq!(stats.pending, 2);
        assert_eq!(stats.max_pending, 10000);
        assert!(stats.oldest_age_ms.is_some());
        assert_eq!(stats.blobs_worth, 0); // 2 < 273
        assert_eq!(stats.pending_nullifiers, 4);
    }

    #[tokio::test]
    async fn test_mempool_full() {
        let Some(mempool) = create_test_mempool_with_config(MempoolConfig { max_pending: 2 })
        else {
            eprintln!("Skipping test: verification keys not found");
            return;
        };

        // Fill the mempool using helper
        mempool.insert_unchecked(make_test_tx(1)).await;
        mempool.insert_unchecked(make_test_tx(2)).await;

        // Try to add another - should fail with MempoolFull
        let result = mempool.add(make_test_tx(3)).await;
        assert_eq!(result, AddResult::MempoolFull);
    }

    #[test]
    fn test_transactions_per_blob_constant() {
        // Verify the constant matches expectation: 4096 / 15 = 273
        assert_eq!(TRANSACTIONS_PER_BLOB, 273);
    }

    #[tokio::test]
    async fn test_force_submit_flag() {
        let Some(mempool) = create_test_mempool() else {
            eprintln!("Skipping test: verification keys not found");
            return;
        };

        // Initially false
        assert!(!mempool.check_and_clear_force_submit());

        // Trigger submit
        mempool.trigger_submit();

        // Should be true and then cleared
        assert!(mempool.check_and_clear_force_submit());

        // Should be false again
        assert!(!mempool.check_and_clear_force_submit());

        // Multiple triggers should still result in one true
        mempool.trigger_submit();
        mempool.trigger_submit();
        assert!(mempool.check_and_clear_force_submit());
        assert!(!mempool.check_and_clear_force_submit());
    }
}
