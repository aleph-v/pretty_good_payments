//! Block building orchestration loop for the sequencer.
//!
//! This module provides the main block building logic:
//! - Fetches deposits from the Deposits contract
//! - Takes transactions from the mempool
//! - Builds blobs using BlobBuilder with proper two-level tree structure
//! - Submits blocks via BlockSubmitter
//! - State is read from the shared StateManager database
//!
//! Block building is triggered when the mempool has enough transactions
//! to fill a blob (~273 transactions). Deposits are fetched at build time.
//!
//! Tree structure:
//! - Block tree (16 levels): Fresh for each block, stores deposits + tx outputs
//! - Root tree (28 levels): Persistent, stores block roots
//!
//! The root tree state is loaded from the database to compute correct anchors.

use crate::blob_builder::{BlobBuilder, BuiltBlob};
use crate::block_submitter::BlockSubmitter;
use crate::error::SequencerError;
use crate::mempool::{Mempool, TRANSACTIONS_PER_BLOB};
use alloy::providers::Provider;
use alloy_primitives::B256;
use pgp_challenger::{RootTreeTracker, StateManager};
use pgp_common::contracts::BlockData;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

/// Maximum transactions for 10 blobs (the EIP-4844 per-transaction limit).
pub const MAX_TRANSACTIONS_10_BLOBS: usize = TRANSACTIONS_PER_BLOB * 10;

/// Configuration for the block builder loop.
#[derive(Debug, Clone)]
pub struct BlockBuilderConfig {
    /// Minimum number of deposits to trigger block submission.
    /// Set to 0 to submit blocks whenever deposits are available.
    pub min_deposits: usize,
    /// Minimum number of transactions to trigger block submission.
    /// Defaults to TRANSACTIONS_PER_BLOB (273) for a full blob.
    /// Set to 0 to submit with any number of transactions (used by /poke).
    pub min_transactions: usize,
    /// Maximum number of transactions to include in a block.
    /// Defaults to TRANSACTIONS_PER_BLOB (273) for a single blob.
    /// Set higher to fill multiple blobs (max 10 blobs = 2730 transactions).
    pub max_transactions: usize,
    /// Interval between checking for new deposits.
    pub check_interval: Duration,
}

impl Default for BlockBuilderConfig {
    fn default() -> Self {
        Self {
            min_deposits: 0,
            min_transactions: TRANSACTIONS_PER_BLOB,
            max_transactions: TRANSACTIONS_PER_BLOB,
            check_interval: Duration::from_secs(5),
        }
    }
}

/// Result of a block building attempt.
#[derive(Debug)]
pub enum BlockBuildResult {
    /// Block was submitted successfully.
    Submitted {
        block_nr: u64,
        anchor: B256,
        num_deposits: usize,
        num_transactions: usize,
        /// The built blobs (for testing/validation).
        blobs: Vec<BuiltBlob>,
        /// The BlockData submitted to the contract.
        block_data: BlockData,
    },
    /// No deposits available for this block (and no transactions).
    NoDeposits,
    /// Not enough deposits to meet minimum threshold.
    InsufficientDeposits { available: usize, required: usize },
    /// Not enough transactions to fill a blob.
    InsufficientTransactions { available: usize, required: usize },
    /// Sequencer not allowed to submit (epoch timing).
    NotAllowed,
    /// Priority sequencer is holding transactions for exclusive period.
    /// This signals that we should NOT submit now, even if we have transactions.
    HoldingForPriorityPeriod,
    /// Error occurred during building/submission.
    Error(SequencerError),
}

/// Try to build and submit a single block.
///
/// This is the core block building function that:
/// 1. Checks if the mempool has enough transactions for a full blob (~273)
/// 2. If yes, takes transactions from the mempool
/// 3. Fetches any deposits for the next block from L1
/// 4. Loads the root tree state to compute correct anchors
/// 5. Builds a blob with transactions + deposits using proper tree structure
/// 6. Submits the block to the contract
/// 7. On failure, returns transactions to the mempool
///
/// The two-level tree structure:
/// - Block tree (16 levels): Fresh for each block, stores leaves
/// - Root tree (28 levels): Loaded from database, stores block roots
///
/// Note: State is updated by the challenger event loop when it processes
/// the NewRoot event from our submission. We don't update state directly.
///
/// Returns `BlockBuildResult` indicating what happened.
///
/// If `force` is true, the minimum transaction threshold is ignored and a block
/// will be submitted with whatever transactions are available (used by /poke).
pub async fn try_build_and_submit_block<P: Provider + Clone>(
    submitter: &BlockSubmitter<P>,
    state: &StateManager,
    config: &BlockBuilderConfig,
    genesis_anchor: B256,
    mempool: &Arc<Mempool>,
    force: bool,
) -> BlockBuildResult {
    let mempool_size = mempool.len().await;
    let is_priority = submitter.is_priority_sequencer();

    // Priority sequencer behavior:
    // - During open period: HOLD transactions (don't submit, wait for exclusive period)
    //   UNLESS force=true (from /poke), then submit immediately
    // - During closed period: DRAIN mempool (submit all transactions up to 10 blobs)
    //
    // Non-priority sequencer behavior:
    // - Normal: submit when allowed (during open period) with configured thresholds
    if is_priority && !force {
        // Check current epoch timing (only if not forced)
        let (epoch, is_closed) = match submitter.current_epoch() {
            Ok(result) => result,
            Err(e) => return BlockBuildResult::Error(e),
        };

        if !is_closed {
            // Priority sequencer in OPEN period: hold transactions for exclusive period
            debug!(
                "Priority sequencer holding {} transactions for exclusive period (epoch {})",
                mempool_size, epoch
            );
            return BlockBuildResult::HoldingForPriorityPeriod;
        }

        // We're in closed period - verify it's our turn
        match submitter.is_our_priority_turn().await {
            Ok(true) => {
                info!(
                    "Priority sequencer's exclusive turn (epoch {}, closed period) - draining mempool ({} txs)",
                    epoch, mempool_size
                );
            }
            Ok(false) => {
                // Closed period but not our turn (another priority sequencer's epoch)
                debug!("Closed period but not our turn (epoch {})", epoch);
                return BlockBuildResult::NotAllowed;
            }
            Err(e) => return BlockBuildResult::Error(e),
        }
    } else if is_priority && force {
        // Priority sequencer with force=true: submit immediately (we're allowed in open period too)
        info!("Priority sequencer force submit triggered via /poke - submitting immediately");
    }

    // Check if we have enough transactions (configurable threshold, default is full blob)
    // Skip this check if:
    // - force=true (triggered by /poke)
    // - priority sequencer in their exclusive period (submit whatever we have)
    let in_priority_window = is_priority && {
        match submitter.current_epoch() {
            Ok((_, is_closed)) => is_closed,
            Err(_) => false,
        }
    };
    let min_transactions = config.min_transactions;

    if !force && !in_priority_window && mempool_size < min_transactions {
        debug!(
            "Not enough transactions: {} / {} required",
            mempool_size, min_transactions
        );
        return BlockBuildResult::InsufficientTransactions {
            available: mempool_size,
            required: min_transactions,
        };
    }

    // If mempool is empty, nothing to do
    if mempool_size == 0 {
        debug!("Mempool is empty, nothing to submit");
        return BlockBuildResult::InsufficientTransactions {
            available: 0,
            required: 1,
        };
    }

    // Get current state from the shared StateManager
    // The latest anchor and block number represent the last validated block
    let prior_anchor = match state.load_latest_anchor() {
        Ok(Some(anchor)) => anchor,
        Ok(None) => {
            // No blocks yet, use genesis anchor
            genesis_anchor
        }
        Err(e) => return BlockBuildResult::Error(SequencerError::ContractError(e.to_string())),
    };

    let next_block_nr = match state.get_latest_block_nr() {
        Ok(Some(latest)) => latest + 1,
        Ok(None) => 0, // First block is block 0
        Err(e) => return BlockBuildResult::Error(SequencerError::ContractError(e.to_string())),
    };

    debug!(
        "Building block {}: anchor={:?}, mempool_size={}",
        next_block_nr, prior_anchor, mempool_size
    );

    // Check if we're allowed to submit:
    // - Non-priority sequencers: always check
    // - Priority sequencers with force=true: check (may not be our turn in closed period)
    // - Priority sequencers without force: already verified above
    if !is_priority || force {
        match submitter.is_allowed().await {
            Ok(true) => {}
            Ok(false) => {
                debug!("Not allowed to submit at this time");
                return BlockBuildResult::NotAllowed;
            }
            Err(e) => {
                return BlockBuildResult::Error(e);
            }
        }
    }

    // Determine how many transactions to take:
    // - Priority sequencer in exclusive period: take ALL (up to 10 blobs)
    // - Otherwise: use configured max_transactions
    let max_to_take = if in_priority_window {
        MAX_TRANSACTIONS_10_BLOBS
    } else {
        config.max_transactions
    };

    // Take transactions from the mempool (FIFO)
    let transactions = mempool.take(max_to_take).await;
    let num_transactions = transactions.len();

    if num_transactions == 0 {
        // No transactions available
        return BlockBuildResult::InsufficientTransactions {
            available: 0,
            required: config.min_transactions.max(1),
        };
    }

    // Fetch deposits for this block (may be empty)
    let deposits = match submitter.get_deposits_for_block(next_block_nr).await {
        Ok(deps) => deps,
        Err(e) => {
            // On error fetching deposits, return transactions to mempool and report error
            if !matches!(e, SequencerError::NoDepositsForBlock(_)) {
                mempool.return_to_front(transactions).await;
                return BlockBuildResult::Error(e);
            }
            // No deposits is fine, we have transactions
            vec![]
        }
    };

    info!(
        "Building block {} with {} transactions and {} deposits",
        next_block_nr,
        num_transactions,
        deposits.len()
    );

    // Load root tree state from the database (hierarchical format)
    let block_roots = match state.load_block_roots() {
        Ok(roots) => roots,
        Err(e) => {
            error!("Failed to load block roots: {}", e);
            mempool.return_to_front(transactions).await;
            return BlockBuildResult::Error(SequencerError::ContractError(e.to_string()));
        }
    };

    // Restore the root tree tracker from persisted state (using hierarchical format)
    let root_tree = if !block_roots.is_empty() {
        RootTreeTracker::from_hierarchical_block_roots(&block_roots)
    } else {
        RootTreeTracker::new()
    };

    // Predict the block index for this block
    // The contract computes: day = (block.timestamp - START) / DAY
    //                        index = lastTimestamp.day == day ? lastTimestamp.index + 1 : 0
    // We need to predict this based on current time and last block's blockIndex
    let (predicted_day, predicted_index) = match submitter.predict_next_block_index().await {
        Ok((day, index)) => (day, index),
        Err(e) => {
            error!("Failed to predict block index: {}", e);
            mempool.return_to_front(transactions).await;
            return BlockBuildResult::Error(e);
        }
    };

    let tree_index = RootTreeTracker::compute_tree_index(predicted_day, predicted_index);

    // Get the root path for this block's position in the root tree
    let root_path = root_tree.get_root_path_for_index(tree_index);

    debug!(
        "Block {} at tree_index {} (day={}, index={}), root_tree has {} blocks",
        next_block_nr,
        tree_index,
        predicted_day,
        predicted_index,
        root_tree.block_count()
    );

    // Build the blob with transactions and deposits using proper tree structure
    let mut blob_builder = BlobBuilder::new(tree_index, root_path);

    let built_block = match blob_builder.build(&deposits, &transactions) {
        Ok(block) => block,
        Err(e) => {
            error!("Failed to build blob: {}", e);
            // Return transactions to mempool on build failure
            mempool.return_to_front(transactions).await;
            return BlockBuildResult::Error(e);
        }
    };

    info!(
        "Built {} blob(s) with {} deposits + {} transactions, submitting block {} (tree_index={})",
        built_block.blobs.len(),
        built_block.total_deposits,
        built_block.total_transactions,
        next_block_nr,
        tree_index
    );

    // Submit the block
    match submitter
        .submit_block(&built_block, prior_anchor, next_block_nr)
        .await
    {
        Ok(result) => {
            info!(
                "Block {} submitted successfully! anchor={:?}, l2_hash={:?}",
                result.block_number, result.anchor, result.l2_block_hash
            );

            // Success! Transactions are consumed (already removed from mempool)
            // State update (including block root persistence) happens via challenger event loop

            BlockBuildResult::Submitted {
                block_nr: result.block_number,
                anchor: result.anchor,
                num_deposits: deposits.len(),
                num_transactions,
                blobs: built_block.blobs,
                block_data: result.block_data,
            }
        }
        Err(e) => {
            error!("Failed to submit block: {}", e);
            // Return transactions to mempool on submission failure
            mempool.return_to_front(transactions).await;
            BlockBuildResult::Error(e)
        }
    }
}

/// Run the block builder loop.
///
/// This is the main entry point for the block building process.
/// It continuously checks for transactions and submits blocks when
/// the mempool has enough to fill a blob.
///
/// # Arguments
/// * `submitter` - The BlockSubmitter for submitting blocks
/// * `state` - The shared StateManager (same database as challenger)
/// * `config` - Configuration for the block builder
/// * `genesis_anchor` - The genesis anchor for when no blocks exist yet
/// * `mempool` - The transaction mempool
/// * `shutdown` - Shutdown signal
pub async fn run_block_builder<P: Provider + Clone>(
    submitter: &BlockSubmitter<P>,
    state: &StateManager,
    config: &BlockBuilderConfig,
    genesis_anchor: B256,
    mempool: &Arc<Mempool>,
    shutdown: Arc<AtomicBool>,
) {
    info!(
        "Starting block builder loop (batch threshold: {} transactions)",
        TRANSACTIONS_PER_BLOB
    );

    while !shutdown.load(Ordering::SeqCst) {
        // Check if a forced submission was requested (via /poke endpoint)
        let force = mempool.check_and_clear_force_submit();
        if force {
            info!("Force submit triggered via /poke endpoint");
        }

        match try_build_and_submit_block(submitter, state, config, genesis_anchor, mempool, force)
            .await
        {
            BlockBuildResult::Submitted {
                block_nr,
                anchor,
                num_deposits,
                num_transactions,
                ..
            } => {
                info!(
                    "Successfully submitted block {} with {} deposits + {} transactions (anchor: {:?})",
                    block_nr, num_deposits, num_transactions, anchor
                );
                // Don't sleep, immediately check for next block
                continue;
            }
            BlockBuildResult::NoDeposits => {
                debug!("No deposits available, waiting...");
            }
            BlockBuildResult::InsufficientDeposits {
                available,
                required,
            } => {
                debug!(
                    "Waiting for more deposits: {}/{} available",
                    available, required
                );
            }
            BlockBuildResult::InsufficientTransactions {
                available,
                required,
            } => {
                debug!(
                    "Waiting for more transactions: {}/{} available",
                    available, required
                );
            }
            BlockBuildResult::NotAllowed => {
                debug!("Not allowed to submit, waiting for open period...");
            }
            BlockBuildResult::HoldingForPriorityPeriod => {
                debug!("Priority sequencer holding transactions for exclusive period...");
            }
            BlockBuildResult::Error(e) => {
                warn!("Block building error: {}", e);
                // Continue loop, will retry next iteration
            }
        }

        // Sleep before checking again
        tokio::select! {
            _ = sleep(config.check_interval) => {}
            _ = wait_for_shutdown(&shutdown) => break,
        }
    }

    info!("Block builder loop stopped");
}

/// Wait until shutdown is requested.
async fn wait_for_shutdown(shutdown: &Arc<AtomicBool>) {
    while !shutdown.load(Ordering::SeqCst) {
        sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mempool::MempoolConfig;
    use pgp_challenger::{Groth16Verifier, StateManager};
    use std::path::PathBuf;

    fn circuits_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../circuits/outputs")
    }

    fn create_test_verifier() -> Option<Groth16Verifier> {
        let circuits = circuits_path();
        let transfer_vk = circuits.join("transfer/transferVKey.json");
        let update_vk = circuits.join("predictableUpdate/predictableUpdateVKey.json");

        if !transfer_vk.exists() || !update_vk.exists() {
            return None;
        }

        Groth16Verifier::new(&transfer_vk, &update_vk).ok()
    }

    #[test]
    fn test_default_config() {
        let config = BlockBuilderConfig::default();
        assert_eq!(config.min_deposits, 0);
        // tree_depth is no longer configurable - it uses the fixed two-level structure
        // (16-level block tree + 28-level root tree)
    }

    #[test]
    fn test_transactions_per_blob() {
        // Verify the threshold is 273 (4096 / 15)
        assert_eq!(TRANSACTIONS_PER_BLOB, 273);
    }

    #[tokio::test]
    async fn test_mempool_integration() {
        let Some(verifier) = create_test_verifier() else {
            eprintln!("Skipping test: verification keys not found");
            return;
        };

        // Basic test that mempool can be used with the block builder types
        let config = MempoolConfig { max_pending: 1000 };
        let state = StateManager::in_memory().unwrap();
        let mempool = Arc::new(Mempool::new(config, state, verifier));

        // Mempool should start empty
        assert!(mempool.is_empty().await);
        assert!(!mempool.has_full_blob().await);
    }

    #[test]
    fn test_compute_tree_index() {
        // tree_index = day * 8192 + index_in_day
        assert_eq!(RootTreeTracker::compute_tree_index(0, 0), 0);
        assert_eq!(RootTreeTracker::compute_tree_index(0, 100), 100);
        assert_eq!(RootTreeTracker::compute_tree_index(1, 0), 8192);
        assert_eq!(RootTreeTracker::compute_tree_index(1, 50), 8242);
    }
}
