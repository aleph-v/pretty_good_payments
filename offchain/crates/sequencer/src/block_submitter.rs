//! Block submission to the Entrypoint contract.
//!
//! This module handles:
//! - Querying deposits for a block from the Deposits contract
//! - Building BlockData structs
//! - Submitting blob transactions to Entrypoint.post()

use crate::blob_builder::{combine_blobs_into_sidecar, combine_blobs_into_sidecar_simple};
use crate::epoch::EpochWatcher;
use crate::error::SequencerError;
use crate::BuiltBlock;
use alloy::network::{EthereumWallet, TransactionBuilder, TransactionBuilder4844};
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolEvent;
use alloy_primitives::{Address, B256, U256};
use pgp_common::contracts::{BlockData, Entrypoint, TimestampAndIndex};
use std::time::Duration;
use tracing::{debug, info};

/// Configuration for the block submitter.
#[derive(Debug, Clone)]
pub struct SubmitterConfig {
    /// The Entrypoint contract address.
    pub entrypoint_address: Address,
    /// The sequencer's address (derived from private key).
    pub sequencer_address: Address,
    /// The private key signer.
    pub signer: PrivateKeySigner,
    /// Timeout for waiting for submission window.
    pub submission_timeout: Duration,
    /// Use SimpleCoder for blob encoding (required for Anvil testing).
    /// Set to false for mainnet/production.
    pub anvil_mode: bool,
}

/// Result of a successful block submission.
#[derive(Debug, Clone)]
pub struct SubmissionResult {
    /// The block number assigned by the contract.
    pub block_number: u64,
    /// The final anchor (merkle root) after this block.
    pub anchor: B256,
    /// The L2 block hash.
    pub l2_block_hash: B256,
    /// The transaction hash of the submission.
    pub tx_hash: B256,
    /// The BlockData submitted to the contract.
    pub block_data: BlockData,
}

/// Submits blocks to the Entrypoint contract.
pub struct BlockSubmitter<P: Provider + Clone> {
    /// Configuration.
    config: SubmitterConfig,
    /// Provider for RPC calls.
    provider: P,
    /// Epoch watcher for timing.
    epoch_watcher: EpochWatcher<P>,
}

impl<P: Provider + Clone> BlockSubmitter<P> {
    /// Create a new BlockSubmitter.
    pub fn new(config: SubmitterConfig, provider: P) -> Self {
        let epoch_watcher = EpochWatcher::new(
            config.entrypoint_address,
            config.sequencer_address,
            provider.clone(),
        );

        Self {
            config,
            provider,
            epoch_watcher,
        }
    }

    /// Initialize the block submitter.
    ///
    /// This syncs the epoch watcher with the blockchain to enable local
    /// epoch timing calculations.
    pub async fn init(&mut self) -> Result<(), SequencerError> {
        self.epoch_watcher.init().await
    }

    /// Get the Entrypoint contract instance.
    fn entrypoint(&self) -> Entrypoint::EntrypointInstance<&P> {
        Entrypoint::new(self.config.entrypoint_address, &self.provider)
    }

    /// Get the current block number from the contract.
    pub async fn get_current_block_number(&self) -> Result<u64, SequencerError> {
        let block_nr = self
            .entrypoint()
            .getCurrentBlocknumber()
            .call()
            .await
            .map_err(|e| {
                SequencerError::ContractError(format!("Failed to get block number: {e}"))
            })?;

        Ok(block_nr.try_into().unwrap_or(0))
    }

    /// Get the genesis anchor from the contract.
    pub async fn get_genesis_anchor(&self) -> Result<B256, SequencerError> {
        let anchor = self
            .entrypoint()
            .GENESIS_ANCHOR()
            .call()
            .await
            .map_err(|e| {
                SequencerError::ContractError(format!("Failed to get genesis anchor: {e}"))
            })?;

        Ok(anchor)
    }

    /// Get deposits for a specific block number.
    pub async fn get_deposits_for_block(&self, block_nr: u64) -> Result<Vec<B256>, SequencerError> {
        let deposits = self
            .entrypoint()
            .getDepositArray(U256::from(block_nr))
            .call()
            .await
            .map_err(|e| SequencerError::ContractError(format!("Failed to get deposits: {e}")))?;

        Ok(deposits)
    }

    /// Wait for the submission window (open epoch period).
    pub async fn wait_for_submission_window(&self) -> Result<(), SequencerError> {
        self.epoch_watcher
            .wait_for_submission_window(self.config.submission_timeout)
            .await
    }

    /// Check if the sequencer is allowed to submit.
    pub async fn is_allowed(&self) -> Result<bool, SequencerError> {
        self.epoch_watcher.is_allowed().await
    }

    /// Check if this sequencer is in the priority list.
    ///
    /// Priority sequencers get exclusive access during the closed period of
    /// their assigned epoch and should hold transactions until that window.
    pub fn is_priority_sequencer(&self) -> bool {
        self.epoch_watcher.is_priority_sequencer()
    }

    /// Check if this is currently our priority turn (closed period AND we're allowed).
    pub async fn is_our_priority_turn(&self) -> Result<bool, SequencerError> {
        self.epoch_watcher.is_our_priority_turn().await
    }

    /// Get the current epoch and whether we're in the closed period.
    ///
    /// Returns (epoch_number, is_closed) using local time calculations.
    pub fn current_epoch(&self) -> Result<(u64, bool), SequencerError> {
        self.epoch_watcher.current_epoch()
    }

    /// Submit a block to the Entrypoint contract.
    ///
    /// # Arguments
    /// * `built_block` - The built block with blob sidecar
    /// * `prior_anchor` - The anchor before this block (for validation)
    /// * `target_block_nr` - The target block number (for deposits)
    ///
    /// # Returns
    /// A `SubmissionResult` with the assigned block number and hashes.
    pub async fn submit_block(
        &self,
        built_block: &BuiltBlock,
        _prior_anchor: B256,
        target_block_nr: u64,
    ) -> Result<SubmissionResult, SequencerError> {
        // Wait for submission window
        debug!("Waiting for submission window...");
        self.wait_for_submission_window().await?;
        info!("Submission window open, submitting block");

        // Validate we have at least one blob
        if built_block.blobs.is_empty() {
            return Err(SequencerError::SubmissionFailed(
                "No blobs in built block".into(),
            ));
        }

        // Combine all blobs into a single sidecar for the transaction
        // This supports multi-blob blocks where deposits/transactions span multiple blobs
        // Use SimpleCoder for Anvil testing, raw KZG for mainnet
        let sidecar = if self.config.anvil_mode {
            combine_blobs_into_sidecar_simple(&built_block.blobs)?
        } else {
            combine_blobs_into_sidecar(&built_block.blobs)?
        };
        let versioned_hashes: Vec<B256> = sidecar.versioned_hashes().collect();

        info!(
            "Submitting block with {} blob(s), {} deposits, {} transactions",
            built_block.blobs.len(),
            built_block.total_deposits,
            built_block.total_transactions
        );

        // Build BlockData struct
        // anchor is the final anchor after all updates in this block
        let block_data = BlockData {
            anchor: built_block.anchor,
            timestamp: U256::ZERO, // Will be set by contract
            numTransactions: U256::from(built_block.total_transactions),
            numDeposits: U256::from(built_block.total_deposits),
            blockNr: U256::from(target_block_nr),
            blockIndex: TimestampAndIndex { day: 0, index: 0 }, // Will be set by contract
            sequencer: self.config.sequencer_address,
            blobhashes: versioned_hashes,
        };

        // Create the calldata for Entrypoint.post()
        let post_calldata = self
            .entrypoint()
            .post(block_data, vec![U256::ZERO])
            .calldata()
            .clone();

        // Build blob transaction with the combined sidecar
        let blob_tx = TransactionRequest::default()
            .with_to(self.config.entrypoint_address)
            .with_input(post_calldata)
            .with_blob_sidecar(sidecar);

        // Send transaction
        debug!("Sending blob transaction...");
        let pending = self.provider.send_transaction(blob_tx).await.map_err(|e| {
            SequencerError::SubmissionFailed(format!("Failed to send transaction: {e}"))
        })?;

        let tx_hash = *pending.tx_hash();
        debug!("Transaction sent: {}", tx_hash);

        // Wait for receipt
        let receipt = pending
            .get_receipt()
            .await
            .map_err(|e| SequencerError::SubmissionFailed(format!("Failed to get receipt: {e}")))?;

        if !receipt.status() {
            return Err(SequencerError::SubmissionFailed(format!(
                "Transaction reverted. Gas used: {}",
                receipt.gas_used
            )));
        }

        // Parse NewRoot event from receipt
        let new_root_logs: Vec<_> = receipt
            .inner
            .logs()
            .iter()
            .filter(|log| log.topic0() == Some(&Entrypoint::NewRoot::SIGNATURE_HASH))
            .collect();

        if new_root_logs.is_empty() {
            return Err(SequencerError::SubmissionFailed(
                "No NewRoot event in receipt".into(),
            ));
        }

        let decoded = new_root_logs[0]
            .log_decode::<Entrypoint::NewRoot>()
            .map_err(|e| {
                SequencerError::SubmissionFailed(format!("Failed to decode NewRoot event: {e}"))
            })?;

        let actual_block_data = decoded.inner.data.data;
        let l2_block_hash = decoded.inner.data.l2BlockHash;
        let block_number: u64 = actual_block_data.blockNr.try_into().unwrap_or(0);

        info!(
            "Block {} submitted successfully (hash: {})",
            block_number, l2_block_hash
        );

        Ok(SubmissionResult {
            block_number,
            anchor: actual_block_data.anchor,
            l2_block_hash,
            tx_hash,
            block_data: actual_block_data,
        })
    }

    /// Predict the next block's index (day, index_in_day) based on current time.
    ///
    /// The contract computes blockIndex as:
    /// - day = (block.timestamp - START) / DAY
    /// - index = lastTimestamp.day == day ? lastTimestamp.index + 1 : 0
    ///
    /// This method predicts what the contract will assign based on current time.
    /// The prediction may be slightly off if there's a day boundary between
    /// prediction and actual mining, which would result in a fraud-able block.
    /// Sequencers should avoid submitting near day boundaries.
    ///
    /// # Returns
    /// A tuple of (day, index_in_day) that the contract is expected to assign.
    pub async fn predict_next_block_index(&self) -> Result<(u64, u64), SequencerError> {
        let entrypoint = self.entrypoint();

        // Get contract's START time
        let start = entrypoint
            .START()
            .call()
            .await
            .map_err(|e| SequencerError::ContractError(format!("Failed to get START: {e}")))?;
        let start_u64: u64 = start
            .try_into()
            .map_err(|_| SequencerError::ContractError("START time too large".to_string()))?;

        // Get contract's lastTimestamp
        let last_ts = entrypoint.lastTimestamp().call().await.map_err(|e| {
            SequencerError::ContractError(format!("Failed to get lastTimestamp: {e}"))
        })?;
        let last_day: u64 = last_ts.day.try_into().unwrap_or(0);
        let last_index: u64 = last_ts.index.try_into().unwrap_or(0);

        // Get current block number to check if this is the first block
        let current_block_nr = self.get_current_block_number().await?;

        // Get current time estimate (use system time as approximation)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("System time before UNIX epoch")
            .as_secs();

        // Add small buffer for mining delay (a few seconds)
        let estimated_block_time = now + 3;

        // Compute predicted day
        const DAY: u64 = 86400;
        let predicted_day = estimated_block_time.saturating_sub(start_u64) / DAY;

        // Compute predicted index
        let predicted_index = if current_block_nr == 0 {
            // First block ever
            0
        } else if last_day == predicted_day {
            // Same day as last block
            last_index + 1
        } else {
            // New day
            0
        };

        debug!(
            "Predicted block index: day={}, index={} (last: day={}, index={}, block_nr={})",
            predicted_day, predicted_index, last_day, last_index, current_block_nr
        );

        Ok((predicted_day, predicted_index))
    }

    /// Register as a sequencer by staking the required amount.
    pub async fn register_sequencer(&self) -> Result<(), SequencerError> {
        let entrypoint = self.entrypoint();

        // Get required stake
        let stake_divisor = U256::from(10u64).pow(U256::from(14));
        let stake_req = entrypoint.requiredStake().call().await.map_err(|e| {
            SequencerError::ContractError(format!("Failed to get required stake: {e}"))
        })?;

        let stake_amount = stake_req * stake_divisor;
        info!("Registering as sequencer with stake: {} wei", stake_amount);

        // Fund the sequencer
        let receipt = entrypoint
            .fund()
            .value(stake_amount)
            .send()
            .await
            .map_err(|e| SequencerError::ContractError(format!("Failed to fund: {e}")))?
            .get_receipt()
            .await
            .map_err(|e| SequencerError::ContractError(format!("Failed to get receipt: {e}")))?;

        if !receipt.status() {
            return Err(SequencerError::ContractError(
                "Sequencer registration failed".into(),
            ));
        }

        info!("Successfully registered as sequencer");
        Ok(())
    }

    /// Get the epoch watcher for timing queries.
    pub fn epoch_watcher(&self) -> &EpochWatcher<P> {
        &self.epoch_watcher
    }
}

/// Create a submitter config from a private key and contract address.
pub fn create_config(
    private_key: &str,
    entrypoint_address: Address,
) -> Result<SubmitterConfig, SequencerError> {
    let private_key = private_key.strip_prefix("0x").unwrap_or(private_key);
    let signer: PrivateKeySigner = private_key
        .parse()
        .map_err(|e| SequencerError::ConfigError(format!("Invalid private key: {e}")))?;

    let sequencer_address = signer.address();

    Ok(SubmitterConfig {
        entrypoint_address,
        sequencer_address,
        signer,
        submission_timeout: Duration::from_secs(30),
        anvil_mode: false, // Production mode - use raw KZG
    })
}

/// Create an Ethereum wallet from a signer.
pub fn create_wallet(signer: &PrivateKeySigner) -> EthereumWallet {
    EthereumWallet::from(signer.clone())
}
