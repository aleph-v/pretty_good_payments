//! Reusable challenger runner for fraud detection and challenge submission.
//!
//! This module provides the core challenger logic that can be used by both the
//! standalone challenger binary and the integrated sequencer.

use alloy::primitives::{Address, B256};
use alloy::providers::Provider;
use eyre::{Result, WrapErr};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::{
    beacon::{create_production_blob_provider, BlobProvider},
    challenge::{memory, BlobWithHash, ChallengeBuilder, ChallengeSubmitter},
    contracts,
    events::ChainEvent,
    groth16::Groth16Verifier,
    snarkjs::SnarkjsProver,
    state::StateManager,
    validators::{
        AnchorLookup, DepositValidator, FraudEvidence, NullifierValidator, RootTreeTracker,
        TransactionValidator, TreeUpdateValidator, BLOCKS_PER_DAY,
    },
};
use pgp_common::blob::ParsedBlock;
use pgp_common::contracts::BlockData;

// Re-export the config trait from common
pub use pgp_common::ChallengerRunnerConfig;

// ============================================================================
// Types
// ============================================================================

/// Detected fraud along with the context needed to challenge it
#[derive(Debug, Clone)]
pub struct FraudWithContext {
    /// The fraud evidence
    pub fraud: FraudEvidence,
    /// Block number containing the fraud
    pub block_nr: u64,
    /// L1 block number (for beacon chain blob retrieval)
    pub l1_block_number: u64,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get a string identifier for the fraud type (for logging and persistence)
pub fn fraud_type_name(fraud: &FraudEvidence) -> &'static str {
    match fraud {
        FraudEvidence::DepositWrongLeaf { .. } => "DepositWrongLeaf",
        FraudEvidence::DepositPaddingNotZero { .. } => "DepositPaddingNotZero",
        FraudEvidence::NullifierDoubleSpend { .. } => "NullifierDoubleSpend",
        FraudEvidence::InvalidTransactionProof { .. } => "InvalidTransactionProof",
        FraudEvidence::InvalidAnchorReference { .. } => "InvalidAnchorReference",
        FraudEvidence::MissingEthKeyAuth { .. } => "MissingEthKeyAuth",
        FraudEvidence::IncorrectTreeUpdate { .. } => "IncorrectTreeUpdate",
    }
}

/// Create a default/genesis BlockData
pub fn default_block_data() -> BlockData {
    BlockData {
        anchor: B256::ZERO,
        timestamp: alloy::primitives::U256::ZERO,
        numTransactions: alloy::primitives::U256::ZERO,
        numDeposits: alloy::primitives::U256::ZERO,
        blockNr: alloy::primitives::U256::ZERO,
        blockIndex: pgp_common::contracts::TimestampAndIndex {
            day: 0u128,
            index: 0u128,
        },
        sequencer: Address::ZERO,
        blobhashes: vec![],
    }
}

// ============================================================================
// ChallengerRunner
// ============================================================================

/// Core challenger runner that handles validation and challenge submission
pub struct ChallengerRunner<P> {
    provider: P,
    state: StateManager,

    // Validators
    deposit_validator: DepositValidator,
    nullifier_validator: NullifierValidator,
    tree_update_validator: TreeUpdateValidator,
    transaction_validator: TransactionValidator,

    // State tracking
    anchor_lookup: AnchorLookup,
    root_tree_tracker: RootTreeTracker,

    // Challenge infrastructure
    challenge_builder: Option<ChallengeBuilder>,
    challenge_submitter: Option<ChallengeSubmitter<P>>,
    blob_provider: Arc<dyn BlobProvider>,
    snarkjs_prover: SnarkjsProver,

    // Configuration
    deposits_address: Address,
    registry_address: Address,
    genesis_anchor: B256,
    max_retries: i32,
    dry_run: bool,
}

impl<P: Provider + Clone> ChallengerRunner<P> {
    /// Create a new ChallengerRunner from configuration
    pub async fn new<C: ChallengerRunnerConfig>(
        provider: P,
        state: StateManager,
        config: &C,
    ) -> Result<Self> {
        // Initialize validators
        let deposit_validator = DepositValidator::new();
        let nullifier_validator = NullifierValidator::new();
        let tree_update_validator = TreeUpdateValidator::new();

        // Initialize transaction validator with verification keys
        let transaction_validator = {
            let transfer_vk_path = config.transfer_verification_key();
            let update_vk_path = config.update_verification_key();
            info!(
                "Loading verification keys from {} and {}...",
                transfer_vk_path, update_vk_path
            );
            let transfer_vk = std::fs::read(transfer_vk_path).map_err(|e| {
                eyre::eyre!(
                    "Failed to read transfer VK from {}: {}",
                    transfer_vk_path,
                    e
                )
            })?;
            let update_vk = std::fs::read(update_vk_path).map_err(|e| {
                eyre::eyre!("Failed to read update VK from {}: {}", update_vk_path, e)
            })?;

            let verifier = Groth16Verifier::from_json(&transfer_vk, &update_vk)
                .map_err(|e| eyre::eyre!("Failed to initialize Groth16 verifier: {}", e))?;
            info!("Transaction validator initialized with verification keys");
            TransactionValidator::new(verifier)
        };

        // Fetch genesis anchor from contract
        let genesis_anchor =
            contracts::fetch_genesis_anchor(provider.clone(), config.entrypoint_address())
                .await
                .wrap_err("Failed to fetch genesis anchor from contract")?;
        info!("Genesis anchor: {:?}", genesis_anchor);

        // Initialize anchor lookup from database
        let mut anchor_lookup = AnchorLookup::new();
        let anchor_count = state.anchor_count()?;
        if anchor_count > 0 {
            info!("Loading {} anchors from database...", anchor_count);
            let mut stmt = state.conn_ref().prepare(
                "SELECT block_nr, update_nr, is_deposit, anchor FROM anchors ORDER BY block_nr",
            )?;
            let rows = stmt.query_map([], |row| {
                let block_nr: i64 = row.get(0)?;
                let update_nr: i64 = row.get(1)?;
                let is_deposit: i32 = row.get(2)?;
                let anchor: Vec<u8> = row.get(3)?;
                Ok((block_nr as u32, update_nr as u32, is_deposit != 0, anchor))
            })?;

            for row in rows {
                let (block_nr, update_nr, is_deposit, anchor_bytes) = row?;
                let anchor = B256::from_slice(&anchor_bytes);
                anchor_lookup.insert(block_nr, update_nr, is_deposit, anchor);
            }
            info!("Loaded {} anchors into memory", anchor_lookup.len());
        }

        info!("{} nullifiers in database", state.nullifier_count()?);

        // Initialize root tree tracker
        let block_roots = state.load_block_roots()?;
        let root_tree_tracker = if !block_roots.is_empty() {
            info!("Restoring root tree from {} block roots", block_roots.len());
            RootTreeTracker::from_block_roots(&block_roots)
        } else {
            info!("Starting root tree from genesis");
            RootTreeTracker::new()
        };
        info!(
            "Root tree tracker: {} blocks tracked, current_anchor={:?}",
            root_tree_tracker.block_count(),
            root_tree_tracker.current_anchor()
        );

        // Initialize blob provider with database storage + beacon fallback
        let blob_provider: Arc<dyn BlobProvider> = {
            let url = config.beacon_api_url();
            info!("Initializing blob provider with database storage + beacon fallback");
            info!("  Database: {}", config.database_path());
            info!("  Beacon API: {}", url);
            info!(
                "  Blob cache size: {} (~{}MB)",
                config.blob_cache_size(),
                config.blob_cache_size() * 131 / 1024
            );
            let provider = create_production_blob_provider(
                config.database_path(),
                url,
                config.blob_cache_size(),
            );
            Arc::new(provider)
        };

        // Initialize challenge infrastructure (only if not in dry run mode)
        let challenge_builder = if !config.dry_run() {
            match ChallengeBuilder::new() {
                Ok(builder) => {
                    info!("Challenge builder initialized");
                    Some(builder)
                }
                Err(e) => {
                    warn!(
                        "Failed to initialize challenge builder: {} - challenges disabled",
                        e
                    );
                    None
                }
            }
        } else {
            None
        };

        let challenge_submitter = if !config.dry_run() {
            Some(ChallengeSubmitter::new(
                provider.clone(),
                config.entrypoint_address(),
            ))
        } else {
            None
        };

        // Initialize snarkjs prover for tree update challenges
        let snarkjs_prover = {
            let snarkjs_path = config.snarkjs_path();
            let wasm_path = config.circuit_wasm_path();
            let zkey_path = config.circuit_zkey_path();
            info!("Initializing snarkjs prover for tree update challenges");
            info!("  snarkjs: {}", snarkjs_path);
            info!("  wasm: {}", wasm_path);
            info!("  zkey: {}", zkey_path);
            SnarkjsProver::new(
                snarkjs_path,
                std::path::Path::new(wasm_path),
                std::path::Path::new(zkey_path),
            )
        };

        Ok(Self {
            provider,
            state,
            deposit_validator,
            nullifier_validator,
            tree_update_validator,
            transaction_validator,
            anchor_lookup,
            root_tree_tracker,
            challenge_builder,
            challenge_submitter,
            blob_provider,
            snarkjs_prover,
            deposits_address: config.deposits_address(),
            registry_address: config
                .transaction_registry_address()
                .unwrap_or(Address::ZERO),
            genesis_anchor,
            max_retries: config.max_challenge_retries() as i32,
            dry_run: config.dry_run(),
        })
    }

    /// Perform startup health checks
    pub async fn perform_health_checks<C: ChallengerRunnerConfig>(&self, config: &C) -> Result<()> {
        info!("Performing startup health checks...");

        // Verify RPC connectivity
        let chain_id = self
            .provider
            .get_chain_id()
            .await
            .wrap_err("Failed to get chain ID from RPC - check RPC URL and connectivity")?;

        if chain_id != config.chain_id() {
            warn!(
                "Chain ID mismatch: config says {}, RPC says {}",
                config.chain_id(),
                chain_id
            );
        }
        info!("  RPC health check passed (chain_id={})", chain_id);

        // Verify database is readable/writable
        let test_key = "health_check_test";
        self.state
            .conn_ref()
            .execute(
                "INSERT OR REPLACE INTO state (key, value) VALUES (?1, ?2)",
                (test_key, &[1u8] as &[u8]),
            )
            .wrap_err("Database write health check failed")?;
        self.state
            .conn_ref()
            .execute("DELETE FROM state WHERE key = ?1", [test_key])
            .wrap_err("Database delete health check failed")?;
        info!("  Database health check passed");

        // Verify beacon API connectivity
        {
            let beacon_url = config.beacon_api_url();
            let client = reqwest::Client::new();
            let health_url = format!("{}/eth/v1/node/health", beacon_url.trim_end_matches('/'));

            match client
                .get(&health_url)
                .timeout(std::time::Duration::from_secs(10))
                .send()
                .await
            {
                Ok(response) => {
                    if response.status().is_success() || response.status().as_u16() == 206 {
                        info!("  Beacon API health check passed");
                    } else {
                        warn!(
                            "Beacon API returned status {}: blob retrieval may fail",
                            response.status()
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        "Beacon API health check failed ({}): blob retrieval from beacon chain may fail",
                        e
                    );
                }
            }
        }

        // Verify entrypoint contract is deployed
        let code = self
            .provider
            .get_code_at(config.entrypoint_address())
            .await
            .wrap_err("Failed to check entrypoint contract code")?;

        if code.is_empty() {
            return Err(eyre::eyre!(
                "No contract deployed at entrypoint address {:?}",
                config.entrypoint_address()
            ));
        }
        info!(
            "  Entrypoint contract verified at {:?}",
            config.entrypoint_address()
        );

        info!("All health checks passed");
        Ok(())
    }

    /// Get the last processed block from state
    pub fn load_last_processed_block(&self) -> Result<Option<u64>> {
        self.state.load_last_processed_block()
    }

    /// Process a single chain event with full validation
    pub async fn process_event(
        &mut self,
        event: &ChainEvent,
        prior_block: &mut Option<BlockData>,
    ) -> Result<Vec<FraudWithContext>> {
        let mut all_fraud = Vec::new();

        match event {
            ChainEvent::NewRoot(new_root) => {
                let block_nr: u64 = new_root
                    .block_number
                    .try_into()
                    .map_err(|_| eyre::eyre!("Block number exceeds u64::MAX"))?;

                info!(
                    "Processing NewRoot: L2 block {}, anchor {:?}, L1 block {}",
                    block_nr, new_root.anchor, new_root.l1_block_number
                );

                self.anchor_lookup.set_current_block(block_nr);

                // Fetch expected deposits
                let expected_deposits = contracts::fetch_expected_deposits(
                    self.provider.clone(),
                    self.deposits_address,
                    new_root.block_number,
                )
                .await?;

                if !expected_deposits.is_empty() {
                    info!(
                        "Fetched {} expected deposits for block {}",
                        expected_deposits.len(),
                        block_nr
                    );
                }

                // Get blob data
                let versioned_hashes = &new_root.block_data.blobhashes;
                if versioned_hashes.is_empty() {
                    warn!(
                        "Block {} has no blob hashes - skipping validation",
                        block_nr
                    );
                    return Ok(all_fraud);
                }

                let blob_data = self
                    .blob_provider
                    .get_blobs(new_root.l1_block_number, versioned_hashes)
                    .await?;

                info!(
                    "Retrieved {} blob(s) for block {}",
                    blob_data.len(),
                    block_nr
                );

                // Parse blob data
                let num_deposits: u64 = new_root
                    .block_data
                    .numDeposits
                    .try_into()
                    .map_err(|_| eyre::eyre!("numDeposits exceeds u64::MAX"))?;
                let num_txs: u64 = new_root
                    .block_data
                    .numTransactions
                    .try_into()
                    .map_err(|_| eyre::eyre!("numTransactions exceeds u64::MAX"))?;

                let blobs: Vec<[B256; pgp_common::types::constants::BLOB_SIZE]> = blob_data
                    .iter()
                    .map(|data| {
                        let mut blob = [B256::ZERO; pgp_common::types::constants::BLOB_SIZE];
                        for (i, chunk) in data.chunks(32).enumerate() {
                            if i >= blob.len() {
                                break;
                            }
                            if chunk.len() == 32 {
                                blob[i] = B256::from_slice(chunk);
                            }
                        }
                        blob
                    })
                    .collect();

                let parsed_block = ParsedBlock::from_blobs(
                    &blobs.to_vec(),
                    num_deposits as usize,
                    num_txs as usize,
                )?;

                info!(
                    "Parsed block {}: {} deposit groups, {} transactions",
                    block_nr,
                    parsed_block.deposit_groups.len(),
                    parsed_block.transactions.len()
                );

                // Populate anchor_lookup from this block's updates
                let block_nr_u32 = block_nr as u32;
                let mut deposit_update_nr: u32 = 0;

                for group in &parsed_block.deposit_groups {
                    self.anchor_lookup.insert(
                        block_nr_u32,
                        deposit_update_nr,
                        true,
                        group.new_root,
                    );
                    self.state.save_anchor(
                        block_nr_u32,
                        deposit_update_nr,
                        true,
                        group.new_root,
                    )?;
                    deposit_update_nr += 1;
                }

                let mut tx_update_nr: u32 = 0;
                for tx in &parsed_block.transactions {
                    self.anchor_lookup
                        .insert(block_nr_u32, tx_update_nr, false, tx.new_root);
                    self.state
                        .save_anchor(block_nr_u32, tx_update_nr, false, tx.new_root)?;
                    tx_update_nr += 1;
                }

                // Save block data
                self.state
                    .save_block_data(&new_root.block_data, new_root.l1_block_number)?;
                debug!(
                    "Saved block data for block {} (L1 block {})",
                    block_nr, new_root.l1_block_number
                );

                // === Validation Phase ===
                let mut raw_fraud = Vec::new();

                // 1. Deposit validation
                let deposit_fraud = self.deposit_validator.validate_block(
                    &new_root.block_data,
                    &parsed_block,
                    &expected_deposits,
                );
                if !deposit_fraud.is_empty() {
                    warn!(
                        "Detected {} deposit fraud(s) in block {}",
                        deposit_fraud.len(),
                        block_nr
                    );
                }
                raw_fraud.extend(deposit_fraud);

                // 2. Nullifier validation
                let nullifier_fraud =
                    self.nullifier_validator
                        .process_block(&self.state, block_nr, &parsed_block)?;
                if !nullifier_fraud.is_empty() {
                    warn!(
                        "Detected {} nullifier fraud(s) in block {}",
                        nullifier_fraud.len(),
                        block_nr
                    );
                }
                raw_fraud.extend(nullifier_fraud);

                // 3. Transaction ZK validation
                let tx_fraud = self
                    .transaction_validator
                    .validate_block(
                        &self.provider,
                        self.registry_address,
                        &new_root.block_data,
                        &parsed_block,
                        &self.anchor_lookup,
                    )
                    .await?;
                if !tx_fraud.is_empty() {
                    warn!(
                        "Detected {} transaction fraud(s) in block {}",
                        tx_fraud.len(),
                        block_nr
                    );
                }
                raw_fraud.extend(tx_fraud);

                // 4. Tree update validation
                let day = new_root.block_data.blockIndex.day as u64;
                let index_in_day = new_root.block_data.blockIndex.index as u64;
                let tree_index = day * BLOCKS_PER_DAY + index_in_day;

                let root_path = self.root_tree_tracker.get_root_path_for_index(tree_index);
                let prior_anchor = self.root_tree_tracker.current_anchor();
                let prior_block_nr = if block_nr > 0 {
                    Some(block_nr - 1)
                } else {
                    None
                };

                debug!(
                    "Tree validation for block {}: tree_index={}, prior_anchor={:?}",
                    block_nr, tree_index, prior_anchor
                );

                let (tree_fraud, final_block_tree_root) =
                    self.tree_update_validator.validate_block(
                        &new_root.block_data,
                        &parsed_block,
                        prior_anchor,
                        prior_block_nr,
                        tree_index,
                        0,
                        &root_path,
                    );
                if !tree_fraud.is_empty() {
                    warn!(
                        "Detected {} tree update fraud(s) in block {}",
                        tree_fraud.len(),
                        block_nr
                    );
                }
                raw_fraud.extend(tree_fraud);

                // Update root tree
                self.state
                    .save_block_root(tree_index, block_nr, final_block_tree_root)?;
                let new_anchor = self
                    .root_tree_tracker
                    .insert_block_root(tree_index, final_block_tree_root);
                debug!(
                    "Inserted block {} tree root {:?} at tree_index {}, new anchor: {:?}",
                    block_nr, final_block_tree_root, tree_index, new_anchor
                );

                // Wrap all fraud with context
                for fraud in raw_fraud {
                    all_fraud.push(FraudWithContext {
                        fraud,
                        block_nr,
                        l1_block_number: new_root.l1_block_number,
                    });
                }

                if all_fraud.is_empty() {
                    info!("Block {} validated successfully", block_nr);
                } else {
                    error!(
                        "Block {} has {} fraud(s) detected!",
                        block_nr,
                        all_fraud.len()
                    );
                }

                *prior_block = Some(new_root.block_data.clone());
            }

            ChainEvent::Rollback(rollback) => {
                let rollback_to: u64 = rollback
                    .to
                    .try_into()
                    .map_err(|_| eyre::eyre!("Rollback target exceeds u64::MAX"))?;

                info!(
                    "Processing Rollback: from {} to {}",
                    rollback.from, rollback.to
                );

                // Delete nullifiers
                self.state.delete_nullifiers_from(rollback_to)?;

                // Delete anchors
                let rollback_from = rollback_to.saturating_add(1) as u32;
                self.state.delete_anchors_from(rollback_from)?;
                self.anchor_lookup.rollback_from(rollback_from);

                // Delete block data
                self.state.delete_blocks_from(rollback_to)?;

                // Delete block roots and rebuild root tree
                self.state.delete_block_roots_from(rollback_to)?;
                let remaining_roots = self.state.load_block_roots()?;
                self.root_tree_tracker = if !remaining_roots.is_empty() {
                    RootTreeTracker::from_block_roots(&remaining_roots)
                } else {
                    RootTreeTracker::new()
                };
                info!(
                    "Root tree rolled back: {} blocks remain, current_anchor={:?}",
                    self.root_tree_tracker.block_count(),
                    self.root_tree_tracker.current_anchor()
                );

                // Delete pending challenges
                self.state.delete_pending_challenges_from(rollback_to)?;

                *prior_block = None;
            }
        }

        Ok(all_fraud)
    }

    /// Submit a challenge for detected fraud
    pub async fn submit_challenge(&self, fraud_ctx: &FraudWithContext) -> Result<B256> {
        let builder = self
            .challenge_builder
            .as_ref()
            .ok_or_else(|| eyre::eyre!("Challenge builder not available (dry-run mode?)"))?;
        let submitter = self
            .challenge_submitter
            .as_ref()
            .ok_or_else(|| eyre::eyre!("Challenge submitter not available (dry-run mode?)"))?;

        // Load block data from database
        let (block_data, _l1) = self
            .state
            .load_block_data(fraud_ctx.block_nr)?
            .ok_or_else(|| eyre::eyre!("Block data not found for block {}", fraud_ctx.block_nr))?;

        // Get prior block for rollback target
        let prior_block_nr = fraud_ctx.block_nr.saturating_sub(1);
        let prior_block = if prior_block_nr > 0 {
            self.state
                .load_block_data(prior_block_nr)?
                .map(|(bd, _)| bd)
                .unwrap_or_else(default_block_data)
        } else {
            default_block_data()
        };

        // Fetch blob data
        if block_data.blobhashes.is_empty() {
            return Err(eyre::eyre!(
                "Block {} has no blob hashes",
                fraud_ctx.block_nr
            ));
        }

        // Fetch all blobs for the current block (multi-blob support)
        let current_blobs_data = self
            .blob_provider
            .get_blobs(fraud_ctx.l1_block_number, &block_data.blobhashes)
            .await?;
        let current_blobs: Vec<BlobWithHash> = current_blobs_data
            .iter()
            .zip(block_data.blobhashes.iter())
            .map(|(data, hash)| BlobWithHash { data, hash: *hash })
            .collect();

        match &fraud_ctx.fraud {
            FraudEvidence::DepositWrongLeaf { .. }
            | FraudEvidence::DepositPaddingNotZero { .. } => {
                info!(
                    "Building deposit challenge for block {}",
                    block_data.blockNr
                );
                let params = builder.build_deposit_challenge(
                    &fraud_ctx.fraud,
                    &current_blobs,
                    prior_block,
                )?;
                submitter.submit_deposit_challenge(params).await
            }

            FraudEvidence::NullifierDoubleSpend {
                first_block_nr,
                second_block_nr,
                nullifier,
                ..
            } => {
                let (first_block_data, first_l1) = self
                    .state
                    .load_block_data(*first_block_nr)?
                    .ok_or_else(|| {
                        eyre::eyre!("First block data not found for block {}", first_block_nr)
                    })?;

                let (second_block_data, second_l1) = self
                    .state
                    .load_block_data(*second_block_nr)?
                    .ok_or_else(|| {
                        eyre::eyre!("Second block data not found for block {}", second_block_nr)
                    })?;

                // Fetch all blobs for first block
                if first_block_data.blobhashes.is_empty() {
                    return Err(eyre::eyre!(
                        "First block {} has no blob hashes",
                        first_block_nr
                    ));
                }
                let first_blobs_data = self
                    .blob_provider
                    .get_blobs(first_l1, &first_block_data.blobhashes)
                    .await?;

                // Fetch all blobs for second block (or reuse first if same block)
                let second_blobs_data = if *first_block_nr == *second_block_nr {
                    first_blobs_data.clone()
                } else {
                    if second_block_data.blobhashes.is_empty() {
                        return Err(eyre::eyre!(
                            "Second block {} has no blob hashes",
                            second_block_nr
                        ));
                    }
                    self.blob_provider
                        .get_blobs(second_l1, &second_block_data.blobhashes)
                        .await?
                };

                // Build BlobWithHash references
                let first_blobs: Vec<BlobWithHash> = first_blobs_data
                    .iter()
                    .zip(first_block_data.blobhashes.iter())
                    .map(|(data, hash)| BlobWithHash { data, hash: *hash })
                    .collect();

                let second_blobs: Vec<BlobWithHash> = second_blobs_data
                    .iter()
                    .zip(second_block_data.blobhashes.iter())
                    .map(|(data, hash)| BlobWithHash { data, hash: *hash })
                    .collect();

                info!(
                    "Building nullifier challenge for blocks {} and {}, nullifier {:?}",
                    first_block_nr, second_block_nr, nullifier
                );

                let params = builder.build_nullifier_challenge(
                    &fraud_ctx.fraud,
                    &first_blobs,
                    &second_blobs,
                    first_block_data,
                    second_block_data,
                    prior_block,
                )?;
                submitter.submit_nullifier_challenge(params).await
            }

            FraudEvidence::InvalidTransactionProof {
                tx_nr,
                anchor_block_nr,
                anchor_update_nr,
                is_deposit,
                ..
            }
            | FraudEvidence::InvalidAnchorReference {
                tx_nr,
                anchor_block_nr,
                anchor_update_nr,
                is_deposit,
                ..
            }
            | FraudEvidence::MissingEthKeyAuth {
                tx_nr,
                anchor_block_nr,
                anchor_update_nr,
                is_deposit,
                ..
            } => {
                info!(
                    "Building transaction challenge for block {} tx {}",
                    block_data.blockNr, tx_nr
                );

                let (prior_anchor_block, prior_anchor_l1) = self
                    .state
                    .load_block_data(*anchor_block_nr as u64)?
                    .ok_or_else(|| {
                        eyre::eyre!("Prior anchor block {} not found", anchor_block_nr)
                    })?;

                let anchor = self
                    .state
                    .load_anchor(*anchor_block_nr, *anchor_update_nr, *is_deposit)?
                    .ok_or_else(|| {
                        eyre::eyre!(
                            "Anchor not found: block={}, update={}, is_deposit={}",
                            anchor_block_nr,
                            anchor_update_nr,
                            is_deposit
                        )
                    })?;

                if prior_anchor_block.blobhashes.is_empty() {
                    return Err(eyre::eyre!(
                        "Prior anchor block {} has no blob hashes",
                        anchor_block_nr
                    ));
                }
                // Fetch all blobs for prior anchor block (multi-blob support)
                let prior_anchor_blobs_data = self
                    .blob_provider
                    .get_blobs(prior_anchor_l1, &prior_anchor_block.blobhashes)
                    .await?;
                let prior_anchor_blobs: Vec<BlobWithHash> = prior_anchor_blobs_data
                    .iter()
                    .zip(prior_anchor_block.blobhashes.iter())
                    .map(|(data, hash)| BlobWithHash { data, hash: *hash })
                    .collect();

                let prior_num_deposits: u64 = prior_anchor_block
                    .numDeposits
                    .try_into()
                    .map_err(|_| eyre::eyre!("Prior block numDeposits exceeds u64::MAX"))?;
                let prior_anchor_field_index = memory::anchor_memory_address(
                    *anchor_update_nr as u64,
                    prior_num_deposits,
                    *is_deposit,
                ) as usize;

                // Note: current_blobs already fetched at the top of submit_challenge

                let params = builder.build_transaction_challenge_multi_blob(
                    &fraud_ctx.fraud,
                    &current_blobs,
                    anchor,
                    prior_anchor_block,
                    &prior_anchor_blobs,
                    prior_anchor_field_index,
                    prior_block,
                )?;
                submitter.submit_transaction_challenge(params).await
            }

            FraudEvidence::IncorrectTreeUpdate {
                update_nr,
                is_tx,
                expected_anchor,
                prior_anchor,
                leaves,
                prior_anchor_block_nr,
                prior_update_nr,
                merkle_data,
                ..
            } => {
                info!(
                    "Building tree update challenge for block {} update {}",
                    block_data.blockNr, update_nr
                );

                let prover = &self.snarkjs_prover;

                let merkle = merkle_data
                    .as_ref()
                    .ok_or_else(|| eyre::eyre!("Tree update challenge requires merkle data"))?;

                // Determine prior anchor blobs and field index
                // Three cases: same block, previous block, or genesis
                let (prior_anchor_blobs_owned, prior_anchor_field_index, is_genesis): (
                    Vec<Vec<u8>>,
                    usize,
                    bool,
                ) = if let Some(prior_upd_nr) = prior_update_nr {
                    // Prior anchor is in the same block - reuse current_blobs
                    let num_deposits: u64 = block_data
                        .numDeposits
                        .try_into()
                        .map_err(|_| eyre::eyre!("numDeposits exceeds u64::MAX"))?;
                    let field_index =
                        memory::anchor_memory_address(*prior_upd_nr, num_deposits, !*is_tx)
                            as usize;
                    // Clone the current blobs data for the prior anchor
                    let blobs_data: Vec<Vec<u8>> =
                        current_blobs.iter().map(|b| b.data.to_vec()).collect();
                    (blobs_data, field_index, false)
                } else if let Some(prior_blk_nr) = prior_anchor_block_nr {
                    // Prior anchor is in a previous block - fetch its blobs
                    let (prior_blk_data, prior_l1) =
                        self.state.load_block_data(*prior_blk_nr)?.ok_or_else(|| {
                            eyre::eyre!("Prior anchor block {} not found", prior_blk_nr)
                        })?;

                    if prior_blk_data.blobhashes.is_empty() {
                        return Err(eyre::eyre!(
                            "Prior anchor block {} has no blob hashes",
                            prior_blk_nr
                        ));
                    }
                    // Fetch all blobs for prior block (multi-blob support)
                    let prior_blobs_data = self
                        .blob_provider
                        .get_blobs(prior_l1, &prior_blk_data.blobhashes)
                        .await?;

                    let prior_num_deposits: u64 = prior_blk_data
                        .numDeposits
                        .try_into()
                        .map_err(|_| eyre::eyre!("Prior numDeposits exceeds u64::MAX"))?;
                    let prior_num_txs: u64 = prior_blk_data
                        .numTransactions
                        .try_into()
                        .map_err(|_| eyre::eyre!("Prior numTransactions exceeds u64::MAX"))?;

                    let num_deposit_groups = prior_num_deposits.div_ceil(3);
                    let last_update_is_tx = prior_num_txs > 0;
                    let last_update_nr = if last_update_is_tx {
                        num_deposit_groups + prior_num_txs - 1
                    } else if num_deposit_groups > 0 {
                        num_deposit_groups - 1
                    } else {
                        0
                    };

                    let field_index = memory::anchor_memory_address(
                        last_update_nr,
                        prior_num_deposits,
                        !last_update_is_tx,
                    ) as usize;

                    (prior_blobs_data, field_index, false) // is_genesis = false
                } else {
                    // Genesis case: first update in block 0
                    // No prior blobs needed - contract validates anchor == GENESIS_ANCHOR directly
                    info!("Using genesis anchor for first tree update challenge");
                    (vec![], 0, true) // is_genesis = true
                };

                // Validate prior update ordering when not genesis
                if let Some(prior_upd) = prior_update_nr {
                    if *prior_upd >= *update_nr {
                        return Err(eyre::eyre!(
                            "Prior update number {} must be less than current update number {}",
                            prior_upd,
                            update_nr
                        ));
                    }
                }

                // Build BlobWithHash for prior anchor blobs (skip for genesis case)
                let prior_anchor_blobs: Vec<BlobWithHash> = if is_genesis {
                    vec![] // Genesis case doesn't need prior blobs
                } else if prior_update_nr.is_some() {
                    // Same block - use current block's hashes
                    prior_anchor_blobs_owned
                        .iter()
                        .zip(block_data.blobhashes.iter())
                        .map(|(data, hash)| BlobWithHash { data, hash: *hash })
                        .collect()
                } else if let Some(prior_blk_nr) = prior_anchor_block_nr {
                    // Previous block - re-fetch to get hashes
                    let (prior_blk_data, _) =
                        self.state.load_block_data(*prior_blk_nr)?.ok_or_else(|| {
                            eyre::eyre!("Prior anchor block {} not found", prior_blk_nr)
                        })?;
                    prior_anchor_blobs_owned
                        .iter()
                        .zip(prior_blk_data.blobhashes.iter())
                        .map(|(data, hash)| BlobWithHash { data, hash: *hash })
                        .collect()
                } else {
                    return Err(eyre::eyre!("No prior anchor information available"));
                };

                // Note: current_blobs already fetched at the top of submit_challenge

                // For genesis case, use genesis_anchor as prior anchor
                let actual_prior_anchor = if is_genesis {
                    self.genesis_anchor
                } else {
                    *prior_anchor
                };

                info!(
                    "Generating ZK proof for tree update: block_index={}, in_block_index={}, is_genesis={}",
                    merkle.block_index, merkle.in_block_index, is_genesis
                );

                let (true_anchor, zk_proof) = prover
                    .generate_update_proof(
                        actual_prior_anchor,
                        merkle.block_root_before,
                        *leaves,
                        merkle.block_index,
                        merkle.in_block_index as u64,
                        merkle.nonzero_field,
                        merkle.block_proofs,
                        merkle.root_path,
                    )
                    .await?;

                if true_anchor != *expected_anchor {
                    warn!(
                        "ZK proof produced different anchor: expected {:?}, got {:?}",
                        expected_anchor, true_anchor
                    );
                    return Err(eyre::eyre!(
                        "ZK proof anchor mismatch: expected {:?}, got {:?}",
                        expected_anchor,
                        true_anchor
                    ));
                }

                info!(
                    "ZK proof generated successfully, true_anchor={:?}",
                    true_anchor
                );

                // Use different challenge builder method for genesis case
                let params = if is_genesis {
                    builder.build_tree_update_challenge_genesis(
                        &fraud_ctx.fraud,
                        &current_blobs,
                        self.genesis_anchor,
                        true_anchor,
                        zk_proof,
                        prior_block,
                    )?
                } else {
                    builder.build_tree_update_challenge_multi_blob(
                        &fraud_ctx.fraud,
                        &current_blobs,
                        actual_prior_anchor,
                        &prior_anchor_blobs,
                        prior_anchor_field_index,
                        true_anchor,
                        zk_proof,
                        prior_block,
                    )?
                };
                submitter.submit_tree_update_challenge(params).await
            }
        }
    }

    /// Retry pending challenges that failed previously
    pub async fn retry_pending_challenges(&self) -> Result<()> {
        let pending = self.state.load_pending_challenges()?;

        if pending.is_empty() {
            return Ok(());
        }

        info!("Retrying {} pending challenge(s)", pending.len());

        for challenge in pending {
            if challenge.retry_count >= self.max_retries {
                warn!(
                    "Pending challenge {} for block {} has exceeded max retries ({}) - skipping",
                    challenge.id, challenge.block_nr, self.max_retries
                );
                continue;
            }

            info!(
                "Retrying challenge {} for block {} (attempt {}, type={})",
                challenge.id,
                challenge.block_nr,
                challenge.retry_count + 1,
                challenge.fraud_type
            );

            // For now, just increment retry count - full retry requires re-validation
            self.state.update_pending_challenge_retry(
                challenge.id,
                Some("Pending challenge retry not fully implemented"),
            )?;
        }

        Ok(())
    }

    /// Save a pending challenge for later retry
    pub fn save_pending_challenge(
        &self,
        fraud_ctx: &FraudWithContext,
        error_msg: &str,
    ) -> Result<()> {
        let fraud_type = fraud_type_name(&fraud_ctx.fraud);
        self.state.save_pending_challenge(
            fraud_ctx.block_nr,
            fraud_ctx.l1_block_number,
            fraud_type,
            &[],
            Some(error_msg),
        )?;
        Ok(())
    }

    /// Save progress to database
    pub fn save_progress(&self, last_block: u64) -> Result<()> {
        self.state.save_last_processed_block(last_block)
    }

    /// Begin database transaction
    pub fn begin_transaction(&self) -> Result<()> {
        self.state.begin_transaction()
    }

    /// Commit database transaction
    pub fn commit_transaction(&self) -> Result<()> {
        self.state.commit_transaction()
    }

    /// Rollback database transaction
    pub fn rollback_transaction(&self) -> Result<()> {
        self.state.rollback_transaction()
    }

    /// Get reference to state manager
    pub fn state(&self) -> &StateManager {
        &self.state
    }

    /// Get current anchor from root tree tracker
    pub fn current_anchor(&self) -> B256 {
        self.root_tree_tracker.current_anchor()
    }

    /// Check if running in dry-run mode
    pub fn is_dry_run(&self) -> bool {
        self.dry_run
    }
}
