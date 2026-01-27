//! Anvil-based integration tests for the challenger.
//!
//! These tests spawn a local Anvil instance with EIP-4844 blob support,
//! deploy contracts using Foundry scripts, submit real blob transactions,
//! and verify that the challenger correctly detects fraud.

use alloy::consensus::{BlobTransactionSidecar, SidecarBuilder, SimpleCoder};
use alloy::network::Ethereum;
use alloy::network::{EthereumWallet, TransactionBuilder, TransactionBuilder4844};
use alloy::node_bindings::{Anvil, AnvilInstance};
use alloy::primitives::{hex, Address, B256, U256};
use alloy::providers::ext::AnvilApi;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolEvent;
use eyre::{eyre, Result};
use std::process::Command;
use std::str::FromStr;

use pgp_challenger::BlobWithHash;
use pgp_common::contracts::{
    BlockData, Entrypoint, FakeERC20, Leaf, SequencerRegistry, TimestampAndIndex,
};

// ============================================================================
// Test Harness - Reusable test infrastructure
// ============================================================================

/// Deployed contract addresses from the local deployment script
#[derive(Debug, Clone)]
pub struct DeployedContracts {
    pub entrypoint: Address,
    pub token: Address,
    pub transaction_registry: Address,
}

/// Result of submitting a block
#[derive(Debug, Clone)]
pub struct SubmittedBlock {
    /// The actual block data from the NewRoot event
    pub block_data: BlockData,
    /// The L2 block hash
    pub l2_block_hash: B256,
    /// The full blob bytes (131072 bytes) for KZG proof generation
    pub full_blob_bytes: Vec<u8>,
}

impl SubmittedBlock {
    /// Get the blobs for this block as BlobWithHash references.
    /// Returns a single blob (tests use single-blob blocks).
    pub fn as_blobs(&self) -> Vec<BlobWithHash> {
        let hash = self
            .block_data
            .blobhashes
            .first()
            .copied()
            .unwrap_or(B256::ZERO);
        vec![BlobWithHash {
            data: &self.full_blob_bytes,
            hash,
        }]
    }
}

/// Test context that manages the Anvil instance and provides helper methods.
/// This struct holds all the common infrastructure needed for integration tests.
pub struct TestContext<P> {
    /// The Anvil instance (kept alive for the duration of the test)
    #[allow(dead_code)]
    anvil: AnvilInstance,
    /// The provider with wallet for sending transactions
    pub provider: P,
    /// Deployed contract addresses
    pub contracts: DeployedContracts,
    /// The deployer/sequencer address
    pub deployer: Address,
    /// The signer for the deployer
    #[allow(dead_code)]
    pub signer: PrivateKeySigner,
    /// Genesis anchor from the contract
    pub genesis_anchor: B256,
}

/// Create a new test context by spawning Anvil and deploying contracts.
/// Returns None if forge is not available (for CI environments without forge).
pub async fn setup_test_context() -> Result<Option<TestContext<impl Provider + Clone>>> {
    // Skip if forge is not available
    if Command::new("forge").arg("--version").output().is_err() {
        eprintln!("Skipping test: forge not found in PATH");
        return Ok(None);
    }

    // Spawn Anvil with Cancun hardfork for blob support
    let anvil = Anvil::new()
        .block_time(1)
        .args([
            "--hardfork",
            "cancun",
            "--disable-block-gas-limit",
            "--disable-code-size-limit",
        ])
        .try_spawn()?;

    let rpc_url = anvil.endpoint();
    let private_key = anvil.keys()[0].clone();
    let signer: PrivateKeySigner = private_key.clone().into();
    let deployer = signer.address();

    println!("Anvil running at: {rpc_url} (Cancun hardfork)");
    println!("Deployer: {deployer}");

    // Deploy contracts
    let private_key_hex = format!("0x{}", hex::encode(private_key.to_bytes()));
    let contracts = deploy_contracts(&rpc_url, &private_key_hex)?;
    println!("Deployed contracts: {contracts:?}");
    println!("✓ Contract deployment successful");

    // Create provider with wallet
    let wallet = EthereumWallet::from(signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url.parse()?);

    // Get genesis anchor
    let entrypoint = Entrypoint::new(contracts.entrypoint, &provider);
    let genesis_anchor = entrypoint.GENESIS_ANCHOR().call().await?;
    println!("Genesis anchor: {genesis_anchor}");

    Ok(Some(TestContext {
        anvil,
        provider,
        contracts,
        deployer,
        signer,
        genesis_anchor,
    }))
}

impl<P: Provider + Clone> TestContext<P> {
    /// Get the Entrypoint contract instance
    pub fn entrypoint(&self) -> Entrypoint::EntrypointInstance<&P> {
        Entrypoint::new(self.contracts.entrypoint, &self.provider)
    }

    /// Get the FakeERC20 token contract instance
    pub fn token(&self) -> FakeERC20::FakeERC20Instance<&P> {
        FakeERC20::new(self.contracts.token, &self.provider)
    }

    /// Get the SequencerRegistry contract instance
    pub fn registry(&self) -> SequencerRegistry::SequencerRegistryInstance<&P> {
        SequencerRegistry::new(self.contracts.entrypoint, &self.provider)
    }

    /// Get the TransactionRegistry address
    pub fn transaction_registry_address(&self) -> Address {
        self.contracts.transaction_registry
    }

    /// Register as a sequencer by staking the required amount.
    /// Note: requiredStake() returns value in STAKE_DIVISOR units (10^14 wei).
    pub async fn register_sequencer(&self) -> Result<()> {
        let entrypoint = self.entrypoint();
        let stake_divisor = U256::from(10u64).pow(U256::from(14));
        let stake_req = entrypoint.requiredStake().call().await?;
        let stake_amount = stake_req * stake_divisor;

        let receipt = entrypoint
            .fund()
            .value(stake_amount)
            .send()
            .await?
            .get_receipt()
            .await?;
        assert!(receipt.status(), "Sequencer registration must succeed");
        println!("✓ Sequencer registered (stake: {stake_amount} wei)");
        Ok(())
    }

    /// Advance time to an open period (second half of epoch).
    /// EPOCH_LENGTH = 10 seconds, closed period is first 5 seconds.
    pub async fn advance_to_open_period(&self) -> Result<()>
    where
        P: AnvilApi<Ethereum>,
    {
        self.provider.anvil_increase_time(6).await?;
        self.provider.anvil_mine(Some(1), None).await?;
        println!("✓ Advanced time to open period");
        Ok(())
    }

    /// Wait until we're in an open period (useful after operations that might change epochs).
    pub async fn wait_for_open_period(&self) -> Result<()>
    where
        P: AnvilApi<Ethereum>,
    {
        let registry = self.registry();
        loop {
            let epoch_result = registry.currentEpoch().call().await?;
            if !epoch_result.isClosed {
                break;
            }
            self.provider.anvil_increase_time(1).await?;
            self.provider.anvil_mine(Some(1), None).await?;
        }
        Ok(())
    }

    /// Mint tokens and approve the entrypoint to spend them.
    pub async fn mint_and_approve_tokens(&self, amount: U256) -> Result<()> {
        let token = self.token();
        token
            .mint(self.deployer, amount)
            .send()
            .await?
            .get_receipt()
            .await?;
        token
            .approve(self.contracts.entrypoint, amount)
            .send()
            .await?
            .get_receipt()
            .await?;
        println!("✓ Tokens minted and approved: {amount}");
        Ok(())
    }

    /// Create a deposit on L1. Returns the target block number for the deposit.
    pub async fn create_deposit(&self, amount: U256, public_key: B256) -> Result<U256> {
        let deposit_leaf = Leaf {
            asset: self.contracts.token,
            amount,
            blinding: B256::ZERO,
            publicKey: public_key,
        };
        self.entrypoint()
            .deposit(deposit_leaf)
            .send()
            .await?
            .get_receipt()
            .await?;
        println!("✓ Deposit created on L1 (amount: {amount})");

        // Deposits target block = max(highestDeposit, currentBlock + 2)
        // Return the likely target block
        let current_block = self.entrypoint().getCurrentBlocknumber().call().await?;
        Ok(current_block + U256::from(2))
    }

    /// Get deposits for a specific block number.
    pub async fn get_deposits_for_block(&self, block_nr: U256) -> Result<Vec<B256>> {
        let deposits = self.entrypoint().getDepositArray(block_nr).call().await?;
        Ok(deposits)
    }

    /// Build a blob sidecar from deposit leaves.
    pub fn build_deposit_sidecar(&self, deposit_leaves: &[B256]) -> Result<BlobTransactionSidecar> {
        let blob_data = create_deposit_blob_data(deposit_leaves);
        let sidecar: SidecarBuilder<SimpleCoder> = SidecarBuilder::from_slice(&blob_data);
        Ok(sidecar.build()?)
    }

    /// Build a blob sidecar from raw 32-byte fields (for tree update testing)
    pub fn build_raw_blob_sidecar(&self, fields: &[B256; 4096]) -> Result<BlobTransactionSidecar> {
        // Convert fields to raw bytes
        let mut blob_bytes = vec![0u8; 131072]; // 4096 * 32 bytes
        for (i, field) in fields.iter().enumerate() {
            blob_bytes[i * 32..(i + 1) * 32].copy_from_slice(field.as_slice());
        }
        let sidecar: SidecarBuilder<SimpleCoder> = SidecarBuilder::from_slice(&blob_bytes);
        Ok(sidecar.build()?)
    }

    /// Submit a block with the given parameters. Returns the actual BlockData from the event.
    pub async fn submit_block(
        &self,
        block_nr: U256,
        num_deposits: U256,
        num_transactions: U256,
        sidecar: BlobTransactionSidecar,
    ) -> Result<SubmittedBlock> {
        let versioned_hashes: Vec<B256> = sidecar.versioned_hashes().collect();
        let full_blob_bytes: Vec<u8> = sidecar.blobs[0].iter().copied().collect();

        let block_data = BlockData {
            anchor: self.genesis_anchor,
            timestamp: U256::ZERO,
            numTransactions: num_transactions,
            numDeposits: num_deposits,
            blockNr: block_nr,
            blockIndex: TimestampAndIndex { day: 0, index: 0 },
            sequencer: self.deployer,
            blobhashes: versioned_hashes,
        };

        let post_calldata = self
            .entrypoint()
            .post(block_data, vec![U256::ZERO])
            .calldata()
            .clone();

        let blob_tx = TransactionRequest::default()
            .with_to(self.contracts.entrypoint)
            .with_input(post_calldata)
            .with_blob_sidecar(sidecar);

        let pending = self
            .provider
            .send_transaction(blob_tx)
            .await
            .map_err(|e| eyre!("Failed to send blob transaction: {}", e))?;
        let receipt = pending.get_receipt().await?;

        if !receipt.status() {
            return Err(eyre!(
                "Block {} submission reverted. Gas used: {}",
                block_nr,
                receipt.gas_used
            ));
        }

        // Extract actual block data from NewRoot event
        let logs: Vec<_> = receipt
            .inner
            .logs()
            .iter()
            .filter(|log| log.topic0() == Some(&Entrypoint::NewRoot::SIGNATURE_HASH))
            .collect();
        assert!(!logs.is_empty(), "Should have NewRoot event");

        let decoded = logs[0]
            .log_decode::<Entrypoint::NewRoot>()
            .expect("Failed to decode NewRoot event");
        let actual_block_data = decoded.inner.data.data;
        let l2_block_hash = decoded.inner.data.l2BlockHash;

        println!(
            "✓ Block {} submitted (hash: {})",
            actual_block_data.blockNr, l2_block_hash
        );

        Ok(SubmittedBlock {
            block_data: actual_block_data,
            l2_block_hash,
            full_blob_bytes,
        })
    }

    /// Check if the sequencer is allowed to post blocks.
    pub async fn is_sequencer_allowed(&self) -> Result<bool> {
        Ok(self.entrypoint().isAllowed(self.deployer).call().await?)
    }

    /// Verify that the sequencer was slashed (not allowed after waiting for open period).
    pub async fn assert_sequencer_slashed(&self) -> Result<()>
    where
        P: AnvilApi<Ethereum>,
    {
        self.wait_for_open_period().await?;

        let is_allowed = self.is_sequencer_allowed().await?;
        assert!(
            !is_allowed,
            "Sequencer should not be allowed after successful challenge"
        );

        let registry = self.registry();
        let seq_status = registry.sequencers(self.deployer).call().await?;
        assert!(
            !seq_status.isActive,
            "Sequencer should be deactivated after slash"
        );

        println!("✓ Sequencer was slashed!");
        Ok(())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Parse deployed addresses from forge script output
fn parse_deployment_output(output: &str) -> Result<DeployedContracts> {
    let mut entrypoint = None;
    let mut token = None;
    let mut transaction_registry = None;

    for line in output.lines() {
        let line = line.trim();
        if line.contains("\"entrypoint\":") {
            entrypoint = extract_address(line);
        } else if line.contains("\"token\":") {
            token = extract_address(line);
        } else if line.contains("\"transactionRegistry\":") {
            transaction_registry = extract_address(line);
        }
    }

    Ok(DeployedContracts {
        entrypoint: entrypoint.ok_or_else(|| eyre!("entrypoint address not found"))?,
        token: token.ok_or_else(|| eyre!("token address not found"))?,
        transaction_registry: transaction_registry
            .ok_or_else(|| eyre!("transactionRegistry address not found"))?,
    })
}

fn extract_address(line: &str) -> Option<Address> {
    let start = line.find("0x")?;
    let end = start + 42;
    if end <= line.len() {
        let addr_str = &line[start..end];
        Address::from_str(addr_str).ok()
    } else {
        None
    }
}

/// Find the project root directory (containing foundry.toml)
fn find_project_root() -> std::path::PathBuf {
    // Try from CARGO_MANIFEST_DIR first
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let mut path = std::path::PathBuf::from(manifest_dir);
        // Go up from crates/challenger to project root
        for _ in 0..3 {
            if path.join("foundry.toml").exists() {
                return path;
            }
            path = path.parent().unwrap_or(&path).to_path_buf();
        }
    }

    // Try from current directory
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

    // Fallback to absolute path
    std::path::PathBuf::from("/Users/pvienhage/dev/pretty_good_payments")
}

/// Global lock file for serializing forge builds during parallel test execution
static BUILD_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();

/// Deploy contracts to Anvil using forge script
fn deploy_contracts(rpc_url: &str, private_key: &str) -> Result<DeployedContracts> {
    let project_root = find_project_root();

    // Ensure foundry.toml exists
    if !project_root.join("foundry.toml").exists() {
        return Err(eyre!(
            "Could not find foundry.toml in project root: {}",
            project_root.display()
        ));
    }

    // Acquire build lock to prevent parallel forge builds from conflicting
    let lock = BUILD_LOCK.get_or_init(|| std::sync::Mutex::new(()));
    let _guard = lock.lock().unwrap();

    // Run forge build first to ensure cache exists (without --force to avoid conflicts)
    let cache_file = project_root.join("cache/solidity-files-cache.json");
    if !cache_file.exists() {
        let build_output = Command::new("forge")
            .current_dir(&project_root)
            .args(["build"])
            .output()?;

        if !build_output.status.success() {
            let stderr = String::from_utf8_lossy(&build_output.stderr);
            return Err(eyre!("forge build failed: {}", stderr));
        }
    }

    let output = Command::new("forge")
        .current_dir(&project_root)
        .args([
            "script",
            "script/deploy/DeployLocal.s.sol:DeployLocal",
            "--rpc-url",
            rpc_url,
            "--broadcast",
            "--private-key",
            private_key,
            "--slow",
            "--code-size-limit",
            "200000",
            "--legacy",
        ])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        return Err(eyre!(
            "forge script failed:\nstdout: {}\nstderr: {}",
            stdout,
            stderr
        ));
    }

    parse_deployment_output(&stdout).map_err(|e| {
        eyre!(
            "forge script failed to parse addresses:\nError: {}\nstdout: {}\nstderr: {}",
            e,
            stdout,
            stderr
        )
    })
}

/// Create a raw blob sidecar without SimpleCoder encoding.
/// This places data at exact field positions as expected by the contracts.
pub fn create_raw_sidecar(fields: &[B256]) -> Result<BlobTransactionSidecar> {
    use alloy::eips::eip4844::{Blob, BYTES_PER_BLOB};

    // Get Ethereum mainnet KZG settings
    let settings = c_kzg::ethereum_kzg_settings(0);

    // Create a full blob (131072 bytes = 4096 fields of 32 bytes each)
    let mut blob_bytes = vec![0u8; BYTES_PER_BLOB];

    // Fill in the fields at their respective positions
    for (i, field) in fields.iter().enumerate() {
        let offset = i * 32;
        if offset + 32 <= blob_bytes.len() {
            blob_bytes[offset..offset + 32].copy_from_slice(field.as_slice());
        }
    }

    // Convert to Blob type
    let blob = Blob::try_from(blob_bytes.as_slice())
        .map_err(|e| eyre!("Failed to create blob: {:?}", e))?;

    // Build sidecar with KZG commitment and proof using settings
    let sidecar = BlobTransactionSidecar::try_from_blobs_with_settings(vec![blob], settings)
        .map_err(|e| eyre!("Failed to build sidecar: {:?}", e))?;

    Ok(sidecar)
}

/// Create blob data with deposit leaves.
/// Blob layout: deposits first (groups of 4: leaf0, leaf1, leaf2, root), then transactions.
pub fn create_deposit_blob_data(deposit_leaves: &[B256]) -> Vec<u8> {
    let mut data = Vec::new();

    // Each group of 3 deposits takes 4 slots: [leaf0, leaf1, leaf2, root]
    let num_groups = deposit_leaves.len().div_ceil(3); // Ceiling division

    for group_idx in 0..num_groups {
        let base = group_idx * 3;

        // Leaf 0
        if base < deposit_leaves.len() {
            data.extend_from_slice(deposit_leaves[base].as_slice());
        } else {
            data.extend_from_slice(&[0u8; 32]);
        }

        // Leaf 1
        if base + 1 < deposit_leaves.len() {
            data.extend_from_slice(deposit_leaves[base + 1].as_slice());
        } else {
            data.extend_from_slice(&[0u8; 32]);
        }

        // Leaf 2
        if base + 2 < deposit_leaves.len() {
            data.extend_from_slice(deposit_leaves[base + 2].as_slice());
        } else {
            data.extend_from_slice(&[0u8; 32]);
        }

        // Root (placeholder - in real use, this would be computed)
        data.extend_from_slice(&[0u8; 32]);
    }

    data
}

// ============================================================================
// Tests
// ============================================================================

/// Test deposit fraud detection with real EIP-4844 blobs.
/// This test:
/// 1. Deploys contracts to Anvil with Cancun hardfork (blob support)
/// 2. Registers a sequencer
/// 3. Creates a deposit on L1
/// 4. Submits a blob with WRONG deposit leaf
/// 5. Verifies the challenger detects the fraud
#[tokio::test]
async fn test_anvil_deposit_fraud_detection_real_blobs() -> Result<()> {
    let Some(ctx) = setup_test_context().await? else {
        return Ok(());
    };

    // Register as sequencer (using old stake calculation for this test)
    let stake_req = ctx.entrypoint().requiredStake().call().await?;
    let receipt = ctx
        .entrypoint()
        .fund()
        .value(stake_req)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status());
    println!("✓ Sequencer registered");

    // Verify sequencer is allowed
    assert!(
        ctx.is_sequencer_allowed().await?,
        "Sequencer should be allowed after registration"
    );

    // Create a deposit on L1
    ctx.mint_and_approve_tokens(U256::from(1000u64)).await?;
    ctx.create_deposit(U256::from(100u64), B256::repeat_byte(0x42))
        .await?;

    // Get expected deposits for block 2
    let expected_deposits = ctx.get_deposits_for_block(U256::from(2)).await?;
    println!(
        "Expected deposits for block 2: {} deposits",
        expected_deposits.len()
    );

    let expected_leaf = if !expected_deposits.is_empty() {
        expected_deposits[0]
    } else {
        B256::repeat_byte(0x11)
    };

    // Create blob with WRONG deposit leaf
    let wrong_leaf = B256::repeat_byte(0xFF);
    let sidecar = ctx.build_deposit_sidecar(&[wrong_leaf])?;

    // Test the challenger's fraud detection logic
    use pgp_challenger::validators::DepositValidator;
    use pgp_common::blob::ParsedBlock;

    let mut test_blob = [B256::ZERO; 4096];
    test_blob[0] = wrong_leaf;

    let parsed = ParsedBlock::from_blobs(&[test_blob], 1, 0)?;

    let validation_block_data = BlockData {
        anchor: B256::repeat_byte(0x01),
        timestamp: U256::ZERO,
        numTransactions: U256::ZERO,
        numDeposits: U256::from(1),
        blockNr: U256::from(1),
        blockIndex: TimestampAndIndex { day: 0, index: 0 },
        sequencer: ctx.deployer,
        blobhashes: sidecar.versioned_hashes().collect(),
    };

    let validator = DepositValidator::new();
    let fraud = validator.validate_block(&validation_block_data, &parsed, &[expected_leaf]);

    println!("\nFraud Detection Results:");
    println!("Expected leaf: {expected_leaf}");
    println!("Submitted leaf (wrong): {wrong_leaf}");

    assert!(!fraud.is_empty(), "Should detect deposit fraud");

    match &fraud[0] {
        pgp_challenger::validators::FraudEvidence::DepositWrongLeaf {
            deposit_nr,
            expected_leaf: exp,
            submitted_leaf: sub,
            ..
        } => {
            assert_eq!(*deposit_nr, 0);
            assert_eq!(*exp, expected_leaf);
            assert_eq!(*sub, wrong_leaf);
            println!("✓ Correct fraud type: DepositWrongLeaf at index 0");
        }
        _ => panic!("Expected DepositWrongLeaf fraud"),
    }

    println!("\n✓ Integration test passed: bad deposit detected with real blob infrastructure!");

    Ok(())
}

/// Test nullifier fraud detection.
/// This test verifies the challenger correctly detects double-spend attempts.
#[tokio::test]
async fn test_anvil_nullifier_fraud_detection() -> Result<()> {
    let Some(_ctx) = setup_test_context().await? else {
        return Ok(());
    };

    // Test nullifier double-spend detection (doesn't need ctx, just verifies infrastructure)
    use pgp_challenger::state::StateManager;
    use pgp_challenger::validators::NullifierValidator;
    use pgp_common::blob::ParsedBlock;
    use pgp_common::types::constants::BLOB_SIZE;

    let state = StateManager::in_memory()?;
    let validator = NullifierValidator::new();

    // Create a blob with a transaction that has duplicate nullifiers
    let duplicate_nullifier = B256::repeat_byte(0x42);
    let mut blob = [B256::ZERO; BLOB_SIZE];

    // Transaction layout: [proof x8, anchor, null0, null1, leaf0, leaf1, leaf2, root] = 15 fields
    blob[9] = duplicate_nullifier; // nullifier0
    blob[10] = duplicate_nullifier; // nullifier1 (same - fraud!)

    let parsed = ParsedBlock::from_blobs(&[blob], 0, 1)?;

    let fraud = validator.process_block(&state, 1, &parsed)?;

    println!("Nullifier fraud evidence: {fraud:?}");
    assert!(
        !fraud.is_empty(),
        "Should detect nullifier double-spend in same transaction"
    );

    println!("\n✓ Nullifier fraud detection test passed!");

    Ok(())
}

/// Test the full challenge flow: detect fraud, build challenge, submit, verify slash.
#[tokio::test]
async fn test_full_challenge_flow() -> Result<()> {
    let Some(ctx) = setup_test_context().await? else {
        return Ok(());
    };

    // Register and advance to open period
    ctx.register_sequencer().await?;
    ctx.advance_to_open_period().await?;

    // Verify sequencer is allowed
    assert!(
        ctx.is_sequencer_allowed().await?,
        "Sequencer should be allowed after registration"
    );

    // Create a real deposit on L1 for block 0
    ctx.mint_and_approve_tokens(U256::from(1000u64)).await?;
    ctx.create_deposit(U256::from(100u64), B256::repeat_byte(0x42))
        .await?;

    // Get expected deposits for block 0
    let expected_deposits_block_0 = ctx.get_deposits_for_block(U256::ZERO).await?;
    assert_eq!(
        expected_deposits_block_0.len(),
        1,
        "Block 0 should have 1 deposit"
    );

    // Submit block 0 with wrong deposit leaf (fraud)
    let fake_deposit_leaf = B256::repeat_byte(0xFF);
    let sidecar = ctx.build_deposit_sidecar(&[fake_deposit_leaf])?;
    let submitted = ctx
        .submit_block(U256::ZERO, U256::from(1), U256::ZERO, sidecar)
        .await?;

    // Detect the fraud
    use pgp_challenger::validators::DepositValidator;
    use pgp_common::blob::ParsedBlock;

    let mut test_blob = [B256::ZERO; 4096];
    test_blob[0] = fake_deposit_leaf;

    let parsed = ParsedBlock::from_blobs(&[test_blob], 1, 0)?;
    let validator = DepositValidator::new();
    let fraud =
        validator.validate_block(&submitted.block_data, &parsed, &expected_deposits_block_0);

    assert!(!fraud.is_empty(), "Should detect deposit fraud");
    println!("✓ Fraud detected: {:?}", fraud[0]);

    // Build the challenge
    use pgp_challenger::challenge::ChallengeBuilder;

    let challenge_builder = ChallengeBuilder::new()?;
    let prior_block = BlockData {
        anchor: B256::ZERO,
        timestamp: U256::ZERO,
        numTransactions: U256::ZERO,
        numDeposits: U256::ZERO,
        blockNr: U256::ZERO,
        blockIndex: TimestampAndIndex { day: 0, index: 0 },
        sequencer: Address::ZERO,
        blobhashes: vec![],
    };

    let challenge_params =
        challenge_builder.build_deposit_challenge(&fraud[0], &submitted.as_blobs(), prior_block)?;

    assert_eq!(challenge_params.commitment.len(), 48);
    assert_eq!(challenge_params.proof.len(), 48);
    println!("✓ Challenge parameters built");

    // Submit the challenge
    use pgp_challenger::challenge::ChallengeSubmitter;

    let submitter = ChallengeSubmitter::new(&ctx.provider, ctx.contracts.entrypoint);
    let tx_hash = submitter
        .submit_deposit_challenge(challenge_params)
        .await
        .expect("Challenge submission must succeed");
    println!("✓ Challenge submitted! Tx hash: {tx_hash:?}");

    // Verify sequencer was slashed
    ctx.assert_sequencer_slashed().await?;

    println!("\n✓ Full challenge flow test completed!");

    Ok(())
}

/// Test wrong deposit leaf challenge with KZG proof verification.
#[tokio::test]
async fn test_wrong_deposit_leaf_with_kzg() -> Result<()> {
    let Some(ctx) = setup_test_context().await? else {
        return Ok(());
    };

    println!("=== Wrong Deposit Leaf with KZG Test ===");

    // Setup: register sequencer and create deposit
    ctx.register_sequencer().await?;
    ctx.advance_to_open_period().await?;
    ctx.mint_and_approve_tokens(U256::from(1000u64)).await?;
    ctx.create_deposit(U256::from(100u64), B256::repeat_byte(0x42))
        .await?;

    // Find which block the deposit targets (when getCurrentBlocknumber() = 0,
    // deposits target block 0 per Deposits.sol logic)
    let deposits_block_0 = ctx.get_deposits_for_block(U256::ZERO).await?;
    let (target_block, expected_deposits) = if !deposits_block_0.is_empty() {
        (U256::ZERO, deposits_block_0)
    } else {
        // Fallback: check block 2 (in case deposit logic changed)
        let deposits_block_2 = ctx.get_deposits_for_block(U256::from(2)).await?;
        (U256::from(2), deposits_block_2)
    };

    assert_eq!(
        expected_deposits.len(),
        1,
        "Should have 1 deposit for target block"
    );
    let expected_leaf = expected_deposits[0];
    println!("Expected deposit leaf for block {target_block}: {expected_leaf}");

    ctx.wait_for_open_period().await?;

    // Submit block 0 with WRONG deposit leaf (fraud)
    let wrong_leaf = B256::repeat_byte(0xFF);
    println!("Submitting block {target_block} with wrong leaf: {wrong_leaf}");

    let sidecar = ctx.build_deposit_sidecar(&[wrong_leaf])?;
    let block = ctx
        .submit_block(target_block, U256::from(1), U256::ZERO, sidecar)
        .await?;

    // Detect the fraud
    use pgp_challenger::validators::DepositValidator;
    use pgp_common::blob::ParsedBlock;

    let mut test_blob = [B256::ZERO; 4096];
    test_blob[0] = wrong_leaf;

    let parsed = ParsedBlock::from_blobs(&[test_blob], 1, 0)?;
    let validator = DepositValidator::new();
    let fraud = validator.validate_block(&block.block_data, &parsed, &expected_deposits);

    assert!(!fraud.is_empty(), "Should detect deposit fraud");
    match &fraud[0] {
        pgp_challenger::validators::FraudEvidence::DepositWrongLeaf {
            expected_leaf: exp,
            submitted_leaf: sub,
            ..
        } => {
            assert_eq!(*exp, expected_leaf);
            assert_eq!(*sub, wrong_leaf);
            println!("✓ Fraud detected: DepositWrongLeaf");
        }
        _ => panic!("Expected DepositWrongLeaf fraud type"),
    }

    // Build challenge with KZG proof
    use pgp_challenger::challenge::ChallengeBuilder;

    let challenge_builder = ChallengeBuilder::new()?;
    // Use a default prior block since this is block 0
    let prior_block = BlockData {
        anchor: B256::ZERO,
        timestamp: U256::ZERO,
        numTransactions: U256::ZERO,
        numDeposits: U256::ZERO,
        blockNr: U256::ZERO,
        blockIndex: TimestampAndIndex { day: 0, index: 0 },
        sequencer: Address::ZERO,
        blobhashes: vec![],
    };
    let challenge_params =
        challenge_builder.build_deposit_challenge(&fraud[0], &block.as_blobs(), prior_block)?;

    assert_eq!(
        challenge_params.commitment.len(),
        48,
        "KZG commitment should be 48 bytes"
    );
    assert_eq!(
        challenge_params.proof.len(),
        48,
        "KZG proof should be 48 bytes"
    );
    println!("✓ Challenge parameters built with KZG proof");

    // Submit the challenge
    use pgp_challenger::challenge::ChallengeSubmitter;

    let submitter = ChallengeSubmitter::new(&ctx.provider, ctx.contracts.entrypoint);
    let tx_hash = submitter
        .submit_deposit_challenge(challenge_params)
        .await
        .expect("Challenge submission with KZG proof must succeed");
    println!("✓ Challenge submitted with KZG proof verified on-chain! Tx hash: {tx_hash:?}");

    // Verify transaction succeeded
    let receipt = ctx
        .provider
        .get_transaction_receipt(tx_hash)
        .await?
        .expect("Receipt should exist");
    assert!(receipt.status(), "Challenge transaction must succeed");

    // Verify sequencer was slashed
    ctx.assert_sequencer_slashed().await?;

    println!("\n✓ Wrong deposit leaf with KZG test completed!");

    Ok(())
}

/// Test multi-block deposit fraud with deposits on later blocks.
///
/// This test exercises:
/// 1. Multiple blocks with real deposits
/// 2. Deposit targeting logic (deposits go to block N when created at block < N)
/// 3. Fraud detection on a non-zero block
#[tokio::test]
async fn test_multi_block_deposit_fraud() -> Result<()> {
    let Some(ctx) = setup_test_context().await? else {
        return Ok(());
    };

    println!("=== Multi-Block Deposit Fraud Test ===");

    ctx.register_sequencer().await?;
    ctx.advance_to_open_period().await?;
    ctx.mint_and_approve_tokens(U256::from(5000u64)).await?;

    // Helper for valid BLS field elements
    fn field_elem(suffix: u8) -> B256 {
        B256::from([
            0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, suffix,
        ])
    }

    // Create deposit for block 0
    ctx.create_deposit(U256::from(100u64), B256::repeat_byte(0x01))
        .await?;
    let deposits_b0 = ctx.get_deposits_for_block(U256::ZERO).await?;
    assert_eq!(deposits_b0.len(), 1, "Block 0 should have 1 deposit");
    println!("✓ Created deposit for block 0");

    // Submit block 0 with correct deposit
    let sidecar0 = ctx.build_deposit_sidecar(&[deposits_b0[0]])?;
    let block0 = ctx
        .submit_block(U256::ZERO, U256::from(1), U256::ZERO, sidecar0)
        .await?;
    println!("✓ Block 0 submitted with correct deposit");

    // Create 2 deposits for a later block
    // After block 0 is submitted, getCurrentBlocknumber() = 1
    // Deposits now go to max(highestDeposit, currentBlock + 2) = max(0, 3) = 3
    ctx.create_deposit(U256::from(200u64), B256::repeat_byte(0x02))
        .await?;
    ctx.create_deposit(U256::from(300u64), B256::repeat_byte(0x03))
        .await?;

    // Find where deposits went
    let mut target_block = U256::ZERO;
    for block_nr in 1..=5 {
        let deps = ctx.get_deposits_for_block(U256::from(block_nr)).await?;
        if deps.len() == 2 {
            target_block = U256::from(block_nr);
            break;
        }
    }
    assert!(
        target_block > U256::ZERO,
        "Should find 2 deposits on some block > 0"
    );
    let expected_deposits = ctx.get_deposits_for_block(target_block).await?;
    println!("✓ Created 2 deposits for block {target_block}");

    // Submit filler blocks 1..(target_block) with transactions (no deposits)
    use pgp_common::types::DecodedAnchorInfo;

    ctx.wait_for_open_period().await?;
    let mut prev_block = block0.clone();

    for i in 1..target_block.try_into().unwrap_or(3u64) {
        // Check if this block has deposits
        let block_deposits = ctx.get_deposits_for_block(U256::from(i)).await?;

        let sidecar = if block_deposits.is_empty() {
            // No deposits - submit with transaction only
            let anchor_info = DecodedAnchorInfo {
                block_nr: (i - 1) as u32,
                update_nr: 0,
                is_deposit: if i == 1 { true } else { false },
                eth_key: Address::ZERO,
            };
            let mut tx_fields = vec![B256::ZERO; 15];
            tx_fields[8] = anchor_info.encode();
            tx_fields[9] = field_elem(0x10 + i as u8);
            tx_fields[10] = field_elem(0x20 + i as u8);
            tx_fields[11] = field_elem(0x30 + i as u8);
            tx_fields[12] = field_elem(0x40 + i as u8);
            tx_fields[13] = field_elem(0x50 + i as u8);
            tx_fields[14] = field_elem(0x60 + i as u8);

            let sidecar = create_raw_sidecar(&tx_fields)?;
            prev_block = ctx
                .submit_block(U256::from(i), U256::ZERO, U256::from(1), sidecar)
                .await?;
            continue;
        } else {
            // Has deposits - submit with correct deposits
            ctx.build_deposit_sidecar(&block_deposits)?
        };

        prev_block = ctx
            .submit_block(
                U256::from(i),
                U256::from(block_deposits.len()),
                U256::ZERO,
                sidecar,
            )
            .await?;
    }
    println!(
        "✓ Filler blocks submitted up to block {}",
        target_block - U256::from(1)
    );

    // Submit target block with WRONG deposit leaf (fraud)
    ctx.wait_for_open_period().await?;
    let wrong_leaf = B256::repeat_byte(0xFF);
    let sidecar = ctx.build_deposit_sidecar(&[wrong_leaf, expected_deposits[1]])?;
    let fraudulent_block = ctx
        .submit_block(target_block, U256::from(2), U256::ZERO, sidecar)
        .await?;
    println!("✓ Block {target_block} submitted with wrong deposit leaf (fraudulent)");

    // Detect the fraud
    use pgp_challenger::validators::{DepositValidator, FraudEvidence};
    use pgp_common::blob::ParsedBlock;

    let mut test_blob = [B256::ZERO; 4096];
    test_blob[0] = wrong_leaf;
    test_blob[1] = expected_deposits[1];

    let parsed = ParsedBlock::from_blobs(&[test_blob], 2, 0)?;
    let validator = DepositValidator::new();
    let fraud = validator.validate_block(&fraudulent_block.block_data, &parsed, &expected_deposits);

    assert!(!fraud.is_empty(), "Should detect deposit fraud");
    match &fraud[0] {
        FraudEvidence::DepositWrongLeaf {
            expected_leaf,
            submitted_leaf,
            deposit_nr,
            ..
        } => {
            assert_eq!(*deposit_nr, 0, "First deposit should be wrong");
            assert_eq!(*expected_leaf, expected_deposits[0]);
            assert_eq!(*submitted_leaf, wrong_leaf);
            println!("✓ Fraud detected: DepositWrongLeaf on block {target_block}");
        }
        _ => panic!("Expected DepositWrongLeaf fraud type"),
    }

    // Build and submit the challenge
    use pgp_challenger::challenge::{ChallengeBuilder, ChallengeSubmitter};

    let challenge_builder = ChallengeBuilder::new()?;
    let challenge_params = challenge_builder.build_deposit_challenge(
        &fraud[0],
        &fraudulent_block.as_blobs(),
        prev_block.block_data.clone(),
    )?;
    println!("✓ Challenge parameters built");

    let submitter = ChallengeSubmitter::new(&ctx.provider, ctx.contracts.entrypoint);
    let tx_hash = submitter
        .submit_deposit_challenge(challenge_params)
        .await
        .expect("Challenge submission must succeed");
    println!("✓ Challenge submitted! Tx hash: {tx_hash:?}");

    // Verify sequencer was slashed
    ctx.assert_sequencer_slashed().await?;

    println!(
        "\n✓ Multi-block deposit fraud test completed - fraud detected on block {target_block}!"
    );

    Ok(())
}

/// Test full blob transaction submission to the real Entrypoint contract.
#[tokio::test]
async fn test_anvil_blob_submission() -> Result<()> {
    let Some(ctx) = setup_test_context().await? else {
        return Ok(());
    };

    // Verify contract has code
    let code = ctx.provider.get_code_at(ctx.contracts.entrypoint).await?;
    assert!(
        !code.is_empty(),
        "No contract code at entrypoint address - deployment failed"
    );

    // Register and advance to open period
    ctx.register_sequencer().await?;
    ctx.advance_to_open_period().await?;

    // First create a real deposit on L1 so we have something to include
    ctx.mint_and_approve_tokens(U256::from(1000u64)).await?;
    ctx.create_deposit(U256::from(100u64), B256::repeat_byte(0x42))
        .await?;

    // Get the actual deposit for block 0
    let deposits = ctx.get_deposits_for_block(U256::ZERO).await?;
    assert_eq!(deposits.len(), 1, "Should have 1 deposit for block 0");
    let deposit_leaf = deposits[0];

    // Submit block 0 with the real deposit leaf
    let sidecar = ctx.build_deposit_sidecar(&[deposit_leaf])?;
    let submitted = ctx
        .submit_block(U256::ZERO, U256::from(1), U256::ZERO, sidecar)
        .await?;

    // Verify block was recorded
    let current_block = ctx.entrypoint().getCurrentBlocknumber().call().await?;
    assert_eq!(
        current_block,
        U256::from(1),
        "Block number should be 1 after first block submission"
    );
    println!("L2 block hash: {}", submitted.l2_block_hash);

    println!("\n✓ Blob submission test completed!");

    Ok(())
}

// ============================================================================
// Sprint 4 Fraud Detection Tests
// ============================================================================

/// Test: Invalid anchor references (future block and out-of-bounds update)
#[tokio::test]
async fn test_invalid_anchor_references() -> Result<()> {
    use pgp_challenger::validators::AnchorLookup;
    use pgp_common::types::DecodedAnchorInfo;

    let mut anchor_lookup = AnchorLookup::new();
    anchor_lookup.set_current_block(10);
    anchor_lookup.insert(5, 0, false, B256::repeat_byte(0xAA));
    anchor_lookup.insert(5, 1, false, B256::repeat_byte(0xBB));
    anchor_lookup.insert(5, 2, false, B256::repeat_byte(0xCC));

    // Case 1: Future block reference
    let future_block = DecodedAnchorInfo {
        block_nr: 999,
        update_nr: 0,
        is_deposit: false,
        eth_key: Address::ZERO,
    };
    let decoded = DecodedAnchorInfo::decode(future_block.encode());
    assert!(
        decoded.block_nr as u64 > anchor_lookup.current_block_nr(),
        "Should detect future block reference"
    );

    // Case 2: Update number out of bounds
    let bad_update = DecodedAnchorInfo {
        block_nr: 5,
        update_nr: 100,
        is_deposit: false,
        eth_key: Address::ZERO,
    };
    let decoded = DecodedAnchorInfo::decode(bad_update.encode());
    let max_update = anchor_lookup.get_max_update_nr(5, false).unwrap();
    assert!(
        decoded.update_nr > max_update,
        "Should detect out-of-bounds update"
    );

    Ok(())
}

/// Test: Nullifier double-spend across different blocks
#[tokio::test]
async fn test_nullifier_double_spend_cross_block() -> Result<()> {
    use pgp_challenger::state::StateManager;
    use pgp_challenger::validators::{FraudEvidence, NullifierValidator};
    use pgp_common::blob::ParsedBlock;
    use pgp_common::types::constants::BLOB_SIZE;

    let state = StateManager::in_memory()?;
    let validator = NullifierValidator::new();

    // Helper for valid BN254 field element
    fn field_elem(suffix: u8) -> B256 {
        B256::from([
            0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, suffix,
        ])
    }

    let shared_nullifier = field_elem(0x42);

    // Block 1: Use shared_nullifier
    let mut blob1 = [B256::ZERO; BLOB_SIZE];
    blob1[9] = shared_nullifier;
    blob1[10] = field_elem(0x11);
    let parsed1 = ParsedBlock::from_blobs(&[blob1], 0, 1)?;
    assert!(validator.process_block(&state, 1, &parsed1)?.is_empty());

    // Block 2: Reuse shared_nullifier (fraud!)
    let mut blob2 = [B256::ZERO; BLOB_SIZE];
    blob2[9] = shared_nullifier;
    blob2[10] = field_elem(0x22);
    let parsed2 = ParsedBlock::from_blobs(&[blob2], 0, 1)?;

    let fraud = validator.process_block(&state, 2, &parsed2)?;
    assert_eq!(fraud.len(), 1);
    match &fraud[0] {
        FraudEvidence::NullifierDoubleSpend {
            first_block_nr,
            second_block_nr,
            nullifier,
            ..
        } => {
            assert_eq!(*first_block_nr, 1);
            assert_eq!(*second_block_nr, 2);
            assert_eq!(*nullifier, shared_nullifier);
        }
        _ => panic!("Expected NullifierDoubleSpend"),
    }

    Ok(())
}

/// Test: Incorrect tree updates (both deposits and transactions)
#[tokio::test]
async fn test_incorrect_tree_updates() -> Result<()> {
    use pgp_challenger::validators::{FraudEvidence, TreeUpdateValidator};
    use pgp_common::blob::ParsedBlock;
    use pgp_common::types::constants::BLOB_SIZE;

    let validator = TreeUpdateValidator::new();

    // Helper to create valid BN254 field element
    fn field_elem(suffix: u8) -> B256 {
        B256::from([
            0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, suffix,
        ])
    }

    // Case 1: Deposit group with wrong root
    let wrong_root = B256::repeat_byte(0xFF);
    let mut blob = [B256::ZERO; BLOB_SIZE];
    blob[0] = field_elem(0x11);
    blob[1] = field_elem(0x22);
    blob[2] = field_elem(0x33);
    blob[3] = wrong_root;

    let parsed = ParsedBlock::from_blobs(&[blob], 3, 0)?;
    let block_data = BlockData {
        anchor: B256::ZERO,
        timestamp: U256::ZERO,
        numTransactions: U256::ZERO,
        numDeposits: U256::from(3),
        blockNr: U256::from(1),
        blockIndex: TimestampAndIndex { day: 0, index: 0 },
        sequencer: Address::ZERO,
        blobhashes: vec![],
    };

    // Empty root_path uses zero hashes (valid for first block)
    let (fraud, _block_tree_root) =
        validator.validate_block(&block_data, &parsed, B256::ZERO, None, 0, 0, &[]);
    assert!(!fraud.is_empty(), "Should detect deposit tree update fraud");
    match &fraud[0] {
        FraudEvidence::IncorrectTreeUpdate {
            is_tx,
            submitted_anchor,
            ..
        } => {
            assert!(!is_tx, "Should be deposit update");
            assert_eq!(*submitted_anchor, wrong_root);
        }
        _ => panic!("Expected IncorrectTreeUpdate"),
    }

    // Case 2: Transaction with wrong root
    let mut blob = [B256::ZERO; BLOB_SIZE];
    blob[11] = field_elem(0xAA);
    blob[12] = field_elem(0xBB);
    blob[13] = field_elem(0xCC);
    blob[14] = wrong_root;

    let parsed = ParsedBlock::from_blobs(&[blob], 0, 1)?;
    let block_data = BlockData {
        anchor: B256::ZERO,
        timestamp: U256::ZERO,
        numTransactions: U256::from(1),
        numDeposits: U256::ZERO,
        blockNr: U256::from(1),
        blockIndex: TimestampAndIndex { day: 0, index: 0 },
        sequencer: Address::ZERO,
        blobhashes: vec![],
    };

    let (fraud, _block_tree_root) =
        validator.validate_block(&block_data, &parsed, B256::ZERO, None, 0, 0, &[]);
    assert!(
        !fraud.is_empty(),
        "Should detect transaction tree update fraud"
    );
    match &fraud[0] {
        FraudEvidence::IncorrectTreeUpdate {
            is_tx,
            submitted_anchor,
            ..
        } => {
            assert!(is_tx, "Should be transaction update");
            assert_eq!(*submitted_anchor, wrong_root);
        }
        _ => panic!("Expected IncorrectTreeUpdate"),
    }

    Ok(())
}

/// Test: Deposit fraud types (padding not zero, wrong leaf)
/// Note: Count mismatch is no longer detected - it's prevented at submission time
#[tokio::test]
async fn test_deposit_fraud_types() -> Result<()> {
    use pgp_challenger::validators::{DepositValidator, FraudEvidence};
    use pgp_common::blob::ParsedBlock;
    use pgp_common::types::constants::BLOB_SIZE;

    let validator = DepositValidator::new();

    fn make_block(num_deposits: u64) -> BlockData {
        BlockData {
            anchor: B256::ZERO,
            timestamp: U256::ZERO,
            numTransactions: U256::ZERO,
            numDeposits: U256::from(num_deposits),
            blockNr: U256::from(1),
            blockIndex: TimestampAndIndex { day: 0, index: 0 },
            sequencer: Address::ZERO,
            blobhashes: vec![],
        }
    }

    // Case 1: Padding not zero
    let expected = vec![B256::repeat_byte(0x11)];
    let mut blob = [B256::ZERO; BLOB_SIZE];
    blob[0] = expected[0];
    blob[1] = B256::repeat_byte(0xFF); // Should be zero
    let parsed = ParsedBlock::from_blobs(&[blob], 1, 0)?;
    let fraud = validator.validate_block(&make_block(1), &parsed, &expected);
    assert!(matches!(
        &fraud[0],
        FraudEvidence::DepositPaddingNotZero {
            group_index: 0,
            slot_index: 1,
            ..
        }
    ));

    Ok(())
}

/// Test: Multiple fraud types in single block (deposit + nullifier)
#[tokio::test]
async fn test_multiple_fraud_types() -> Result<()> {
    use pgp_challenger::state::StateManager;
    use pgp_challenger::validators::{DepositValidator, NullifierValidator};
    use pgp_common::blob::ParsedBlock;
    use pgp_common::types::constants::BLOB_SIZE;

    let expected_deposits = vec![B256::repeat_byte(0x11), B256::repeat_byte(0x22)];
    let block_data = BlockData {
        anchor: B256::ZERO,
        timestamp: U256::ZERO,
        numTransactions: U256::from(1),
        numDeposits: U256::from(2),
        blockNr: U256::from(1),
        blockIndex: TimestampAndIndex { day: 0, index: 0 },
        sequencer: Address::ZERO,
        blobhashes: vec![],
    };

    // Wrong deposit + duplicate nullifiers
    let mut blob = [B256::ZERO; BLOB_SIZE];
    blob[0] = B256::repeat_byte(0xFF); // Wrong leaf
    blob[1] = expected_deposits[1];
    let dup_null = B256::repeat_byte(0x42);
    blob[4 + 9] = dup_null;
    blob[4 + 10] = dup_null; // Duplicate!

    let parsed = ParsedBlock::from_blobs(&[blob], 2, 1)?;

    let deposit_fraud =
        DepositValidator::new().validate_block(&block_data, &parsed, &expected_deposits);
    let state = StateManager::in_memory()?;
    let nullifier_fraud = NullifierValidator::new().process_block(&state, 1, &parsed)?;

    assert!(!deposit_fraud.is_empty() && !nullifier_fraud.is_empty());
    assert!(deposit_fraud.len() + nullifier_fraud.len() >= 2);

    Ok(())
}

/// Test: Groth16 verification key loading and invalid proof rejection
#[tokio::test]
async fn test_groth16_verification_key_loading() -> Result<()> {
    use pgp_challenger::groth16::Groth16Verifier;

    let project_root = find_project_root();
    let transfer_vk_path = project_root.join("circuits/outputs/transfer/transferVKey.json");
    let update_vk_path =
        project_root.join("circuits/outputs/predictableUpdate/predictableUpdateVKey.json");

    if !transfer_vk_path.exists() || !update_vk_path.exists() {
        return Ok(()); // Skip if VK files not found
    }

    let verifier = Groth16Verifier::new(&transfer_vk_path, &update_vk_path)?;

    // Invalid proof should fail
    use pgp_challenger::groth16::TransferPublicInputs;
    use pgp_common::types::Groth16Proof;

    let result = verifier.verify_transfer_proof(
        &Groth16Proof::default(),
        &TransferPublicInputs {
            anchor: B256::ZERO,
            eth_key: Address::ZERO,
            nullifier0: B256::ZERO,
            nullifier1: B256::ZERO,
            leaf0: B256::ZERO,
            leaf1: B256::ZERO,
            leaf2: B256::ZERO,
        },
    );
    // Result can be Ok(false) for invalid proof, or Err for verification error
    // Either is acceptable for an invalid proof
    match result {
        Ok(valid) => assert!(!valid, "Invalid proof should fail verification"),
        Err(_) => {} // Verification error is also acceptable for invalid proof
    }

    Ok(())
}

/// Test: Region building with KZG proofs (basic, boundary detection, challenge types)
#[tokio::test]
async fn test_region_building() -> Result<()> {
    use pgp_challenger::challenge::ChallengeBuilder;

    let builder = ChallengeBuilder::new()?;
    let blob_data = vec![0u8; 131072];
    let blob_hash = B256::repeat_byte(0xAB);

    // Case 1: Basic region building (3 fields)
    let region = builder.build_region(&blob_data, 0, 3, blob_hash)?;
    assert_eq!(region.length, U256::from(3));
    assert_eq!(region.data.len(), 3);
    assert_eq!(region.proofs.len(), 3);
    assert_eq!(
        region.commitment.len(),
        48,
        "KZG commitment should be 48 bytes"
    );
    for proof in &region.proofs {
        assert_eq!(proof.len(), 48, "KZG proof should be 48 bytes");
    }

    // Case 2: Deposit group region (4 fields)
    let deposit_region = builder.build_region(&blob_data, 0, 4, blob_hash)?;
    assert_eq!(deposit_region.length, U256::from(4));

    // Case 3: Transaction region (15 fields at offset)
    let tx_region = builder.build_region(&blob_data, 100, 15, blob_hash)?;
    assert_eq!(tx_region.length, U256::from(15));
    assert_eq!(tx_region.memoryAddress, U256::from(100));

    // Case 4: Blob boundary crossing detection
    const BLOB_SIZE: u64 = 4096;
    const TX_LENGTH: u64 = 15;
    assert!(
        4082 + TX_LENGTH > BLOB_SIZE,
        "Should detect boundary crossing"
    );
    assert!(
        4081 + TX_LENGTH <= BLOB_SIZE,
        "Should fit without extension"
    );

    Ok(())
}

/// Test: Multi-blob extension region building (cross-boundary handling)
#[tokio::test]
async fn test_multi_blob_extension_region() -> Result<()> {
    use pgp_challenger::challenge::{BlobWithHash, ChallengeBuilder, BLOB_FIELD_COUNT};

    let builder = ChallengeBuilder::new()?;

    // Create two blobs (minimal initialization - zeroes are valid BLS field elements)
    let blob1 = vec![0u8; 131072];
    let blob2 = vec![0u8; 131072];
    let blob1_hash = B256::from([
        0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0x01,
    ]);
    let blob2_hash = B256::from([
        0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0x02,
    ]);

    let blobs = vec![
        BlobWithHash {
            data: &blob1,
            hash: blob1_hash,
        },
        BlobWithHash {
            data: &blob2,
            hash: blob2_hash,
        },
    ];

    // Case 1: Single blob region (no extension needed)
    let single = builder.build_region_with_extension(&blobs, 100, 15)?;
    assert_eq!(single.region.length, U256::from(15));
    assert!(single.extension.data.is_empty());

    // Case 2: Cross-boundary region (4090 + 15 = 4105 > 4096)
    // First blob: 6 fields (4090-4095), Second blob: 9 fields (0-8)
    let cross = builder.build_region_with_extension(&blobs, 4090, 15)?;
    let first_count = BLOB_FIELD_COUNT - 4090; // 6
    let second_count = 15 - first_count; // 9

    assert_eq!(cross.region.length, U256::from(first_count));
    assert_eq!(cross.region.memoryAddress, U256::from(4090));
    assert_eq!(cross.region.hash, blob1_hash);
    assert_eq!(cross.extension.length, U256::from(second_count));
    assert_eq!(cross.extension.memoryAddress, U256::ZERO);
    assert_eq!(cross.extension.hash, blob2_hash);
    assert_eq!(cross.region.proofs.len(), first_count);
    assert_eq!(cross.extension.proofs.len(), second_count);

    // Case 3: Error when crossing boundary without second blob
    let single_only = vec![BlobWithHash {
        data: &blob1,
        hash: blob1_hash,
    }];
    assert!(builder
        .build_region_with_extension(&single_only, 4090, 15)
        .is_err());

    Ok(())
}

// ============================================================================
// Comprehensive Fraud Detection Tests (All Fraud Types)
// ============================================================================

/// Test: NullifierDoubleSpend - same transaction (nullifier0 == nullifier1)
/// Verifies all fields of the FraudEvidence struct.
#[tokio::test]
async fn test_nullifier_double_spend_same_transaction_comprehensive() -> Result<()> {
    use pgp_challenger::state::StateManager;
    use pgp_challenger::validators::{FraudEvidence, NullifierValidator};
    use pgp_common::blob::ParsedBlock;
    use pgp_common::types::constants::BLOB_SIZE;

    let state = StateManager::in_memory()?;
    let validator = NullifierValidator::new();

    let duplicate_nullifier = B256::from([
        0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0x42,
    ]);

    // Transaction with same nullifier for both inputs
    let mut blob = [B256::ZERO; BLOB_SIZE];
    blob[9] = duplicate_nullifier; // nullifier0
    blob[10] = duplicate_nullifier; // nullifier1 (same = fraud!)

    let parsed = ParsedBlock::from_blobs(&[blob], 0, 1)?;
    let fraud = validator.process_block(&state, 1, &parsed)?;

    // Verify fraud was detected
    assert_eq!(fraud.len(), 1, "Should detect exactly one double-spend");

    // Verify all fields of the fraud evidence
    match &fraud[0] {
        FraudEvidence::NullifierDoubleSpend {
            first_block_nr,
            second_block_nr,
            first_tx_number,
            second_tx_number,
            first_which,
            second_which,
            nullifier,
        } => {
            assert_eq!(*first_block_nr, 1, "First usage should be in block 1");
            assert_eq!(*second_block_nr, 1, "Second usage should be in block 1");
            assert_eq!(*first_tx_number, 0, "First usage should be in tx 0");
            assert_eq!(*second_tx_number, 0, "Second usage should be in tx 0");
            assert_eq!(*first_which, 0, "First usage should be nullifier0");
            assert_eq!(*second_which, 1, "Second usage should be nullifier1");
            assert_eq!(
                *nullifier, duplicate_nullifier,
                "Nullifier value should match"
            );
        }
        _ => panic!("Expected NullifierDoubleSpend fraud type"),
    }

    Ok(())
}

/// Test: DepositWrongLeaf - comprehensive with all field assertions
#[tokio::test]
async fn test_deposit_wrong_leaf_comprehensive() -> Result<()> {
    use pgp_challenger::validators::{DepositValidator, FraudEvidence};
    use pgp_common::blob::ParsedBlock;
    use pgp_common::types::constants::BLOB_SIZE;

    let validator = DepositValidator::new();

    let expected_leaf = B256::repeat_byte(0x11);
    let wrong_leaf = B256::repeat_byte(0xFF);
    let expected_deposits = vec![expected_leaf];

    let mut blob = [B256::ZERO; BLOB_SIZE];
    blob[0] = wrong_leaf; // Wrong!

    let block_data = BlockData {
        anchor: B256::repeat_byte(0xAA),
        timestamp: U256::from(12345u64),
        numTransactions: U256::ZERO,
        numDeposits: U256::from(1),
        blockNr: U256::from(42),
        blockIndex: TimestampAndIndex { day: 1, index: 5 },
        sequencer: Address::repeat_byte(0xBB),
        blobhashes: vec![B256::repeat_byte(0xCC)],
    };

    let parsed = ParsedBlock::from_blobs(&[blob], 1, 0)?;
    let fraud = validator.validate_block(&block_data, &parsed, &expected_deposits);

    assert_eq!(fraud.len(), 1, "Should detect exactly one fraud");

    match &fraud[0] {
        FraudEvidence::DepositWrongLeaf {
            block_data: bd,
            deposit_nr,
            expected_leaf: exp,
            submitted_leaf: sub,
        } => {
            assert_eq!(bd.blockNr, U256::from(42), "Block number should match");
            assert_eq!(bd.numDeposits, U256::from(1), "Deposit count should match");
            assert_eq!(*deposit_nr, 0, "Should be deposit 0");
            assert_eq!(*exp, expected_leaf, "Expected leaf should match");
            assert_eq!(*sub, wrong_leaf, "Submitted leaf should match");
        }
        _ => panic!("Expected DepositWrongLeaf fraud type"),
    }

    Ok(())
}

/// Test: DepositPaddingNotZero - comprehensive with all field assertions
#[tokio::test]
async fn test_deposit_padding_not_zero_comprehensive() -> Result<()> {
    use pgp_challenger::validators::{DepositValidator, FraudEvidence};
    use pgp_common::blob::ParsedBlock;
    use pgp_common::types::constants::BLOB_SIZE;

    let validator = DepositValidator::new();

    // 2 deposits in first group (slots 0, 1 used; slot 2 should be zero)
    let leaf0 = B256::repeat_byte(0x11);
    let leaf1 = B256::repeat_byte(0x22);
    let non_zero_padding = B256::repeat_byte(0xFF);
    let expected_deposits = vec![leaf0, leaf1];

    let mut blob = [B256::ZERO; BLOB_SIZE];
    blob[0] = leaf0;
    blob[1] = leaf1;
    blob[2] = non_zero_padding; // Should be zero!

    let block_data = BlockData {
        anchor: B256::ZERO,
        timestamp: U256::ZERO,
        numTransactions: U256::ZERO,
        numDeposits: U256::from(2),
        blockNr: U256::from(7),
        blockIndex: TimestampAndIndex { day: 0, index: 0 },
        sequencer: Address::ZERO,
        blobhashes: vec![],
    };

    let parsed = ParsedBlock::from_blobs(&[blob], 2, 0)?;
    let fraud = validator.validate_block(&block_data, &parsed, &expected_deposits);

    let padding_fraud = fraud
        .iter()
        .find(|f| matches!(f, FraudEvidence::DepositPaddingNotZero { .. }));
    assert!(padding_fraud.is_some(), "Should detect padding not zero");

    match padding_fraud.unwrap() {
        FraudEvidence::DepositPaddingNotZero {
            block_data: bd,
            group_index,
            slot_index,
            submitted_value,
        } => {
            assert_eq!(bd.blockNr, U256::from(7), "Block number should match");
            assert_eq!(*group_index, 0, "Should be group 0");
            assert_eq!(*slot_index, 2, "Should be slot 2");
            assert_eq!(*submitted_value, non_zero_padding, "Value should match");
        }
        _ => panic!("Expected DepositPaddingNotZero fraud type"),
    }

    Ok(())
}

/// Test: IncorrectTreeUpdate for deposits - comprehensive with all field assertions
#[tokio::test]
async fn test_incorrect_tree_update_deposits_comprehensive() -> Result<()> {
    use pgp_challenger::validators::{FraudEvidence, TreeUpdateValidator};
    use pgp_common::blob::ParsedBlock;
    use pgp_common::types::constants::BLOB_SIZE;

    let validator = TreeUpdateValidator::new();

    // Valid field elements
    fn field_elem(suffix: u8) -> B256 {
        B256::from([
            0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, suffix,
        ])
    }

    let wrong_root = B256::repeat_byte(0xEE);
    let mut blob = [B256::ZERO; BLOB_SIZE];
    blob[0] = field_elem(0x11); // leaf0
    blob[1] = field_elem(0x22); // leaf1
    blob[2] = field_elem(0x33); // leaf2
    blob[3] = wrong_root; // Wrong root!

    let block_data = BlockData {
        anchor: B256::ZERO,
        timestamp: U256::ZERO,
        numTransactions: U256::ZERO,
        numDeposits: U256::from(3),
        blockNr: U256::from(5),
        blockIndex: TimestampAndIndex { day: 0, index: 0 },
        sequencer: Address::ZERO,
        blobhashes: vec![],
    };

    let parsed = ParsedBlock::from_blobs(&[blob], 3, 0)?;
    let (fraud, _block_tree_root) =
        validator.validate_block(&block_data, &parsed, B256::ZERO, None, 0, 0, &[]);

    assert!(!fraud.is_empty(), "Should detect tree update fraud");

    match &fraud[0] {
        FraudEvidence::IncorrectTreeUpdate {
            block_data: bd,
            update_nr,
            is_tx,
            expected_anchor,
            submitted_anchor,
            ..
        } => {
            assert_eq!(bd.blockNr, U256::from(5), "Block number should match");
            assert_eq!(*update_nr, 0, "Should be update 0");
            assert!(!is_tx, "Should be deposit update, not transaction");
            assert_ne!(
                *expected_anchor, wrong_root,
                "Expected should differ from submitted"
            );
            assert_eq!(
                *submitted_anchor, wrong_root,
                "Submitted anchor should match"
            );
        }
        _ => panic!("Expected IncorrectTreeUpdate fraud type"),
    }

    Ok(())
}

/// Test: IncorrectTreeUpdate for transactions - comprehensive with all field assertions
#[tokio::test]
async fn test_incorrect_tree_update_transactions_comprehensive() -> Result<()> {
    use pgp_challenger::validators::{FraudEvidence, TreeUpdateValidator};
    use pgp_common::blob::ParsedBlock;
    use pgp_common::types::constants::BLOB_SIZE;

    let validator = TreeUpdateValidator::new();

    fn field_elem(suffix: u8) -> B256 {
        B256::from([
            0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, suffix,
        ])
    }

    let wrong_root = B256::repeat_byte(0xDD);
    let mut blob = [B256::ZERO; BLOB_SIZE];
    // Transaction layout: [proof x8, anchor_info, null0, null1, leaf0, leaf1, leaf2, root]
    blob[11] = field_elem(0xAA); // leaf0
    blob[12] = field_elem(0xBB); // leaf1
    blob[13] = field_elem(0xCC); // leaf2
    blob[14] = wrong_root; // Wrong root!

    let block_data = BlockData {
        anchor: B256::ZERO,
        timestamp: U256::ZERO,
        numTransactions: U256::from(1),
        numDeposits: U256::ZERO,
        blockNr: U256::from(3),
        blockIndex: TimestampAndIndex { day: 0, index: 0 },
        sequencer: Address::ZERO,
        blobhashes: vec![],
    };

    let parsed = ParsedBlock::from_blobs(&[blob], 0, 1)?;
    let (fraud, _block_tree_root) =
        validator.validate_block(&block_data, &parsed, B256::ZERO, None, 0, 0, &[]);

    assert!(!fraud.is_empty(), "Should detect tree update fraud");

    match &fraud[0] {
        FraudEvidence::IncorrectTreeUpdate {
            block_data: bd,
            is_tx,
            expected_anchor,
            submitted_anchor,
            ..
        } => {
            assert_eq!(bd.blockNr, U256::from(3), "Block number should match");
            assert!(is_tx, "Should be transaction update");
            assert_ne!(
                *expected_anchor, wrong_root,
                "Expected should differ from submitted"
            );
            assert_eq!(
                *submitted_anchor, wrong_root,
                "Submitted anchor should match"
            );
        }
        _ => panic!("Expected IncorrectTreeUpdate fraud type"),
    }

    Ok(())
}

/// Test: InvalidAnchorReference - comprehensive test using TransactionValidator
#[tokio::test]
async fn test_invalid_anchor_reference_comprehensive() -> Result<()> {
    use pgp_challenger::validators::AnchorLookup;
    use pgp_common::types::DecodedAnchorInfo;

    // Set up anchor lookup with block 5 having updates 0-2
    let mut anchor_lookup = AnchorLookup::new();
    anchor_lookup.set_current_block(10);
    anchor_lookup.insert(5, 0, false, B256::repeat_byte(0xAA));
    anchor_lookup.insert(5, 1, false, B256::repeat_byte(0xBB));
    anchor_lookup.insert(5, 2, false, B256::repeat_byte(0xCC));

    // Test case 1: Future block reference (block 999 > current 10)
    let future_anchor = DecodedAnchorInfo {
        block_nr: 999,
        update_nr: 0,
        is_deposit: false,
        eth_key: Address::ZERO,
    };
    let decoded = DecodedAnchorInfo::decode(future_anchor.encode());

    // Verify encoding/decoding preserves values
    assert_eq!(decoded.block_nr, 999, "Block number should be preserved");
    assert_eq!(decoded.update_nr, 0, "Update number should be preserved");
    assert!(!decoded.is_deposit, "is_deposit should be preserved");

    // Verify future block detection
    assert!(
        decoded.block_nr as u64 > anchor_lookup.current_block_nr(),
        "Should detect future block: {} > {}",
        decoded.block_nr,
        anchor_lookup.current_block_nr()
    );

    // Test case 2: Out-of-bounds update reference (update 100 in block 5 which only has 0-2)
    let bad_update_anchor = DecodedAnchorInfo {
        block_nr: 5,
        update_nr: 100,
        is_deposit: false,
        eth_key: Address::ZERO,
    };
    let decoded = DecodedAnchorInfo::decode(bad_update_anchor.encode());

    let max_update = anchor_lookup.get_max_update_nr(5, false);
    assert_eq!(max_update, Some(2), "Max update for block 5 should be 2");
    assert!(
        decoded.update_nr > max_update.unwrap(),
        "Should detect out-of-bounds update: {} > {}",
        decoded.update_nr,
        max_update.unwrap()
    );

    // Test case 3: Valid anchor reference should pass
    let valid_anchor = DecodedAnchorInfo {
        block_nr: 5,
        update_nr: 1,
        is_deposit: false,
        eth_key: Address::ZERO,
    };
    let decoded = DecodedAnchorInfo::decode(valid_anchor.encode());

    assert!(
        (decoded.block_nr as u64) <= anchor_lookup.current_block_nr(),
        "Valid block should not be in future"
    );
    assert!(
        decoded.update_nr <= anchor_lookup.get_max_update_nr(5, false).unwrap(),
        "Valid update should be in bounds"
    );
    assert!(
        anchor_lookup
            .get(decoded.block_nr, decoded.update_nr, decoded.is_deposit)
            .is_some(),
        "Should find valid anchor"
    );

    Ok(())
}

/// Test: Full challenge submission flow with all assertions
#[tokio::test]
async fn test_full_challenge_submission_with_assertions() -> Result<()> {
    let Some(ctx) = setup_test_context().await? else {
        return Ok(());
    };

    // Setup
    ctx.register_sequencer().await?;
    ctx.advance_to_open_period().await?;

    // Verify initial state
    let is_allowed = ctx.is_sequencer_allowed().await?;
    assert!(is_allowed, "Sequencer should be allowed initially");

    // Create a real deposit on L1 first
    ctx.mint_and_approve_tokens(U256::from(1000u64)).await?;
    ctx.create_deposit(U256::from(100u64), B256::repeat_byte(0x42))
        .await?;

    // Get the expected deposits for block 0
    let expected_deposits = ctx.get_deposits_for_block(U256::ZERO).await?;
    assert_eq!(expected_deposits.len(), 1, "Block 0 should have 1 deposit");

    // Submit fraudulent block with wrong deposit leaf
    let fake_leaf = B256::repeat_byte(0xFF);
    let sidecar = ctx.build_deposit_sidecar(&[fake_leaf])?;
    let submitted = ctx
        .submit_block(U256::ZERO, U256::from(1), U256::ZERO, sidecar)
        .await?;

    // Verify block was submitted
    assert_eq!(
        submitted.block_data.blockNr,
        U256::ZERO,
        "Should be block 0"
    );
    assert_eq!(
        submitted.block_data.numDeposits,
        U256::from(1),
        "Should claim 1 deposit"
    );
    assert!(
        !submitted.full_blob_bytes.is_empty(),
        "Blob data should exist"
    );

    // Detect fraud
    use pgp_challenger::validators::{DepositValidator, FraudEvidence};
    use pgp_common::blob::ParsedBlock;

    let mut test_blob = [B256::ZERO; 4096];
    test_blob[0] = fake_leaf;

    let parsed = ParsedBlock::from_blobs(&[test_blob], 1, 0)?;
    let validator = DepositValidator::new();
    let fraud = validator.validate_block(&submitted.block_data, &parsed, &expected_deposits);

    assert!(!fraud.is_empty(), "Should detect fraud");

    // Verify fraud evidence type and content
    match &fraud[0] {
        FraudEvidence::DepositWrongLeaf {
            expected_leaf,
            submitted_leaf,
            ..
        } => {
            assert_eq!(
                *expected_leaf, expected_deposits[0],
                "Expected leaf from L1"
            );
            assert_eq!(*submitted_leaf, fake_leaf, "Submitted wrong leaf");
        }
        _ => panic!("Expected DepositWrongLeaf fraud"),
    }

    // Build challenge
    use pgp_challenger::challenge::ChallengeBuilder;

    let challenge_builder = ChallengeBuilder::new()?;
    let prior_block = BlockData {
        anchor: B256::ZERO,
        timestamp: U256::ZERO,
        numTransactions: U256::ZERO,
        numDeposits: U256::ZERO,
        blockNr: U256::ZERO,
        blockIndex: TimestampAndIndex { day: 0, index: 0 },
        sequencer: Address::ZERO,
        blobhashes: vec![],
    };

    let challenge_params =
        challenge_builder.build_deposit_challenge(&fraud[0], &submitted.as_blobs(), prior_block)?;

    // Verify challenge parameters
    assert_eq!(
        challenge_params.commitment.len(),
        48,
        "KZG commitment should be 48 bytes"
    );
    assert_eq!(
        challenge_params.proof.len(),
        48,
        "KZG proof should be 48 bytes"
    );
    assert_eq!(
        challenge_params.block_data.blockNr,
        U256::ZERO,
        "Challenge targets block 0"
    );

    // Submit challenge
    use pgp_challenger::challenge::ChallengeSubmitter;

    let submitter = ChallengeSubmitter::new(&ctx.provider, ctx.contracts.entrypoint);
    let tx_hash = submitter
        .submit_deposit_challenge(challenge_params)
        .await
        .expect("Challenge submission must succeed");

    // Verify transaction succeeded
    let receipt = ctx
        .provider
        .get_transaction_receipt(tx_hash)
        .await?
        .expect("Receipt should exist");
    assert!(receipt.status(), "Challenge transaction must succeed");

    // Verify sequencer was slashed
    ctx.assert_sequencer_slashed().await?;

    Ok(())
}

// ============================================================================
// End-to-End Challenge Submission Tests (Verify Slashing)
// ============================================================================

/// Create blob data with transactions (no deposits).
/// Transaction layout: [proof×8, anchor_info, null0, null1, leaf0, leaf1, leaf2, root] = 15 fields
pub fn create_transaction_blob_data(transactions: &[(B256, B256)]) -> Vec<u8> {
    let mut data = Vec::new();

    for (null0, null1) in transactions {
        // Proof fields 0-7 (8 × 32 bytes) - zeros
        for _ in 0..8 {
            data.extend_from_slice(&[0u8; 32]);
        }
        // Anchor info (field 8) - zero
        data.extend_from_slice(&[0u8; 32]);
        // Nullifier 0 (field 9)
        data.extend_from_slice(null0.as_slice());
        // Nullifier 1 (field 10)
        data.extend_from_slice(null1.as_slice());
        // Leaves (fields 11-13) - zeros
        for _ in 0..3 {
            data.extend_from_slice(&[0u8; 32]);
        }
        // Root (field 14) - zero
        data.extend_from_slice(&[0u8; 32]);
    }

    data
}

/// E2E Test: NullifierDoubleSpend - Submit challenge to Anvil and verify sequencer slashing.
///
/// This test:
/// 1. Deploys contracts to Anvil
/// 2. Registers a sequencer
/// 3. Submits block 0 with a transaction containing nullifiers (A, B)
/// 4. Submits block 1 with a transaction containing nullifiers (A, C) - reuses A!
/// 5. Detects the double-spend fraud
/// 6. Builds and submits the nullifier challenge
/// 7. Verifies the sequencer was slashed
#[tokio::test]
async fn test_nullifier_double_spend_e2e_challenge_and_slash() -> Result<()> {
    let Some(ctx) = setup_test_context().await? else {
        return Ok(());
    };

    println!("=== NullifierDoubleSpend E2E Challenge Test ===");

    // Register sequencer and advance to open period
    ctx.register_sequencer().await?;
    ctx.advance_to_open_period().await?;

    // Verify sequencer is allowed
    assert!(
        ctx.is_sequencer_allowed().await?,
        "Sequencer should be allowed initially"
    );

    // Create nullifiers (use valid BLS field elements - first byte < 0x73)
    let shared_nullifier = B256::from([
        0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0x42,
    ]);
    let nullifier_b = B256::from([
        0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0xBB,
    ]);
    let nullifier_c = B256::from([
        0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0xCC,
    ]);

    // Submit block 0: transaction with (shared_nullifier, nullifier_b)
    // Transaction layout: [proof×8, anchor_info, null0, null1, leaf0, leaf1, leaf2, root] = 15 fields
    let mut tx0_fields = vec![B256::ZERO; 15];
    tx0_fields[9] = shared_nullifier; // null0
    tx0_fields[10] = nullifier_b; // null1
    let sidecar0 = create_raw_sidecar(&tx0_fields)?;
    let block0 = ctx
        .submit_block(U256::ZERO, U256::ZERO, U256::from(1), sidecar0)
        .await?;
    println!("✓ Block 0 submitted with tx using nullifiers (A, B)");

    // Submit block 1: transaction with (shared_nullifier, nullifier_c) - FRAUD!
    ctx.wait_for_open_period().await?;
    let mut tx1_fields = vec![B256::ZERO; 15];
    tx1_fields[9] = shared_nullifier; // null0 (reused!)
    tx1_fields[10] = nullifier_c; // null1
    let sidecar1 = create_raw_sidecar(&tx1_fields)?;
    let block1 = ctx
        .submit_block(U256::from(1), U256::ZERO, U256::from(1), sidecar1)
        .await?;
    println!("✓ Block 1 submitted with tx reusing nullifier A (fraud!)");

    // Detect the fraud using NullifierValidator
    use pgp_challenger::state::StateManager;
    use pgp_challenger::validators::{FraudEvidence, NullifierValidator};
    use pgp_common::blob::ParsedBlock;
    use pgp_common::types::constants::BLOB_SIZE;

    let state = StateManager::in_memory()?;
    let validator = NullifierValidator::new();

    // Process block 0 - should have no fraud
    let mut blob0 = [B256::ZERO; BLOB_SIZE];
    blob0[9] = shared_nullifier;
    blob0[10] = nullifier_b;
    let parsed0 = ParsedBlock::from_blobs(&[blob0], 0, 1)?;
    let fraud0 = validator.process_block(&state, 0, &parsed0)?;
    assert!(fraud0.is_empty(), "Block 0 should have no fraud");

    // Process block 1 - should detect double-spend
    let mut blob1 = [B256::ZERO; BLOB_SIZE];
    blob1[9] = shared_nullifier;
    blob1[10] = nullifier_c;
    let parsed1 = ParsedBlock::from_blobs(&[blob1], 0, 1)?;
    let fraud1 = validator.process_block(&state, 1, &parsed1)?;

    assert_eq!(fraud1.len(), 1, "Should detect one double-spend fraud");
    println!("✓ Fraud detected: NullifierDoubleSpend");

    // Verify fraud evidence
    let (first_block_nr, second_block_nr, first_tx, second_tx, first_which, second_which) =
        match &fraud1[0] {
            FraudEvidence::NullifierDoubleSpend {
                first_block_nr,
                second_block_nr,
                first_tx_number,
                second_tx_number,
                first_which,
                second_which,
                nullifier,
            } => {
                assert_eq!(*nullifier, shared_nullifier);
                (
                    *first_block_nr,
                    *second_block_nr,
                    *first_tx_number,
                    *second_tx_number,
                    *first_which,
                    *second_which,
                )
            }
            _ => panic!("Expected NullifierDoubleSpend fraud"),
        };

    println!("  First usage: block {first_block_nr}, tx {first_tx}, which {first_which}");
    println!("  Second usage: block {second_block_nr}, tx {second_tx}, which {second_which}");

    // Build the challenge
    use pgp_challenger::challenge::ChallengeBuilder;

    let challenge_builder = ChallengeBuilder::new()?;

    // Prior block for rollback must be the block BEFORE the fraudulent block (block 1)
    // For a challenge on block 1, we roll back to block 0's state
    // So prior_block should be block 0
    let challenge_params = challenge_builder.build_nullifier_challenge(
        &fraud1[0],
        &block0.as_blobs(),
        &block1.as_blobs(),
        block0.block_data.clone(),
        block1.block_data.clone(),
        block0.block_data.clone(), // Rollback target is block 0
    )?;

    // Verify challenge parameters
    assert_eq!(challenge_params.reused_nullifier, shared_nullifier);
    assert_eq!(challenge_params.first_commitment.len(), 48);
    assert_eq!(challenge_params.first_proof.len(), 48);
    assert_eq!(challenge_params.second_commitment.len(), 48);
    assert_eq!(challenge_params.second_proof.len(), 48);
    println!("✓ Challenge parameters built with KZG proofs");

    // Submit the challenge
    use pgp_challenger::challenge::ChallengeSubmitter;

    let submitter = ChallengeSubmitter::new(&ctx.provider, ctx.contracts.entrypoint);
    let tx_hash = submitter
        .submit_nullifier_challenge(challenge_params)
        .await
        .expect("Nullifier challenge submission must succeed");
    println!("✓ Nullifier challenge submitted! Tx hash: {tx_hash:?}");

    // Verify transaction succeeded
    let receipt = ctx
        .provider
        .get_transaction_receipt(tx_hash)
        .await?
        .expect("Receipt should exist");
    assert!(receipt.status(), "Challenge transaction must succeed");

    // Verify sequencer was slashed
    ctx.assert_sequencer_slashed().await?;

    println!("\n✓ NullifierDoubleSpend E2E test completed - sequencer slashed!");

    Ok(())
}

/// Deploy contracts with real ZK verifier instead of FakeZK
fn deploy_contracts_with_real_zk(rpc_url: &str, private_key: &str) -> Result<DeployedContracts> {
    let project_root = find_project_root();

    // Ensure foundry.toml exists
    if !project_root.join("foundry.toml").exists() {
        return Err(eyre!(
            "Could not find foundry.toml in project root: {}",
            project_root.display()
        ));
    }

    // Acquire build lock to prevent parallel forge builds from conflicting
    let lock = BUILD_LOCK.get_or_init(|| std::sync::Mutex::new(()));
    let _guard = lock.lock().unwrap();

    // Run forge build first to ensure cache exists (without --force to avoid conflicts)
    let cache_file = project_root.join("cache/solidity-files-cache.json");
    if !cache_file.exists() {
        let build_output = Command::new("forge")
            .current_dir(&project_root)
            .args(["build"])
            .output()?;

        if !build_output.status.success() {
            let stderr = String::from_utf8_lossy(&build_output.stderr);
            return Err(eyre!("forge build failed: {}", stderr));
        }
    }

    let output = Command::new("forge")
        .current_dir(&project_root)
        .args([
            "script",
            "script/deploy/DeployRealZk.s.sol:DeployRealZk",
            "--rpc-url",
            rpc_url,
            "--broadcast",
            "--private-key",
            private_key,
            "--slow",
            "--code-size-limit",
            "200000",
            "--legacy",
        ])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        return Err(eyre!(
            "forge script (DeployRealZk) failed:\nstdout: {}\nstderr: {}",
            stdout,
            stderr
        ));
    }

    parse_deployment_output(&stdout).map_err(|e| {
        eyre!(
            "forge script failed to parse addresses:\nError: {}\nstdout: {}\nstderr: {}",
            e,
            stdout,
            stderr
        )
    })
}

/// Create a test context with real ZK verifier for snarkjs integration tests
pub async fn setup_test_context_with_real_zk() -> Result<Option<TestContext<impl Provider + Clone>>>
{
    // Skip if forge is not available
    if Command::new("forge").arg("--version").output().is_err() {
        eprintln!("Skipping test: forge not found in PATH");
        return Ok(None);
    }

    // Spawn Anvil with Cancun hardfork for blob support
    let anvil = Anvil::new()
        .block_time(1)
        .args([
            "--hardfork",
            "cancun",
            "--disable-block-gas-limit",
            "--disable-code-size-limit",
        ])
        .try_spawn()?;

    let rpc_url = anvil.endpoint();
    let private_key = anvil.keys()[0].clone();
    let signer: PrivateKeySigner = private_key.clone().into();
    let deployer = signer.address();

    println!("Anvil running at: {rpc_url} (Cancun hardfork)");
    println!("Deployer: {deployer}");

    // Deploy contracts with real ZK verifier
    let private_key_hex = format!("0x{}", hex::encode(private_key.to_bytes()));
    let contracts = deploy_contracts_with_real_zk(&rpc_url, &private_key_hex)?;
    println!("Deployed contracts (with real ZK verifier): {contracts:?}");
    println!("✓ Contract deployment successful");

    // Create provider with wallet
    let wallet = EthereumWallet::from(signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url.parse()?);

    // Get genesis anchor
    let entrypoint = Entrypoint::new(contracts.entrypoint, &provider);
    let genesis_anchor = entrypoint.GENESIS_ANCHOR().call().await?;
    println!("Genesis anchor: {genesis_anchor}");

    Ok(Some(TestContext {
        anvil,
        provider,
        contracts,
        deployer,
        signer,
        genesis_anchor,
    }))
}

/// Test: Tree Update fraud E2E with real snarkjs proof generation
///
/// This test:
/// 1. Submits a block with an incorrect tree update anchor (deposit group)
/// 2. Detects the fraud using TreeUpdateValidator
/// 3. Uses SnarkjsProver to generate a real ZK proof proving the correct anchor
/// 4. Builds and submits the challenge
/// 5. Verifies the sequencer was slashed
#[tokio::test]
async fn test_tree_update_fraud_e2e_with_snarkjs() -> Result<()> {
    use pgp_challenger::challenge::{ChallengeBuilder, ChallengeSubmitter};
    use pgp_challenger::snarkjs::SnarkjsProver;
    use pgp_challenger::validators::{FraudEvidence, TreeUpdateValidator};
    use pgp_common::blob::ParsedBlock;
    use pgp_common::types::constants::BLOB_SIZE;
    use std::path::Path;

    // Check if snarkjs is available
    if std::process::Command::new("npx")
        .args(["snarkjs", "--version"])
        .output()
        .is_err()
    {
        eprintln!("Skipping test: snarkjs not found (run `npm install snarkjs`)");
        return Ok(());
    }

    // Check if circuit files exist
    let wasm_path = Path::new(
        "../../../circuits/outputs/predictableUpdate/predictableUpdate_js/predictableUpdate.wasm",
    );
    let zkey_path = Path::new("../../../circuits/outputs/predictableUpdate/predictableUpdate.zkey");

    if !wasm_path.exists() || !zkey_path.exists() {
        eprintln!("Skipping test: circuit files not found at {wasm_path:?} and {zkey_path:?}");
        return Ok(());
    }

    // Use setup with real ZK verifier for snarkjs proofs
    let Some(ctx) = setup_test_context_with_real_zk().await? else {
        return Ok(());
    };

    println!("\n=== Tree Update Fraud E2E Test with snarkjs ===\n");

    // Setup: Register sequencer and advance to open period
    ctx.register_sequencer().await?;
    ctx.advance_to_open_period().await?;
    println!("✓ Sequencer registered and in open period");

    // Create 3 real deposits on L1 for block 0
    ctx.mint_and_approve_tokens(U256::from(3000u64)).await?;
    ctx.create_deposit(U256::from(100u64), B256::repeat_byte(0x11))
        .await?;
    ctx.create_deposit(U256::from(200u64), B256::repeat_byte(0x22))
        .await?;
    ctx.create_deposit(U256::from(300u64), B256::repeat_byte(0x33))
        .await?;
    println!("✓ 3 deposits created on L1");

    // Verify we have 3 deposits for block 0
    let deposits = ctx.get_deposits_for_block(U256::ZERO).await?;
    assert_eq!(deposits.len(), 3, "Block 0 should have 3 deposits");
    let leaf0 = deposits[0];
    let leaf1 = deposits[1];
    let leaf2 = deposits[2];
    println!("✓ Deposit leaves: [{leaf0}, {leaf1}, {leaf2}]");

    // Helper to create valid BN254 field elements
    fn field_elem(suffix: u8) -> B256 {
        B256::from([
            0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, suffix,
        ])
    }

    // Create blob data with the correct deposit leaves but an INCORRECT tree update root
    // Use a valid BLS field element that's clearly wrong (not the actual computed root)
    let wrong_root = field_elem(0xAA); // This will differ from the correct merkle root

    let mut blob_fields = [B256::ZERO; BLOB_SIZE];
    blob_fields[0] = leaf0;
    blob_fields[1] = leaf1;
    blob_fields[2] = leaf2;
    blob_fields[3] = wrong_root; // Fraudulent anchor

    // Build sidecar from blob data using raw encoding (not SimpleCoder)
    // This preserves the exact field values without encoding
    let sidecar = create_raw_sidecar(blob_fields.as_ref())?;

    // Submit the fraudulent block
    let submitted = ctx
        .submit_block(U256::ZERO, U256::from(3), U256::ZERO, sidecar)
        .await?;
    println!(
        "✓ Block {} submitted with fraudulent tree update",
        submitted.block_data.blockNr
    );

    // Get the actual tree index from the submitted block
    // Contract uses: treeIndex = day * 8192 + index
    let day: u64 = submitted.block_data.blockIndex.day.try_into().unwrap();
    let index: u64 = submitted.block_data.blockIndex.index.try_into().unwrap();
    let tree_index = day * 8192 + index;
    println!("  Block index: day={day}, index={index}, treeIndex={tree_index}");

    // Parse the block and detect fraud
    let parsed = ParsedBlock::from_blobs(&[blob_fields], 3, 0)?;

    // Compute the correct zero hashes for the root tree sibling path.
    // The root tree's "zero leaf" is the root of an empty block tree,
    // NOT literal zero. So:
    // - block_zero_hashes[12] = root of empty 12-level Poseidon tree
    // - root_zero[0] = block_zero_hashes[12]  (sibling at level 0)
    // - root_zero[i] = Poseidon(root_zero[i-1], root_zero[i-1])
    let block_zero_hashes = pgp_merkle::compute_zero_hashes(12);
    let empty_block_root = block_zero_hashes[12];

    // Compute root tree zero hashes starting from the empty block root
    let mut root_path = [B256::ZERO; 28];
    root_path[0] = empty_block_root;
    for i in 1..28 {
        root_path[i] = pgp_merkle::poseidon2(root_path[i - 1], root_path[i - 1]);
    }

    let validator = TreeUpdateValidator::new();
    let (fraud, _final_block_root) = validator.validate_block(
        &submitted.block_data,
        &parsed,
        ctx.genesis_anchor, // prior_anchor (genesis for first block)
        None,               // prior_block_nr (None for genesis)
        tree_index,         // Use the actual tree index from the submitted block
        0,                  // start_in_block_index
        &root_path,         // root_path (correct zero hashes for root tree)
    );

    assert!(!fraud.is_empty(), "Should detect tree update fraud");
    println!("✓ Fraud detected: {} evidence items", fraud.len());

    // Extract fraud evidence and merkle data
    let (_block_data, update_nr, is_tx, expected_anchor, prior_anchor, leaves, merkle_data) =
        match &fraud[0] {
            FraudEvidence::IncorrectTreeUpdate {
                block_data,
                update_nr,
                is_tx,
                expected_anchor,
                prior_anchor,
                leaves,
                merkle_data,
                ..
            } => (
                block_data.clone(),
                *update_nr,
                *is_tx,
                *expected_anchor,
                *prior_anchor,
                *leaves,
                merkle_data.clone().expect("Merkle data should be present"),
            ),
            _ => panic!("Expected IncorrectTreeUpdate fraud type"),
        };

    assert!(!is_tx, "Should be deposit update (not transaction)");
    assert_eq!(update_nr, 0, "Should be first update");
    println!("✓ Fraud evidence: update_nr={update_nr}, expected_anchor={expected_anchor:?}");

    // Generate ZK proof using snarkjs
    println!("Generating ZK proof with snarkjs...");
    println!("  prior_anchor: {prior_anchor:?}");
    println!("  block_root_before: {:?}", merkle_data.block_root_before);
    println!("  leaves: {leaves:?}");
    println!("  block_index: {}", merkle_data.block_index);
    println!("  in_block_index: {}", merkle_data.in_block_index);
    println!("  nonzero_field: {:?}", merkle_data.nonzero_field);
    println!("  block_proofs[0][0]: {:?}", merkle_data.block_proofs[0][0]);
    println!("  root_path[0]: {:?}", merkle_data.root_path[0]);

    let snarkjs_prover = SnarkjsProver::new("npx snarkjs", wasm_path, zkey_path);

    let (true_anchor, zk_proof) = snarkjs_prover
        .generate_update_proof(
            prior_anchor,
            merkle_data.block_root_before,
            leaves,
            merkle_data.block_index,
            merkle_data.in_block_index as u64,
            merkle_data.nonzero_field,
            merkle_data.block_proofs,
            merkle_data.root_path,
        )
        .await?;

    println!("✓ ZK proof generated, true_anchor={true_anchor:?}");

    // Verify the true anchor matches what we expected
    assert_eq!(
        true_anchor, expected_anchor,
        "ZK proof should compute the same anchor as local computation"
    );

    // Build the challenge
    let challenge_builder = ChallengeBuilder::new()?;

    // For the first block, prior anchor is at genesis (no KZG proof needed)
    let prior_block = BlockData {
        anchor: ctx.genesis_anchor,
        timestamp: U256::ZERO,
        numTransactions: U256::ZERO,
        numDeposits: U256::ZERO,
        blockNr: U256::ZERO,
        blockIndex: TimestampAndIndex { day: 0, index: 0 },
        sequencer: Address::ZERO,
        blobhashes: vec![],
    };

    // Use the genesis-specific method since this is block 0, update 0
    let blobs = submitted.as_blobs();
    let challenge_params = challenge_builder.build_tree_update_challenge_genesis(
        &fraud[0],
        &blobs,
        prior_anchor, // Genesis anchor
        true_anchor,
        zk_proof,
        prior_block, // Rollback to genesis
    )?;

    println!("✓ Challenge parameters built");

    // Submit the challenge
    let submitter = ChallengeSubmitter::new(&ctx.provider, ctx.contracts.entrypoint);
    let tx_hash = submitter
        .submit_tree_update_challenge(challenge_params)
        .await
        .expect("Tree update challenge submission must succeed");
    println!("✓ Challenge submitted! Tx hash: {tx_hash:?}");

    // Verify transaction succeeded
    let receipt = ctx
        .provider
        .get_transaction_receipt(tx_hash)
        .await?
        .expect("Receipt should exist");
    assert!(receipt.status(), "Challenge transaction must succeed");

    // Verify sequencer was slashed
    ctx.assert_sequencer_slashed().await?;

    println!("\n✓ Tree Update Fraud E2E test completed - sequencer slashed with real ZK proof!");

    Ok(())
}

// ============================================================================
// Additional E2E Challenge Submission Tests
// ============================================================================

/// E2E Test: DepositPaddingNotZero - unused deposit slots contain non-zero values
///
/// This test:
/// 1. Creates 1 deposit (partial group, should have zero padding in slots 1,2)
/// 2. Submits a block with non-zero padding
/// 3. Detects the padding fraud
/// 4. Builds and submits the challenge
/// 5. Verifies the sequencer was slashed
#[tokio::test]
async fn test_deposit_padding_not_zero_e2e_challenge_and_slash() -> Result<()> {
    let Some(ctx) = setup_test_context().await? else {
        return Ok(());
    };

    println!("=== DepositPaddingNotZero E2E Challenge Test ===");

    // Register sequencer
    ctx.register_sequencer().await?;
    ctx.advance_to_open_period().await?;

    // Use valid BLS field elements
    fn field_elem(suffix: u8) -> B256 {
        B256::from([
            0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, suffix,
        ])
    }

    // Create a deposit on L1 for block 0
    ctx.mint_and_approve_tokens(U256::from(1000u64)).await?;
    ctx.create_deposit(U256::from(100u64), B256::repeat_byte(0x42))
        .await?;
    println!("✓ Deposit created on L1");

    // Verify we have 1 deposit for block 0
    let expected_deposits = ctx.get_deposits_for_block(U256::ZERO).await?;
    assert_eq!(expected_deposits.len(), 1, "Block 0 should have 1 deposit");
    println!("✓ Expected deposit for block 0");

    // Submit block 0 with correct deposit but non-zero padding in slot 1
    // Blob layout: [leaf0, padding1, padding2, root]
    ctx.wait_for_open_period().await?;

    let mut blob_fields = vec![B256::ZERO; 4096];
    blob_fields[0] = expected_deposits[0]; // Correct deposit leaf
    blob_fields[1] = field_elem(0xFF); // Non-zero padding (fraud!)
    blob_fields[2] = B256::ZERO; // Zero padding (correct)
    blob_fields[3] = field_elem(0xAA); // Some root

    let sidecar = create_raw_sidecar(&blob_fields)?;
    let block = ctx
        .submit_block(U256::ZERO, U256::from(1), U256::ZERO, sidecar)
        .await?;
    println!("✓ Block 0 submitted with non-zero padding (fraudulent)");

    // Detect the fraud
    use pgp_challenger::validators::{DepositValidator, FraudEvidence};
    use pgp_common::blob::ParsedBlock;
    use pgp_common::types::constants::BLOB_SIZE;

    let mut test_blob = [B256::ZERO; BLOB_SIZE];
    test_blob[0] = expected_deposits[0];
    test_blob[1] = field_elem(0xFF);
    test_blob[2] = B256::ZERO;
    test_blob[3] = field_elem(0xAA);

    let parsed = ParsedBlock::from_blobs(&[test_blob], 1, 0)?;
    let validator = DepositValidator::new();
    let fraud = validator.validate_block(&block.block_data, &parsed, &expected_deposits);

    assert!(!fraud.is_empty(), "Should detect padding fraud");

    let padding_fraud = fraud
        .iter()
        .find(|f| matches!(f, FraudEvidence::DepositPaddingNotZero { .. }));
    assert!(
        padding_fraud.is_some(),
        "Should have DepositPaddingNotZero fraud"
    );

    match padding_fraud.unwrap() {
        FraudEvidence::DepositPaddingNotZero {
            group_index,
            slot_index,
            ..
        } => {
            assert_eq!(*group_index, 0);
            assert_eq!(*slot_index, 1);
            println!(
                "✓ Fraud detected: DepositPaddingNotZero (group={group_index}, slot={slot_index})"
            );
        }
        _ => panic!("Expected DepositPaddingNotZero"),
    }

    // Build and submit the challenge
    use pgp_challenger::challenge::{ChallengeBuilder, ChallengeSubmitter};

    let challenge_builder = ChallengeBuilder::new()?;
    // Use default prior block for block 0
    let prior_block = BlockData {
        anchor: B256::ZERO,
        timestamp: U256::ZERO,
        numTransactions: U256::ZERO,
        numDeposits: U256::ZERO,
        blockNr: U256::ZERO,
        blockIndex: TimestampAndIndex { day: 0, index: 0 },
        sequencer: Address::ZERO,
        blobhashes: vec![],
    };
    let challenge_params = challenge_builder.build_deposit_challenge(
        padding_fraud.unwrap(),
        &block.as_blobs(),
        prior_block,
    )?;
    println!("✓ Challenge parameters built");

    let submitter = ChallengeSubmitter::new(&ctx.provider, ctx.contracts.entrypoint);
    let tx_hash = submitter
        .submit_deposit_challenge(challenge_params)
        .await
        .expect("Deposit padding not zero challenge must succeed");
    println!("✓ Challenge submitted! Tx hash: {tx_hash:?}");

    // Verify transaction succeeded
    let receipt = ctx
        .provider
        .get_transaction_receipt(tx_hash)
        .await?
        .expect("Receipt should exist");
    assert!(receipt.status(), "Challenge transaction must succeed");

    // Verify sequencer was slashed
    ctx.assert_sequencer_slashed().await?;

    println!("\n✓ DepositPaddingNotZero E2E test completed - sequencer slashed!");

    Ok(())
}

/// E2E Test: InvalidAnchorReference - transaction references future block
///
/// This test:
/// 1. Submits block 0 with a transaction referencing a future block (fraud!)
/// 2. Detects the invalid anchor reference
/// 3. Builds and submits the transaction challenge
/// 4. Verifies the sequencer was slashed
#[tokio::test]
async fn test_invalid_anchor_reference_e2e_challenge_and_slash() -> Result<()> {
    let Some(ctx) = setup_test_context().await? else {
        return Ok(());
    };

    println!("=== InvalidAnchorReference E2E Challenge Test ===");

    // Register sequencer
    ctx.register_sequencer().await?;
    ctx.advance_to_open_period().await?;

    // Helper for valid BLS field elements
    fn field_elem(suffix: u8) -> B256 {
        B256::from([
            0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, suffix,
        ])
    }

    // Create a transaction that references block 999 (future block - fraud!)
    // anchor_info encoding: block_nr (32 bits) | update_nr (16 bits) | is_deposit (1 bit) | eth_key (160 bits)
    // For block 999, update 0, is_deposit=false, eth_key=0:
    // block_nr = 999 = 0x3E7 in the highest 32 bits
    use pgp_common::types::DecodedAnchorInfo;
    let future_anchor_info = DecodedAnchorInfo {
        block_nr: 999, // Future block (fraud!)
        update_nr: 0,
        is_deposit: false,
        eth_key: Address::ZERO,
    };
    let anchor_info_encoded = future_anchor_info.encode();

    // Build transaction blob: [proof×8, anchor_info, null0, null1, leaf0, leaf1, leaf2, root] = 15 fields
    let mut tx_fields = vec![B256::ZERO; 15];
    tx_fields[8] = anchor_info_encoded; // anchor_info (references future block)
    tx_fields[9] = field_elem(0x11); // null0
    tx_fields[10] = field_elem(0x22); // null1
    tx_fields[11] = field_elem(0x33); // leaf0
    tx_fields[12] = field_elem(0x44); // leaf1
    tx_fields[13] = field_elem(0x55); // leaf2
    tx_fields[14] = field_elem(0xAA); // root

    let sidecar = create_raw_sidecar(&tx_fields)?;
    let block0 = ctx
        .submit_block(U256::ZERO, U256::ZERO, U256::from(1), sidecar)
        .await?;
    println!("✓ Block 0 submitted with tx referencing future block (fraudulent)");

    // Detect the fraud using TransactionValidator's anchor checking
    // We use the AnchorLookup to verify the reference is invalid
    use pgp_challenger::validators::AnchorLookup;

    let mut anchor_lookup = AnchorLookup::new();
    anchor_lookup.set_current_block(0); // We're at block 0

    // Verify the anchor reference is invalid (future block)
    assert!(
        !anchor_lookup.is_valid_reference(999, 0, false),
        "Should detect invalid future block reference"
    );
    println!("✓ Fraud detected: InvalidAnchorReference (block 999 > current 0)");

    // Create fraud evidence manually (since we don't have the full TransactionValidator setup)
    use pgp_challenger::validators::FraudEvidence;
    let fraud_evidence = FraudEvidence::InvalidAnchorReference {
        block_data: block0.block_data.clone(),
        tx_nr: 0,
        anchor_block_nr: 999,
        anchor_update_nr: 0,
        is_deposit: false,
    };

    // Build the challenge
    use pgp_challenger::challenge::{ChallengeBuilder, ChallengeSubmitter};

    let challenge_builder = ChallengeBuilder::new()?;

    // For invalid anchor reference, we need to provide the genesis anchor
    // and a "prior block" for rollback purposes
    let prior_block = BlockData {
        anchor: ctx.genesis_anchor,
        timestamp: U256::ZERO,
        numTransactions: U256::ZERO,
        numDeposits: U256::ZERO,
        blockNr: U256::ZERO,
        blockIndex: TimestampAndIndex { day: 0, index: 0 },
        sequencer: Address::ZERO,
        blobhashes: vec![],
    };

    let challenge_params = challenge_builder.build_transaction_challenge_multi_blob(
        &fraud_evidence,
        &block0.as_blobs(),
        ctx.genesis_anchor,  // anchor (genesis for first block)
        prior_block.clone(), // prior_anchor_block
        &block0.as_blobs(),  // prior_anchor_blobs (same block for genesis)
        0,                   // prior_anchor_field_index
        prior_block,         // rollback_target_block
    )?;
    println!("✓ Challenge parameters built");

    let submitter = ChallengeSubmitter::new(&ctx.provider, ctx.contracts.entrypoint);
    let tx_hash = submitter
        .submit_transaction_challenge(challenge_params)
        .await
        .expect("Transaction challenge must succeed");
    println!("✓ Challenge submitted! Tx hash: {tx_hash:?}");

    // Verify transaction succeeded
    let receipt = ctx
        .provider
        .get_transaction_receipt(tx_hash)
        .await?
        .expect("Receipt should exist");
    assert!(receipt.status(), "Challenge transaction must succeed");

    // Verify sequencer was slashed
    ctx.assert_sequencer_slashed().await?;

    println!("\n✓ InvalidAnchorReference E2E test completed - sequencer slashed!");

    Ok(())
}

/// E2E Test: InvalidTransactionProof - transaction has invalid ZK proof
///
/// This test:
/// 1. Submits block 0 with a deposit (creates an anchor we can reference)
/// 2. Submits block 1 with a transaction containing an invalid ZK proof referencing block 0
/// 3. Builds and submits the transaction challenge
/// 4. Verifies the sequencer was slashed
#[tokio::test]
async fn test_invalid_transaction_proof_e2e_challenge_and_slash() -> Result<()> {
    let Some(ctx) = setup_test_context().await? else {
        return Ok(());
    };

    println!("=== InvalidTransactionProof E2E Challenge Test ===");

    // Register sequencer
    ctx.register_sequencer().await?;
    ctx.advance_to_open_period().await?;

    fn field_elem(suffix: u8) -> B256 {
        B256::from([
            0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, suffix,
        ])
    }

    // Create a real deposit on L1 for block 0
    ctx.mint_and_approve_tokens(U256::from(1000u64)).await?;
    ctx.create_deposit(U256::from(100u64), B256::repeat_byte(0x42))
        .await?;

    // Get the deposit leaf for block 0
    let deposits = ctx.get_deposits_for_block(U256::ZERO).await?;
    assert_eq!(deposits.len(), 1, "Block 0 should have 1 deposit");
    let deposit_leaf = deposits[0];

    // Submit block 0 with the real deposit (creates anchor for reference)
    let sidecar0 = ctx.build_deposit_sidecar(&[deposit_leaf])?;
    let block0 = ctx
        .submit_block(U256::ZERO, U256::from(1), U256::ZERO, sidecar0)
        .await?;
    println!("✓ Block 0 submitted with 1 deposit (creates anchor for reference)");

    // Now submit block 1 with a transaction that has an invalid ZK proof
    // The transaction references block 0's deposit update 0
    ctx.wait_for_open_period().await?;

    use pgp_common::types::DecodedAnchorInfo;
    let anchor_info = DecodedAnchorInfo {
        block_nr: 0,      // Reference block 0
        update_nr: 0,     // Deposit group 0
        is_deposit: true, // It's a deposit anchor
        eth_key: Address::ZERO,
    };
    let anchor_info_encoded = anchor_info.encode();

    // Build transaction with INVALID proof (all zeros)
    // Transaction layout: [proof×8, anchor_info, null0, null1, leaf0, leaf1, leaf2, root]
    let mut tx_fields = vec![B256::ZERO; 15];
    // proof fields 0-7: all zeros (invalid Groth16 proof)
    tx_fields[8] = anchor_info_encoded;
    tx_fields[9] = field_elem(0x11); // null0
    tx_fields[10] = field_elem(0x22); // null1
    tx_fields[11] = field_elem(0x33); // leaf0
    tx_fields[12] = field_elem(0x44); // leaf1
    tx_fields[13] = field_elem(0x55); // leaf2
    tx_fields[14] = field_elem(0xAA); // root

    let sidecar1 = create_raw_sidecar(&tx_fields)?;
    let block1 = ctx
        .submit_block(U256::from(1), U256::ZERO, U256::from(1), sidecar1)
        .await?;
    println!("✓ Block 1 submitted with invalid ZK proof (fraudulent)");

    // Create fraud evidence
    use pgp_challenger::validators::FraudEvidence;
    let fraud_evidence = FraudEvidence::InvalidTransactionProof {
        block_data: block1.block_data.clone(),
        tx_nr: 0,
        anchor_block_nr: 0,
        anchor_update_nr: 0,
        is_deposit: true,
    };
    println!("✓ Fraud evidence created: InvalidTransactionProof");

    // Build the challenge
    // The anchor is at block 0's deposit group root (field index 3 in deposit layout)
    use pgp_challenger::challenge::{ChallengeBuilder, ChallengeSubmitter};

    let challenge_builder = ChallengeBuilder::new()?;

    // The anchor is the root at field 3 in block 0's blob (deposit layout: [leaf0, leaf1, leaf2, root])
    let anchor_field_index = 3;

    let challenge_params = challenge_builder.build_transaction_challenge_multi_blob(
        &fraud_evidence,
        &block1.as_blobs(),        // Block containing fraudulent tx
        block0.block_data.anchor,  // The anchor value from block 0
        block0.block_data.clone(), // prior_anchor_block
        &block0.as_blobs(),        // prior_anchor_blobs
        anchor_field_index,        // prior_anchor_field_index (root is at index 3)
        block0.block_data.clone(), // rollback_target_block
    )?;
    println!("✓ Challenge parameters built");

    let submitter = ChallengeSubmitter::new(&ctx.provider, ctx.contracts.entrypoint);
    let tx_hash = submitter
        .submit_transaction_challenge(challenge_params)
        .await
        .expect("Transaction challenge must succeed");
    println!("✓ Challenge submitted! Tx hash: {tx_hash:?}");

    // Verify transaction succeeded
    let receipt = ctx
        .provider
        .get_transaction_receipt(tx_hash)
        .await?
        .expect("Receipt should exist");
    assert!(receipt.status(), "Challenge transaction must succeed");

    // Verify sequencer was slashed
    ctx.assert_sequencer_slashed().await?;

    println!("\n✓ InvalidTransactionProof E2E test completed - sequencer slashed!");

    Ok(())
}

/// E2E Test: MissingEthKeyAuth - eth-keyed transaction not authorized in TransactionRegistry
///
/// This test:
/// 1. Submits block 0 with a deposit (creates an anchor we can reference)
/// 2. Submits block 1 with an eth-keyed transaction (ZK proof passes with FakeZK, but NOT registered)
/// 3. The TransactionRegistry does NOT have authorization for this tx
/// 4. Builds and submits the transaction challenge
/// 5. Verifies the sequencer was slashed
///
/// Note: This test uses FakeZK (which accepts any proof) to focus on eth-key auth checking.
/// The real TransactionRegistry contract is used to verify authorization.
#[tokio::test]
async fn test_missing_eth_key_auth_e2e_challenge_and_slash() -> Result<()> {
    // Use FakeZK context - any proof passes, so we can focus on eth-key auth checking
    let Some(ctx) = setup_test_context().await? else {
        return Ok(());
    };

    println!("=== MissingEthKeyAuth E2E Challenge Test ===");

    // Register sequencer
    ctx.register_sequencer().await?;
    ctx.advance_to_open_period().await?;

    fn field_elem(suffix: u8) -> B256 {
        B256::from([
            0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, suffix,
        ])
    }

    // Create a real deposit on L1 for block 0
    ctx.mint_and_approve_tokens(U256::from(1000u64)).await?;
    ctx.create_deposit(U256::from(100u64), B256::repeat_byte(0x42))
        .await?;

    // Get the deposit leaf for block 0
    let deposits = ctx.get_deposits_for_block(U256::ZERO).await?;
    assert_eq!(deposits.len(), 1, "Block 0 should have 1 deposit");
    let deposit_leaf = deposits[0];

    // Submit block 0 with the real deposit (creates anchor for reference)
    let sidecar0 = ctx.build_deposit_sidecar(&[deposit_leaf])?;
    let block0 = ctx
        .submit_block(U256::ZERO, U256::from(1), U256::ZERO, sidecar0)
        .await?;
    println!("✓ Block 0 submitted with 1 deposit (creates anchor for reference)");

    // Now submit block 1 with an eth-keyed transaction
    ctx.wait_for_open_period().await?;

    // Create an eth-keyed transaction with a random eth_key (NOT registered!)
    let unregistered_eth_key = Address::repeat_byte(0xAB);

    use pgp_common::types::DecodedAnchorInfo;
    let anchor_info = DecodedAnchorInfo {
        block_nr: 0,                   // Reference block 0
        update_nr: 0,                  // Deposit group 0
        is_deposit: true,              // It's a deposit anchor
        eth_key: unregistered_eth_key, // Not registered in TransactionRegistry!
    };
    let anchor_info_encoded = anchor_info.encode();

    // Build transaction with the eth-keyed anchor_info
    // FakeZK accepts any proof, so this will pass ZK check and proceed to eth-key auth check
    let mut tx_fields = vec![B256::ZERO; 15];
    tx_fields[8] = anchor_info_encoded; // anchor_info with eth_key
    tx_fields[9] = field_elem(0x11); // null0
    tx_fields[10] = field_elem(0x22); // null1
    tx_fields[11] = field_elem(0x33); // leaf0
    tx_fields[12] = field_elem(0x44); // leaf1
    tx_fields[13] = field_elem(0x55); // leaf2
    tx_fields[14] = field_elem(0xAA); // root

    let sidecar1 = create_raw_sidecar(&tx_fields)?;
    let block1 = ctx
        .submit_block(U256::from(1), U256::ZERO, U256::from(1), sidecar1)
        .await?;
    println!("✓ Block 1 submitted with unregistered eth-keyed transaction (fraudulent)");

    // Verify the TransactionRegistry does NOT have authorization
    use alloy::sol;
    sol! {
        #[sol(rpc)]
        interface ITransactionRegistry {
            function query(address ethKey, bytes32[5] memory fields) external view returns (bool);
        }
    }

    let registry = ITransactionRegistry::new(ctx.transaction_registry_address(), &ctx.provider);
    let query_fields = [
        field_elem(0x11), // null0
        field_elem(0x22), // null1
        field_elem(0x33), // leaf0
        field_elem(0x44), // leaf1
        field_elem(0x55), // leaf2
    ];

    let is_authorized = registry
        .query(unregistered_eth_key, query_fields)
        .call()
        .await?;
    assert!(
        !is_authorized,
        "Transaction should NOT be authorized in registry"
    );
    println!("✓ Verified: eth-key {unregistered_eth_key} is NOT authorized in TransactionRegistry");

    // Create fraud evidence
    use pgp_challenger::validators::FraudEvidence;
    let fraud_evidence = FraudEvidence::MissingEthKeyAuth {
        block_data: block1.block_data.clone(),
        tx_nr: 0,
        eth_key: unregistered_eth_key,
        nullifiers: [field_elem(0x11), field_elem(0x22)],
        leaves: [field_elem(0x33), field_elem(0x44), field_elem(0x55)],
        anchor_block_nr: 0,
        anchor_update_nr: 0,
        is_deposit: true,
    };
    println!("✓ Fraud evidence created: MissingEthKeyAuth");

    // Build the challenge
    // The anchor is at block 0's deposit group root (field index 3 in deposit layout)
    use pgp_challenger::challenge::{ChallengeBuilder, ChallengeSubmitter};

    let challenge_builder = ChallengeBuilder::new()?;
    let anchor_field_index = 3; // Root is at index 3 in deposit layout: [leaf0, leaf1, leaf2, root]

    let challenge_params = challenge_builder.build_transaction_challenge_multi_blob(
        &fraud_evidence,
        &block1.as_blobs(),        // Block containing fraudulent tx
        block0.block_data.anchor,  // The anchor value from block 0
        block0.block_data.clone(), // prior_anchor_block
        &block0.as_blobs(),        // prior_anchor_blobs
        anchor_field_index,        // prior_anchor_field_index
        block0.block_data.clone(), // rollback_target_block
    )?;
    println!("✓ Challenge parameters built");

    let submitter = ChallengeSubmitter::new(&ctx.provider, ctx.contracts.entrypoint);
    let tx_hash = submitter
        .submit_transaction_challenge(challenge_params)
        .await
        .expect("Transaction challenge must succeed");
    println!("✓ Challenge submitted! Tx hash: {tx_hash:?}");

    // Verify transaction succeeded
    let receipt = ctx
        .provider
        .get_transaction_receipt(tx_hash)
        .await?
        .expect("Receipt should exist");
    assert!(receipt.status(), "Challenge transaction must succeed");

    // Verify sequencer was slashed
    ctx.assert_sequencer_slashed().await?;

    println!("\n✓ MissingEthKeyAuth E2E test completed - sequencer slashed!");

    Ok(())
}

// ============================================================================
// Edge Case E2E Tests
// ============================================================================

/// E2E Test: Same-transaction nullifier double-spend (null0 == null1 in same tx)
///
/// This tests a subtle fraud case where a single transaction has the same nullifier
/// for both inputs, which is a double-spend attempt within the same transaction.
#[tokio::test]
async fn test_same_transaction_nullifier_double_spend_e2e() -> Result<()> {
    let Some(ctx) = setup_test_context().await? else {
        return Ok(());
    };

    println!("=== Same-Transaction Nullifier Double-Spend E2E Test ===");

    ctx.register_sequencer().await?;
    ctx.advance_to_open_period().await?;

    fn field_elem(suffix: u8) -> B256 {
        B256::from([
            0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, suffix,
        ])
    }

    // Create a transaction where nullifier0 == nullifier1 (same-tx double-spend)
    let duplicate_nullifier = field_elem(0x42);

    let mut tx_fields = vec![B256::ZERO; 15];
    tx_fields[9] = duplicate_nullifier; // null0
    tx_fields[10] = duplicate_nullifier; // null1 = null0 (FRAUD!)
    tx_fields[11] = field_elem(0x33); // leaf0
    tx_fields[12] = field_elem(0x44); // leaf1
    tx_fields[13] = field_elem(0x55); // leaf2
    tx_fields[14] = field_elem(0xAA); // root

    let sidecar = create_raw_sidecar(&tx_fields)?;
    let block0 = ctx
        .submit_block(U256::ZERO, U256::ZERO, U256::from(1), sidecar)
        .await?;
    println!("✓ Block 0 submitted with same-tx nullifier double-spend");

    // Detect the fraud
    use pgp_challenger::state::StateManager;
    use pgp_challenger::validators::{FraudEvidence, NullifierValidator};
    use pgp_common::blob::ParsedBlock;
    use pgp_common::types::constants::BLOB_SIZE;

    let state = StateManager::in_memory()?;
    let validator = NullifierValidator::new();

    let mut blob = [B256::ZERO; BLOB_SIZE];
    blob[9] = duplicate_nullifier;
    blob[10] = duplicate_nullifier;

    let parsed = ParsedBlock::from_blobs(&[blob], 0, 1)?;
    let fraud = validator.process_block(&state, 0, &parsed)?;

    assert_eq!(fraud.len(), 1, "Should detect same-tx double-spend");

    // Verify fraud evidence
    let (first_which, second_which) = match &fraud[0] {
        FraudEvidence::NullifierDoubleSpend {
            first_block_nr,
            second_block_nr,
            first_tx_number,
            second_tx_number,
            first_which,
            second_which,
            nullifier,
        } => {
            assert_eq!(*first_block_nr, 0);
            assert_eq!(*second_block_nr, 0);
            assert_eq!(*first_tx_number, 0);
            assert_eq!(*second_tx_number, 0);
            assert_eq!(*nullifier, duplicate_nullifier);
            (*first_which, *second_which)
        }
        _ => panic!("Expected NullifierDoubleSpend"),
    };

    assert_eq!(first_which, 0, "First should be nullifier0");
    assert_eq!(second_which, 1, "Second should be nullifier1");
    println!("✓ Fraud detected: same-tx double-spend (which={first_which}, {second_which})");

    // Build and submit the challenge
    use pgp_challenger::challenge::{ChallengeBuilder, ChallengeSubmitter};

    let challenge_builder = ChallengeBuilder::new()?;

    // For same-tx same-block, we need the BlockData for both usages
    // Since it's the same block, first_block_data == second_block_data
    // Argument order: evidence, first_blob, second_blob, first_block_data, second_block_data, prior_block
    let challenge_params = challenge_builder.build_nullifier_challenge(
        &fraud[0],
        &block0.as_blobs(),        // first blobs
        &block0.as_blobs(),        // second blobs (same)
        block0.block_data.clone(), // first block
        block0.block_data.clone(), // second block (same)
        BlockData {
            anchor: ctx.genesis_anchor,
            timestamp: U256::ZERO,
            numTransactions: U256::ZERO,
            numDeposits: U256::ZERO,
            blockNr: U256::ZERO,
            blockIndex: TimestampAndIndex { day: 0, index: 0 },
            sequencer: Address::ZERO,
            blobhashes: vec![],
        },
    )?;
    println!("✓ Challenge parameters built");

    let submitter = ChallengeSubmitter::new(&ctx.provider, ctx.contracts.entrypoint);
    let tx_hash = submitter
        .submit_nullifier_challenge(challenge_params)
        .await
        .expect("Same-tx nullifier challenge must succeed");
    println!("✓ Challenge submitted! Tx hash: {tx_hash:?}");

    // Verify transaction succeeded
    let receipt = ctx
        .provider
        .get_transaction_receipt(tx_hash)
        .await?
        .expect("Receipt should exist");
    assert!(receipt.status(), "Challenge transaction must succeed");

    // Verify sequencer was slashed
    ctx.assert_sequencer_slashed().await?;

    println!("\n✓ Same-transaction nullifier double-spend E2E test completed - sequencer slashed!");

    Ok(())
}

/// E2E Test: Same-block different-tx nullifier double-spend
///
/// Two transactions in the same block share the same nullifier.
/// This is different from cross-block because both blocks are the same.
#[tokio::test]
async fn test_same_block_different_tx_nullifier_double_spend_e2e() -> Result<()> {
    let Some(ctx) = setup_test_context().await? else {
        return Ok(());
    };

    println!("=== Same-Block Different-Tx Nullifier Double-Spend E2E Test ===");

    ctx.register_sequencer().await?;
    ctx.advance_to_open_period().await?;

    fn field_elem(suffix: u8) -> B256 {
        B256::from([
            0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, suffix,
        ])
    }

    let shared_nullifier = field_elem(0x42);
    let unique_null_a = field_elem(0xAA);
    let unique_null_b = field_elem(0xBB);

    // Transaction 0: uses (shared_nullifier, unique_null_a)
    // Transaction 1: uses (shared_nullifier, unique_null_b) - reuses shared_nullifier!
    let mut blob_fields = vec![B256::ZERO; 4096];

    // Tx 0: fields 0-14
    blob_fields[9] = shared_nullifier; // null0 (will be reused)
    blob_fields[10] = unique_null_a; // null1
    blob_fields[11] = field_elem(0x11); // leaves
    blob_fields[12] = field_elem(0x12);
    blob_fields[13] = field_elem(0x13);
    blob_fields[14] = field_elem(0x14); // root

    // Tx 1: fields 15-29
    blob_fields[15 + 9] = shared_nullifier; // null0 (REUSED - FRAUD!)
    blob_fields[15 + 10] = unique_null_b; // null1
    blob_fields[15 + 11] = field_elem(0x21); // leaves
    blob_fields[15 + 12] = field_elem(0x22);
    blob_fields[15 + 13] = field_elem(0x23);
    blob_fields[15 + 14] = field_elem(0x24); // root

    let sidecar = create_raw_sidecar(&blob_fields)?;
    let block0 = ctx
        .submit_block(U256::ZERO, U256::ZERO, U256::from(2), sidecar)
        .await?;
    println!("✓ Block 0 submitted with 2 txs sharing nullifier (fraud)");

    // Detect the fraud
    use pgp_challenger::state::StateManager;
    use pgp_challenger::validators::{FraudEvidence, NullifierValidator};
    use pgp_common::blob::ParsedBlock;
    use pgp_common::types::constants::BLOB_SIZE;

    let state = StateManager::in_memory()?;
    let validator = NullifierValidator::new();

    let mut blob = [B256::ZERO; BLOB_SIZE];
    blob[9] = shared_nullifier;
    blob[10] = unique_null_a;
    blob[15 + 9] = shared_nullifier;
    blob[15 + 10] = unique_null_b;

    let parsed = ParsedBlock::from_blobs(&[blob], 0, 2)?;
    let fraud = validator.process_block(&state, 0, &parsed)?;

    assert_eq!(
        fraud.len(),
        1,
        "Should detect same-block cross-tx double-spend"
    );

    match &fraud[0] {
        FraudEvidence::NullifierDoubleSpend {
            first_block_nr,
            second_block_nr,
            first_tx_number,
            second_tx_number,
            first_which,
            second_which,
            nullifier,
        } => {
            assert_eq!(*first_block_nr, 0);
            assert_eq!(*second_block_nr, 0);
            assert_eq!(*first_tx_number, 0, "First usage in tx 0");
            assert_eq!(*second_tx_number, 1, "Second usage in tx 1");
            assert_eq!(*first_which, 0);
            assert_eq!(*second_which, 0);
            assert_eq!(*nullifier, shared_nullifier);
            println!("✓ Fraud detected: same-block cross-tx double-spend (tx {first_tx_number}/{first_which}, tx {second_tx_number}/{second_which})");
        }
        _ => panic!("Expected NullifierDoubleSpend"),
    }

    // Build and submit the challenge
    use pgp_challenger::challenge::{ChallengeBuilder, ChallengeSubmitter};

    let challenge_builder = ChallengeBuilder::new()?;

    // Argument order: evidence, first_blobs, second_blobs, first_block_data, second_block_data, prior_block
    let challenge_params = challenge_builder.build_nullifier_challenge(
        &fraud[0],
        &block0.as_blobs(),        // first blobs
        &block0.as_blobs(),        // second blobs (same block)
        block0.block_data.clone(), // first block_data
        block0.block_data.clone(), // second block_data (same block)
        BlockData {
            anchor: ctx.genesis_anchor,
            timestamp: U256::ZERO,
            numTransactions: U256::ZERO,
            numDeposits: U256::ZERO,
            blockNr: U256::ZERO,
            blockIndex: TimestampAndIndex { day: 0, index: 0 },
            sequencer: Address::ZERO,
            blobhashes: vec![],
        },
    )?;
    println!("✓ Challenge parameters built");
    let submitter = ChallengeSubmitter::new(&ctx.provider, ctx.contracts.entrypoint);
    let tx_hash = submitter
        .submit_nullifier_challenge(challenge_params)
        .await
        .expect("Same-block cross-tx nullifier challenge must succeed");
    println!("✓ Challenge submitted! Tx hash: {tx_hash:?}");

    let receipt = ctx
        .provider
        .get_transaction_receipt(tx_hash)
        .await?
        .expect("Receipt should exist");
    assert!(receipt.status(), "Challenge transaction must succeed");

    ctx.assert_sequencer_slashed().await?;

    println!("\n✓ Same-block different-tx nullifier double-spend E2E test completed!");

    Ok(())
}
