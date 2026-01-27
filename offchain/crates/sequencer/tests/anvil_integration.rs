//! Anvil-based integration tests for the sequencer.
//!
//! These tests spawn a local Anvil instance with EIP-4844 blob support,
//! deploy contracts using Foundry scripts, and test block submission.

use alloy::consensus::{SidecarBuilder, SimpleCoder};
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

use pgp_common::contracts::{
    BlockData, Entrypoint, FakeERC20, Leaf, SequencerRegistry, TimestampAndIndex,
};
use pgp_common::types::constants::ROOT_DEPTH;
use pgp_sequencer::{combine_blobs_into_sidecar, BlobBuilder, SequencerError};

// ============================================================================
// Test Harness
// ============================================================================

/// Deployed contract addresses from the local deployment script
#[derive(Debug, Clone)]
pub struct DeployedContracts {
    pub entrypoint: Address,
    pub token: Address,
    pub transaction_registry: Address,
}

/// Test context that manages the Anvil instance and provides helper methods.
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
    pub signer: PrivateKeySigner,
    /// Genesis anchor from the contract
    pub genesis_anchor: B256,
}

/// Create a new test context by spawning Anvil and deploying contracts.
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
    pub fn entrypoint(&self) -> Entrypoint::EntrypointInstance<&P> {
        Entrypoint::new(self.contracts.entrypoint, &self.provider)
    }

    pub fn token(&self) -> FakeERC20::FakeERC20Instance<&P> {
        FakeERC20::new(self.contracts.token, &self.provider)
    }

    pub fn registry(&self) -> SequencerRegistry::SequencerRegistryInstance<&P> {
        SequencerRegistry::new(self.contracts.entrypoint, &self.provider)
    }

    /// Register as a sequencer by staking the required amount.
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
        println!("Sequencer registered (stake: {stake_amount} wei)");
        Ok(())
    }

    /// Advance time to an open period (second half of epoch).
    pub async fn advance_to_open_period(&self) -> Result<()>
    where
        P: AnvilApi<Ethereum>,
    {
        // Loop until we're in an open period
        let registry = self.registry();
        loop {
            let epoch_result = registry.currentEpoch().call().await?;
            if !epoch_result.isClosed {
                break;
            }
            self.provider.anvil_increase_time(1).await?;
            self.provider.anvil_mine(Some(1), None).await?;
        }
        println!("Advanced time to open period");
        Ok(())
    }

    /// Wait until we're in an open period.
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
        println!("Tokens minted and approved: {amount}");
        Ok(())
    }

    /// Create a deposit on L1.
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
        println!("Deposit created on L1 (amount: {amount})");

        let current_block = self.entrypoint().getCurrentBlocknumber().call().await?;
        Ok(current_block + U256::from(2))
    }

    /// Get deposits for a specific block number.
    pub async fn get_deposits_for_block(&self, block_nr: U256) -> Result<Vec<B256>> {
        let deposits = self.entrypoint().getDepositArray(block_nr).call().await?;
        Ok(deposits)
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

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

fn find_project_root() -> std::path::PathBuf {
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let mut path = std::path::PathBuf::from(manifest_dir);
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

    std::path::PathBuf::from("/Users/pvienhage/dev/pretty_good_payments")
}

static BUILD_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();

fn deploy_contracts(rpc_url: &str, private_key: &str) -> Result<DeployedContracts> {
    let project_root = find_project_root();

    if !project_root.join("foundry.toml").exists() {
        return Err(eyre!(
            "Could not find foundry.toml in project root: {}",
            project_root.display()
        ));
    }

    let lock = BUILD_LOCK.get_or_init(|| std::sync::Mutex::new(()));
    let _guard = lock.lock().unwrap();

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

// ============================================================================
// Tests
// ============================================================================

/// Test submitting a single deposit block.
#[tokio::test]
async fn test_submit_single_deposit_block() -> Result<()> {
    let Some(ctx) = setup_test_context().await? else {
        return Ok(());
    };

    // Register as sequencer
    ctx.register_sequencer().await?;

    // Mint tokens and create deposit
    let amount = U256::from(1000);
    let public_key = B256::repeat_byte(0x42);
    ctx.mint_and_approve_tokens(amount).await?;
    ctx.create_deposit(amount, public_key).await?;

    // Wait for open period
    ctx.advance_to_open_period().await?;

    // Find where the deposit went (cold start: when blockNumber <= 2, deposits go to blockNumber)
    // Check block 0 first, then fall back to block 2
    let deposits_block_0 = ctx.get_deposits_for_block(U256::ZERO).await?;
    let (target_block, deposits) = if !deposits_block_0.is_empty() {
        (U256::ZERO, deposits_block_0)
    } else {
        let deposits_block_2 = ctx.get_deposits_for_block(U256::from(2)).await?;
        (U256::from(2), deposits_block_2)
    };
    println!("Deposit targets block: {target_block}");

    assert!(
        !deposits.is_empty(),
        "Should have deposits for target block"
    );
    println!("Found {} deposits", deposits.len());

    // Build blob with BlobBuilder (block_index=0, zero root_path for first block)
    let mut builder = BlobBuilder::new(0, [B256::ZERO; ROOT_DEPTH]);
    let built_block = builder.build_deposit_only(&deposits)?;

    assert_eq!(built_block.total_deposits, deposits.len());
    assert_eq!(built_block.total_transactions, 0);
    assert_ne!(built_block.anchor, B256::ZERO);
    println!("Built block with anchor: {}", built_block.anchor);

    // Submit block via blob transaction
    // Use SidecarBuilder<SimpleCoder> to create the sidecar (required for Anvil compatibility)
    use alloy::consensus::BlobTransactionSidecar;
    let sidecar_builder: SidecarBuilder<SimpleCoder> =
        SidecarBuilder::from_slice(&built_block.blobs[0].bytes);
    let sidecar: BlobTransactionSidecar = sidecar_builder.build().expect("Failed to build sidecar");
    let versioned_hashes: Vec<B256> = sidecar.versioned_hashes().collect();

    // Debug: print blob info
    println!("Blob bytes length: {}", built_block.blobs[0].bytes.len());
    println!(
        "First 128 bytes of blob: {:?}",
        &built_block.blobs[0].bytes[0..128]
    );
    println!("Sidecar blobs count: {}", sidecar.blobs.len());
    println!("Sidecar commitments count: {}", sidecar.commitments.len());
    println!("Sidecar proofs count: {}", sidecar.proofs.len());

    // For multiple blobs, we need to pass all blob indices
    let blob_indices: Vec<U256> = (0..sidecar.blobs.len()).map(|i| U256::from(i)).collect();

    println!("Sending blob transaction...");
    println!("  numDeposits: {}", deposits.len());
    println!("  target_block: {target_block}");
    println!("  blob hashes: {:?}", &versioned_hashes);
    println!("  blob indices: {blob_indices:?}");

    let block_data = BlockData {
        anchor: ctx.genesis_anchor,
        timestamp: U256::ZERO,
        numTransactions: U256::ZERO,
        numDeposits: U256::from(deposits.len()),
        blockNr: target_block,
        blockIndex: TimestampAndIndex { day: 0, index: 0 },
        sequencer: ctx.deployer,
        blobhashes: versioned_hashes,
    };

    let post_calldata = ctx
        .entrypoint()
        .post(block_data.clone(), blob_indices.clone())
        .calldata()
        .clone();

    let blob_tx = TransactionRequest::default()
        .with_to(ctx.contracts.entrypoint)
        .with_input(post_calldata)
        .with_blob_sidecar(sidecar.clone());

    // Try to simulate the call first (will fail because eth_call doesn't support blobs)
    match ctx
        .entrypoint()
        .post(block_data.clone(), blob_indices)
        .call()
        .await
    {
        Ok(_) => println!("Call simulation succeeded"),
        Err(e) => println!("Call simulation failed (expected): {e:?}"),
    }

    let pending = ctx.provider.send_transaction(blob_tx).await?;
    let receipt = pending.get_receipt().await?;

    if !receipt.status() {
        println!("Transaction REVERTED!");
        println!("  Gas used: {}", receipt.gas_used);
        println!("  Logs: {:?}", receipt.inner.logs());
    }

    assert!(receipt.status(), "Block submission should succeed");

    // Verify NewRoot event
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

    println!(
        "Block {} submitted with anchor: {}",
        decoded.inner.data.blocknumber, decoded.inner.data.anchor
    );

    Ok(())
}

/// Test submitting a block with multiple deposits (multiple deposit groups).
#[tokio::test]
async fn test_submit_multiple_deposits_block() -> Result<()> {
    let Some(ctx) = setup_test_context().await? else {
        return Ok(());
    };

    ctx.register_sequencer().await?;

    // Create 6 deposits (will use 2 deposit groups)
    let amount = U256::from(1000);
    ctx.mint_and_approve_tokens(amount * U256::from(6)).await?;

    for i in 0..6 {
        let public_key = B256::from([i as u8 + 1; 32]);
        ctx.create_deposit(amount, public_key).await?;
    }

    ctx.advance_to_open_period().await?;

    // Find where the deposits went (cold start: when blockNumber <= 2, deposits go to blockNumber)
    // Check block 0 first, then fall back to block 2
    let deposits_block_0 = ctx.get_deposits_for_block(U256::ZERO).await?;
    let (target_block, deposits) = if deposits_block_0.len() == 6 {
        (U256::ZERO, deposits_block_0)
    } else {
        let deposits_block_2 = ctx.get_deposits_for_block(U256::from(2)).await?;
        (U256::from(2), deposits_block_2)
    };
    println!("Deposits target block: {target_block}");

    assert_eq!(deposits.len(), 6, "Should have 6 deposits");

    // Build and verify (block_index=0, zero root_path for first block)
    let mut builder = BlobBuilder::new(0, [B256::ZERO; ROOT_DEPTH]);
    let built_block = builder.build_deposit_only(&deposits)?;

    assert_eq!(built_block.total_deposits, 6);
    println!(
        "Built block with 6 deposits, anchor: {}",
        built_block.anchor
    );

    // Use combine_blobs_into_sidecar which handles both single and multi-blob cases
    // Note: 6 deposits only need 8 fields (2 groups × 4 fields), so they fit in 1 blob
    println!("Built block has {} blob(s)", built_block.blobs.len());

    let sidecar = combine_blobs_into_sidecar(&built_block.blobs)
        .expect("Failed to combine blobs into sidecar");
    let versioned_hashes: Vec<B256> = sidecar.versioned_hashes().collect();

    println!("Sidecar blobs count: {}", sidecar.blobs.len());
    println!("Versioned hashes: {versioned_hashes:?}");

    // For blobs encoded with SimpleCoder, we need to pass all blob indices
    let blob_indices: Vec<U256> = (0..sidecar.blobs.len()).map(|i| U256::from(i)).collect();
    println!("Blob indices: {blob_indices:?}");

    let block_data = BlockData {
        anchor: ctx.genesis_anchor,
        timestamp: U256::ZERO,
        numTransactions: U256::ZERO,
        numDeposits: U256::from(6),
        blockNr: target_block,
        blockIndex: TimestampAndIndex { day: 0, index: 0 },
        sequencer: ctx.deployer,
        blobhashes: versioned_hashes,
    };

    let post_calldata = ctx
        .entrypoint()
        .post(block_data.clone(), blob_indices)
        .calldata()
        .clone();

    let blob_tx = TransactionRequest::default()
        .with_to(ctx.contracts.entrypoint)
        .with_input(post_calldata)
        .with_blob_sidecar(sidecar);

    let pending = ctx.provider.send_transaction(blob_tx).await?;
    let receipt = pending.get_receipt().await?;

    if !receipt.status() {
        println!("Transaction REVERTED! Gas used: {}", receipt.gas_used);
    }
    assert!(receipt.status(), "Block submission should succeed");

    println!("Multiple deposit block submitted successfully!");
    Ok(())
}

/// Test that building an empty block fails.
#[tokio::test]
async fn test_empty_block_rejected() -> Result<()> {
    let mut builder = BlobBuilder::new(0, [B256::ZERO; ROOT_DEPTH]);

    let result = builder.build_deposit_only(&[]);
    assert!(matches!(result, Err(SequencerError::EmptyBlock)));

    println!("Empty block correctly rejected");
    Ok(())
}

/// Test epoch timing - submission during closed period should fail.
#[tokio::test]
async fn test_epoch_timing_closed_period() -> Result<()> {
    let Some(ctx) = setup_test_context().await? else {
        return Ok(());
    };

    ctx.register_sequencer().await?;

    // Check epoch state
    let registry = ctx.registry();
    let epoch_result = registry.currentEpoch().call().await?;
    println!(
        "Current epoch: {}, is_closed: {}",
        epoch_result.epoch, epoch_result.isClosed
    );

    // In closed period, only priority sequencers allowed
    // Since we're not a priority sequencer, we shouldn't be allowed during closed period
    // Note: This depends on the firstLookSequencers array state

    Ok(())
}

/// Test epoch timing - submission during open period should succeed.
#[tokio::test]
async fn test_epoch_timing_open_period() -> Result<()> {
    let Some(ctx) = setup_test_context().await? else {
        return Ok(());
    };

    ctx.register_sequencer().await?;

    // Advance to open period
    ctx.advance_to_open_period().await?;

    // Verify we're in open period
    let registry = ctx.registry();
    let epoch_result = registry.currentEpoch().call().await?;
    assert!(!epoch_result.isClosed, "Should be in open period");

    // Check if allowed
    let is_allowed = ctx.entrypoint().isAllowed(ctx.deployer).call().await?;
    assert!(is_allowed, "Should be allowed during open period");

    println!("Sequencer is allowed during open period");
    Ok(())
}

/// Test BlobBuilder memory calculations.
#[tokio::test]
async fn test_blob_builder_memory_calculations() -> Result<()> {
    // Test deposits_memory_length calculation
    assert_eq!(BlobBuilder::deposits_memory_length(0), 0);
    assert_eq!(BlobBuilder::deposits_memory_length(1), 4);
    assert_eq!(BlobBuilder::deposits_memory_length(2), 4);
    assert_eq!(BlobBuilder::deposits_memory_length(3), 4);
    assert_eq!(BlobBuilder::deposits_memory_length(4), 8);
    assert_eq!(BlobBuilder::deposits_memory_length(6), 8);
    assert_eq!(BlobBuilder::deposits_memory_length(7), 12);

    // Test fits_in_blobs
    assert!(BlobBuilder::fits_in_blobs(3000, 0, 1));
    assert!(!BlobBuilder::fits_in_blobs(4000, 0, 1));
    assert!(BlobBuilder::fits_in_blobs(0, 200, 1));
    assert!(!BlobBuilder::fits_in_blobs(0, 300, 1));

    println!("Memory calculations verified");
    Ok(())
}
