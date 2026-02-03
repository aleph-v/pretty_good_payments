//! Deposit command - deposit from L1 to L2.
//!
//! This command handles deposits from L1 to L2:
//! 1. For ERC20 tokens: Approves the entrypoint contract to spend tokens
//! 2. Calls the deposit function on the Entrypoint contract
//! 3. The deposit will be included in a future L2 block by the sequencer
//!
//! The deposit creates a leaf with:
//! - asset: the ERC20 token address
//! - amount: the deposit amount
//! - blinding: a constant value (set by the contract)
//! - publicKey: your L2 wallet public key

use crate::commands::util::{parse_address, parse_amount};
use crate::config::ClientConfig;
use crate::wallet::Wallet;
use alloy::network::EthereumWallet;
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolEvent;
use eyre::{Result, WrapErr};
use pgp_common::contracts::{Entrypoint, FakeERC20, Leaf};
use std::str::FromStr;
use tracing::info;

/// Run the deposit command.
pub async fn run(config: &ClientConfig, amount: &str, asset_str: Option<&str>) -> Result<()> {
    // Load wallet
    let wallet = Wallet::load(&config.wallet_path).wrap_err_with(|| {
        format!(
            "Failed to load wallet from {}",
            config.wallet_path.display()
        )
    })?;

    // Parse amount
    let amount = parse_amount(amount)?;

    // Parse asset (default to native token - but deposits require ERC20)
    let asset = if let Some(asset_str) = asset_str {
        parse_address(asset_str)?
    } else {
        eyre::bail!("Deposits require an ERC20 token address. Use --asset <address>");
    };

    // Check RPC URL
    let rpc_url = config.rpc_url.as_ref().ok_or_else(|| {
        eyre::eyre!("Ethereum RPC URL required for deposits. Set --rpc or ETH_RPC_URL")
    })?;

    // Check private key
    let eth_private_key = config.eth_private_key.as_ref().ok_or_else(|| {
        eyre::eyre!("Ethereum private key required for deposits. Set --eth-key or ETH_PRIVATE_KEY")
    })?;

    // Check entrypoint address
    let entrypoint_address = config.entrypoint_address.ok_or_else(|| {
        eyre::eyre!("Entrypoint contract address required. Set --entrypoint or PGP_ENTRYPOINT")
    })?;

    println!("Deposit");
    println!("=======");
    println!(
        "To: 0x{} (your L2 wallet)",
        hex::encode(wallet.public_key())
    );
    println!("Amount: {}", amount);
    println!("Asset: 0x{}", hex::encode(asset));
    println!("L1 RPC: {}", rpc_url);
    println!("Entrypoint: 0x{}", hex::encode(entrypoint_address));
    println!();

    // Create signer from private key
    let signer = PrivateKeySigner::from_str(eth_private_key)
        .map_err(|e| eyre::eyre!("Invalid private key: {}", e))?;
    let l1_address = signer.address();
    println!("L1 wallet: 0x{}", hex::encode(l1_address));

    // Create provider with wallet
    let eth_wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .wallet(eth_wallet)
        .connect_http(rpc_url.parse().wrap_err("Invalid RPC URL")?);

    // Get token contract
    let token = FakeERC20::new(asset, &provider);

    // Check token balance
    println!("Checking token balance...");
    let balance = token
        .balanceOf(l1_address)
        .call()
        .await
        .wrap_err("Failed to get token balance")?;
    println!("Token balance: {}", balance);

    if balance < amount {
        eyre::bail!(
            "Insufficient token balance: have {}, need {}",
            balance,
            amount
        );
    }

    // Step 1: Approve the entrypoint to spend tokens
    println!();
    println!("Step 1: Approving entrypoint to spend tokens...");
    let approve_tx = token
        .approve(entrypoint_address, amount)
        .send()
        .await
        .wrap_err("Failed to send approve transaction")?;

    let approve_receipt = approve_tx
        .get_receipt()
        .await
        .wrap_err("Failed to get approve receipt")?;

    if !approve_receipt.status() {
        eyre::bail!("Approve transaction failed");
    }
    println!(
        "Approval confirmed: 0x{}",
        hex::encode(approve_receipt.transaction_hash)
    );

    // Step 2: Call deposit on the entrypoint
    println!();
    println!("Step 2: Calling deposit...");

    // Build the leaf - blinding will be overwritten by contract with BLINDING constant
    let leaf = Leaf {
        asset,
        amount,
        blinding: alloy_primitives::B256::ZERO, // Will be set to BLINDING constant by contract
        publicKey: wallet.public_key(),
    };

    let entrypoint = Entrypoint::new(entrypoint_address, &provider);
    let deposit_tx = entrypoint
        .deposit(leaf)
        .send()
        .await
        .wrap_err("Failed to send deposit transaction")?;

    let deposit_receipt = deposit_tx
        .get_receipt()
        .await
        .wrap_err("Failed to get deposit receipt")?;

    if !deposit_receipt.status() {
        eyre::bail!("Deposit transaction failed");
    }

    // Parse deposit event
    let deposit_logs: Vec<_> = deposit_receipt
        .inner
        .logs()
        .iter()
        .filter(|log| log.topic0() == Some(&Entrypoint::Deposit::SIGNATURE_HASH))
        .collect();

    if let Some(log) = deposit_logs.first() {
        if let Ok(decoded) = log.log_decode::<Entrypoint::Deposit>() {
            let event = decoded.inner.data;
            println!();
            println!("Deposit successful!");
            println!("==================");
            println!(
                "Transaction: 0x{}",
                hex::encode(deposit_receipt.transaction_hash)
            );
            println!("Leaf hash: 0x{}", hex::encode(event.leafHash));
            println!("Target L2 block: {}", event.block);
            println!("Deposit index: {}", event.number);
            println!();
            println!("Your deposit will be included in L2 block {}.", event.block);
            println!("Run 'pgp-client sync' after that block is confirmed to see your balance.");

            info!(
                "Deposit: {} tokens to L2 wallet 0x{} (block {})",
                amount,
                hex::encode(wallet.public_key()),
                event.block
            );
        }
    } else {
        println!();
        println!(
            "Deposit transaction confirmed: 0x{}",
            hex::encode(deposit_receipt.transaction_hash)
        );
        println!("(Could not parse deposit event)");
    }

    Ok(())
}
