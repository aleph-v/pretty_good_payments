//! Withdraw execute command - execute pending L1 withdrawals.
//!
//! This is Stage 2 of the withdrawal process:
//! 1. Find pending withdrawals that have been included in L2 blocks
//! 2. Fetch KZG proofs from the sequencer
//! 3. Submit the proofs to the L1 Withdraw contract
//! 4. Funds are released to the recipient

use crate::api::SequencerClient;
use crate::commands::util::{address_to_b256, parse_address};
use crate::config::ClientConfig;
use crate::wallet::PendingWithdrawals;
use alloy::network::EthereumWallet;
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::{Address, B256, U256};
use eyre::{Result, WrapErr};
use pgp_common::contracts::{BlockData, Leaf, TimestampAndIndex, Withdraw};
use std::str::FromStr;
use tracing::info;

/// Run the withdraw-execute command.
///
/// This performs Stage 2 of the withdrawal: submitting KZG proofs to L1.
pub async fn run(config: &ClientConfig, index: Option<usize>) -> Result<()> {
    // Check RPC URL
    let rpc_url = config.rpc_url.as_ref().ok_or_else(|| {
        eyre::eyre!("Ethereum RPC URL required for withdrawals. Set --rpc or ETH_RPC_URL")
    })?;

    // Check private key
    let eth_private_key = config.eth_private_key.as_ref().ok_or_else(|| {
        eyre::eyre!(
            "Ethereum private key required for withdrawals. Set --eth-key or ETH_PRIVATE_KEY"
        )
    })?;

    // Check withdraw contract address
    let withdraw_address = config.withdraw_address.ok_or_else(|| {
        eyre::eyre!("Withdraw contract address required. Set --withdraw or PGP_WITHDRAW")
    })?;

    // Load pending withdrawals
    let pending_path = config.pending_withdrawals_path();
    let mut pending_withdrawals =
        PendingWithdrawals::load(&pending_path).wrap_err("Failed to load pending withdrawals")?;

    let unexecuted: Vec<_> = pending_withdrawals
        .unexecuted()
        .into_iter()
        .cloned()
        .collect();

    if unexecuted.is_empty() {
        println!("No pending withdrawals to execute.");
        println!("Use 'pgp-client withdraw' first to create an L2 withdrawal transaction.");
        return Ok(());
    }

    println!("Withdraw Execute (Stage 2: L1 Claim)");
    println!("====================================");
    println!("Pending withdrawals: {}", unexecuted.len());
    println!();

    // List pending withdrawals
    for (i, w) in unexecuted.iter().enumerate() {
        let asset_str = if w.asset == Address::ZERO {
            "Native".to_string()
        } else {
            format!("0x{}", hex::encode(w.asset))
        };
        let status = if w.block_nr == 0 {
            "Waiting for block inclusion".to_string()
        } else {
            format!(
                "Block {}, tx {}, output {}",
                w.block_nr, w.tx_nr, w.output_index
            )
        };
        println!(
            "  [{}] {} {} to 0x{} ({})",
            i,
            w.amount,
            asset_str,
            hex::encode(w.recipient),
            status
        );
    }
    println!();

    // Determine which withdrawal to execute
    let withdrawal_index = if let Some(idx) = index {
        if idx >= unexecuted.len() {
            eyre::bail!(
                "Invalid withdrawal index: {} (have {} pending)",
                idx,
                unexecuted.len()
            );
        }
        idx
    } else if unexecuted.len() == 1 {
        0
    } else {
        println!("Multiple pending withdrawals. Specify which to execute with --index <n>");
        return Ok(());
    };

    let withdrawal = &unexecuted[withdrawal_index];
    println!("Executing withdrawal [{}]:", withdrawal_index);
    println!("  Amount: {}", withdrawal.amount);
    println!(
        "  Asset: {}",
        if withdrawal.asset == Address::ZERO {
            "Native".to_string()
        } else {
            format!("0x{}", hex::encode(withdrawal.asset))
        }
    );
    println!("  Recipient: 0x{}", hex::encode(withdrawal.recipient));
    println!(
        "  Leaf commitment: 0x{}",
        hex::encode(withdrawal.leaf_commitment)
    );
    println!();

    // Check if we know the block number
    if withdrawal.block_nr == 0 {
        println!("This withdrawal hasn't been included in an L2 block yet.");
        println!("Please wait for block inclusion, then run 'pgp-client sync' to update.");
        println!();
        println!("You can also try to find it by searching for the leaf commitment.");
        return find_withdrawal_block(config, withdrawal.leaf_commitment).await;
    }

    // Create sequencer client
    let client = SequencerClient::new(&config.sequencer_url);

    // Get withdrawal proof from sequencer
    println!("Fetching KZG proof from sequencer...");
    let proof_response = client
        .get_withdrawal_proof(withdrawal.leaf_commitment, withdrawal.block_nr)
        .await
        .wrap_err("Failed to get withdrawal proof from sequencer")?;

    if !proof_response.found {
        eyre::bail!("Withdrawal proof not found: {}", proof_response.message);
    }

    let block_data_resp = proof_response
        .block_data
        .ok_or_else(|| eyre::eyre!("Withdrawal proof response missing block data"))?;
    let tx_nr = proof_response
        .tx_nr
        .ok_or_else(|| eyre::eyre!("Withdrawal proof response missing tx_nr"))?;
    let which = proof_response
        .which
        .ok_or_else(|| eyre::eyre!("Withdrawal proof response missing which"))?;
    let commitment_hex = proof_response
        .commitment
        .ok_or_else(|| eyre::eyre!("Withdrawal proof response missing commitment"))?;
    let proof_hex = proof_response
        .proof
        .ok_or_else(|| eyre::eyre!("Withdrawal proof response missing proof"))?;

    println!("  Block: {}", block_data_resp.block_nr);
    println!("  Transaction: {}", tx_nr);
    println!("  Output: {}", which);
    println!("  Commitment: {}", commitment_hex);
    println!("  Proof: {}", proof_hex);
    println!();

    // Convert hex strings to bytes
    let commitment_bytes =
        hex::decode(commitment_hex.trim_start_matches("0x")).wrap_err("Invalid commitment hex")?;
    let proof_bytes =
        hex::decode(proof_hex.trim_start_matches("0x")).wrap_err("Invalid proof hex")?;

    // Parse sequencer address
    let sequencer_addr = parse_address(&block_data_resp.sequencer)?;

    // Build BlockData struct for contract call
    let block_data = BlockData {
        anchor: block_data_resp.anchor,
        timestamp: U256::from_str(&block_data_resp.timestamp).wrap_err("Invalid timestamp")?,
        numTransactions: U256::from(block_data_resp.num_transactions),
        numDeposits: U256::from(block_data_resp.num_deposits),
        blockNr: U256::from(block_data_resp.block_nr),
        blockIndex: TimestampAndIndex {
            day: block_data_resp.day as u128,
            index: block_data_resp.block_in_day as u128,
        },
        sequencer: sequencer_addr,
        blobhashes: block_data_resp.blobhashes,
    };

    // Build Leaf struct for contract call
    // For withdrawals: publicKey=0, blinding=recipient address
    let leaf = Leaf {
        asset: withdrawal.asset,
        amount: withdrawal.amount,
        blinding: address_to_b256(withdrawal.recipient),
        publicKey: B256::ZERO,
    };

    // Create signer from private key
    let signer = PrivateKeySigner::from_str(eth_private_key)
        .map_err(|e| eyre::eyre!("Invalid private key: {}", e))?;
    let l1_address = signer.address();
    println!("L1 wallet: 0x{}", hex::encode(l1_address));
    println!("Withdraw contract: 0x{}", hex::encode(withdraw_address));
    println!();

    // Create provider with wallet
    let eth_wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .wallet(eth_wallet)
        .connect_http(rpc_url.parse().wrap_err("Invalid RPC URL")?);

    // Get Withdraw contract instance
    let withdraw_contract = Withdraw::new(withdraw_address, &provider);

    // Check if already withdrawn
    let key = (tx_nr << 2) + (which as u64);
    let already_withdrawn = withdraw_contract
        .withdrawn(U256::from(block_data_resp.block_nr), U256::from(key))
        .call()
        .await
        .wrap_err("Failed to check withdrawal status")?;

    if already_withdrawn {
        println!("This withdrawal has already been executed on L1!");
        // Mark as executed in our local state
        pending_withdrawals.mark_executed(
            withdrawal.block_nr,
            withdrawal.tx_nr,
            withdrawal.output_index,
            B256::ZERO, // We don't know the tx hash
        );
        pending_withdrawals.save(&pending_path)?;
        return Ok(());
    }

    // Call withdraw function
    println!("Submitting withdrawal to L1...");
    let withdraw_tx = withdraw_contract
        .withdraw(
            leaf,
            block_data,
            U256::from(tx_nr),
            U256::from(which),
            commitment_bytes.into(),
            proof_bytes.into(),
        )
        .send()
        .await
        .wrap_err("Failed to send withdraw transaction")?;

    let withdraw_receipt = withdraw_tx
        .get_receipt()
        .await
        .wrap_err("Failed to get withdraw receipt")?;

    if !withdraw_receipt.status() {
        eyre::bail!("Withdraw transaction failed");
    }

    let tx_hash = withdraw_receipt.transaction_hash;
    println!();
    println!("Withdrawal successful!");
    println!("======================");
    println!("Transaction: 0x{}", hex::encode(tx_hash));
    println!(
        "Amount: {} sent to 0x{}",
        withdrawal.amount,
        hex::encode(withdrawal.recipient)
    );

    // Mark withdrawal as executed
    pending_withdrawals.mark_executed(
        withdrawal.block_nr,
        withdrawal.tx_nr,
        withdrawal.output_index,
        tx_hash,
    );
    pending_withdrawals.save(&pending_path)?;

    info!(
        "Withdrawal executed: {} to 0x{} (tx 0x{})",
        withdrawal.amount,
        hex::encode(withdrawal.recipient),
        hex::encode(tx_hash)
    );

    Ok(())
}

/// Try to find which block contains the withdrawal leaf.
async fn find_withdrawal_block(config: &ClientConfig, leaf_commitment: B256) -> Result<()> {
    let client = SequencerClient::new(&config.sequencer_url);

    println!("Searching for withdrawal in recent blocks...");

    // Get current sync status
    let status = client
        .get_sync_status()
        .await
        .wrap_err("Failed to get sync status")?;

    // Search recent blocks (last 10)
    let start_block = status.latest_block_nr.saturating_sub(10);
    for block_nr in start_block..=status.latest_block_nr {
        let result = client.get_withdrawal_proof(leaf_commitment, block_nr).await;
        if let Ok(response) = result {
            if response.found {
                println!("Found withdrawal in block {}!", block_nr);
                println!("  Transaction: {}", response.tx_nr.unwrap_or(0));
                println!("  Output: {}", response.which.unwrap_or(0));
                println!();
                println!("Update your pending withdrawal with this block info and try again.");
                return Ok(());
            }
        }
    }

    println!(
        "Withdrawal not found in recent blocks ({} to {}).",
        start_block, status.latest_block_nr
    );
    println!("The transaction may not have been included yet. Try again later.");

    Ok(())
}

/// List all pending withdrawals.
pub async fn list(config: &ClientConfig) -> Result<()> {
    let pending_path = config.pending_withdrawals_path();
    let pending_withdrawals =
        PendingWithdrawals::load(&pending_path).wrap_err("Failed to load pending withdrawals")?;

    println!("Pending Withdrawals");
    println!("===================");

    if pending_withdrawals.withdrawals.is_empty() {
        println!("No pending withdrawals.");
        return Ok(());
    }

    for (i, w) in pending_withdrawals.withdrawals.iter().enumerate() {
        let asset_str = if w.asset == Address::ZERO {
            "Native".to_string()
        } else {
            format!("0x{}", hex::encode(w.asset))
        };

        let status = if w.executed {
            format!(
                "Executed (tx: 0x{})",
                hex::encode(w.execution_tx.unwrap_or_default())
            )
        } else if w.block_nr == 0 {
            "Waiting for block inclusion".to_string()
        } else {
            format!(
                "Ready (block {}, tx {}, output {})",
                w.block_nr, w.tx_nr, w.output_index
            )
        };

        println!(
            "[{}] {} {} to 0x{}\n    Status: {}",
            i,
            w.amount,
            asset_str,
            hex::encode(w.recipient),
            status
        );
    }

    let pending = pending_withdrawals.pending_count();
    let total = pending_withdrawals.withdrawals.len();
    println!();
    println!(
        "Total: {} ({} pending, {} executed)",
        total,
        pending,
        total - pending
    );

    Ok(())
}

/// Update a pending withdrawal with block info found manually.
pub async fn update(
    config: &ClientConfig,
    index: usize,
    block_nr: u64,
    tx_nr: u64,
    output_index: u8,
) -> Result<()> {
    let pending_path = config.pending_withdrawals_path();
    let mut pending_withdrawals =
        PendingWithdrawals::load(&pending_path).wrap_err("Failed to load pending withdrawals")?;

    if index >= pending_withdrawals.withdrawals.len() {
        eyre::bail!("Invalid withdrawal index: {}", index);
    }

    let w = &mut pending_withdrawals.withdrawals[index];
    if w.executed {
        eyre::bail!("Withdrawal {} is already executed", index);
    }

    w.block_nr = block_nr;
    w.tx_nr = tx_nr;
    w.output_index = output_index;

    pending_withdrawals.save(&pending_path)?;

    println!("Updated withdrawal [{}]:", index);
    println!("  Block: {}", block_nr);
    println!("  Transaction: {}", tx_nr);
    println!("  Output: {}", output_index);

    Ok(())
}
