//! Withdraw command - withdraw from L2 to L1.

use crate::config::ClientConfig;
use crate::wallet::Wallet;
use alloy_primitives::{Address, U256};
use eyre::{Result, WrapErr};

/// Run the withdraw command.
pub async fn run(
    config: &ClientConfig,
    to: &str,
    amount: &str,
    asset_str: Option<&str>,
) -> Result<()> {
    // Load wallet
    let wallet = Wallet::load(&config.wallet_path)
        .wrap_err_with(|| format!("Failed to load wallet from {}", config.wallet_path.display()))?;

    // Parse L1 recipient address
    let recipient = parse_address(to)?;

    // Parse amount
    let amount = parse_amount(amount)?;

    // Parse asset (default to native token)
    let asset = if let Some(asset_str) = asset_str {
        parse_address(asset_str)?
    } else {
        Address::ZERO
    };

    println!("Withdraw");
    println!("========");
    println!("From: {} (L2)", hex::encode(wallet.public_key()));
    println!("To: 0x{} (L1)", hex::encode(recipient));
    println!("Amount: {}", amount);
    println!(
        "Asset: {}",
        if asset == Address::ZERO {
            "Native".to_string()
        } else {
            format!("0x{}", hex::encode(asset))
        }
    );
    println!();

    // Check balance
    let balance = wallet.balance(Some(asset));
    if balance < amount {
        eyre::bail!(
            "Insufficient balance: have {}, need {}",
            balance,
            amount
        );
    }

    // Select notes for spending
    let (selected_notes, change) = wallet
        .select_notes_for_amount(asset, amount)
        .ok_or_else(|| eyre::eyre!("Failed to select notes for amount"))?;

    println!("Selected {} notes for withdrawal", selected_notes.len());
    println!("Change: {}", change);
    println!();

    // TODO: Implement withdrawal
    // This requires:
    // 1. Fetching merkle proofs for selected notes
    // 2. Building the ZK witness with withdrawal output (public_key = 0)
    // 3. Generating the Groth16 proof
    // 4. Submitting to the sequencer
    // 5. Waiting for L2 confirmation and L1 finalization

    println!("Withdrawal not yet implemented");
    println!();
    println!("This feature requires:");
    println!("  - Merkle proof sync (run 'pgp-client sync' first)");
    println!("  - ZK proof generation with withdrawal flag");
    println!("  - Transaction submission to sequencer");

    Ok(())
}

fn parse_amount(s: &str) -> Result<U256> {
    if let Ok(n) = s.parse::<u128>() {
        return Ok(U256::from(n));
    }
    if s.starts_with("0x") {
        let bytes = hex::decode(&s[2..])
            .wrap_err("Invalid hex amount")?;
        return Ok(U256::from_be_slice(&bytes));
    }
    eyre::bail!("Invalid amount format: {}", s)
}

fn parse_address(s: &str) -> Result<Address> {
    let bytes = hex::decode(s.trim_start_matches("0x"))
        .wrap_err("Invalid address format")?;
    if bytes.len() != 20 {
        eyre::bail!("Address must be 20 bytes");
    }
    Ok(Address::from_slice(&bytes))
}
