//! Transfer command - send tokens on L2.

use crate::config::ClientConfig;
use crate::wallet::Wallet;
use alloy_primitives::{Address, B256, U256};
use eyre::{Result, WrapErr};

/// Run the transfer command.
pub async fn run(
    config: &ClientConfig,
    to: &str,
    amount: &str,
    asset_str: Option<&str>,
) -> Result<()> {
    // Load wallet
    let wallet = Wallet::load(&config.wallet_path)
        .wrap_err_with(|| format!("Failed to load wallet from {}", config.wallet_path.display()))?;

    // Parse recipient public key
    let recipient = parse_public_key(to)?;

    // Parse amount
    let amount = parse_amount(amount)?;

    // Parse asset (default to native token)
    let asset = if let Some(asset_str) = asset_str {
        parse_address(asset_str)?
    } else {
        Address::ZERO
    };

    println!("Transfer");
    println!("========");
    println!("From: {}", hex::encode(wallet.public_key()));
    println!("To: {}", hex::encode(recipient));
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

    println!("Selected {} notes for transfer", selected_notes.len());
    println!("Change: {}", change);
    println!();

    // TODO: Build and submit transaction
    // This requires:
    // 1. Fetching merkle proofs for selected notes
    // 2. Building the ZK witness
    // 3. Generating the Groth16 proof
    // 4. Submitting to the sequencer

    println!("Transfer not yet implemented - would send {} to {}", amount, hex::encode(recipient));
    println!();
    println!("This feature requires:");
    println!("  - Merkle proof sync (run 'pgp-client sync' first)");
    println!("  - ZK proof generation");
    println!("  - Transaction submission to sequencer");

    Ok(())
}

fn parse_public_key(s: &str) -> Result<B256> {
    let bytes = hex::decode(s.trim_start_matches("0x"))
        .wrap_err("Invalid public key format")?;
    if bytes.len() != 32 {
        eyre::bail!("Public key must be 32 bytes");
    }
    Ok(B256::from_slice(&bytes))
}

fn parse_amount(s: &str) -> Result<U256> {
    // Try parsing as decimal
    if let Ok(n) = s.parse::<u128>() {
        return Ok(U256::from(n));
    }

    // Try parsing as hex
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
