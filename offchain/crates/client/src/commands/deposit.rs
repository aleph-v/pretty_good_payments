//! Deposit command - deposit from L1 to L2.

use crate::config::ClientConfig;
use crate::wallet::Wallet;
use alloy_primitives::{Address, U256};
use eyre::{Result, WrapErr};

/// Run the deposit command.
pub async fn run(config: &ClientConfig, amount: &str, asset_str: Option<&str>) -> Result<()> {
    // Load wallet
    let wallet = Wallet::load(&config.wallet_path)
        .wrap_err_with(|| format!("Failed to load wallet from {}", config.wallet_path.display()))?;

    // Parse amount
    let amount = parse_amount(amount)?;

    // Parse asset (default to native token)
    let asset = if let Some(asset_str) = asset_str {
        parse_address(asset_str)?
    } else {
        Address::ZERO
    };

    // Check RPC URL
    let rpc_url = config.rpc_url.as_ref().ok_or_else(|| {
        eyre::eyre!("Ethereum RPC URL required for deposits. Set --rpc or ETH_RPC_URL")
    })?;

    println!("Deposit");
    println!("=======");
    println!("To: {} (your L2 wallet)", hex::encode(wallet.public_key()));
    println!("Amount: {}", amount);
    println!(
        "Asset: {}",
        if asset == Address::ZERO {
            "Native".to_string()
        } else {
            format!("0x{}", hex::encode(asset))
        }
    );
    println!("L1 RPC: {}", rpc_url);
    println!();

    // TODO: Implement deposit
    // This requires:
    // 1. Connecting to L1 RPC
    // 2. Calling the deposit contract
    // 3. Waiting for L1 confirmation
    // 4. The deposit will be included in a future L2 block

    println!("Deposit not yet implemented");
    println!();
    println!("This feature requires:");
    println!("  - L1 wallet/signer configuration");
    println!("  - Deposit contract interaction");

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
