//! Balance command - show wallet balances.

use crate::config::ClientConfig;
use crate::wallet::Wallet;
use alloy_primitives::Address;
use eyre::{Result, WrapErr};

/// Run the balance command.
pub async fn run(config: &ClientConfig, asset_filter: Option<&str>) -> Result<()> {
    // Load wallet
    let wallet = Wallet::load(&config.wallet_path)
        .wrap_err_with(|| format!("Failed to load wallet from {}", config.wallet_path.display()))?;

    // Parse asset filter if provided
    let asset_filter: Option<Address> = if let Some(asset_str) = asset_filter {
        let bytes = hex::decode(asset_str.trim_start_matches("0x"))
            .wrap_err("Invalid asset address")?;
        if bytes.len() != 20 {
            eyre::bail!("Asset address must be 20 bytes");
        }
        Some(Address::from_slice(&bytes))
    } else {
        None
    };

    println!("Wallet Balance");
    println!("==============");
    println!("Public key: {}", hex::encode(wallet.public_key()));
    println!();

    let assets = wallet.assets();
    if assets.is_empty() {
        println!("No assets in wallet");
        return Ok(());
    }

    let mut total_shown = 0;
    for asset in assets {
        // Skip if filter doesn't match
        if let Some(filter) = asset_filter {
            if asset != filter {
                continue;
            }
        }

        let balance = wallet.balance(Some(asset));
        let unspent_count = wallet.unspent_notes_for_asset(asset).len();

        let asset_name = if asset == Address::ZERO {
            "Native Token".to_string()
        } else {
            format!("0x{}", hex::encode(asset))
        };

        println!("{}", asset_name);
        println!("  Balance: {}", balance);
        println!("  Notes: {}", unspent_count);
        println!();

        total_shown += 1;
    }

    if total_shown == 0 && asset_filter.is_some() {
        println!("No balance for specified asset");
    }

    Ok(())
}
