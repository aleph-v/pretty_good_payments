//! Wallet management commands.

use crate::config::ClientConfig;
use crate::wallet::Wallet;
use eyre::{Result, WrapErr};

/// Create a new wallet.
pub async fn create(config: &ClientConfig, seed: Option<&str>) -> Result<()> {
    if Wallet::exists(&config.wallet_path) {
        eyre::bail!(
            "Wallet already exists at {}. Use 'wallet import' to replace it.",
            config.wallet_path.display()
        );
    }

    let seed = seed.map(|s| s.to_string()).unwrap_or_else(|| {
        // Generate a random seed phrase (in production, use BIP39)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("pgp-wallet-{}-{}", now, std::process::id())
    });

    let wallet = Wallet::new(&seed);
    wallet
        .save(&config.wallet_path)
        .wrap_err("Failed to save wallet")?;

    println!("Wallet created successfully!");
    println!("Path: {}", config.wallet_path.display());
    println!("Public key: {}", hex::encode(wallet.public_key()));
    println!();
    println!("IMPORTANT: Save your seed phrase securely:");
    println!("  {seed}");

    Ok(())
}

/// Show wallet info.
pub async fn info(config: &ClientConfig) -> Result<()> {
    let wallet = Wallet::load(&config.wallet_path).wrap_err_with(|| {
        format!(
            "Failed to load wallet from {}",
            config.wallet_path.display()
        )
    })?;

    println!("Wallet Info");
    println!("============");
    println!("Path: {}", config.wallet_path.display());
    println!("Public key: {}", hex::encode(wallet.public_key()));
    println!();
    println!("Notes: {} total", wallet.notes.len());
    println!("  Unspent: {}", wallet.unspent_notes().len());
    println!(
        "  Spent: {}",
        wallet.notes.len() - wallet.unspent_notes().len()
    );
    println!();

    let assets = wallet.assets();
    if assets.is_empty() {
        println!("No assets in wallet");
    } else {
        println!("Balances:");
        for asset in assets {
            let balance = wallet.balance(Some(asset));
            let asset_str = if asset == alloy_primitives::Address::ZERO {
                "Native".to_string()
            } else {
                hex::encode(asset)
            };
            println!("  {asset_str}: {balance}");
        }
    }

    Ok(())
}

/// Export seed phrase.
pub async fn export(config: &ClientConfig) -> Result<()> {
    let wallet = Wallet::load(&config.wallet_path).wrap_err_with(|| {
        format!(
            "Failed to load wallet from {}",
            config.wallet_path.display()
        )
    })?;

    println!("Seed phrase:");
    println!("  {}", wallet.seed);
    println!();
    println!("WARNING: Keep this seed phrase secret!");

    Ok(())
}

/// Import wallet from seed phrase.
pub async fn import(config: &ClientConfig, seed: &str) -> Result<()> {
    if Wallet::exists(&config.wallet_path) {
        // Ask for confirmation in a real CLI
        println!(
            "WARNING: Wallet already exists at {}",
            config.wallet_path.display()
        );
        println!("Overwriting...");
    }

    let wallet = Wallet::new(seed);
    wallet
        .save(&config.wallet_path)
        .wrap_err("Failed to save wallet")?;

    println!("Wallet imported successfully!");
    println!("Path: {}", config.wallet_path.display());
    println!("Public key: {}", hex::encode(wallet.public_key()));

    Ok(())
}
