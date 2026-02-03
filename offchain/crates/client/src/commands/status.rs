//! Status command - show wallet and system status overview.
//!
//! Displays:
//! - Wallet info (public key)
//! - Asset balances with note counts
//! - Pending withdrawals
//! - Sync status from sequencer

use crate::api::SequencerClient;
use crate::cache::ProofCache;
use crate::config::ClientConfig;
use crate::wallet::{PendingWithdrawals, Wallet};
use alloy_primitives::{Address, B256, U256};
use eyre::Result;
use std::collections::HashMap;

/// Run the status command.
pub async fn run(config: &ClientConfig) -> Result<()> {
    println!("PGP Client Status");
    println!("==================");
    println!();

    // Load wallet
    let wallet_result = Wallet::load(&config.wallet_path);
    let wallet = match wallet_result {
        Ok(w) => Some(w),
        Err(_) => {
            println!("Wallet: Not found at {}", config.wallet_path.display());
            println!("        Run 'pgp-client wallet create' to create a new wallet.");
            println!();
            None
        }
    };

    if let Some(ref wallet) = wallet {
        print_wallet_info(wallet);
        print_balances(wallet);
    }

    // Load pending withdrawals
    let pending_path = config.pending_withdrawals_path();
    if let Ok(pending) = PendingWithdrawals::load(&pending_path) {
        print_pending_withdrawals(&pending);
    }

    // Load cache info
    let cache_path = config.cache_path();
    if let Ok(cache) = ProofCache::load(&cache_path) {
        print_cache_info(&cache);
    }

    // Try to get sync status from sequencer
    let client = SequencerClient::new(&config.sequencer_url);
    match client.get_sync_status().await {
        Ok(status) => {
            print_sync_status(&status, &config.sequencer_url);
        }
        Err(e) => {
            println!("Sequencer Status");
            println!("----------------");
            println!("  URL: {}", config.sequencer_url);
            println!("  Status: Unavailable ({e})");
            println!();
        }
    }

    // Print config info
    print_config_info(config);

    Ok(())
}

fn print_wallet_info(wallet: &Wallet) {
    println!("Wallet");
    println!("------");
    println!("  Public Key: 0x{}", hex::encode(wallet.public_key()));
    println!("  Notes: {} total", wallet.notes.len());
    println!("  Spent Nullifiers: {}", wallet.spent_nullifiers.len());
    println!("  TX Counter: {}", wallet.tx_counter);
    println!();
}

fn print_balances(wallet: &Wallet) {
    println!("Balances");
    println!("--------");

    // Group notes by asset
    let mut asset_info: HashMap<Address, (U256, usize, usize)> = HashMap::new();

    for note in &wallet.notes {
        let entry = asset_info.entry(note.asset).or_insert((U256::ZERO, 0, 0));
        if note.spent {
            entry.2 += 1; // spent count
        } else {
            entry.0 += note.amount; // balance
            entry.1 += 1; // unspent count
        }
    }

    if asset_info.is_empty() {
        println!("  No assets found.");
        println!("  Use 'pgp-client deposit' to deposit funds from L1.");
    } else {
        // Sort by asset address, with native (zero) first
        let mut assets: Vec<_> = asset_info.into_iter().collect();
        assets.sort_by_key(|(addr, _)| *addr);

        for (asset, (balance, unspent, spent)) in assets {
            let asset_str = if asset == Address::ZERO {
                "Native".to_string()
            } else {
                format!("0x{}", hex::encode(asset))
            };

            println!("  {asset_str}: {balance} ({unspent} notes, {spent} spent)");
        }
    }
    println!();
}

fn print_pending_withdrawals(pending: &PendingWithdrawals) {
    let unexecuted: Vec<_> = pending.unexecuted();
    let executed = pending.withdrawals.len() - unexecuted.len();

    println!("Pending Withdrawals");
    println!("-------------------");

    if pending.withdrawals.is_empty() {
        println!("  None");
    } else {
        println!(
            "  Total: {} ({} pending, {} executed)",
            pending.withdrawals.len(),
            unexecuted.len(),
            executed
        );

        if !unexecuted.is_empty() {
            println!();
            for (i, w) in unexecuted.iter().enumerate() {
                let asset_str = if w.asset == Address::ZERO {
                    "Native".to_string()
                } else {
                    format!("0x{}...", &hex::encode(w.asset)[..8])
                };

                let status = if w.block_nr == 0 {
                    "Awaiting block".to_string()
                } else {
                    format!("Ready (block {})", w.block_nr)
                };

                println!(
                    "  [{}] {} {} -> 0x{}... ({})",
                    i,
                    w.amount,
                    asset_str,
                    &hex::encode(w.recipient)[..8],
                    status
                );
            }
        }
    }
    println!();
}

fn print_cache_info(cache: &ProofCache) {
    println!("Proof Cache");
    println!("-----------");

    // Count non-zero day roots
    let finalized = cache.day_roots.iter().filter(|r| **r != B256::ZERO).count();
    println!("  Day Roots Cached: {finalized}");

    if !cache.day_roots.is_empty() {
        // Find the latest non-zero day
        let latest_day = cache
            .day_roots
            .iter()
            .enumerate()
            .rev()
            .find(|(_, r)| **r != B256::ZERO)
            .map(|(i, _)| i);

        if let Some(day) = latest_day {
            println!("  Latest Day: {day}");
        }
    }

    if let Some(ref current_day) = cache.current_day_block_roots {
        let non_zero = current_day
            .block_roots
            .iter()
            .filter(|r| r.root != B256::ZERO)
            .count();
        println!(
            "  Current Day: {} (with {} blocks)",
            current_day.day, non_zero
        );
    }

    println!("  Last Sync Block: {}", cache.last_sync.block_nr);
    println!();
}

fn print_sync_status(status: &crate::api::SyncStatusResponse, url: &str) {
    println!("Sequencer Status");
    println!("----------------");
    println!("  URL: {url}");
    println!("  Status: Connected");
    println!("  Latest Block: {}", status.latest_block_nr);
    println!("  Latest Day: {}", status.latest_day);
    println!("  Block in Day: {}", status.latest_block_in_day);
    println!(
        "  Current Anchor: 0x{}...{}",
        &hex::encode(status.current_anchor)[..8],
        &hex::encode(status.current_anchor)[56..]
    );
    println!();
}

fn print_config_info(config: &ClientConfig) {
    println!("Configuration");
    println!("-------------");
    println!("  Wallet: {}", config.wallet_path.display());
    println!("  Sequencer: {}", config.sequencer_url);

    if let Some(ref rpc) = config.rpc_url {
        println!("  ETH RPC: {rpc}");
    } else {
        println!("  ETH RPC: Not configured");
    }

    if config.eth_private_key.is_some() {
        println!("  ETH Key: Configured");
    } else {
        println!("  ETH Key: Not configured");
    }

    if let Some(addr) = config.entrypoint_address {
        println!("  Entrypoint: 0x{}", hex::encode(addr));
    } else {
        println!("  Entrypoint: Not configured");
    }

    if let Some(addr) = config.withdraw_address {
        println!("  Withdraw: 0x{}", hex::encode(addr));
    } else {
        println!("  Withdraw: Not configured");
    }

    if let Some(ref path) = config.circuits_path {
        println!("  Circuits: {}", path.display());
    }
    println!();
}
