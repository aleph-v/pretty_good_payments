//! Sync command - fetch merkle proofs from sequencer.

use crate::api::SequencerClient;
use crate::cache::{ProofCache, StashedBlockProof, StashedDayProof};
use crate::config::ClientConfig;
use crate::wallet::Wallet;
use eyre::{Result, WrapErr};
use tracing::info;

/// Run the sync command.
pub async fn run(config: &ClientConfig, full: bool) -> Result<()> {
    // Load wallet
    let wallet = Wallet::load(&config.wallet_path)
        .wrap_err_with(|| format!("Failed to load wallet from {}", config.wallet_path.display()))?;

    // Load or create cache
    let cache_path = config.cache_path();
    let mut cache = if full {
        info!("Full sync requested, clearing cache");
        ProofCache::new()
    } else {
        ProofCache::load(&cache_path).unwrap_or_else(|_| {
            info!("No existing cache, starting fresh");
            ProofCache::new()
        })
    };

    // Connect to sequencer
    let client = SequencerClient::new(&config.sequencer_url);

    // Get sync status
    info!("Fetching sync status from {}", config.sequencer_url);
    let status = client.get_sync_status().await?;

    println!("Sequencer Status");
    println!("================");
    println!("Latest block: {}", status.latest_block_nr);
    println!("Latest day: {}", status.latest_day);
    println!("Current anchor: {}", hex::encode(status.current_anchor));
    println!();

    // Check if cache is stale
    let cache_anchor = cache.last_sync.anchor;
    let is_stale = cache_anchor != status.current_anchor;

    if is_stale && !full {
        info!(
            "Cache is stale (cached anchor: {}, current: {})",
            hex::encode(cache_anchor),
            hex::encode(status.current_anchor)
        );
    }

    // Get positions of all unspent notes
    let unspent_notes = wallet.unspent_notes();
    if unspent_notes.is_empty() {
        println!("No unspent notes to sync");
        cache.set_last_sync(status.current_anchor, status.latest_block_nr);
        cache.save(&cache_path)?;
        return Ok(());
    }

    println!("Syncing proofs for {} unspent notes", unspent_notes.len());

    // Determine which positions need refresh
    let positions: Vec<_> = unspent_notes.iter().map(|n| n.position).collect();
    let needs_refresh = if full || is_stale {
        positions.clone()
    } else {
        cache.needs_refresh(&positions, status.current_anchor)
    };

    if needs_refresh.is_empty() {
        println!("All proofs are up to date");
    } else {
        println!("Fetching proofs for {} positions", needs_refresh.len());

        // Group by day to minimize API calls
        let mut days_needed: std::collections::HashSet<u16> = std::collections::HashSet::new();
        for pos in &needs_refresh {
            days_needed.insert(pos.day);
        }

        // Fetch day paths
        for day in &days_needed {
            info!("Fetching day path for day {}", day);
            let day_path_response = client.get_day_path(*day).await?;

            cache.stash_day_proof(StashedDayProof {
                day: *day,
                day_path: day_path_response.day_path,
                day_root: day_path_response.day_root,
                fetched_at_anchor: status.current_anchor,
            });
        }

        // Fetch block paths for each position
        for pos in &needs_refresh {
            info!(
                "Fetching block path for day={}, block={}",
                pos.day, pos.block_in_day
            );
            let block_path_response = client
                .get_block_path(pos.day, pos.block_in_day)
                .await?;

            // Get the day path we just fetched
            let day_proof = cache.get_day_proof(pos.day).unwrap();

            cache.stash_block_proof(StashedBlockProof {
                day: pos.day,
                block_in_day: pos.block_in_day,
                block_path: block_path_response.block_path,
                block_root: block_path_response.block_root,
                day_path: day_proof.day_path,
                fetched_at_anchor: status.current_anchor,
            });
        }

        println!("Synced {} day proofs and {} block proofs",
            days_needed.len(),
            needs_refresh.len()
        );
    }

    // Update sync point and save
    cache.set_last_sync(status.current_anchor, status.latest_block_nr);
    cache.save(&cache_path)?;

    println!("Sync complete!");
    println!("Cache saved to: {}", cache_path.display());

    Ok(())
}
