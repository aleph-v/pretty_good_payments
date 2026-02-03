//! Sync command - fetch merkle proofs from sequencer.
//!
//! Privacy considerations:
//! - Day roots and block roots are shared across all notes, so fetching them
//!   doesn't reveal which specific notes we own.
//! - Block tree proofs are note-specific, but we fetch them during sync rather
//!   than at transfer time, so they don't leak transfer intent.
//! - For best privacy, sync should be called before each transfer to use the
//!   most recent anchor available.
//!
//! Proof storage strategy:
//! - Block siblings (16 levels): Stored with each note, immutable once committed
//! - Block-in-day siblings (13 levels): Stored with each note, immutable once day ends
//! - Day roots: Stored in cache, used to compute day paths dynamically

use crate::api::SequencerClient;
use crate::cache::{CachedBlockRoots, ProofCache};
use crate::config::ClientConfig;
use crate::wallet::{PendingWithdrawals, StoredProof, Wallet};
use alloy_primitives::B256;
use eyre::{Result, WrapErr};
use pgp_merkle::hierarchy::BLOCK_IN_DAY_DEPTH;
use pgp_merkle::{poseidon2, BlockRoot};
use std::collections::HashSet;
use tracing::info;

/// Result of a sync operation.
#[derive(Debug, Clone)]
pub struct SyncResult {
    /// The anchor after sync
    pub anchor: B256,
    /// Block number corresponding to the anchor
    pub block_nr: u64,
    /// Number of day roots fetched
    pub days_synced: usize,
    /// Number of block proofs stored with notes
    pub blocks_synced: usize,
    /// Number of leaf proofs stored with notes
    pub leaves_synced: usize,
    /// Whether the cache was stale and needed refresh
    pub was_stale: bool,
    /// Number of pending withdrawals updated with block info
    pub withdrawals_found: usize,
}

/// Options for sync behavior.
#[derive(Debug, Clone, Default)]
pub struct SyncOptions {
    /// Force full sync, ignoring cache
    pub full: bool,
    /// Suppress info logging (for use during transfer)
    pub quiet: bool,
}

/// Sync proofs for a wallet's unspent notes.
///
/// This is the core sync function that can be called from both the CLI sync
/// command and automatically before transfers for better privacy.
///
/// The sync process:
/// 1. Fetch FINALIZED day roots incrementally (past days only, they don't change)
/// 2. Fetch current day's block roots (changes with every block, keyed by block_nr)
/// 3. For notes without stored proofs: fetch and store block tree proofs (16 levels)
/// 4. For notes in past days with incomplete proofs: finalize with block-in-day siblings (13 levels)
///
/// # Arguments
/// * `wallet` - The wallet containing notes to sync proofs for (will be mutated to store proofs)
/// * `cache` - The proof cache to update (will be modified in place)
/// * `client` - The sequencer client to fetch proofs from
/// * `options` - Sync options (full sync, quiet mode)
///
/// # Returns
/// A `SyncResult` containing sync statistics and the new anchor.
pub async fn sync_proofs(
    wallet: &mut Wallet,
    cache: &mut ProofCache,
    client: &SequencerClient,
    options: &SyncOptions,
) -> Result<SyncResult> {
    // Get sync status from sequencer
    let status = client.get_sync_status().await?;

    // Check if cache is stale
    let is_stale = cache.is_stale(status.current_anchor);

    if is_stale && !options.quiet {
        info!(
            "Cache is stale (cached anchor: {}, current: {})",
            hex::encode(cache.last_sync.anchor),
            hex::encode(status.current_anchor)
        );
    }

    // Clear cache if full sync requested
    if options.full {
        if !options.quiet {
            info!("Full sync requested, clearing cache");
        }
        cache.clear();
    }

    let mut days_synced = 0;
    let mut blocks_synced = 0;
    let mut leaves_synced = 0;

    // Step 1: Fetch FINALIZED day roots incrementally
    // Finalized days (0 to latest_day-1) don't change, so only fetch missing ones
    if status.latest_day > 0 {
        let last_finalized_day = status.latest_day - 1;
        let first_missing_day = if options.full {
            0
        } else {
            cache.finalized_days_cached() as u16
        };

        if first_missing_day <= last_finalized_day {
            if !options.quiet {
                info!(
                    "Fetching finalized day roots ({} to {})",
                    first_missing_day, last_finalized_day
                );
            }
            let day_roots_response = client
                .get_day_roots(first_missing_day, last_finalized_day)
                .await?;
            cache.update_day_roots(&day_roots_response.day_roots);
            days_synced = day_roots_response.day_roots.len();
        }
    }

    // Step 2: Fetch current day's block roots (includes the current day's root)
    // The current day's root changes with EVERY new block, so we check block_nr.
    // IMPORTANT: set_current_day_block_roots also updates day_roots[current_day],
    // which is needed for compute_day_path to work against the current anchor.
    if cache.needs_current_day_refresh(status.latest_day, status.latest_block_nr) || options.full {
        if !options.quiet {
            info!(
                "Fetching block roots for current day {} (block {})",
                status.latest_day, status.latest_block_nr
            );
        }
        let block_roots_response = client.get_block_roots(status.latest_day).await?;
        cache.set_current_day_block_roots(CachedBlockRoots {
            day: status.latest_day,
            block_roots: block_roots_response.block_roots,
            day_root: block_roots_response.day_root,
            fetched_at_block_nr: status.latest_block_nr,
            fetched_at_anchor: status.current_anchor,
        });
    }

    // Get unspent notes
    let unspent_notes = wallet.unspent_notes();
    if unspent_notes.is_empty() {
        cache.set_last_sync(
            status.current_anchor,
            status.latest_block_nr,
            status.latest_day,
        );
        return Ok(SyncResult {
            anchor: status.current_anchor,
            block_nr: status.latest_block_nr,
            days_synced,
            blocks_synced: 0,
            leaves_synced: 0,
            was_stale: is_stale,
            withdrawals_found: 0,
        });
    }

    // Step 3: Collect info about notes needing block proofs (before mutating)
    let notes_for_block_proof: Vec<(B256, u64, u32)> = wallet
        .notes_needing_block_proof()
        .iter()
        .map(|n| (n.commitment, n.block_nr, n.leaf_index))
        .collect();

    // Fetch and store block proofs for notes that don't have them yet
    for (commitment, block_nr, leaf_index) in notes_for_block_proof {
        if !options.quiet {
            info!(
                "Fetching block proof for block={}, leaf={}",
                block_nr, leaf_index
            );
        }
        let leaf_response = client.get_block_tree_proof(block_nr, leaf_index).await?;

        // Create a StoredProof with just the block-level proof
        let proof =
            StoredProof::new_partial(leaf_response.block_siblings, leaf_response.block_root);

        // Store with the note
        wallet.store_block_proof(commitment, proof);
        leaves_synced += 1;
    }

    // Step 4: Collect info about notes needing day finalization (before mutating)
    let notes_for_finalization: Vec<(u16, u16)> = wallet
        .notes_needing_day_finalization(status.latest_day)
        .iter()
        .map(|n| (n.position.day, n.position.block_in_day))
        .collect();

    // Group by day to minimize API calls
    let mut days_to_finalize: HashSet<u16> = HashSet::new();
    for (day, _) in &notes_for_finalization {
        days_to_finalize.insert(*day);
    }

    // For each past day that needs finalization, fetch block roots and compute paths
    for day in &days_to_finalize {
        if !options.quiet {
            info!("Finalizing proofs for day {} (fetching block roots)", day);
        }

        // Fetch all block roots for this day
        let block_roots_response = client.get_block_roots(*day).await?;
        let day_root = block_roots_response.day_root;

        // Collect all block-in-day positions for this day
        let blocks_in_day: HashSet<u16> = notes_for_finalization
            .iter()
            .filter(|(d, _)| *d == *day)
            .map(|(_, b)| *b)
            .collect();

        // Compute block-in-day paths locally from block roots
        let mut block_paths: Vec<(u16, [B256; BLOCK_IN_DAY_DEPTH])> = Vec::new();
        for block_in_day in blocks_in_day {
            let path = compute_block_in_day_path(&block_roots_response.block_roots, block_in_day);
            block_paths.push((block_in_day, path));
            blocks_synced += 1;
        }

        // Finalize all notes in this day
        wallet.finalize_day_proofs(*day, &block_paths, day_root);
    }

    // Note: Current day block roots were already fetched in Step 2 above.
    // This ensures we have the latest day root for computing day paths.

    // Update sync point
    cache.set_last_sync(
        status.current_anchor,
        status.latest_block_nr,
        status.latest_day,
    );

    Ok(SyncResult {
        anchor: status.current_anchor,
        block_nr: status.latest_block_nr,
        days_synced,
        blocks_synced,
        leaves_synced,
        was_stale: is_stale,
        withdrawals_found: 0,
    })
}

/// Compute the block-in-day merkle path from a list of block roots.
///
/// This computes the 13-level path from a specific block root to the day root
/// without making additional API calls - all computation is done locally.
fn compute_block_in_day_path(
    block_roots: &[BlockRoot],
    block_in_day: u16,
) -> [B256; BLOCK_IN_DAY_DEPTH] {
    const NUM_BLOCKS: usize = 1 << BLOCK_IN_DAY_DEPTH; // 8192
    let mut leaves = vec![B256::ZERO; NUM_BLOCKS];

    // Fill in the non-zero block roots
    for root in block_roots {
        let idx = root.block_in_day as usize;
        if idx < NUM_BLOCKS {
            leaves[idx] = root.root;
        }
    }

    // Compute the merkle tree level by level and extract siblings
    let mut siblings = [B256::ZERO; BLOCK_IN_DAY_DEPTH];
    let mut current_level = leaves;
    let mut idx = block_in_day as usize;

    for level in 0..BLOCK_IN_DAY_DEPTH {
        let sibling_idx = idx ^ 1;
        siblings[level] = current_level[sibling_idx];

        let mut next_level = Vec::with_capacity(current_level.len() / 2);
        for i in (0..current_level.len()).step_by(2) {
            next_level.push(poseidon2(current_level[i], current_level[i + 1]));
        }
        current_level = next_level;
        idx /= 2;
    }

    siblings
}

/// Run the sync command (CLI entry point).
pub async fn run(config: &ClientConfig, full: bool) -> Result<()> {
    // Load wallet
    let mut wallet = Wallet::load(&config.wallet_path).wrap_err_with(|| {
        format!(
            "Failed to load wallet from {}",
            config.wallet_path.display()
        )
    })?;

    // Load or create cache
    let cache_path = config.cache_path();
    let mut cache = if full {
        ProofCache::new()
    } else {
        ProofCache::load(&cache_path).unwrap_or_else(|_| {
            info!("No existing cache, starting fresh");
            ProofCache::new()
        })
    };

    // Connect to sequencer
    let client = SequencerClient::new(&config.sequencer_url);

    // Get sync status for display
    info!("Fetching sync status from {}", config.sequencer_url);
    let status = client.get_sync_status().await?;

    println!("Sequencer Status");
    println!("================");
    println!("Latest block: {}", status.latest_block_nr);
    println!("Latest day: {}", status.latest_day);
    println!("Current anchor: {}", hex::encode(status.current_anchor));
    println!();

    // Get note count for display
    let unspent_notes = wallet.unspent_notes();
    if unspent_notes.is_empty() {
        println!("No unspent notes to sync");
    } else {
        println!("Syncing proofs for {} unspent notes", unspent_notes.len());
    }

    // Perform sync
    let options = SyncOptions { full, quiet: false };
    let result = sync_proofs(&mut wallet, &mut cache, &client, &options).await?;

    // Save wallet (proofs may have been stored with notes)
    wallet.save(&config.wallet_path)?;

    // Save cache
    cache.save(&cache_path)?;

    // Search for pending withdrawals that need block info
    let withdrawals_found =
        sync_pending_withdrawals(config, &client, status.latest_block_nr).await?;

    // Print results
    if result.days_synced == 0 && result.blocks_synced == 0 && result.leaves_synced == 0 {
        if !wallet.unspent_notes().is_empty() {
            println!("All proofs are up to date");
        }
    } else {
        println!(
            "Synced {} day roots, {} block proofs, and {} leaf proofs",
            result.days_synced, result.blocks_synced, result.leaves_synced
        );
    }

    if withdrawals_found > 0 {
        println!(
            "Found block info for {} pending withdrawal(s)",
            withdrawals_found
        );
    }

    println!("Sync complete!");
    println!("Cache saved to: {}", cache_path.display());

    Ok(())
}

/// Search for pending withdrawals that need block info and update them.
///
/// This searches recent blocks for any pending withdrawals with block_nr == 0
/// and updates them with the actual block and transaction info.
async fn sync_pending_withdrawals(
    config: &ClientConfig,
    client: &SequencerClient,
    latest_block_nr: u64,
) -> Result<usize> {
    let pending_path = config.pending_withdrawals_path();
    let mut pending_withdrawals = match PendingWithdrawals::load(&pending_path) {
        Ok(p) => p,
        Err(_) => return Ok(0), // No pending withdrawals file
    };

    // Find withdrawals that need block info
    let needs_update: Vec<(usize, B256)> = pending_withdrawals
        .withdrawals
        .iter()
        .enumerate()
        .filter(|(_, w)| !w.executed && w.block_nr == 0)
        .map(|(i, w)| (i, w.leaf_commitment))
        .collect();

    if needs_update.is_empty() {
        return Ok(0);
    }

    info!(
        "Searching for {} pending withdrawal(s) in recent blocks",
        needs_update.len()
    );

    let mut found_count = 0;

    // Search recent blocks (last 50 blocks should be plenty)
    let search_depth = 50;
    let start_block = latest_block_nr.saturating_sub(search_depth);

    for (idx, leaf_commitment) in needs_update {
        // Search blocks from newest to oldest (more likely to find recent txs first)
        for block_nr in (start_block..=latest_block_nr).rev() {
            match client.get_withdrawal_proof(leaf_commitment, block_nr).await {
                Ok(response) if response.found => {
                    // Found it!
                    let w = &mut pending_withdrawals.withdrawals[idx];
                    w.block_nr = block_nr;
                    w.tx_nr = response.tx_nr.unwrap_or(0);
                    w.output_index = response.which.unwrap_or(0);

                    info!(
                        "Found withdrawal 0x{}... in block {}, tx {}, output {}",
                        &hex::encode(leaf_commitment)[..8],
                        block_nr,
                        w.tx_nr,
                        w.output_index
                    );
                    found_count += 1;
                    break;
                }
                Ok(_) => {
                    // Not found in this block, continue searching
                }
                Err(e) => {
                    // Log but continue - might be a temporary error or block doesn't exist
                    tracing::debug!("Error searching block {} for withdrawal: {}", block_nr, e);
                }
            }
        }
    }

    // Save updated pending withdrawals if any were found
    if found_count > 0 {
        pending_withdrawals.save(&pending_path)?;
    }

    Ok(found_count)
}
