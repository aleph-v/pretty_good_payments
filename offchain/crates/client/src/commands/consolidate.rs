//! Consolidate command - combine multiple notes into fewer notes.
//!
//! This command helps with note management by combining multiple notes
//! of the same asset type into fewer notes using a map-reduce approach.
//!
//! With n notes, we submit n/2 transactions in parallel, each combining
//! 2 notes into 1. This reduces n notes to ceil(n/2) notes in one round.
//! If you have more than 2 notes, you'll need to run consolidate again
//! after syncing to continue the reduction.
//!
//! Example with 8 notes:
//! - Round 1: Submit 4 transactions in parallel: (0,1), (2,3), (4,5), (6,7)
//! - After sync: 4 notes remain
//! - Round 2: Submit 2 transactions in parallel: (0,1), (2,3)
//! - After sync: 2 notes remain
//! - Round 3: Submit 1 transaction: (0,1)
//! - After sync: 1 note remains

use crate::api::SequencerClient;
use crate::cache::ProofCache;
use crate::commands::sync::{sync_proofs, SyncOptions};
use crate::commands::util::parse_address;
use crate::config::ClientConfig;
use crate::proof::{TransferProver, TransferWitness, WitnessInputNote, WitnessOutputNote};
use crate::wallet::keys::{compute_transfer_blinding, derive_blinding};
use crate::wallet::{TrackedNote, Wallet};
use alloy_primitives::{Address, B256, U256};
use eyre::{Result, WrapErr};
use pgp_common::types::{DecodedAnchorInfo, ParsedTransaction};
use pgp_merkle::HierarchicalProof;
use tracing::info;

/// Run the consolidate command.
///
/// Consolidates notes using a map-reduce approach: pairs of notes are
/// combined in parallel, reducing n notes to ceil(n/2) notes per round.
pub async fn run(config: &ClientConfig, asset_str: Option<&str>) -> Result<()> {
    // Load wallet
    let mut wallet = Wallet::load(&config.wallet_path).wrap_err_with(|| {
        format!(
            "Failed to load wallet from {}",
            config.wallet_path.display()
        )
    })?;

    // Parse asset filter (if provided)
    let asset_filter = if let Some(asset_str) = asset_str {
        Some(parse_address(asset_str)?)
    } else {
        None
    };

    println!("Consolidate Notes (Map-Reduce)");
    println!("==============================");
    println!("Wallet: 0x{}", hex::encode(wallet.public_key()));
    if let Some(asset) = asset_filter {
        println!(
            "Asset: {}",
            if asset == Address::ZERO {
                "Native".to_string()
            } else {
                format!("0x{}", hex::encode(asset))
            }
        );
    } else {
        println!("Asset: All");
    }
    println!();

    // Get assets to consolidate
    let assets_to_consolidate: Vec<Address> = if let Some(asset) = asset_filter {
        vec![asset]
    } else {
        wallet.assets()
    };

    if assets_to_consolidate.is_empty() {
        println!("No assets to consolidate.");
        return Ok(());
    }

    // Check which assets actually need consolidation (more than 1 note)
    let mut consolidation_needed = Vec::new();
    for asset in &assets_to_consolidate {
        let notes = wallet.unspent_notes_for_asset(*asset);
        if notes.len() > 1 {
            consolidation_needed.push((*asset, notes.len()));
        }
    }

    if consolidation_needed.is_empty() {
        println!("No consolidation needed - all assets have at most 1 note.");
        return Ok(());
    }

    println!("Assets needing consolidation:");
    for (asset, count) in &consolidation_needed {
        let asset_str = if *asset == Address::ZERO {
            "Native".to_string()
        } else {
            format!("0x{}", hex::encode(asset))
        };
        let pairs = *count / 2;
        let remaining = (*count).div_ceil(2); // ceil(count/2)
        println!(
            "  {asset_str}: {count} notes -> {pairs} pairs -> {remaining} notes after this round"
        );
    }
    println!();

    // Create sequencer client
    let client = SequencerClient::new(&config.sequencer_url);

    // Load or create cache
    let cache_path = config.cache_path();
    let mut cache = ProofCache::load(&cache_path).unwrap_or_else(|_| {
        info!("No existing cache, starting fresh");
        ProofCache::new()
    });

    // Sync proofs first
    println!("Syncing proofs...");
    let sync_result = sync_proofs(
        &mut wallet,
        &mut cache,
        &client,
        &SyncOptions {
            full: false,
            quiet: true,
        },
    )
    .await
    .wrap_err("Failed to sync proofs")?;

    println!(
        "Using anchor: 0x{} (block {})",
        hex::encode(sync_result.anchor),
        sync_result.block_nr
    );
    println!();

    // Save updated cache
    cache.save(&cache_path)?;

    // Get zkey path
    let zkey_path = config.transfer_zkey_path();
    if !zkey_path.exists() {
        eyre::bail!("Transfer circuit zkey not found at {}", zkey_path.display());
    }

    let prover = TransferProver::new(&zkey_path);

    // Process each asset with map-reduce
    let mut total_transactions = 0;
    let mut total_notes_consolidated = 0;
    let mut notes_after_sync = 0;

    for (asset, note_count) in &consolidation_needed {
        let asset_str = if *asset == Address::ZERO {
            "Native".to_string()
        } else {
            format!("0x{}", hex::encode(*asset))
        };

        println!("Consolidating {asset_str}...");

        // Get all unspent notes for this asset
        let notes: Vec<TrackedNote> = wallet
            .unspent_notes_for_asset(*asset)
            .into_iter()
            .cloned()
            .collect();

        // Create pairs for map-reduce
        let pairs: Vec<_> = notes.chunks(2).collect();
        let num_pairs_to_consolidate = pairs.iter().filter(|p| p.len() == 2).count();
        let unpaired = if notes.len() % 2 == 1 { 1 } else { 0 };

        println!(
            "  {note_count} notes -> {num_pairs_to_consolidate} pairs to consolidate, {unpaired} unpaired"
        );

        // Build all consolidation transactions in parallel
        println!("  Building {num_pairs_to_consolidate} consolidation transactions...");

        let mut built_transactions = Vec::new();
        let mut pairs_with_notes: Vec<(Vec<TrackedNote>, U256)> = Vec::new();

        for pair in &pairs {
            if pair.len() == 2 {
                let pair_notes: Vec<TrackedNote> = pair.to_vec();
                let pair_amount: U256 = pair_notes.iter().map(|n| n.amount).sum();
                pairs_with_notes.push((pair_notes, pair_amount));
            }
            // Single notes (unpaired) are left as-is
        }

        // Build transactions for all pairs
        for (i, (pair_notes, pair_amount)) in pairs_with_notes.iter().enumerate() {
            let tx = build_consolidation(
                &mut wallet,
                &cache,
                &prover,
                pair_notes,
                *asset,
                *pair_amount,
                sync_result.anchor,
                sync_result.block_nr,
            )
            .await
            .wrap_err_with(|| format!("Failed to build transaction for pair {i}"))?;

            built_transactions.push((tx, pair_notes.clone()));
        }

        // Submit all transactions
        println!("  Submitting {} transactions...", built_transactions.len());

        let mut accepted = 0;
        let mut rejected = 0;

        for (i, (tx_result, pair_notes)) in built_transactions.into_iter().enumerate() {
            let response = client
                .submit_transaction(tx_result.transaction)
                .await
                .wrap_err_with(|| format!("Failed to submit transaction {i}"))?;

            if response.accepted {
                accepted += 1;

                // Mark input notes as spent
                for note in &pair_notes {
                    let nullifier_index = note.position.to_flat_index();
                    let nullifier = pgp_merkle::compute_nullifier(
                        wallet.spending_key(),
                        note.blinding,
                        nullifier_index,
                    );
                    wallet.mark_note_spent(note.commitment, nullifier);
                }

                total_notes_consolidated += 2;
            } else {
                rejected += 1;
                println!("    Transaction {} rejected: {}", i, response.message);
            }
        }

        println!("  Submitted: {accepted} accepted, {rejected} rejected");
        total_transactions += accepted;

        // Calculate notes remaining after this round syncs
        let notes_remaining = accepted + unpaired; // Each accepted tx produces 1 note
        notes_after_sync += notes_remaining;

        if notes_remaining > 1 {
            println!("  After sync: {notes_remaining} notes (run consolidate again to continue)");
        } else {
            println!("  After sync: {notes_remaining} note (fully consolidated!)");
        }
    }

    // Save wallet
    wallet.save(&config.wallet_path)?;

    println!();
    println!("Consolidation round complete!");
    println!("=============================");
    println!("Transactions submitted: {total_transactions}");
    println!(
        "Notes consolidated: {} -> {}",
        total_notes_consolidated + notes_after_sync,
        notes_after_sync
    );
    println!();

    if notes_after_sync > consolidation_needed.len() {
        // More notes than assets means some assets still have multiple notes
        println!("Next steps:");
        println!("  1. Wait for transactions to be included in L2 blocks");
        println!("  2. Run 'pgp-client sync' to fetch the new notes");
        println!("  3. Run 'pgp-client consolidate' again to continue reduction");
    } else {
        println!("All assets will be fully consolidated after sync!");
        println!("Run 'pgp-client sync' after blocks are confirmed to see your balance.");
    }

    info!(
        "Consolidation: {} transactions, {} notes -> {}",
        total_transactions,
        total_notes_consolidated + notes_after_sync,
        notes_after_sync
    );

    Ok(())
}

/// Result of building a consolidation transaction.
struct ConsolidationResult {
    transaction: ParsedTransaction,
}

/// Build a single consolidation transaction.
#[allow(clippy::too_many_arguments)]
async fn build_consolidation(
    wallet: &mut Wallet,
    cache: &ProofCache,
    prover: &TransferProver,
    notes: &[TrackedNote],
    asset: Address,
    total_amount: U256,
    anchor: B256,
    block_nr: u64,
) -> Result<ConsolidationResult> {
    // Build merkle proofs for input notes
    let mut input_notes = Vec::with_capacity(notes.len());

    for note in notes {
        if !note.has_stored_proof() {
            eyre::bail!(
                "Missing stored proof for note at block {}. Run sync first.",
                note.block_nr
            );
        }

        let day_path = cache.compute_day_path(note.position.day).ok_or_else(|| {
            eyre::eyre!(
                "Cannot compute day path for day {}. Run sync first.",
                note.position.day
            )
        })?;

        let proof = if note.has_complete_proof() {
            note.build_hierarchical_proof(day_path).ok_or_else(|| {
                eyre::eyre!(
                    "Failed to build hierarchical proof for block {} leaf {}",
                    note.block_nr,
                    note.leaf_index
                )
            })?
        } else {
            let stored_proof = note.stored_proof.as_ref().unwrap();
            let block_in_day_path = cache
                .compute_block_in_day_path(note.position.day, note.position.block_in_day)
                .ok_or_else(|| {
                    eyre::eyre!(
                        "Cannot compute block-in-day path for day {} block {}. Run sync first.",
                        note.position.day,
                        note.position.block_in_day
                    )
                })?;

            HierarchicalProof::new(
                note.position,
                note.commitment,
                stored_proof.block_siblings,
                block_in_day_path,
                day_path,
            )
        };

        input_notes.push(WitnessInputNote {
            asset: note.asset,
            amount: note.amount,
            blinding: note.blinding,
            public_key: wallet.public_key(),
            proof,
        });
    }

    // Get tx counter for deterministic blinding
    let tx_counter = wallet.next_tx_counter();

    // Compute input leaves hash
    let leaf0 = pgp_merkle::compute_leaf_hash(
        input_notes[0].asset,
        input_notes[0].amount,
        input_notes[0].blinding,
        input_notes[0].public_key,
    );
    let leaf1 = if input_notes.len() > 1 {
        pgp_merkle::compute_leaf_hash(
            input_notes[1].asset,
            input_notes[1].amount,
            input_notes[1].blinding,
            input_notes[1].public_key,
        )
    } else {
        B256::ZERO
    };
    let leaves_in_hash = pgp_merkle::poseidon2(leaf0, leaf1);

    // Derive blinding for consolidated output
    let output_random = derive_blinding(wallet.spending_key(), "consolidate", tx_counter);
    let output_blinding = compute_transfer_blinding(output_random, leaves_in_hash);

    // Build witness
    let mut witness = TransferWitness::new(wallet.spending_key(), anchor);

    for input in input_notes {
        witness.add_input(input);
    }

    // Single output: consolidated note to self
    witness.add_output(WitnessOutputNote {
        asset,
        amount: total_amount,
        blinding: output_blinding,
        random: output_random,
        public_key: wallet.public_key(),
    });

    // Validate witness
    witness.validate().map_err(|e| eyre::eyre!(e))?;

    // Generate ZK proof
    let (proof, nullifiers, output_leaves) = prover
        .generate_proof(&witness)
        .await
        .wrap_err("Failed to generate consolidation proof")?;

    // Build ParsedTransaction
    let block_nr_u32: u32 = block_nr
        .try_into()
        .map_err(|_| eyre::eyre!("Block number {} exceeds u32 maximum", block_nr))?;

    let anchor_info = DecodedAnchorInfo {
        block_nr: block_nr_u32,
        update_nr: 0,
        is_deposit: false,
        eth_key: Address::ZERO,
    };

    let transaction = ParsedTransaction {
        proof,
        anchor_info: anchor_info.encode(),
        nullifier0: nullifiers[0],
        nullifier1: nullifiers[1],
        leaf0: output_leaves[0],
        leaf1: output_leaves[1],
        leaf2: output_leaves[2],
        new_root: B256::ZERO,
    };

    Ok(ConsolidationResult { transaction })
}
