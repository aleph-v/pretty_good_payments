//! Transfer command - send tokens on L2.
//!
//! Privacy: For best privacy, this command syncs proofs from the sequencer
//! before building the transfer. This ensures we always use the most recent
//! anchor available, making it harder for observers to correlate sync timing
//! with spending intent.
//!
//! Proof construction:
//! - For finalized notes (past days): Uses stored proof (29 levels) + computed day path (15 levels)
//! - For current day notes: Uses stored block siblings (16) + computed block-in-day (13) + computed day path (15)

use crate::api::SequencerClient;
use crate::cache::ProofCache;
use crate::commands::sync::{sync_proofs, SyncOptions};
use crate::commands::util::{parse_address, parse_amount, parse_public_key};
use crate::config::ClientConfig;
use crate::proof::{TransferProver, TransferWitness, WitnessInputNote, WitnessOutputNote};
use crate::wallet::keys::{compute_transfer_blinding, derive_blinding};
use crate::wallet::{TrackedNote, Wallet};
use alloy_primitives::{Address, B256, U256};
use eyre::{Result, WrapErr};
use pgp_common::types::{DecodedAnchorInfo, Groth16Proof, ParsedTransaction};
use pgp_merkle::HierarchicalProof;
use std::path::Path;
use tracing::info;

/// Result of building a transfer transaction (before submission).
#[derive(Debug, Clone)]
pub struct BuiltTransfer {
    /// The generated ZK proof
    pub proof: Groth16Proof,
    /// Nullifiers for spent notes
    pub nullifiers: [B256; 2],
    /// Output leaf commitments
    pub output_leaves: [B256; 3],
    /// The complete transaction ready for submission
    pub transaction: ParsedTransaction,
    /// Notes that were selected for spending
    pub spent_notes: Vec<TrackedNote>,
    /// The anchor used in the proof
    pub anchor: B256,
    /// Block number the anchor corresponds to
    pub anchor_block_nr: u64,
}

/// Build a transfer transaction without submitting it.
///
/// This function contains the core transfer logic and can be used for testing.
/// It builds the witness, generates the proof, and returns the transaction.
///
/// # Arguments
/// * `wallet` - The sender's wallet (will be mutated to increment tx_counter)
/// * `cache` - Proof cache with merkle proofs
/// * `zkey_path` - Path to the transfer circuit proving key
/// * `recipient` - Recipient's public key
/// * `amount` - Amount to transfer
/// * `asset` - Asset address (Address::ZERO for native token)
///
/// # Returns
/// A `BuiltTransfer` containing the proof and transaction, or an error.
pub async fn build_transfer(
    wallet: &mut Wallet,
    cache: &ProofCache,
    zkey_path: &Path,
    recipient: B256,
    amount: U256,
    asset: Address,
) -> Result<BuiltTransfer> {
    // Check balance
    let balance = wallet.balance(Some(asset));
    if balance < amount {
        eyre::bail!("Insufficient balance: have {}, need {}", balance, amount);
    }

    // Select notes for spending
    let (selected_notes_refs, change) = wallet
        .select_notes_for_amount(asset, amount)
        .ok_or_else(|| eyre::eyre!("Failed to select notes for amount"))?;

    // Clone the selected notes
    let selected_notes: Vec<_> = selected_notes_refs.into_iter().cloned().collect();

    // Check if all notes have stored proofs
    let mut missing_proofs = Vec::new();
    for note in &selected_notes {
        if !note.has_stored_proof() {
            missing_proofs.push((note.block_nr, note.leaf_index));
        }
    }

    if !missing_proofs.is_empty() {
        eyre::bail!(
            "Missing stored proofs for {} note(s). Run sync first.",
            missing_proofs.len()
        );
    }

    // Use the cached anchor
    let cached_anchor = cache.last_sync.anchor;
    let cached_block_nr = cache.last_sync.block_nr;

    if cached_anchor == B256::ZERO {
        eyre::bail!("No sync data available. Run sync first.");
    }

    // Build merkle proofs by combining stored proofs with computed day paths
    let mut input_notes = Vec::with_capacity(selected_notes.len());

    for note in &selected_notes {
        // Compute the day path (15 levels) from cached day roots
        let day_path = cache.compute_day_path(note.position.day).ok_or_else(|| {
            eyre::eyre!(
                "Cannot compute day path for day {}. Run sync first.",
                note.position.day
            )
        })?;

        let proof = if note.has_complete_proof() {
            // Finalized day: use stored proof (29 levels) + computed day path (15 levels)
            note.build_hierarchical_proof(day_path).ok_or_else(|| {
                eyre::eyre!(
                    "Failed to build hierarchical proof for block {} leaf {}",
                    note.block_nr,
                    note.leaf_index
                )
            })?
        } else {
            // Current day: compute block-in-day path and build proof manually
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

    // Build transfer witness with deterministic blindings
    let tx_counter = wallet.next_tx_counter();

    // Compute input leaves hash (required for blinding derivation)
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

    // Derive randoms and compute blindings for output notes
    let recipient_random =
        derive_blinding(wallet.spending_key(), "transfer", (tx_counter << 8) | 0);
    let recipient_blinding = compute_transfer_blinding(recipient_random, leaves_in_hash);

    let change_random = derive_blinding(wallet.spending_key(), "transfer", (tx_counter << 8) | 1);
    let change_blinding = compute_transfer_blinding(change_random, leaves_in_hash);

    // Build witness
    let mut witness = TransferWitness::new(wallet.spending_key(), cached_anchor);

    for input in input_notes {
        witness.add_input(input);
    }

    // Add output note for recipient
    witness.add_output(WitnessOutputNote {
        asset,
        amount,
        blinding: recipient_blinding,
        random: recipient_random,
        public_key: recipient,
    });

    // Add change note (to self) if there's change
    if change > U256::ZERO {
        witness.add_output(WitnessOutputNote {
            asset,
            amount: change,
            blinding: change_blinding,
            random: change_random,
            public_key: wallet.public_key(),
        });
    }

    // Validate witness
    witness.validate().map_err(|e| eyre::eyre!(e))?;

    // Generate ZK proof
    if !zkey_path.exists() {
        eyre::bail!("Transfer circuit zkey not found at {}", zkey_path.display());
    }

    let prover = TransferProver::new(zkey_path);
    let (proof, nullifiers, output_leaves) = prover
        .generate_proof(&witness)
        .await
        .wrap_err("Failed to generate transfer proof")?;

    // Build ParsedTransaction
    // Validate block number fits in u32 (protocol limit)
    let block_nr_u32: u32 = cached_block_nr
        .try_into()
        .map_err(|_| eyre::eyre!("Block number {} exceeds u32 maximum", cached_block_nr))?;

    let anchor_info = DecodedAnchorInfo {
        block_nr: block_nr_u32,
        update_nr: 0,
        is_deposit: false,
        eth_key: Address::ZERO,
    };

    let transaction = ParsedTransaction {
        proof: proof.clone(),
        anchor_info: anchor_info.encode(),
        nullifier0: nullifiers[0],
        nullifier1: nullifiers[1],
        leaf0: output_leaves[0],
        leaf1: output_leaves[1],
        leaf2: output_leaves[2],
        new_root: B256::ZERO,
    };

    Ok(BuiltTransfer {
        proof,
        nullifiers,
        output_leaves,
        transaction,
        spent_notes: selected_notes,
        anchor: cached_anchor,
        anchor_block_nr: cached_block_nr,
    })
}

/// Run the transfer command.
pub async fn run(
    config: &ClientConfig,
    to: &str,
    amount: &str,
    asset_str: Option<&str>,
) -> Result<()> {
    // Load wallet
    let mut wallet = Wallet::load(&config.wallet_path).wrap_err_with(|| {
        format!(
            "Failed to load wallet from {}",
            config.wallet_path.display()
        )
    })?;

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
    println!("From: 0x{}", hex::encode(wallet.public_key()));
    println!("To: 0x{}", hex::encode(recipient));
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

    // Create sequencer client
    let client = SequencerClient::new(&config.sequencer_url);

    // Load or create cache
    let cache_path = config.cache_path();
    let mut cache = ProofCache::load(&cache_path).unwrap_or_else(|_| {
        info!("No existing cache, starting fresh");
        ProofCache::new()
    });

    // Sync proofs before transfer for best privacy
    // This ensures we always use the most recent anchor available
    println!("Syncing proofs for latest anchor...");
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
    .wrap_err_with(|| {
        format!(
            "Failed to sync proofs from sequencer at {}",
            config.sequencer_url
        )
    })?;

    println!(
        "Using anchor: 0x{} (block {})",
        hex::encode(sync_result.anchor),
        sync_result.block_nr
    );

    if sync_result.was_stale {
        println!(
            "  (refreshed {} day, {} block, {} leaf proofs)",
            sync_result.days_synced, sync_result.blocks_synced, sync_result.leaves_synced
        );
    }
    println!();

    // Save updated cache
    cache.save(&cache_path)?;

    // Build the transfer transaction using the core logic
    println!("Building transfer...");
    let zkey_path = config.transfer_zkey_path();
    let built = build_transfer(&mut wallet, &cache, &zkey_path, recipient, amount, asset).await?;

    println!("Proof generated successfully!");
    println!("  Nullifier 0: 0x{}", hex::encode(built.nullifiers[0]));
    println!("  Nullifier 1: 0x{}", hex::encode(built.nullifiers[1]));
    println!("  Output leaf 0: 0x{}", hex::encode(built.output_leaves[0]));
    println!("  Output leaf 1: 0x{}", hex::encode(built.output_leaves[1]));
    println!("  Output leaf 2: 0x{}", hex::encode(built.output_leaves[2]));
    println!();

    // Submit to sequencer
    println!("Submitting transaction to sequencer...");
    let response = client
        .submit_transaction(built.transaction)
        .await
        .wrap_err("Failed to submit transaction")?;

    if response.accepted {
        println!("Transaction accepted!");
        println!("  Message: {}", response.message);
        println!("  Mempool size: {}", response.mempool_size);

        // Mark input notes as spent
        for note in &built.spent_notes {
            let nullifier_index = note.position.to_flat_index();
            let nullifier = pgp_merkle::compute_nullifier(
                wallet.spending_key(),
                note.blinding,
                nullifier_index,
            );
            wallet.mark_note_spent(note.commitment, nullifier);
        }

        // Save wallet with updated tx_counter and spent notes
        wallet.save(&config.wallet_path)?;
        println!("Wallet updated.");

        info!(
            "Transfer submitted: {} to 0x{}",
            amount,
            hex::encode(recipient)
        );
    } else {
        eyre::bail!("Transaction rejected: {}", response.message);
    }

    Ok(())
}
