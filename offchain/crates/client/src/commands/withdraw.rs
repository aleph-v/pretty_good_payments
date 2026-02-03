//! Withdraw command - withdraw from L2 to L1.
//!
//! Withdrawals are a two-stage process:
//!
//! **Stage 1 (L2 - this command):**
//! - Create a transfer to publicKey=0 with blinding=recipient_address
//! - This makes the note unspendable on L2 (no one can derive key for pubkey 0)
//! - Submit the transaction to the sequencer
//! - Save pending withdrawal info locally
//!
//! **Stage 2 (L1 - separate command `withdraw-execute`):**
//! - Wait for the L2 block to be confirmed on L1
//! - Submit KZG proof to the Withdraw contract
//! - Funds are released to the recipient

use crate::api::SequencerClient;
use crate::cache::ProofCache;
use crate::commands::sync::{sync_proofs, SyncOptions};
use crate::commands::util::{address_to_b256, parse_address, parse_amount};
use crate::config::ClientConfig;
use crate::proof::{TransferProver, TransferWitness, WitnessInputNote, WitnessOutputNote};
use crate::wallet::keys::{compute_transfer_blinding, derive_blinding};
use crate::wallet::{PendingWithdrawal, PendingWithdrawals, Wallet};
use alloy_primitives::{Address, B256, U256};
use eyre::{Result, WrapErr};
use pgp_common::types::{DecodedAnchorInfo, ParsedTransaction};
use pgp_merkle::HierarchicalProof;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

/// Run the withdraw command.
///
/// This performs Stage 1 of the withdrawal: creating an L2 transaction
/// with publicKey=0 and blinding=recipient_address.
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

    println!("Withdraw (Stage 1: L2 Transfer)");
    println!("================================");
    println!("From: 0x{} (L2)", hex::encode(wallet.public_key()));
    println!("To: 0x{} (L1)", hex::encode(recipient));
    println!("Amount: {amount}");
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
        eyre::bail!("Insufficient balance: have {}, need {}", balance, amount);
    }

    // Select notes for spending
    let (selected_notes_refs, change) = wallet
        .select_notes_for_amount(asset, amount)
        .ok_or_else(|| eyre::eyre!("Failed to select notes for amount"))?;

    let selected_notes: Vec<_> = selected_notes_refs.into_iter().cloned().collect();

    println!("Selected {} notes for withdrawal", selected_notes.len());
    if change > U256::ZERO {
        println!("Change: {change} (returned to your wallet)");
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

    // Sync proofs
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
    println!();

    // Save updated cache
    cache.save(&cache_path)?;

    // Check if all notes have stored proofs
    for note in &selected_notes {
        if !note.has_stored_proof() {
            eyre::bail!(
                "Missing stored proof for note at block {}. Run sync first.",
                note.block_nr
            );
        }
    }

    // Build merkle proofs
    let mut input_notes = Vec::with_capacity(selected_notes.len());
    for note in &selected_notes {
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

    // Build transfer witness with withdrawal output
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

    // For the withdrawal output:
    // - publicKey = 0 (makes it unspendable on L2)
    // - blinding encodes the recipient: bytes32(uint256(uint160(recipient)))
    let withdrawal_blinding = address_to_b256(recipient);

    // Derive random for the withdrawal (even though publicKey=0, circuit still needs valid random)
    let withdrawal_random = derive_blinding(wallet.spending_key(), "withdraw", tx_counter);

    // For change output (if any), derive blinding normally
    let change_random = derive_blinding(wallet.spending_key(), "transfer", (tx_counter << 8) | 1);
    let change_blinding = compute_transfer_blinding(change_random, leaves_in_hash);

    // Build witness
    let mut witness = TransferWitness::new(wallet.spending_key(), sync_result.anchor);

    for input in input_notes {
        witness.add_input(input);
    }

    // Add withdrawal output (publicKey = 0, blinding = recipient address)
    witness.add_output(WitnessOutputNote {
        asset,
        amount,
        blinding: withdrawal_blinding,
        random: withdrawal_random,
        public_key: B256::ZERO, // Makes it unspendable on L2
    });

    // Add change output (to self) if there's change
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
    println!("Generating withdrawal proof...");
    let zkey_path = config.transfer_zkey_path();
    if !zkey_path.exists() {
        eyre::bail!("Transfer circuit zkey not found at {}", zkey_path.display());
    }

    let prover = TransferProver::new(&zkey_path);
    let (proof, nullifiers, output_leaves) = prover
        .generate_proof(&witness)
        .await
        .wrap_err("Failed to generate withdrawal proof")?;

    println!("Proof generated successfully!");
    println!("  Withdrawal output: 0x{}", hex::encode(output_leaves[0]));
    if change > U256::ZERO {
        println!("  Change output: 0x{}", hex::encode(output_leaves[1]));
    }
    println!();

    // Build ParsedTransaction
    let block_nr_u32: u32 = sync_result
        .block_nr
        .try_into()
        .map_err(|_| eyre::eyre!("Block number {} exceeds u32 maximum", sync_result.block_nr))?;

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

    // Submit to sequencer
    println!("Submitting withdrawal transaction to sequencer...");
    let response = client
        .submit_transaction(transaction)
        .await
        .wrap_err("Failed to submit withdrawal transaction")?;

    if response.accepted {
        println!("Withdrawal transaction accepted!");
        println!("  Message: {}", response.message);
        println!("  Mempool size: {}", response.mempool_size);
        println!();

        // Mark input notes as spent
        for note in &selected_notes {
            let nullifier_index = note.position.to_flat_index();
            let nullifier = pgp_merkle::compute_nullifier(
                wallet.spending_key(),
                note.blinding,
                nullifier_index,
            );
            wallet.mark_note_spent(note.commitment, nullifier);
        }

        // Save wallet
        wallet.save(&config.wallet_path)?;

        // Create pending withdrawal record
        // Note: We don't know the exact block_nr and tx_nr yet - these will be
        // determined when the sequencer includes the transaction in a block.
        // For now, we store what we know and will update when we can query the sequencer.
        let pending = PendingWithdrawal {
            tx_id: Some(hex::encode(output_leaves[0]).to_string()),
            block_nr: 0,     // Unknown until included in block
            tx_nr: 0,        // Unknown until included in block
            output_index: 0, // The withdrawal is always output 0
            asset,
            amount,
            recipient,
            leaf_commitment: output_leaves[0],
            executed: false,
            execution_tx: None,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        // Load and save pending withdrawals
        let pending_path = config.pending_withdrawals_path();
        let mut pending_withdrawals =
            PendingWithdrawals::load(&pending_path).unwrap_or_else(|_| PendingWithdrawals::new());
        pending_withdrawals.add(pending);
        pending_withdrawals.save(&pending_path)?;

        println!("Stage 1 complete!");
        println!("==================");
        println!("Your withdrawal transaction has been submitted to the sequencer.");
        println!("Pending withdrawal saved to: {}", pending_path.display());
        println!();
        println!("Next steps:");
        println!("  1. Wait for the transaction to be included in an L2 block");
        println!("  2. Wait for the block to be confirmed on L1 (challenge period)");
        println!("  3. Run 'pgp-client withdraw-execute' to claim funds on L1");

        info!(
            "Withdrawal initiated: {} to 0x{}",
            amount,
            hex::encode(recipient)
        );
    } else {
        eyre::bail!("Withdrawal transaction rejected: {}", response.message);
    }

    Ok(())
}
