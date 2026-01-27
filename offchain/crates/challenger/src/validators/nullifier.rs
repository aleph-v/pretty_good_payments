//! Nullifier tracking for double-spend detection.
//!
//! Every transaction reveals two nullifiers (one per input note).
//! If the same nullifier is used twice, it's a double-spend attempt.
//! Nullifiers are checked via batch SQL queries for efficiency.

use alloy::primitives::B256;
use eyre::Result;
use std::collections::HashMap;
use tracing::{debug, info, warn};

use super::FraudEvidence;
use crate::state::StateManager;
use pgp_common::blob::ParsedBlock;

/// Compact record of where a nullifier was first seen.
/// Stored in SQLite for O(log n) lookups with constant memory usage.
#[derive(Debug, Clone, Copy)]
pub struct NullifierRecord {
    /// Block where the nullifier was used
    pub block_nr: u64,
    /// Transaction index within the block
    pub tx_index: u32,
    /// Which nullifier in the transaction (0 or 1)
    pub which: u8,
}

/// Validates nullifiers against the database to detect double-spends.
/// Stateless - all data is stored in SQLite via StateManager.
#[derive(Debug, Default)]
pub struct NullifierValidator;

impl NullifierValidator {
    /// Create a new nullifier validator
    pub fn new() -> Self {
        Self
    }

    /// Process a block and check for double-spend attempts.
    /// Uses batch queries for efficiency: one query to check all nullifiers,
    /// one transaction to save all new nullifiers.
    /// Also detects duplicates within the same block.
    pub fn process_block(
        &self,
        state: &StateManager,
        block_nr: u64,
        block: &ParsedBlock,
    ) -> Result<Vec<FraudEvidence>> {
        let mut fraud = Vec::new();

        if block.transactions.is_empty() {
            return Ok(fraud);
        }

        debug!(
            "Processing {} transactions for nullifiers in block {}",
            block.transactions.len(),
            block_nr
        );

        // Step 1: Collect ALL nullifiers from this block with their metadata
        // Note: We track ALL nullifiers including B256::ZERO. While zero nullifiers
        // are unlikely to occur with valid proofs, a fraudulent sequencer could
        // include them, and they must still be tracked for double-spend detection.
        let mut block_nullifiers: Vec<(B256, NullifierRecord)> = Vec::new();
        // Track first occurrence within this block for in-block duplicate detection
        let mut seen_in_block: HashMap<B256, NullifierRecord> = HashMap::new();

        for (tx_idx, tx) in block.transactions.iter().enumerate() {
            let tx_idx_u32 = tx_idx as u32;

            for (which, nullifier) in [(0u8, tx.nullifier0), (1u8, tx.nullifier1)] {
                let record = NullifierRecord {
                    block_nr,
                    tx_index: tx_idx_u32,
                    which,
                };

                // Check for duplicate within this block
                if let Some(first) = seen_in_block.get(&nullifier) {
                    warn!(
                        "In-block double-spend! nullifier={}, first=tx {} which {}, second=tx {} which {}",
                        nullifier, first.tx_index, first.which, tx_idx, which
                    );
                    fraud.push(FraudEvidence::NullifierDoubleSpend {
                        first_block_nr: block_nr,
                        second_block_nr: block_nr,
                        first_tx_number: first.tx_index,
                        second_tx_number: tx_idx_u32,
                        first_which: first.which,
                        second_which: which,
                        nullifier,
                    });
                } else {
                    seen_in_block.insert(nullifier, record);
                    block_nullifiers.push((nullifier, record));
                }
            }
        }

        if block_nullifiers.is_empty() {
            return Ok(fraud);
        }

        // Step 2: Batch query database for cross-block duplicates
        let nullifier_hashes: Vec<B256> = block_nullifiers.iter().map(|(n, _)| *n).collect();
        let existing = state.get_nullifiers_batch(&nullifier_hashes)?;

        // Check which nullifiers already exist in database (cross-block double-spend)
        let mut new_nullifiers: Vec<(B256, NullifierRecord)> = Vec::new();
        for (nullifier, record) in block_nullifiers {
            if let Some(first) = existing.get(&nullifier) {
                warn!(
                    "Cross-block double-spend! nullifier={}, first=block {} tx {} which {}, second=block {} tx {} which {}",
                    nullifier, first.block_nr, first.tx_index, first.which,
                    block_nr, record.tx_index, record.which
                );
                fraud.push(FraudEvidence::NullifierDoubleSpend {
                    first_block_nr: first.block_nr,
                    second_block_nr: block_nr,
                    first_tx_number: first.tx_index,
                    second_tx_number: record.tx_index,
                    first_which: first.which,
                    second_which: record.which,
                    nullifier,
                });
            } else {
                new_nullifiers.push((nullifier, record));
            }
        }

        // Step 3: Batch save all new nullifiers
        if !new_nullifiers.is_empty() {
            debug!(
                "Saving {} new nullifiers for block {}",
                new_nullifiers.len(),
                block_nr
            );
            state.save_nullifiers_batch(&new_nullifiers)?;
        }

        if !fraud.is_empty() {
            info!(
                "Found {} double-spend attempts in block {}",
                fraud.len(),
                block_nr
            );
        }

        Ok(fraud)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp_common::blob::Blob;
    use pgp_common::types::constants::BLOB_SIZE;

    fn create_blob_with_transactions(nullifiers: &[(B256, B256)]) -> Blob {
        let mut blob = [B256::ZERO; BLOB_SIZE];

        // Transaction layout: [proof x8, anchor, null0, null1, leaf0, leaf1, leaf2, root] = 15 fields
        for (tx_idx, (null0, null1)) in nullifiers.iter().enumerate() {
            let base = tx_idx * 15;
            // Proof (8 fields) - leave as zero
            // Anchor (1 field) - leave as zero
            blob[base + 9] = *null0; // nullifier0
            blob[base + 10] = *null1; // nullifier1
                                      // Leaves and root - leave as zero
        }

        blob
    }

    #[test]
    fn test_nullifier_validator_no_double_spend() {
        let state = StateManager::in_memory().unwrap();
        let validator = NullifierValidator::new();

        let null1 = B256::repeat_byte(0x11);
        let null2 = B256::repeat_byte(0x22);
        let null3 = B256::repeat_byte(0x33);
        let null4 = B256::repeat_byte(0x44);

        // Block 1 with unique nullifiers
        let blob = create_blob_with_transactions(&[(null1, null2), (null3, null4)]);
        let parsed_block = ParsedBlock::from_blobs(&[blob], 0, 2).unwrap();

        let fraud = validator.process_block(&state, 1, &parsed_block).unwrap();
        assert!(
            fraud.is_empty(),
            "Should not detect fraud with unique nullifiers"
        );
        assert_eq!(state.nullifier_count().unwrap(), 4);
    }

    #[test]
    fn test_nullifier_validator_detects_double_spend_same_block() {
        let state = StateManager::in_memory().unwrap();
        let validator = NullifierValidator::new();

        let null1 = B256::repeat_byte(0x11);
        let null2 = B256::repeat_byte(0x22);

        // Block with duplicate nullifier in different transactions
        let blob = create_blob_with_transactions(&[(null1, null2), (null1, B256::ZERO)]);
        let parsed_block = ParsedBlock::from_blobs(&[blob], 0, 2).unwrap();

        let fraud = validator.process_block(&state, 1, &parsed_block).unwrap();
        assert_eq!(fraud.len(), 1, "Should detect one double-spend");

        match &fraud[0] {
            FraudEvidence::NullifierDoubleSpend {
                first_tx_number,
                second_tx_number,
                first_which,
                second_which,
                nullifier,
                ..
            } => {
                assert_eq!(*first_tx_number, 0);
                assert_eq!(*second_tx_number, 1);
                assert_eq!(*first_which, 0);
                assert_eq!(*second_which, 0);
                assert_eq!(*nullifier, null1);
            }
            _ => panic!("Expected NullifierDoubleSpend fraud"),
        }
    }

    #[test]
    fn test_nullifier_validator_detects_double_spend_different_blocks() {
        let state = StateManager::in_memory().unwrap();
        let validator = NullifierValidator::new();

        let null1 = B256::repeat_byte(0x11);
        let null2 = B256::repeat_byte(0x22);

        // Block 1
        let blob1 = create_blob_with_transactions(&[(null1, null2)]);
        let parsed_block1 = ParsedBlock::from_blobs(&[blob1], 0, 1).unwrap();

        let fraud1 = validator.process_block(&state, 1, &parsed_block1).unwrap();
        assert!(fraud1.is_empty());

        // Block 2 reuses null1
        let blob2 = create_blob_with_transactions(&[(null1, B256::ZERO)]);
        let parsed_block2 = ParsedBlock::from_blobs(&[blob2], 0, 1).unwrap();

        let fraud2 = validator.process_block(&state, 2, &parsed_block2).unwrap();
        assert_eq!(fraud2.len(), 1, "Should detect cross-block double-spend");
    }

    #[test]
    fn test_nullifier_validator_detects_double_spend_same_transaction() {
        let state = StateManager::in_memory().unwrap();
        let validator = NullifierValidator::new();

        // Same nullifier used for both inputs in a single transaction
        let null1 = B256::repeat_byte(0x11);

        let blob = create_blob_with_transactions(&[(null1, null1)]);
        let parsed_block = ParsedBlock::from_blobs(&[blob], 0, 1).unwrap();

        let fraud = validator.process_block(&state, 1, &parsed_block).unwrap();
        assert_eq!(
            fraud.len(),
            1,
            "Should detect double-spend within same transaction"
        );

        match &fraud[0] {
            FraudEvidence::NullifierDoubleSpend {
                first_block_nr,
                second_block_nr,
                first_tx_number,
                second_tx_number,
                first_which,
                second_which,
                nullifier,
            } => {
                assert_eq!(*first_block_nr, 1);
                assert_eq!(*second_block_nr, 1);
                assert_eq!(*first_tx_number, 0, "Both uses in same transaction");
                assert_eq!(*second_tx_number, 0, "Both uses in same transaction");
                assert_eq!(*first_which, 0, "First use is nullifier0");
                assert_eq!(*second_which, 1, "Second use is nullifier1");
                assert_eq!(*nullifier, null1);
            }
            _ => panic!("Expected NullifierDoubleSpend fraud"),
        }
    }

    #[test]
    fn test_nullifier_validator_rollback() {
        let state = StateManager::in_memory().unwrap();
        let validator = NullifierValidator::new();

        // Process blocks 1, 2, 3, each with 2 unique non-zero nullifiers
        for block_nr in 1..=3u64 {
            let null0 = B256::repeat_byte(block_nr as u8);
            let null1 = B256::repeat_byte((block_nr + 10) as u8);
            let blob = create_blob_with_transactions(&[(null0, null1)]);
            let parsed_block = ParsedBlock::from_blobs(&[blob], 0, 1).unwrap();
            validator
                .process_block(&state, block_nr, &parsed_block)
                .unwrap();
        }

        // 3 blocks * 2 nullifiers each = 6 total
        assert_eq!(state.nullifier_count().unwrap(), 6);

        // Rollback from block 2 using StateManager (keeps only block 1)
        state.delete_nullifiers_from(2).unwrap();
        assert_eq!(
            state.nullifier_count().unwrap(),
            2,
            "Should only keep nullifiers from block 1 (2 per block)"
        );
    }

    #[test]
    fn test_nullifier_validator_tracks_zero_nullifiers() {
        // Zero nullifiers are now tracked like any other nullifier.
        // While B256::ZERO is unlikely to be a valid nullifier output,
        // fraudulent proofs could use it, and we must detect double-spends.
        let state = StateManager::in_memory().unwrap();
        let validator = NullifierValidator::new();

        let blob = create_blob_with_transactions(&[(B256::ZERO, B256::ZERO)]);
        let parsed_block = ParsedBlock::from_blobs(&[blob], 0, 1).unwrap();

        // Same transaction uses ZERO twice - should detect as double-spend
        let fraud = validator.process_block(&state, 1, &parsed_block).unwrap();
        assert_eq!(
            fraud.len(),
            1,
            "Should detect double-spend of B256::ZERO within same transaction"
        );

        // Only the first ZERO is tracked (second was duplicate)
        assert_eq!(
            state.nullifier_count().unwrap(),
            1,
            "Should track zero nullifiers (the first occurrence)"
        );
    }

    #[test]
    fn test_nullifier_validator_zero_cross_block_double_spend() {
        // Test that zero nullifiers are checked for cross-block double-spend
        let state = StateManager::in_memory().unwrap();
        let validator = NullifierValidator::new();

        // Block 1: uses B256::ZERO once
        let blob1 = create_blob_with_transactions(&[(B256::ZERO, B256::repeat_byte(1))]);
        let parsed_block1 = ParsedBlock::from_blobs(&[blob1], 0, 1).unwrap();
        let fraud1 = validator.process_block(&state, 1, &parsed_block1).unwrap();
        assert!(fraud1.is_empty(), "Block 1 should have no fraud");
        assert_eq!(state.nullifier_count().unwrap(), 2);

        // Block 2: uses B256::ZERO again - should detect cross-block double-spend
        let blob2 = create_blob_with_transactions(&[(B256::ZERO, B256::repeat_byte(2))]);
        let parsed_block2 = ParsedBlock::from_blobs(&[blob2], 0, 1).unwrap();
        let fraud2 = validator.process_block(&state, 2, &parsed_block2).unwrap();
        assert_eq!(
            fraud2.len(),
            1,
            "Should detect B256::ZERO double-spend across blocks"
        );

        match &fraud2[0] {
            FraudEvidence::NullifierDoubleSpend {
                first_block_nr,
                second_block_nr,
                nullifier,
                ..
            } => {
                assert_eq!(*first_block_nr, 1);
                assert_eq!(*second_block_nr, 2);
                assert_eq!(*nullifier, B256::ZERO);
            }
            _ => panic!("Expected NullifierDoubleSpend fraud"),
        }
    }
}
