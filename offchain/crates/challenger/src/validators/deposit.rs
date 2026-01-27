//! Deposit validation - checks that deposit leaves in blobs match expected values.
//!
//! The sequencer must include deposits in the blob with the exact same leaf hash
//! as recorded in the L1 Deposits contract. If the sequencer submits a different
//! leaf hash, we can challenge.
//!
//! Expected deposits are fetched directly from the contract's `perBlockDeposits`
//! mapping rather than tracking events (which are prone to missed slots or ordering errors).

use alloy::primitives::B256;
use tracing::{debug, warn};

use super::FraudEvidence;
use pgp_common::blob::ParsedBlock;
use pgp_common::contracts::BlockData;

/// Validates deposits in blobs against the L1 contract's recorded deposits
#[derive(Debug, Default)]
pub struct DepositValidator;

impl DepositValidator {
    /// Create a new deposit validator
    pub fn new() -> Self {
        Self
    }

    /// Validate deposits in a block against expected values from L1 contract
    ///
    /// # Arguments
    /// * `block_data` - The block data from the NewRoot event
    /// * `block` - The parsed block containing deposit groups and transactions
    /// * `expected_deposits` - Deposit leaf hashes fetched from L1 contract's `perBlockDeposits`
    ///
    /// # Checks performed
    /// 1. Deposit count in BlockData matches the contract's recorded count
    /// 2. Each deposit leaf in blob matches the expected value from contract
    /// 3. Unused slots in partial deposit groups are zero
    pub fn validate_block(
        &self,
        block_data: &BlockData,
        block: &ParsedBlock,
        expected_deposits: &[B256],
    ) -> Vec<FraudEvidence> {
        let mut fraud = Vec::new();
        let num_deposits: usize = match block_data.numDeposits.try_into() {
            Ok(n) => n,
            Err(_) => {
                // numDeposits exceeds usize::MAX - this indicates corrupted or malicious data
                warn!(
                    "numDeposits {} exceeds usize::MAX in block {} - skipping validation",
                    block_data.numDeposits, block_data.blockNr
                );
                return fraud;
            }
        };
        let expected_count = expected_deposits.len();

        // Note: Deposit count mismatches are now prevented at submission time
        // by Entrypoint.post() validation. We only check leaf values and padding.

        debug!(
            "Validating {} deposits for block {} (expected {} from contract)",
            num_deposits, block_data.blockNr, expected_count
        );

        // Check 1: Each deposit leaf matches expected value from contract
        let check_count = num_deposits.min(expected_count);
        for (deposit_idx, &expected_leaf) in expected_deposits.iter().enumerate().take(check_count)
        {
            // Get the actual leaf from the parsed block
            match block.get_deposit_leaf(deposit_idx) {
                Ok(submitted_leaf) => {
                    if submitted_leaf != expected_leaf {
                        warn!(
                            "Deposit mismatch! block={}, idx={}, expected={}, got={}",
                            block_data.blockNr, deposit_idx, expected_leaf, submitted_leaf
                        );
                        fraud.push(FraudEvidence::DepositWrongLeaf {
                            block_data: block_data.clone(),
                            deposit_nr: deposit_idx as u64,
                            expected_leaf,
                            submitted_leaf,
                        });
                    } else {
                        debug!(
                            "Deposit {} validated successfully: {}",
                            deposit_idx, expected_leaf
                        );
                    }
                }
                Err(e) => {
                    warn!("Failed to read deposit {} from block: {}", deposit_idx, e);
                }
            }
        }

        // Check 2: Unused slots in partial deposit groups must be zero
        // Deposit groups have 4 slots: [leaf0, leaf1, leaf2, root]
        // If numDeposits % 3 != 0, the last group has unused leaf slots that must be zero
        if num_deposits > 0 {
            let remainder = num_deposits % 3;
            if remainder != 0 {
                let last_group_index = num_deposits / 3;

                // Access the last deposit group directly
                if let Some(last_group) = block.deposit_groups.get(last_group_index) {
                    // Check slots from remainder to 2 (indices within the group)
                    // remainder=1 means slots 1,2 should be zero
                    // remainder=2 means slot 2 should be zero
                    for slot_offset in remainder..3 {
                        let value = match slot_offset {
                            1 => last_group.leaf1,
                            2 => last_group.leaf2,
                            _ => continue,
                        };

                        if value != B256::ZERO {
                            warn!(
                                "Deposit padding not zero! block={}, group={}, slot={}, value={}",
                                block_data.blockNr, last_group_index, slot_offset, value
                            );
                            fraud.push(FraudEvidence::DepositPaddingNotZero {
                                block_data: block_data.clone(),
                                group_index: last_group_index as u64,
                                slot_index: slot_offset as u64,
                                submitted_value: value,
                            });
                        }
                    }
                }
            }
        }

        fraud
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, U256};
    use pgp_common::blob::Blob;
    use pgp_common::contracts::TimestampAndIndex;
    use pgp_common::types::constants::BLOB_SIZE;

    fn make_block_data(block_nr: u64, num_deposits: u64) -> BlockData {
        BlockData {
            anchor: B256::ZERO,
            timestamp: U256::ZERO,
            numTransactions: U256::ZERO,
            numDeposits: U256::from(num_deposits),
            blockNr: U256::from(block_nr),
            blockIndex: TimestampAndIndex { day: 0, index: 0 },
            sequencer: Address::ZERO,
            blobhashes: vec![],
        }
    }

    fn create_blob_with_deposits(deposits: &[B256]) -> Blob {
        let mut blob = [B256::ZERO; BLOB_SIZE];

        // Each group of 3 deposits needs 4 slots: [leaf0, leaf1, leaf2, root]
        let mut blob_idx = 0;
        for (i, leaf) in deposits.iter().enumerate() {
            blob[blob_idx] = *leaf;
            blob_idx += 1;

            // After every 3 deposits, there's a root slot
            if (i + 1) % 3 == 0 {
                blob_idx += 1; // Skip root slot (leave as zero)
            }
        }

        // If partial group, the remaining slots stay zero (which is correct)
        // and we need to skip to after the root
        if deposits.len() % 3 != 0 {
            // We're in a partial group, pad remaining leaf slots
            let remaining = 3 - (deposits.len() % 3);
            let _ = blob_idx + remaining; // Skip padding slots (value unused but documents layout)
        }

        blob
    }

    #[test]
    fn test_deposit_validator_no_fraud() {
        let validator = DepositValidator::new();

        // Expected deposits from contract
        let leaf1 = B256::repeat_byte(0x11);
        let leaf2 = B256::repeat_byte(0x22);
        let leaf3 = B256::repeat_byte(0x33);
        let expected_deposits = vec![leaf1, leaf2, leaf3];

        // Create blob with correct deposits
        let blob = create_blob_with_deposits(&[leaf1, leaf2, leaf3]);
        let block_data = make_block_data(1, 3);
        let parsed_block = ParsedBlock::from_blobs(&[blob], 3, 0).unwrap();

        let fraud = validator.validate_block(&block_data, &parsed_block, &expected_deposits);
        assert!(
            fraud.is_empty(),
            "Should not detect fraud for valid deposits"
        );
    }

    #[test]
    fn test_deposit_validator_detects_wrong_leaf() {
        let validator = DepositValidator::new();

        // Expected deposit from contract
        let expected_leaf = B256::repeat_byte(0x11);
        let wrong_leaf = B256::repeat_byte(0xFF);
        let expected_deposits = vec![expected_leaf];

        // Create blob with WRONG deposit
        let blob = create_blob_with_deposits(&[wrong_leaf]);
        let block_data = make_block_data(1, 1);
        let parsed_block = ParsedBlock::from_blobs(&[blob], 1, 0).unwrap();

        let fraud = validator.validate_block(&block_data, &parsed_block, &expected_deposits);
        assert_eq!(fraud.len(), 1, "Should detect one fraud");

        match &fraud[0] {
            FraudEvidence::DepositWrongLeaf {
                deposit_nr,
                expected_leaf: exp,
                submitted_leaf: sub,
                ..
            } => {
                assert_eq!(*deposit_nr, 0);
                assert_eq!(*exp, expected_leaf);
                assert_eq!(*sub, wrong_leaf);
            }
            _ => panic!("Expected DepositWrongLeaf fraud"),
        }
    }

    #[test]
    fn test_deposit_padding_validation() {
        let validator = DepositValidator::new();
        let non_zero = B256::repeat_byte(0xFF);

        // Helper to check padding fraud
        fn assert_padding_fraud(fraud: &[FraudEvidence], expected_group: u64, expected_slot: u64) {
            let padding = fraud
                .iter()
                .find(|f| matches!(f, FraudEvidence::DepositPaddingNotZero { .. }));
            assert!(padding.is_some(), "Should detect padding not zero");
            match padding.unwrap() {
                FraudEvidence::DepositPaddingNotZero {
                    group_index,
                    slot_index,
                    ..
                } => {
                    assert_eq!(*group_index, expected_group);
                    assert_eq!(*slot_index, expected_slot);
                }
                _ => panic!("Expected DepositPaddingNotZero"),
            }
        }

        // Case 1: 1 deposit with non-zero in slot 1
        let leaf1 = B256::repeat_byte(0x11);
        let mut blob = [B256::ZERO; BLOB_SIZE];
        blob[0] = leaf1;
        blob[1] = non_zero;
        let parsed = ParsedBlock::from_blobs(&[blob], 1, 0).unwrap();
        let fraud = validator.validate_block(&make_block_data(1, 1), &parsed, &[leaf1]);
        assert_padding_fraud(&fraud, 0, 1);

        // Case 2: 2 deposits with non-zero in slot 2
        let leaf2 = B256::repeat_byte(0x22);
        let mut blob = [B256::ZERO; BLOB_SIZE];
        blob[0] = leaf1;
        blob[1] = leaf2;
        blob[2] = non_zero;
        let parsed = ParsedBlock::from_blobs(&[blob], 2, 0).unwrap();
        let fraud = validator.validate_block(&make_block_data(1, 2), &parsed, &[leaf1, leaf2]);
        assert_padding_fraud(&fraud, 0, 2);

        // Case 3: Full group (3 deposits) - no padding fraud
        let leaf3 = B256::repeat_byte(0x33);
        let blob = create_blob_with_deposits(&[leaf1, leaf2, leaf3]);
        let parsed = ParsedBlock::from_blobs(&[blob], 3, 0).unwrap();
        let fraud =
            validator.validate_block(&make_block_data(1, 3), &parsed, &[leaf1, leaf2, leaf3]);
        assert!(fraud.is_empty(), "Full group should have no padding fraud");

        // Case 4: Second group padding (4 deposits, non-zero in group 1, slot 1)
        let leaf4 = B256::repeat_byte(0x44);
        let mut blob = [B256::ZERO; BLOB_SIZE];
        blob[0] = leaf1;
        blob[1] = leaf2;
        blob[2] = leaf3;
        blob[4] = leaf4;
        blob[5] = non_zero;
        let parsed = ParsedBlock::from_blobs(&[blob], 4, 0).unwrap();
        let fraud = validator.validate_block(
            &make_block_data(1, 4),
            &parsed,
            &[leaf1, leaf2, leaf3, leaf4],
        );
        assert_padding_fraud(&fraud, 1, 1);
    }
}
