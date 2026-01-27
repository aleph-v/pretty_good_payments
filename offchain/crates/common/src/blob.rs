//! Blob data parsing matching the layout defined in BlobData.sol.
//!
//! Blob structure:
//! ```text
//! [deposits range][transactions range]
//! ```
//!
//! Each deposit group: `[leaf0, leaf1, leaf2, new_root]` (4 fields)
//! Each transaction: `[proof(8), anchor_info, null0, null1, leaf0, leaf1, leaf2, new_root]` (15 fields)

use crate::types::{
    constants::{BLOB_SIZE, DEPOSIT_GROUP_SIZE, TX_SIZE},
    Groth16Proof, ParsedDepositGroup, ParsedTransaction,
};
use alloy_primitives::B256;
use thiserror::Error;

/// Errors that can occur during blob parsing
#[derive(Debug, Error)]
pub enum BlobParseError {
    #[error("Blob {blob_index} has invalid size: expected {expected}, got {actual}")]
    InvalidBlobSize {
        blob_index: usize,
        expected: usize,
        actual: usize,
    },

    #[error("No blobs provided")]
    NoBlobs,

    #[error(
        "Insufficient blob space: need {needed} fields, have {available} across {num_blobs} blobs"
    )]
    InsufficientBlobSpace {
        needed: usize,
        available: usize,
        num_blobs: usize,
    },

    #[error("Memory address {address} out of bounds (max {max})")]
    AddressOutOfBounds { address: usize, max: usize },

    #[error("Invalid deposit index {index} for {num_deposits} deposits")]
    InvalidDepositIndex { index: usize, num_deposits: usize },

    #[error("Invalid transaction index {index} for {num_transactions} transactions")]
    InvalidTransactionIndex {
        index: usize,
        num_transactions: usize,
    },
}

/// A single blob - exactly 4096 field elements
pub type Blob = [B256; BLOB_SIZE];

/// A fully parsed block extracted from blob data.
///
/// This struct provides a clean interface for accessing deposit groups and transactions
/// without exposing memory address calculations.
#[derive(Debug, Clone, Default)]
pub struct ParsedBlock {
    /// All deposit groups in the block (each group contains up to 3 deposits + new root)
    pub deposit_groups: Vec<ParsedDepositGroup>,
    /// All transactions in the block
    pub transactions: Vec<ParsedTransaction>,
    /// Number of actual deposits (may be less than deposit_groups.len() * 3 for partial last group)
    pub num_deposits: usize,
}

impl ParsedBlock {
    /// Parse a block from one or more blobs.
    ///
    /// # Arguments
    /// * `blobs` - Array of blobs, each exactly 4096 B256 elements
    /// * `num_deposits` - Number of deposits in the block
    /// * `num_transactions` - Number of transactions in the block
    ///
    /// # Errors
    /// Returns an error if:
    /// - No blobs are provided
    /// - Any blob is not exactly 4096 elements
    /// - There isn't enough space for the specified deposits and transactions
    pub fn from_blobs(
        blobs: &[Blob],
        num_deposits: usize,
        num_transactions: usize,
    ) -> Result<Self, BlobParseError> {
        if blobs.is_empty() {
            return Err(BlobParseError::NoBlobs);
        }

        // Calculate required space
        let deposits_length = Self::deposits_memory_length(num_deposits);
        let total_needed = deposits_length + num_transactions * TX_SIZE;
        let total_available = blobs.len() * BLOB_SIZE;

        if total_needed > total_available {
            return Err(BlobParseError::InsufficientBlobSpace {
                needed: total_needed,
                available: total_available,
                num_blobs: blobs.len(),
            });
        }

        // Create a linear view of all blob data for easier parsing
        let blob_reader = BlobReader::new(blobs);

        // Parse deposit groups
        let num_groups = num_deposits.div_ceil(3); // Ceiling division
        let mut deposit_groups = Vec::with_capacity(num_groups);

        for group_idx in 0..num_groups {
            let start = group_idx * DEPOSIT_GROUP_SIZE;
            deposit_groups.push(ParsedDepositGroup {
                leaf0: blob_reader.get(start)?,
                leaf1: blob_reader.get(start + 1)?,
                leaf2: blob_reader.get(start + 2)?,
                new_root: blob_reader.get(start + 3)?,
            });
        }

        // Parse transactions
        let mut transactions = Vec::with_capacity(num_transactions);

        for tx_idx in 0..num_transactions {
            let start = deposits_length + tx_idx * TX_SIZE;

            let proof = Groth16Proof {
                a_x: blob_reader.get(start)?,
                a_y: blob_reader.get(start + 1)?,
                b_x0: blob_reader.get(start + 2)?,
                b_x1: blob_reader.get(start + 3)?,
                b_y0: blob_reader.get(start + 4)?,
                b_y1: blob_reader.get(start + 5)?,
                c_x: blob_reader.get(start + 6)?,
                c_y: blob_reader.get(start + 7)?,
            };

            transactions.push(ParsedTransaction {
                proof,
                anchor_info: blob_reader.get(start + 8)?,
                nullifier0: blob_reader.get(start + 9)?,
                nullifier1: blob_reader.get(start + 10)?,
                leaf0: blob_reader.get(start + 11)?,
                leaf1: blob_reader.get(start + 12)?,
                leaf2: blob_reader.get(start + 13)?,
                new_root: blob_reader.get(start + 14)?,
            });
        }

        Ok(Self {
            deposit_groups,
            transactions,
            num_deposits,
        })
    }

    /// Parse a block from a vector of blob vectors (convenience method).
    ///
    /// This method validates that each blob is exactly 4096 elements.
    pub fn from_blob_vecs(
        blobs: &[Vec<B256>],
        num_deposits: usize,
        num_transactions: usize,
    ) -> Result<Self, BlobParseError> {
        // Validate all blobs are correct size
        for (i, blob) in blobs.iter().enumerate() {
            if blob.len() != BLOB_SIZE {
                return Err(BlobParseError::InvalidBlobSize {
                    blob_index: i,
                    expected: BLOB_SIZE,
                    actual: blob.len(),
                });
            }
        }

        if blobs.is_empty() {
            return Err(BlobParseError::NoBlobs);
        }

        // Calculate required space
        let deposits_length = Self::deposits_memory_length(num_deposits);
        let total_needed = deposits_length + num_transactions * TX_SIZE;
        let total_available = blobs.len() * BLOB_SIZE;

        if total_needed > total_available {
            return Err(BlobParseError::InsufficientBlobSpace {
                needed: total_needed,
                available: total_available,
                num_blobs: blobs.len(),
            });
        }

        // Create a linear view for easier parsing
        let blob_reader = VecBlobReader::new(blobs);

        // Parse deposit groups
        let num_groups = num_deposits.div_ceil(3);
        let mut deposit_groups = Vec::with_capacity(num_groups);

        for group_idx in 0..num_groups {
            let start = group_idx * DEPOSIT_GROUP_SIZE;
            deposit_groups.push(ParsedDepositGroup {
                leaf0: blob_reader.get(start)?,
                leaf1: blob_reader.get(start + 1)?,
                leaf2: blob_reader.get(start + 2)?,
                new_root: blob_reader.get(start + 3)?,
            });
        }

        // Parse transactions
        let mut transactions = Vec::with_capacity(num_transactions);

        for tx_idx in 0..num_transactions {
            let start = deposits_length + tx_idx * TX_SIZE;

            let proof = Groth16Proof {
                a_x: blob_reader.get(start)?,
                a_y: blob_reader.get(start + 1)?,
                b_x0: blob_reader.get(start + 2)?,
                b_x1: blob_reader.get(start + 3)?,
                b_y0: blob_reader.get(start + 4)?,
                b_y1: blob_reader.get(start + 5)?,
                c_x: blob_reader.get(start + 6)?,
                c_y: blob_reader.get(start + 7)?,
            };

            transactions.push(ParsedTransaction {
                proof,
                anchor_info: blob_reader.get(start + 8)?,
                nullifier0: blob_reader.get(start + 9)?,
                nullifier1: blob_reader.get(start + 10)?,
                leaf0: blob_reader.get(start + 11)?,
                leaf1: blob_reader.get(start + 12)?,
                leaf2: blob_reader.get(start + 13)?,
                new_root: blob_reader.get(start + 14)?,
            });
        }

        Ok(Self {
            deposit_groups,
            transactions,
            num_deposits,
        })
    }

    /// Calculate memory length required for deposits.
    /// Each 3 deposits use 4 slots (3 leaves + 1 root). Rounds up for partial groups.
    pub fn deposits_memory_length(num_deposits: usize) -> usize {
        if num_deposits == 0 {
            return 0;
        }
        let num_groups = num_deposits.div_ceil(3);
        num_groups * DEPOSIT_GROUP_SIZE
    }

    /// Get the number of deposit groups.
    pub fn num_deposit_groups(&self) -> usize {
        self.deposit_groups.len()
    }

    /// Get a specific deposit leaf by its absolute index (0 to num_deposits-1).
    ///
    /// This handles the group structure internally.
    pub fn get_deposit_leaf(&self, deposit_index: usize) -> Result<B256, BlobParseError> {
        if deposit_index >= self.num_deposits {
            return Err(BlobParseError::InvalidDepositIndex {
                index: deposit_index,
                num_deposits: self.num_deposits,
            });
        }

        let group_idx = deposit_index / 3;
        let leaf_idx = deposit_index % 3;

        let group = &self.deposit_groups[group_idx];
        Ok(match leaf_idx {
            0 => group.leaf0,
            1 => group.leaf1,
            2 => group.leaf2,
            _ => unreachable!(),
        })
    }

    /// Get all deposit leaves as a flat vector.
    pub fn get_all_deposit_leaves(&self) -> Vec<B256> {
        let mut leaves = Vec::with_capacity(self.num_deposits);
        for i in 0..self.num_deposits {
            if let Ok(leaf) = self.get_deposit_leaf(i) {
                leaves.push(leaf);
            }
        }
        leaves
    }

    /// Get the new root after a specific deposit group.
    pub fn get_deposit_group_root(&self, group_index: usize) -> Result<B256, BlobParseError> {
        self.deposit_groups
            .get(group_index)
            .map(|g| g.new_root)
            .ok_or(BlobParseError::InvalidDepositIndex {
                index: group_index,
                num_deposits: self.deposit_groups.len(),
            })
    }

    /// Get the new root after a specific transaction.
    pub fn get_transaction_root(&self, tx_index: usize) -> Result<B256, BlobParseError> {
        self.transactions.get(tx_index).map(|t| t.new_root).ok_or(
            BlobParseError::InvalidTransactionIndex {
                index: tx_index,
                num_transactions: self.transactions.len(),
            },
        )
    }

    /// Get nullifiers for a specific transaction.
    pub fn get_transaction_nullifiers(
        &self,
        tx_index: usize,
    ) -> Result<(B256, B256), BlobParseError> {
        self.transactions
            .get(tx_index)
            .map(|t| (t.nullifier0, t.nullifier1))
            .ok_or(BlobParseError::InvalidTransactionIndex {
                index: tx_index,
                num_transactions: self.transactions.len(),
            })
    }

    /// Iterate over all non-zero nullifiers in the block.
    ///
    /// Returns tuples of (tx_index, which_nullifier, nullifier_value).
    pub fn iter_nullifiers(&self) -> impl Iterator<Item = (usize, usize, B256)> + '_ {
        self.transactions
            .iter()
            .enumerate()
            .flat_map(|(tx_idx, tx)| {
                let mut nullifiers = Vec::new();
                if tx.nullifier0 != B256::ZERO {
                    nullifiers.push((tx_idx, 0, tx.nullifier0));
                }
                if tx.nullifier1 != B256::ZERO {
                    nullifiers.push((tx_idx, 1, tx.nullifier1));
                }
                nullifiers
            })
    }

    /// Get the prior root for a deposit group (the root before this group was applied).
    ///
    /// For group 0, this would be the anchor from BlockData.
    /// For group N > 0, this is the new_root from group N-1.
    pub fn get_deposit_prior_root(
        &self,
        group_index: usize,
    ) -> Result<Option<B256>, BlobParseError> {
        if group_index >= self.deposit_groups.len() {
            return Err(BlobParseError::InvalidDepositIndex {
                index: group_index,
                num_deposits: self.deposit_groups.len(),
            });
        }

        if group_index == 0 {
            Ok(None) // Prior root is from BlockData.anchor
        } else {
            Ok(Some(self.deposit_groups[group_index - 1].new_root))
        }
    }

    /// Get the prior root for a transaction (the root before this tx was applied).
    ///
    /// For tx 0, this is either the last deposit group's root, or the anchor if no deposits.
    /// For tx N > 0, this is the new_root from tx N-1.
    pub fn get_transaction_prior_root(
        &self,
        tx_index: usize,
    ) -> Result<Option<B256>, BlobParseError> {
        if tx_index >= self.transactions.len() {
            return Err(BlobParseError::InvalidTransactionIndex {
                index: tx_index,
                num_transactions: self.transactions.len(),
            });
        }

        if tx_index == 0 {
            // Prior root is either last deposit group's root or BlockData.anchor
            if let Some(last_group) = self.deposit_groups.last() {
                Ok(Some(last_group.new_root))
            } else {
                Ok(None) // Prior root is from BlockData.anchor
            }
        } else {
            Ok(Some(self.transactions[tx_index - 1].new_root))
        }
    }

    /// Get the final root after all updates in the block.
    pub fn final_root(&self) -> Option<B256> {
        // Check transactions first (they come after deposits)
        if let Some(last_tx) = self.transactions.last() {
            return Some(last_tx.new_root);
        }
        // Otherwise check deposit groups
        if let Some(last_group) = self.deposit_groups.last() {
            return Some(last_group.new_root);
        }
        None
    }
}

/// Helper to read from an array of fixed-size blobs
struct BlobReader<'a> {
    blobs: &'a [Blob],
}

impl<'a> BlobReader<'a> {
    fn new(blobs: &'a [Blob]) -> Self {
        Self { blobs }
    }

    fn get(&self, address: usize) -> Result<B256, BlobParseError> {
        let blob_idx = address / BLOB_SIZE;
        let field_idx = address % BLOB_SIZE;

        self.blobs
            .get(blob_idx)
            .and_then(|blob| blob.get(field_idx))
            .copied()
            .ok_or(BlobParseError::AddressOutOfBounds {
                address,
                max: self.blobs.len() * BLOB_SIZE,
            })
    }
}

/// Helper to read from a vector of blob vectors
struct VecBlobReader<'a> {
    blobs: &'a [Vec<B256>],
}

impl<'a> VecBlobReader<'a> {
    fn new(blobs: &'a [Vec<B256>]) -> Self {
        Self { blobs }
    }

    fn get(&self, address: usize) -> Result<B256, BlobParseError> {
        let blob_idx = address / BLOB_SIZE;
        let field_idx = address % BLOB_SIZE;

        self.blobs
            .get(blob_idx)
            .and_then(|blob| blob.get(field_idx))
            .copied()
            .ok_or(BlobParseError::AddressOutOfBounds {
                address,
                max: self.blobs.len() * BLOB_SIZE,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_blob_array(fill_value: u8) -> Blob {
        let mut blob = [B256::ZERO; BLOB_SIZE];
        for (i, field) in blob.iter_mut().enumerate() {
            *field = B256::from(alloy_primitives::U256::from(
                i + (fill_value as usize) * 10000,
            ));
        }
        blob
    }

    fn create_test_blob_vec(size: usize) -> Vec<B256> {
        (0..size)
            .map(|i| B256::from(alloy_primitives::U256::from(i)))
            .collect()
    }

    #[test]
    fn test_deposits_memory_length() {
        assert_eq!(ParsedBlock::deposits_memory_length(0), 0);
        assert_eq!(ParsedBlock::deposits_memory_length(1), 4);
        assert_eq!(ParsedBlock::deposits_memory_length(2), 4);
        assert_eq!(ParsedBlock::deposits_memory_length(3), 4);
        assert_eq!(ParsedBlock::deposits_memory_length(4), 8);
        assert_eq!(ParsedBlock::deposits_memory_length(6), 8);
        assert_eq!(ParsedBlock::deposits_memory_length(7), 12);
    }

    #[test]
    fn test_parse_block_no_blobs() {
        let blobs: Vec<Blob> = vec![];
        let result = ParsedBlock::from_blobs(&blobs, 0, 0);
        assert!(matches!(result, Err(BlobParseError::NoBlobs)));
    }

    #[test]
    fn test_parse_block_with_deposits() {
        let blob = create_test_blob_array(0);
        let blobs = vec![blob];

        let block = ParsedBlock::from_blobs(&blobs, 6, 0).unwrap();

        assert_eq!(block.num_deposits, 6);
        assert_eq!(block.deposit_groups.len(), 2);
        assert_eq!(block.transactions.len(), 0);

        // Check first group
        let g0 = &block.deposit_groups[0];
        assert_eq!(g0.leaf0, B256::from(alloy_primitives::U256::from(0)));
        assert_eq!(g0.leaf1, B256::from(alloy_primitives::U256::from(1)));
        assert_eq!(g0.leaf2, B256::from(alloy_primitives::U256::from(2)));
        assert_eq!(g0.new_root, B256::from(alloy_primitives::U256::from(3)));

        // Check second group
        let g1 = &block.deposit_groups[1];
        assert_eq!(g1.leaf0, B256::from(alloy_primitives::U256::from(4)));
    }

    #[test]
    fn test_parse_block_with_transactions() {
        let blob = create_test_blob_array(0);
        let blobs = vec![blob];

        let block = ParsedBlock::from_blobs(&blobs, 0, 2).unwrap();

        assert_eq!(block.num_deposits, 0);
        assert_eq!(block.deposit_groups.len(), 0);
        assert_eq!(block.transactions.len(), 2);

        // Check first transaction
        let tx0 = &block.transactions[0];
        assert_eq!(tx0.anchor_info, B256::from(alloy_primitives::U256::from(8)));
        assert_eq!(tx0.nullifier0, B256::from(alloy_primitives::U256::from(9)));
        assert_eq!(tx0.nullifier1, B256::from(alloy_primitives::U256::from(10)));
        assert_eq!(tx0.leaf0, B256::from(alloy_primitives::U256::from(11)));
        assert_eq!(tx0.new_root, B256::from(alloy_primitives::U256::from(14)));

        // Check second transaction starts at offset 15
        let tx1 = &block.transactions[1];
        assert_eq!(
            tx1.anchor_info,
            B256::from(alloy_primitives::U256::from(15 + 8))
        );
    }

    #[test]
    fn test_parse_block_mixed() {
        let blob = create_test_blob_array(0);
        let blobs = vec![blob];

        let block = ParsedBlock::from_blobs(&blobs, 3, 1).unwrap();

        assert_eq!(block.num_deposits, 3);
        assert_eq!(block.deposit_groups.len(), 1);
        assert_eq!(block.transactions.len(), 1);

        // Deposits use 4 fields, then transaction starts
        let tx = &block.transactions[0];
        assert_eq!(
            tx.anchor_info,
            B256::from(alloy_primitives::U256::from(4 + 8))
        );
    }

    #[test]
    fn test_get_deposit_leaf() {
        let blob = create_test_blob_array(0);
        let blobs = vec![blob];
        let block = ParsedBlock::from_blobs(&blobs, 5, 0).unwrap();

        // Deposits 0, 1, 2 in group 0
        assert_eq!(
            block.get_deposit_leaf(0).unwrap(),
            B256::from(alloy_primitives::U256::from(0))
        );
        assert_eq!(
            block.get_deposit_leaf(1).unwrap(),
            B256::from(alloy_primitives::U256::from(1))
        );
        assert_eq!(
            block.get_deposit_leaf(2).unwrap(),
            B256::from(alloy_primitives::U256::from(2))
        );

        // Deposits 3, 4 in group 1 (starting at field 4)
        assert_eq!(
            block.get_deposit_leaf(3).unwrap(),
            B256::from(alloy_primitives::U256::from(4))
        );
        assert_eq!(
            block.get_deposit_leaf(4).unwrap(),
            B256::from(alloy_primitives::U256::from(5))
        );

        // Deposit 5 is out of bounds
        assert!(block.get_deposit_leaf(5).is_err());
    }

    #[test]
    fn test_get_all_deposit_leaves() {
        let blob = create_test_blob_array(0);
        let blobs = vec![blob];
        let block = ParsedBlock::from_blobs(&blobs, 4, 0).unwrap();

        let leaves = block.get_all_deposit_leaves();
        assert_eq!(leaves.len(), 4);
        assert_eq!(leaves[0], B256::from(alloy_primitives::U256::from(0)));
        assert_eq!(leaves[1], B256::from(alloy_primitives::U256::from(1)));
        assert_eq!(leaves[2], B256::from(alloy_primitives::U256::from(2)));
        assert_eq!(leaves[3], B256::from(alloy_primitives::U256::from(4))); // Skips root at index 3
    }

    #[test]
    fn test_iter_nullifiers() {
        let mut blob = [B256::ZERO; BLOB_SIZE];
        // Set up a transaction with non-zero nullifiers at positions 9 and 10
        blob[9] = B256::repeat_byte(0x11);
        blob[10] = B256::repeat_byte(0x22);

        let blobs = vec![blob];
        let block = ParsedBlock::from_blobs(&blobs, 0, 1).unwrap();

        let nullifiers: Vec<_> = block.iter_nullifiers().collect();
        assert_eq!(nullifiers.len(), 2);
        assert_eq!(nullifiers[0], (0, 0, B256::repeat_byte(0x11)));
        assert_eq!(nullifiers[1], (0, 1, B256::repeat_byte(0x22)));
    }

    #[test]
    fn test_prior_roots() {
        let blob = create_test_blob_array(0);
        let blobs = vec![blob];
        let block = ParsedBlock::from_blobs(&blobs, 6, 2).unwrap();

        // First deposit group has no prior root in blob
        assert_eq!(block.get_deposit_prior_root(0).unwrap(), None);

        // Second deposit group's prior is first group's new_root
        assert_eq!(
            block.get_deposit_prior_root(1).unwrap(),
            Some(B256::from(alloy_primitives::U256::from(3)))
        );

        // First tx's prior is last deposit group's new_root
        assert_eq!(
            block.get_transaction_prior_root(0).unwrap(),
            Some(B256::from(alloy_primitives::U256::from(7)))
        );

        // Second tx's prior is first tx's new_root
        let first_tx_root = block.transactions[0].new_root;
        assert_eq!(
            block.get_transaction_prior_root(1).unwrap(),
            Some(first_tx_root)
        );
    }

    #[test]
    fn test_final_root() {
        let blob = create_test_blob_array(0);
        let blobs = vec![blob];

        // Block with only deposits
        let block1 = ParsedBlock::from_blobs(&blobs, 3, 0).unwrap();
        assert_eq!(block1.final_root(), Some(block1.deposit_groups[0].new_root));

        // Block with deposits and transactions
        let block2 = ParsedBlock::from_blobs(&blobs, 3, 1).unwrap();
        assert_eq!(block2.final_root(), Some(block2.transactions[0].new_root));

        // Empty block
        let block3 = ParsedBlock::from_blobs(&blobs, 0, 0).unwrap();
        assert_eq!(block3.final_root(), None);
    }

    #[test]
    fn test_from_blob_vecs_validates_size() {
        let small_blob = create_test_blob_vec(100);
        let result = ParsedBlock::from_blob_vecs(&[small_blob], 0, 0);

        assert!(matches!(
            result,
            Err(BlobParseError::InvalidBlobSize { .. })
        ));
    }

    #[test]
    fn test_from_blob_vecs_success() {
        let blob = create_test_blob_vec(BLOB_SIZE);
        let block = ParsedBlock::from_blob_vecs(&[blob], 3, 1).unwrap();

        assert_eq!(block.num_deposits, 3);
        assert_eq!(block.deposit_groups.len(), 1);
        assert_eq!(block.transactions.len(), 1);
    }

    #[test]
    fn test_insufficient_blob_space() {
        let blob = create_test_blob_array(0);
        let blobs = vec![blob];

        // Try to parse way more data than fits in one blob
        let result = ParsedBlock::from_blobs(&blobs, 0, 1000);

        assert!(matches!(
            result,
            Err(BlobParseError::InsufficientBlobSpace { .. })
        ));
    }
}
