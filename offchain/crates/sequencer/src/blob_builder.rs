//! Blob builder for constructing blob data from deposits and transactions.
//!
//! The blob layout matches BlobData.sol:
//! ```text
//! [deposits range][transactions range]
//! ```
//!
//! Deposits: Each group of 3 deposits uses 4 fields `[leaf0, leaf1, leaf2, new_root]`
//! Transactions: Each transaction uses 15 fields `[proof(8), anchor_info, null0, null1, leaf0, leaf1, leaf2, new_root]`
//!
//! The `new_root` after each update is the full anchor (root of the 28-level root tree)
//! computed by combining the current block tree root with the root tree path.
//!
//! Supports multi-blob blocks: when deposits + transactions don't fit in a single blob,
//! they are split across multiple blobs with merkle tree state preserved across boundaries.

use crate::error::SequencerError;
use alloy::consensus::BlobTransactionSidecar;
use alloy::eips::eip4844::{Blob, BYTES_PER_BLOB};
use alloy_primitives::B256;
use pgp_challenger::BlockTreeTracker;
use pgp_common::types::constants::{
    BLOB_SIZE, DEPOSIT_GROUP_SIZE, MAX_DEPOSITS, MAX_LEAVES, ROOT_DEPTH, TX_SIZE,
};
use pgp_common::types::ParsedTransaction;

/// Maximum number of blobs per block (EIP-4844 limit per transaction)
pub const MAX_BLOBS_PER_BLOCK: usize = 10;

/// A fully built blob with all required data.
#[derive(Debug, Clone)]
pub struct BuiltBlob {
    /// Raw blob bytes (131072 bytes = 4096 fields * 32 bytes).
    pub bytes: Vec<u8>,
    /// The blob transaction sidecar ready for submission.
    pub sidecar: BlobTransactionSidecar,
    /// Number of deposits included in this blob.
    pub num_deposits: usize,
    /// Number of transactions included in this blob.
    pub num_transactions: usize,
}

/// Result of building blobs for a block.
#[derive(Debug, Clone)]
pub struct BuiltBlock {
    /// The built blobs (typically just one).
    pub blobs: Vec<BuiltBlob>,
    /// Final merkle root after all updates.
    pub anchor: B256,
    /// Total number of deposits across all blobs.
    pub total_deposits: usize,
    /// Total number of transactions across all blobs.
    pub total_transactions: usize,
}

/// Builder for constructing blob data from deposits and transactions.
///
/// Uses the two-level tree structure:
/// - Block tree (16 levels): Fresh for each block, stores leaves
/// - Root tree (28 levels): Persistent, stores block roots
///
/// The `new_root` after each update is the full anchor (root tree root with
/// current block tree root at the block's position).
pub struct BlobBuilder {
    /// Block tree tracker from challenger (handles anchor computation).
    /// This is Clone, allowing snapshots for rollback if block submission fails.
    tree_tracker: BlockTreeTracker,
}

impl BlobBuilder {
    /// Create a new BlobBuilder for a block.
    ///
    /// # Arguments
    /// * `tree_index` - Position of this block in the root tree (tree_index = day * 8192 + index_in_day)
    /// * `root_path` - The 28 sibling hashes for this block's position in the root tree
    pub fn new(tree_index: u64, root_path: [B256; ROOT_DEPTH]) -> Self {
        Self {
            tree_tracker: BlockTreeTracker::new(tree_index as usize, &root_path),
        }
    }

    /// Get a reference to the tree tracker.
    pub fn tree_tracker(&self) -> &BlockTreeTracker {
        &self.tree_tracker
    }

    /// Get a mutable reference to the tree tracker.
    pub fn tree_tracker_mut(&mut self) -> &mut BlockTreeTracker {
        &mut self.tree_tracker
    }

    /// Get the current block tree root (for storage in root tree after block is complete).
    pub fn block_root(&self) -> B256 {
        self.tree_tracker.block_root()
    }

    /// Get the tree index (position in root tree).
    pub fn tree_index(&self) -> u64 {
        self.tree_tracker.block_index()
    }

    /// Calculate the memory length required for deposits.
    /// Each 3 deposits use 4 slots (3 leaves + 1 root). Rounds up for partial groups.
    pub fn deposits_memory_length(num_deposits: usize) -> usize {
        if num_deposits == 0 {
            return 0;
        }
        let num_groups = num_deposits.div_ceil(3); // Ceiling division
        num_groups * DEPOSIT_GROUP_SIZE
    }

    /// Calculate the total memory length required.
    pub fn total_memory_length(num_deposits: usize, num_transactions: usize) -> usize {
        Self::deposits_memory_length(num_deposits) + num_transactions * TX_SIZE
    }

    /// Check if deposits and transactions fit in the available blobs.
    pub fn fits_in_blobs(num_deposits: usize, num_transactions: usize, num_blobs: usize) -> bool {
        let needed = Self::total_memory_length(num_deposits, num_transactions);
        let available = num_blobs * BLOB_SIZE;
        needed < available // Strict less-than per contract validation
    }

    /// Calculate the minimum number of blobs needed for the given data.
    pub fn required_blobs(num_deposits: usize, num_transactions: usize) -> usize {
        let needed = Self::total_memory_length(num_deposits, num_transactions);
        if needed == 0 {
            return 1; // At least one blob for empty validation
        }
        // Ceiling division: (needed + BLOB_SIZE - 1) / BLOB_SIZE
        // But we need strict less-than, so if needed == BLOB_SIZE we need 2 blobs
        (needed / BLOB_SIZE) + 1
    }

    /// Build blob data from deposits and transactions.
    ///
    /// Supports multi-blob blocks: when deposits + transactions don't fit in a single blob,
    /// they are automatically split across multiple blobs with merkle tree state preserved.
    ///
    /// # Arguments
    /// * `deposits` - Deposit leaf hashes to include
    /// * `transactions` - Parsed transactions to include (with ZK proofs and outputs)
    ///
    /// # Returns
    /// A `BuiltBlock` containing the blob sidecars and final anchor.
    pub fn build(
        &mut self,
        deposits: &[B256],
        transactions: &[ParsedTransaction],
    ) -> Result<BuiltBlock, SequencerError> {
        let num_deposits = deposits.len();
        let num_transactions = transactions.len();

        // Validate block is not empty
        if num_deposits == 0 && num_transactions == 0 {
            return Err(SequencerError::EmptyBlock);
        }

        // Validate limits
        if num_deposits > MAX_DEPOSITS {
            return Err(SequencerError::TooManyDeposits(num_deposits, MAX_DEPOSITS));
        }
        // Each deposit produces 1 leaf, each transaction produces 3 leaves
        let total_leaves = num_deposits + num_transactions * 3;
        if total_leaves > MAX_LEAVES {
            return Err(SequencerError::TooManyLeaves(total_leaves, MAX_LEAVES));
        }

        // Calculate how many blobs we need
        let required_blobs = Self::required_blobs(num_deposits, num_transactions);
        if required_blobs > MAX_BLOBS_PER_BLOCK {
            return Err(SequencerError::TooManyDeposits(
                num_deposits,
                MAX_DEPOSITS, // Exceeds even max blob capacity
            ));
        }

        // Build blob data across multiple blobs
        let mut built_blobs = Vec::with_capacity(required_blobs);
        let mut current_blob_fields: Vec<B256> = vec![B256::ZERO; BLOB_SIZE];
        let mut field_idx = 0;
        let mut deposits_in_current_blob = 0;
        let mut transactions_in_current_blob = 0;

        // Process deposits in groups of 3
        let num_groups = num_deposits.div_ceil(3);
        for group_idx in 0..num_groups {
            // Check if this group fits in current blob
            if field_idx + DEPOSIT_GROUP_SIZE > BLOB_SIZE {
                // Finalize current blob and start a new one
                let blob = finalize_blob(
                    &current_blob_fields,
                    deposits_in_current_blob,
                    transactions_in_current_blob,
                )?;
                built_blobs.push(blob);

                // Reset for new blob
                current_blob_fields = vec![B256::ZERO; BLOB_SIZE];
                field_idx = 0;
                deposits_in_current_blob = 0;
                transactions_in_current_blob = 0;
            }

            let base = group_idx * 3;

            // Leaf 0 (or zero if past end of deposits)
            let leaf0 = deposits.get(base).copied().unwrap_or(B256::ZERO);
            current_blob_fields[field_idx] = leaf0;
            field_idx += 1;

            // Leaf 1
            let leaf1 = deposits.get(base + 1).copied().unwrap_or(B256::ZERO);
            current_blob_fields[field_idx] = leaf1;
            field_idx += 1;

            // Leaf 2
            let leaf2 = deposits.get(base + 2).copied().unwrap_or(B256::ZERO);
            current_blob_fields[field_idx] = leaf2;
            field_idx += 1;

            // Count actual deposits in this group
            let group_deposits = (base..base + 3).filter(|&i| i < num_deposits).count();
            deposits_in_current_blob += group_deposits;

            // Apply the 3-leaf update to the tree builder
            // This inserts the leaves into the block tree and computes the full anchor
            let leaves = [leaf0, leaf1, leaf2];
            let new_anchor = self.tree_tracker.apply_update(leaves);
            current_blob_fields[field_idx] = new_anchor;
            field_idx += 1;
        }

        // Process transactions
        for tx in transactions {
            // Check if this transaction fits in current blob
            if field_idx + TX_SIZE > BLOB_SIZE {
                // Finalize current blob and start a new one
                let blob = finalize_blob(
                    &current_blob_fields,
                    deposits_in_current_blob,
                    transactions_in_current_blob,
                )?;
                built_blobs.push(blob);

                // Reset for new blob
                current_blob_fields = vec![B256::ZERO; BLOB_SIZE];
                field_idx = 0;
                deposits_in_current_blob = 0;
                transactions_in_current_blob = 0;
            }

            // Proof fields (8)
            current_blob_fields[field_idx] = tx.proof.a_x;
            current_blob_fields[field_idx + 1] = tx.proof.a_y;
            current_blob_fields[field_idx + 2] = tx.proof.b_x0;
            current_blob_fields[field_idx + 3] = tx.proof.b_x1;
            current_blob_fields[field_idx + 4] = tx.proof.b_y0;
            current_blob_fields[field_idx + 5] = tx.proof.b_y1;
            current_blob_fields[field_idx + 6] = tx.proof.c_x;
            current_blob_fields[field_idx + 7] = tx.proof.c_y;
            field_idx += 8;

            // Anchor info
            current_blob_fields[field_idx] = tx.anchor_info;
            field_idx += 1;

            // Nullifiers
            current_blob_fields[field_idx] = tx.nullifier0;
            current_blob_fields[field_idx + 1] = tx.nullifier1;
            field_idx += 2;

            // Output leaves
            current_blob_fields[field_idx] = tx.leaf0;
            current_blob_fields[field_idx + 1] = tx.leaf1;
            current_blob_fields[field_idx + 2] = tx.leaf2;
            field_idx += 3;

            // Apply the 3-leaf update to the tree builder
            let leaves = [tx.leaf0, tx.leaf1, tx.leaf2];
            let new_anchor = self.tree_tracker.apply_update(leaves);
            current_blob_fields[field_idx] = new_anchor;
            field_idx += 1;

            transactions_in_current_blob += 1;
        }

        // Finalize the last blob (always needed since we have content)
        let blob = finalize_blob(
            &current_blob_fields,
            deposits_in_current_blob,
            transactions_in_current_blob,
        )?;
        built_blobs.push(blob);

        let final_anchor = self.tree_tracker.current_anchor();

        Ok(BuiltBlock {
            blobs: built_blobs,
            anchor: final_anchor,
            total_deposits: num_deposits,
            total_transactions: num_transactions,
        })
    }

    /// Build a deposit-only block (no transactions).
    pub fn build_deposit_only(&mut self, deposits: &[B256]) -> Result<BuiltBlock, SequencerError> {
        self.build(deposits, &[])
    }
}

/// Convert blob fields (4096 B256 values) to raw bytes (131072 bytes).
fn fields_to_bytes(fields: &[B256]) -> Vec<u8> {
    let mut bytes = vec![0u8; BYTES_PER_BLOB];
    for (i, field) in fields.iter().enumerate() {
        let offset = i * 32;
        if offset + 32 <= bytes.len() {
            bytes[offset..offset + 32].copy_from_slice(field.as_slice());
        }
    }
    bytes
}

/// Finalize a blob by converting fields to bytes and creating KZG sidecar.
fn finalize_blob(
    fields: &[B256],
    num_deposits: usize,
    num_transactions: usize,
) -> Result<BuiltBlob, SequencerError> {
    let blob_bytes = fields_to_bytes(fields);
    let sidecar = create_sidecar(&blob_bytes)?;

    Ok(BuiltBlob {
        bytes: blob_bytes,
        sidecar,
        num_deposits,
        num_transactions,
    })
}

/// Create a KZG sidecar from raw blob bytes.
fn create_sidecar(blob_bytes: &[u8]) -> Result<BlobTransactionSidecar, SequencerError> {
    // Get Ethereum mainnet KZG settings
    let settings = c_kzg::ethereum_kzg_settings(0);

    // Convert to Blob type
    let blob = Blob::try_from(blob_bytes)
        .map_err(|e| SequencerError::KzgError(format!("Failed to create blob: {e:?}")))?;

    // Build sidecar with KZG commitment and proof
    let sidecar = BlobTransactionSidecar::try_from_blobs_with_settings(vec![blob], settings)
        .map_err(|e| SequencerError::KzgError(format!("Failed to build sidecar: {e:?}")))?;

    Ok(sidecar)
}

/// Create a sidecar from raw 32-byte field elements.
pub fn create_raw_sidecar(fields: &[B256]) -> Result<BlobTransactionSidecar, SequencerError> {
    let mut padded_fields = vec![B256::ZERO; BLOB_SIZE];
    for (i, field) in fields.iter().enumerate() {
        if i < BLOB_SIZE {
            padded_fields[i] = *field;
        }
    }
    let blob_bytes = fields_to_bytes(&padded_fields);
    create_sidecar(&blob_bytes)
}

/// Combine multiple BuiltBlobs into a single BlobTransactionSidecar for submission.
///
/// This is needed because a blob transaction can include multiple blobs, but they
/// must be submitted together with a combined sidecar.
///
/// Note: This uses raw KZG computation which is correct for mainnet but may not
/// work with Anvil. For Anvil testing, use `combine_blobs_into_sidecar_simple`.
pub fn combine_blobs_into_sidecar(
    blobs: &[BuiltBlob],
) -> Result<BlobTransactionSidecar, SequencerError> {
    if blobs.is_empty() {
        return Err(SequencerError::EmptyBlock);
    }

    if blobs.len() > MAX_BLOBS_PER_BLOCK {
        return Err(SequencerError::TooManyDeposits(
            blobs.len(),
            MAX_BLOBS_PER_BLOCK,
        ));
    }

    // Get Ethereum mainnet KZG settings
    let settings = c_kzg::ethereum_kzg_settings(0);

    // Convert all blobs
    let blob_data: Result<Vec<Blob>, _> = blobs
        .iter()
        .map(|b| Blob::try_from(b.bytes.as_slice()))
        .collect();

    let blob_data =
        blob_data.map_err(|e| SequencerError::KzgError(format!("Failed to create blob: {e:?}")))?;

    // Build combined sidecar
    let sidecar = BlobTransactionSidecar::try_from_blobs_with_settings(blob_data, settings)
        .map_err(|e| SequencerError::KzgError(format!("Failed to build sidecar: {e:?}")))?;

    Ok(sidecar)
}

/// Combine multiple BuiltBlobs into a sidecar using SimpleCoder (for Anvil testing).
///
/// Anvil's blob handling differs from mainnet. This function uses `SidecarBuilder<SimpleCoder>`
/// which is compatible with Anvil for testing purposes.
///
/// For mainnet/production, use `combine_blobs_into_sidecar` instead.
pub fn combine_blobs_into_sidecar_simple(
    blobs: &[BuiltBlob],
) -> Result<BlobTransactionSidecar, SequencerError> {
    use alloy::consensus::{SidecarBuilder, SimpleCoder};

    if blobs.is_empty() {
        return Err(SequencerError::EmptyBlock);
    }

    if blobs.len() > MAX_BLOBS_PER_BLOCK {
        return Err(SequencerError::TooManyDeposits(
            blobs.len(),
            MAX_BLOBS_PER_BLOCK,
        ));
    }

    // Concatenate all blob bytes
    let mut combined_bytes = Vec::new();
    for blob in blobs {
        combined_bytes.extend_from_slice(&blob.bytes);
    }

    // Build sidecar using SimpleCoder (Anvil compatible)
    let sidecar_builder: SidecarBuilder<SimpleCoder> = SidecarBuilder::from_slice(&combined_bytes);
    let sidecar = sidecar_builder
        .build()
        .map_err(|e| SequencerError::KzgError(format!("Failed to build simple sidecar: {e}")))?;

    Ok(sidecar)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a test blob builder with default (zero) root path at block index 0
    fn test_blob_builder() -> BlobBuilder {
        BlobBuilder::new(0, [B256::ZERO; ROOT_DEPTH])
    }

    /// Create a test blob builder at a specific block index
    fn test_blob_builder_at(block_index: u64) -> BlobBuilder {
        BlobBuilder::new(block_index, [B256::ZERO; ROOT_DEPTH])
    }

    #[test]
    fn test_deposits_memory_length() {
        assert_eq!(BlobBuilder::deposits_memory_length(0), 0);
        assert_eq!(BlobBuilder::deposits_memory_length(1), 4);
        assert_eq!(BlobBuilder::deposits_memory_length(2), 4);
        assert_eq!(BlobBuilder::deposits_memory_length(3), 4);
        assert_eq!(BlobBuilder::deposits_memory_length(4), 8);
        assert_eq!(BlobBuilder::deposits_memory_length(6), 8);
        assert_eq!(BlobBuilder::deposits_memory_length(7), 12);
    }

    #[test]
    fn test_fits_in_blobs() {
        // Empty fits
        assert!(BlobBuilder::fits_in_blobs(0, 0, 1));

        // Max deposits that fit (approximate)
        assert!(BlobBuilder::fits_in_blobs(3000, 0, 1));

        // Too many deposits
        assert!(!BlobBuilder::fits_in_blobs(4000, 0, 1));

        // Transactions only
        assert!(BlobBuilder::fits_in_blobs(0, 200, 1));

        // Too many transactions
        assert!(!BlobBuilder::fits_in_blobs(0, 300, 1)); // 300 * 15 = 4500 > 4096
    }

    #[test]
    fn test_build_empty_block_fails() {
        let mut builder = test_blob_builder();

        let result = builder.build(&[], &[]);
        assert!(matches!(result, Err(SequencerError::EmptyBlock)));
    }

    #[test]
    fn test_build_deposit_only() {
        let mut builder = test_blob_builder();

        let deposits = vec![
            B256::repeat_byte(0x01),
            B256::repeat_byte(0x02),
            B256::repeat_byte(0x03),
        ];

        let result = builder.build_deposit_only(&deposits);
        assert!(result.is_ok());

        let built = result.unwrap();
        assert_eq!(built.total_deposits, 3);
        assert_eq!(built.total_transactions, 0);
        assert_eq!(built.blobs.len(), 1);
        assert_ne!(built.anchor, B256::ZERO);
    }

    #[test]
    fn test_build_multiple_deposit_groups() {
        let mut builder = test_blob_builder();

        // 5 deposits = 2 groups (3 + 2)
        let deposits: Vec<B256> = (1..=5).map(|i| B256::repeat_byte(i as u8)).collect();

        let result = builder.build_deposit_only(&deposits);
        assert!(result.is_ok());

        let built = result.unwrap();
        assert_eq!(built.total_deposits, 5);

        // Verify blob structure: 2 groups * 4 fields = 8 fields
        // Check that fields are populated
        let bytes = &built.blobs[0].bytes;
        // First deposit should be at offset 0
        assert_eq!(&bytes[0..32], B256::repeat_byte(0x01).as_slice());
        // Second deposit at offset 32
        assert_eq!(&bytes[32..64], B256::repeat_byte(0x02).as_slice());
    }

    #[test]
    fn test_fields_to_bytes() {
        let fields = vec![B256::repeat_byte(0xAB); 10];
        let bytes = fields_to_bytes(&fields);

        assert_eq!(bytes.len(), BYTES_PER_BLOB);

        // First 10 fields should have the value
        for i in 0..10 {
            let offset = i * 32;
            assert_eq!(
                &bytes[offset..offset + 32],
                B256::repeat_byte(0xAB).as_slice()
            );
        }

        // Rest should be zeros
        assert_eq!(bytes[320], 0);
    }

    #[test]
    fn test_required_blobs() {
        // Empty or small data
        assert_eq!(BlobBuilder::required_blobs(0, 0), 1);
        assert_eq!(BlobBuilder::required_blobs(3, 0), 1);
        assert_eq!(BlobBuilder::required_blobs(0, 10), 1);

        // Data that fills most of one blob
        // 3000 deposits = 1000 groups * 4 = 4000 fields
        assert_eq!(BlobBuilder::required_blobs(3000, 0), 1);

        // Many transactions
        // 273 tx = 4095 fields, fits in 1 blob
        // 274 tx = 4110 fields, needs 2 blobs
        assert_eq!(BlobBuilder::required_blobs(0, 273), 1);
        assert_eq!(BlobBuilder::required_blobs(0, 274), 2);

        // Mixed deposits and transactions
        // 1500 deposits (2000 fields) + 140 tx (2100 fields) = 4100 fields, needs 2 blobs
        assert_eq!(BlobBuilder::required_blobs(1500, 140), 2);
    }

    #[test]
    fn test_multi_blob_fits() {
        // Small amount fits in 1 blob
        assert!(BlobBuilder::fits_in_blobs(100, 0, 1));

        // Large amount that almost fills blob still fits
        assert!(BlobBuilder::fits_in_blobs(3000, 0, 1)); // 4000 fields < 4096

        // Just over one blob needs 2
        // 3060 deposits = 1020 groups = 4080 fields, fits in 1
        assert!(BlobBuilder::fits_in_blobs(3060, 0, 1));
        // 3063 deposits = 1021 groups = 4084 fields, still fits in 1
        assert!(BlobBuilder::fits_in_blobs(3063, 0, 1));
        // Adding transactions pushes it over
        assert!(!BlobBuilder::fits_in_blobs(3063, 1, 1)); // 4084 + 15 = 4099 > 4096

        // Multi-blob scenarios
        assert!(BlobBuilder::fits_in_blobs(3063, 1, 2)); // Fits in 2 blobs
    }

    /// Create a valid field element for testing (small enough to fit in BN254 field)
    fn test_field_element(i: usize) -> B256 {
        // Use small values that fit in the BN254 field
        let mut bytes = [0u8; 32];
        // Put the index in the last 4 bytes (little-endian-ish)
        bytes[28] = ((i >> 24) & 0xFF) as u8;
        bytes[29] = ((i >> 16) & 0xFF) as u8;
        bytes[30] = ((i >> 8) & 0xFF) as u8;
        bytes[31] = (i & 0xFF) as u8;
        B256::from(bytes)
    }

    #[test]
    fn test_build_many_deposits() {
        let mut builder = test_blob_builder();

        // Create a moderate number of deposits to test scaling
        // (not too many to avoid stack overflow in merkle tree)
        let deposits: Vec<B256> = (0..100).map(test_field_element).collect();

        let result = builder.build_deposit_only(&deposits);
        assert!(result.is_ok(), "Build should succeed: {:?}", result.err());

        let built = result.unwrap();
        assert_eq!(built.total_deposits, 100);

        // 100 deposits = 34 groups * 4 = 136 fields, fits in 1 blob
        assert_eq!(built.blobs.len(), 1, "Should fit in 1 blob");

        // Anchor should be non-zero
        assert_ne!(built.anchor, B256::ZERO);
    }

    #[test]
    fn test_combine_blobs_empty_error() {
        // Test that combining empty blobs returns an error
        let result = combine_blobs_into_sidecar(&[]);
        assert!(matches!(result, Err(SequencerError::EmptyBlock)));
    }

    #[test]
    fn test_different_block_index_different_anchor() {
        // Same deposits at different block indices should produce different anchors
        let deposits = vec![
            B256::repeat_byte(0x01),
            B256::repeat_byte(0x02),
            B256::repeat_byte(0x03),
        ];

        let mut builder1 = test_blob_builder_at(0);
        let mut builder2 = test_blob_builder_at(1);

        let result1 = builder1.build_deposit_only(&deposits).unwrap();
        let result2 = builder2.build_deposit_only(&deposits).unwrap();

        // Different positions in root tree = different anchors
        assert_ne!(result1.anchor, result2.anchor);
    }

    #[test]
    fn test_anchor_computation_deterministic() {
        let deposits = vec![
            B256::repeat_byte(0x01),
            B256::repeat_byte(0x02),
            B256::repeat_byte(0x03),
        ];

        let mut builder1 = test_blob_builder_at(5);
        let mut builder2 = test_blob_builder_at(5);

        let result1 = builder1.build_deposit_only(&deposits).unwrap();
        let result2 = builder2.build_deposit_only(&deposits).unwrap();

        // Same inputs should produce same anchor
        assert_eq!(result1.anchor, result2.anchor);
    }
}
