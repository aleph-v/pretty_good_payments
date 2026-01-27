//! Challenge submission module for fraud proofs.
//!
//! This module handles converting detected fraud into on-chain challenge transactions.

use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::Provider;
use eyre::{eyre, Result};
use tracing::{debug, info};

/// Safely convert U256 to u64, returning error if value exceeds u64::MAX
fn u256_to_u64(value: U256, field_name: &str) -> Result<u64> {
    value.try_into().map_err(|_| {
        eyre!(
            "{} value {} exceeds u64::MAX - data is corrupted or malicious",
            field_name,
            value
        )
    })
}

use crate::kzg::{KzgFieldProof, KzgProver};
use crate::validators::FraudEvidence;
use pgp_common::contracts::{
    BlockData, DepositChallenge, NullifierChallenge, NullifierLoader, Proof, Region,
    TransactionChallenge, TreeUpdateChallenge,
};

/// Number of 32-byte fields per blob (4096 fields = 131072 bytes)
pub const BLOB_FIELD_COUNT: usize = 4096;

/// Represents a blob with its data and versioned hash
#[derive(Debug, Clone)]
pub struct BlobWithHash<'a> {
    /// Raw blob bytes (131072 bytes)
    pub data: &'a [u8],
    /// Versioned blob hash (from EIP-4844)
    pub hash: B256,
}

/// Result of building regions that may span blob boundaries
#[derive(Debug, Clone)]
pub struct RegionPair {
    /// Main region (always populated)
    pub region: Region,
    /// Extension region (populated if data crosses blob boundary)
    pub extension: Region,
}

/// Data required to submit a deposit wrong leaf challenge
#[derive(Debug, Clone)]
pub struct DepositChallengeParams {
    /// Block data containing the fraudulent deposit
    pub block_data: BlockData,
    /// Index of the fraudulent deposit
    pub deposit_nr: u64,
    /// The value the sequencer put in the blob
    pub sequencer_submitted_leaf: [u8; 32],
    /// 48-byte KZG commitment for the blob
    pub commitment: Bytes,
    /// 48-byte KZG proof for the leaf
    pub proof: Bytes,
    /// Block data for rollback target (block before the fraudulent one)
    pub prior_block: BlockData,
}

/// Data required to submit a nullifier double-spend challenge
#[derive(Debug, Clone)]
pub struct NullifierChallengeParams {
    /// Reused nullifier value
    pub reused_nullifier: B256,
    /// Block containing first usage
    pub first_block_data: BlockData,
    /// Block containing second usage
    pub second_block_data: BlockData,
    /// Transaction number in first block
    pub first_tx_number: u64,
    /// Transaction number in second block
    pub second_tx_number: u64,
    /// Which nullifier in first tx (0 or 1)
    pub first_which: u8,
    /// Which nullifier in second tx (0 or 1)
    pub second_which: u8,
    /// KZG commitment for first block's blob
    pub first_commitment: Bytes,
    /// KZG proof for first nullifier
    pub first_proof: Bytes,
    /// KZG commitment for second block's blob
    pub second_commitment: Bytes,
    /// KZG proof for second nullifier
    pub second_proof: Bytes,
    /// Block data for rollback target
    pub prior_block: BlockData,
}

/// Data required to submit a transaction ZK challenge
#[derive(Debug, Clone)]
pub struct TransactionChallengeParams {
    /// Block containing the fraudulent transaction
    pub block_data: BlockData,
    /// Transaction number
    pub tx_nr: u64,
    /// Region containing the transaction data
    pub region: Region,
    /// Extension region (for additional data if needed)
    pub extension_region: Region,
    /// Anchor value from the referenced block/update
    pub anchor: B256,
    /// Block containing the prior anchor
    pub prior_anchor_block: BlockData,
    /// KZG commitment for prior anchor block's blob
    pub prior_anchor_commitment: Bytes,
    /// KZG proof for prior anchor
    pub prior_anchor_proof: Bytes,
    /// Block data for rollback target
    pub rollback_target_block: BlockData,
}

/// Data required to submit a tree update challenge
#[derive(Debug, Clone)]
pub struct TreeUpdateChallengeParams {
    /// Block containing the incorrect tree update
    pub block_data: BlockData,
    /// Update number within the block
    pub update_nr: u64,
    /// Whether this is a transaction update (vs deposit)
    pub is_tx: bool,
    /// Region containing the update data
    pub region: Region,
    /// Extension region (for additional data if needed)
    pub extension_region: Region,
    /// Prior anchor before this update
    pub prior_anchor: B256,
    /// KZG commitment for prior anchor proof
    pub prior_anchor_commitment: Bytes,
    /// KZG proof for prior anchor
    pub prior_anchor_proof: Bytes,
    /// True anchor computed by challenger
    pub true_anchor: B256,
    /// ZK proof of correct computation
    pub zk_proof: Proof,
    /// Block data for rollback target
    pub rollback_target_block: BlockData,
}

/// Challenge builder for constructing fraud proof transactions
pub struct ChallengeBuilder {
    kzg_prover: KzgProver,
}

impl ChallengeBuilder {
    /// Create a new challenge builder
    pub fn new() -> Result<Self> {
        let kzg_prover = KzgProver::new()?;
        Ok(Self { kzg_prover })
    }

    /// Compute the blob memory address for a deposit leaf
    ///
    /// Each 3 deposits use 4 slots: [leaf0, leaf1, leaf2, root]
    /// So deposit at index N is at memory address: N + N/3
    pub fn deposit_leaf_memory_address(deposit_nr: u64) -> usize {
        let n = deposit_nr as usize;
        n + n / 3
    }

    /// Build challenge parameters for a deposit wrong leaf fraud
    ///
    /// # Arguments
    /// * `evidence` - The fraud evidence (must be DepositWrongLeaf variant)
    /// * `blobs` - All blobs for the block with their hashes
    /// * `prior_block` - Block data for the block before the fraudulent one
    pub fn build_deposit_challenge(
        &self,
        evidence: &FraudEvidence,
        blobs: &[BlobWithHash],
        prior_block: BlockData,
    ) -> Result<DepositChallengeParams> {
        if blobs.is_empty() {
            return Err(eyre!("No blobs provided for deposit challenge"));
        }

        // Extract the fraud evidence
        let (block_data, deposit_nr, _submitted_leaf) = match evidence {
            FraudEvidence::DepositWrongLeaf {
                block_data,
                deposit_nr,
                submitted_leaf,
                ..
            } => (block_data.clone(), *deposit_nr, *submitted_leaf),
            FraudEvidence::DepositCountMismatch { block_data, .. } => {
                // For count mismatch, we can challenge any deposit index
                // that would be invalid - use the first one that doesn't exist
                let submitted_count = u256_to_u64(block_data.numDeposits, "numDeposits")?;
                (block_data.clone(), submitted_count, [0u8; 32].into())
            }
            FraudEvidence::DepositPaddingNotZero {
                block_data,
                group_index,
                slot_index,
                submitted_value,
            } => {
                // Validate slot_index is in valid range (0, 1, or 2)
                if *slot_index > 2 {
                    return Err(eyre!(
                        "Invalid slot_index {} in DepositPaddingNotZero (must be 0, 1, or 2)",
                        slot_index
                    ));
                }

                // For padding not zero, compute the deposit number from group and slot
                let deposit_nr = group_index
                    .checked_mul(3)
                    .and_then(|g| g.checked_add(*slot_index))
                    .ok_or_else(|| eyre!("Deposit number overflow"))?;
                (block_data.clone(), deposit_nr, *submitted_value)
            }
            _ => return Err(eyre!("Expected deposit-related fraud evidence")),
        };

        // Calculate the global memory address for this deposit
        let memory_address = Self::deposit_leaf_memory_address(deposit_nr);

        // Generate the KZG proof from the correct blob
        let (kzg_proof, _blob_hash) = self.generate_proof_multi_blob(blobs, memory_address)?;

        // Use the actual value from the blob (kzg_proof.value), not the decoded submitted_leaf.
        // The blob may have been encoded (e.g., by SimpleCoder), so the raw blob bytes
        // may differ from the logical leaf value.
        Ok(DepositChallengeParams {
            block_data,
            deposit_nr,
            sequencer_submitted_leaf: kzg_proof.value.into(),
            commitment: Bytes::from(kzg_proof.commitment),
            proof: Bytes::from(kzg_proof.proof),
            prior_block,
        })
    }

    /// Generate a KZG proof for a specific field index
    pub fn generate_proof(&self, blob_data: &[u8], field_index: usize) -> Result<KzgFieldProof> {
        self.kzg_prover.generate_proof(blob_data, field_index)
    }

    /// Compute blob commitment
    pub fn compute_commitment(&self, blob_data: &[u8]) -> Result<Vec<u8>> {
        self.kzg_prover.compute_commitment(blob_data)
    }

    /// Generate a KZG proof for a global memory address across multiple blobs.
    ///
    /// This converts the global address to the correct blob and local field index,
    /// then generates the proof from the appropriate blob.
    ///
    /// # Arguments
    /// * `blobs` - Array of blobs with their hashes
    /// * `global_address` - Memory address across all blobs (0-based)
    ///
    /// # Returns
    /// * `KzgFieldProof` - The proof for the field
    /// * `B256` - The blob hash that was used (needed for challenge submission)
    pub fn generate_proof_multi_blob(
        &self,
        blobs: &[BlobWithHash],
        global_address: usize,
    ) -> Result<(KzgFieldProof, B256)> {
        let (blob_index, local_index) = memory::global_to_local_address(global_address);

        if blob_index >= blobs.len() {
            return Err(eyre!(
                "Global address {} requires blob {}, but only {} blobs provided",
                global_address,
                blob_index,
                blobs.len()
            ));
        }

        let blob = &blobs[blob_index];
        let proof = self.generate_proof(blob.data, local_index)?;
        Ok((proof, blob.hash))
    }

    /// Build a Region struct with KZG proofs for a contiguous blob region
    ///
    /// # Arguments
    /// * `blob_data` - Raw blob bytes (131072 bytes)
    /// * `start_address` - Starting memory address in the blob
    /// * `length` - Number of 32-byte fields to include
    /// * `blob_hash` - The versioned blob hash
    pub fn build_region(
        &self,
        blob_data: &[u8],
        start_address: usize,
        length: usize,
        blob_hash: B256,
    ) -> Result<Region> {
        let commitment = self.compute_commitment(blob_data)?;

        let mut data = Vec::with_capacity(length);
        let mut proofs = Vec::with_capacity(length);

        for i in 0..length {
            let field_index = start_address + i;
            let kzg_proof = self.generate_proof(blob_data, field_index)?;

            data.push(B256::from(kzg_proof.value));
            proofs.push(Bytes::from(kzg_proof.proof));
        }

        Ok(Region {
            length: U256::from(length),
            memoryAddress: U256::from(start_address),
            data,
            proofs,
            commitment: Bytes::from(commitment),
            hash: blob_hash,
        })
    }

    /// Build a region pair (main + extension) that handles blob boundary crossing
    ///
    /// When data spans across blob boundaries (each blob has 4096 fields), this method
    /// splits the region into two parts:
    /// - `region`: Fields from the first blob
    /// - `extension`: Fields from the second blob (if boundary is crossed)
    ///
    /// # Arguments
    /// * `blobs` - Slice of blobs with their hashes (in order)
    /// * `global_start_address` - Starting memory address across all blobs
    /// * `length` - Total number of 32-byte fields to include
    ///
    /// # Returns
    /// A `RegionPair` with the main region and extension region
    pub fn build_region_with_extension(
        &self,
        blobs: &[BlobWithHash],
        global_start_address: usize,
        length: usize,
    ) -> Result<RegionPair> {
        if blobs.is_empty() {
            return Err(eyre!("No blobs provided"));
        }

        // Calculate which blob the start address is in
        let start_blob_index = global_start_address / BLOB_FIELD_COUNT;
        let local_start_address = global_start_address % BLOB_FIELD_COUNT;

        // Check if we have enough blobs
        if start_blob_index >= blobs.len() {
            return Err(eyre!(
                "Start address {} is in blob {}, but only {} blobs provided",
                global_start_address,
                start_blob_index,
                blobs.len()
            ));
        }

        // Check if the region crosses a blob boundary
        let end_local_address = local_start_address + length;
        let crosses_boundary = end_local_address > BLOB_FIELD_COUNT;

        if !crosses_boundary {
            // Simple case: all data fits in one blob
            let region = self.build_region(
                blobs[start_blob_index].data,
                local_start_address,
                length,
                blobs[start_blob_index].hash,
            )?;

            let extension = Self::empty_region();

            Ok(RegionPair { region, extension })
        } else {
            // Complex case: data spans two blobs
            let first_blob_count = BLOB_FIELD_COUNT - local_start_address;
            let second_blob_count = length - first_blob_count;

            // Verify we have the second blob
            if start_blob_index + 1 >= blobs.len() {
                return Err(eyre!(
                    "Region crosses blob boundary but second blob not provided. \
                     Start: {}, length: {}, first_blob_count: {}, second_blob_count: {}",
                    global_start_address,
                    length,
                    first_blob_count,
                    second_blob_count
                ));
            }

            debug!(
                "Building region with extension: start={}, length={}, first_count={}, second_count={}",
                global_start_address, length, first_blob_count, second_blob_count
            );

            // Build main region from first blob
            let region = self.build_region(
                blobs[start_blob_index].data,
                local_start_address,
                first_blob_count,
                blobs[start_blob_index].hash,
            )?;

            // Build extension region from second blob (starts at index 0)
            let extension = self.build_region(
                blobs[start_blob_index + 1].data,
                0,
                second_blob_count,
                blobs[start_blob_index + 1].hash,
            )?;

            Ok(RegionPair { region, extension })
        }
    }

    /// Create an empty region (for when no extension is needed)
    pub fn empty_region() -> Region {
        Region {
            length: U256::ZERO,
            memoryAddress: U256::ZERO,
            data: vec![],
            proofs: vec![],
            commitment: Bytes::new(),
            hash: B256::ZERO,
        }
    }

    /// Build challenge parameters for a nullifier double-spend fraud
    ///
    /// # Arguments
    /// * `evidence` - The fraud evidence
    /// * `first_blobs` - All blobs for the first block (where nullifier first appears)
    /// * `second_blobs` - All blobs for the second block (where nullifier is reused)
    /// * `first_block_data` - Block data for the first block
    /// * `second_block_data` - Block data for the second block
    /// * `prior_block` - Block data for the block before the second (fraudulent) block
    pub fn build_nullifier_challenge(
        &self,
        evidence: &FraudEvidence,
        first_blobs: &[BlobWithHash],
        second_blobs: &[BlobWithHash],
        first_block_data: BlockData,
        second_block_data: BlockData,
        prior_block: BlockData,
    ) -> Result<NullifierChallengeParams> {
        if first_blobs.is_empty() {
            return Err(eyre!("No blobs provided for first block"));
        }
        if second_blobs.is_empty() {
            return Err(eyre!("No blobs provided for second block"));
        }

        let (nullifier, first_tx, second_tx, first_which, second_which) = match evidence {
            FraudEvidence::NullifierDoubleSpend {
                nullifier,
                first_tx_number,
                second_tx_number,
                first_which,
                second_which,
                ..
            } => (
                *nullifier,
                *first_tx_number as u64,
                *second_tx_number as u64,
                *first_which,
                *second_which,
            ),
            _ => return Err(eyre!("Expected NullifierDoubleSpend fraud evidence")),
        };

        let num_deposits_first = u256_to_u64(first_block_data.numDeposits, "first numDeposits")?;
        let num_deposits_second = u256_to_u64(second_block_data.numDeposits, "second numDeposits")?;

        // Calculate global memory addresses
        let first_addr =
            memory::nullifier_memory_address(first_tx, num_deposits_first, first_which as u64);
        let second_addr =
            memory::nullifier_memory_address(second_tx, num_deposits_second, second_which as u64);

        // Generate KZG proofs from the correct blobs
        let (first_kzg, _) = self.generate_proof_multi_blob(first_blobs, first_addr as usize)?;
        let (second_kzg, _) = self.generate_proof_multi_blob(second_blobs, second_addr as usize)?;

        Ok(NullifierChallengeParams {
            reused_nullifier: nullifier,
            first_block_data,
            second_block_data,
            first_tx_number: first_tx,
            second_tx_number: second_tx,
            first_which,
            second_which,
            first_commitment: Bytes::from(first_kzg.commitment),
            first_proof: Bytes::from(first_kzg.proof),
            second_commitment: Bytes::from(second_kzg.commitment),
            second_proof: Bytes::from(second_kzg.proof),
            prior_block,
        })
    }

    /// Build challenge parameters for an invalid transaction proof
    ///
    /// DEPRECATED: This convenience method only works for single-blob blocks.
    /// Use `build_transaction_challenge_multi_blob` for proper multi-blob support.
    #[deprecated(note = "Use build_transaction_challenge_multi_blob for multi-blob support")]
    pub fn build_transaction_challenge(
        &self,
        evidence: &FraudEvidence,
        blob_data: &[u8],
        anchor: B256,
        prior_anchor_block: BlockData,
        prior_anchor_blob_data: &[u8],
        prior_anchor_field_index: usize,
        rollback_target_block: BlockData,
    ) -> Result<TransactionChallengeParams> {
        let (block_data, _tx_nr) = match evidence {
            FraudEvidence::InvalidTransactionProof {
                block_data, tx_nr, ..
            } => (block_data.clone(), *tx_nr),
            FraudEvidence::InvalidAnchorReference {
                block_data, tx_nr, ..
            } => (block_data.clone(), *tx_nr),
            FraudEvidence::MissingEthKeyAuth {
                block_data, tx_nr, ..
            } => (block_data.clone(), *tx_nr),
            _ => return Err(eyre!("Expected transaction-related fraud evidence")),
        };

        let blob_hash = block_data.blobhashes.first().copied().unwrap_or(B256::ZERO);
        let blobs = vec![BlobWithHash {
            data: blob_data,
            hash: blob_hash,
        }];

        let prior_blob_hash = prior_anchor_block
            .blobhashes
            .first()
            .copied()
            .unwrap_or(B256::ZERO);
        let prior_blobs = vec![BlobWithHash {
            data: prior_anchor_blob_data,
            hash: prior_blob_hash,
        }];

        self.build_transaction_challenge_multi_blob(
            evidence,
            &blobs,
            anchor,
            prior_anchor_block,
            &prior_blobs,
            prior_anchor_field_index,
            rollback_target_block,
        )
    }

    /// Build challenge parameters for an invalid transaction proof (multi-blob version)
    ///
    /// This method handles transactions that may span across blob boundaries.
    /// Each blob has 4096 fields, so a transaction (14 fields for challenge) starting at
    /// position 4090 would need data from two blobs.
    ///
    /// Note: Transaction challenge requires 14 fields (8 proof + anchor_info + 2 nullifiers + 3 leaves).
    /// The new_root field (15th field) is NOT included in the challenge region.
    ///
    /// # Arguments
    /// * `evidence` - The fraud evidence (must be transaction-related)
    /// * `blobs` - All blobs for this block, in order
    /// * `anchor` - The anchor value from the referenced block/update
    /// * `prior_anchor_block` - Block containing the prior anchor
    /// * `prior_anchor_blobs` - All blobs for the prior anchor block
    /// * `prior_anchor_field_index` - Global field index of the prior anchor
    /// * `rollback_target_block` - Block to rollback to after successful challenge
    pub fn build_transaction_challenge_multi_blob(
        &self,
        evidence: &FraudEvidence,
        blobs: &[BlobWithHash],
        anchor: B256,
        prior_anchor_block: BlockData,
        prior_anchor_blobs: &[BlobWithHash],
        prior_anchor_field_index: usize,
        rollback_target_block: BlockData,
    ) -> Result<TransactionChallengeParams> {
        if blobs.is_empty() {
            return Err(eyre!("No blobs provided for current block"));
        }
        if prior_anchor_blobs.is_empty() {
            return Err(eyre!("No blobs provided for prior anchor block"));
        }

        let (block_data, tx_nr) = match evidence {
            FraudEvidence::InvalidTransactionProof {
                block_data, tx_nr, ..
            } => (block_data.clone(), *tx_nr),
            FraudEvidence::InvalidAnchorReference {
                block_data, tx_nr, ..
            } => (block_data.clone(), *tx_nr),
            FraudEvidence::MissingEthKeyAuth {
                block_data, tx_nr, ..
            } => (block_data.clone(), *tx_nr),
            _ => return Err(eyre!("Expected transaction-related fraud evidence")),
        };

        let num_deposits = u256_to_u64(block_data.numDeposits, "numDeposits")?;
        let tx_start = memory::tx_memory_address(tx_nr, num_deposits) as usize;

        // Build region pair (handles boundary crossing)
        // Transaction challenge requires 14 fields (not 15 - excludes new_root)
        let region_pair = self.build_region_with_extension(blobs, tx_start, 14)?;

        // Prior anchor proof - use multi-blob helper for global address
        let (prior_anchor_kzg, _) =
            self.generate_proof_multi_blob(prior_anchor_blobs, prior_anchor_field_index)?;

        Ok(TransactionChallengeParams {
            block_data,
            tx_nr,
            region: region_pair.region,
            extension_region: region_pair.extension,
            anchor,
            prior_anchor_block,
            prior_anchor_commitment: Bytes::from(prior_anchor_kzg.commitment),
            prior_anchor_proof: Bytes::from(prior_anchor_kzg.proof),
            rollback_target_block,
        })
    }

    /// Build challenge parameters for an incorrect tree update
    ///
    /// DEPRECATED: This convenience method only works for single-blob blocks.
    /// Use `build_tree_update_challenge_multi_blob` for proper multi-blob support.
    #[deprecated(note = "Use build_tree_update_challenge_multi_blob for multi-blob support")]
    pub fn build_tree_update_challenge(
        &self,
        evidence: &FraudEvidence,
        blob_data: &[u8],
        prior_anchor: B256,
        prior_anchor_blob_data: &[u8],
        prior_anchor_field_index: usize,
        true_anchor: B256,
        zk_proof: Proof,
        rollback_target_block: BlockData,
    ) -> Result<TreeUpdateChallengeParams> {
        let (block_data, _, _) = match evidence {
            FraudEvidence::IncorrectTreeUpdate {
                block_data,
                update_nr,
                is_tx,
                ..
            } => (block_data.clone(), *update_nr, *is_tx),
            _ => return Err(eyre!("Expected IncorrectTreeUpdate fraud evidence")),
        };

        let blob_hash = block_data.blobhashes.first().copied().unwrap_or(B256::ZERO);
        let blobs = vec![BlobWithHash {
            data: blob_data,
            hash: blob_hash,
        }];

        let prior_blob_hash = B256::ZERO; // No prior block data available in this deprecated API
        let prior_blobs = vec![BlobWithHash {
            data: prior_anchor_blob_data,
            hash: prior_blob_hash,
        }];

        self.build_tree_update_challenge_multi_blob(
            evidence,
            &blobs,
            prior_anchor,
            &prior_blobs,
            prior_anchor_field_index,
            true_anchor,
            zk_proof,
            rollback_target_block,
        )
    }

    /// Build challenge parameters for an incorrect tree update (multi-blob version)
    ///
    /// This method handles tree updates that may span across blob boundaries.
    /// While deposit groups (4 fields) are unlikely to cross boundaries,
    /// transaction updates (15 fields) might if they start near a boundary.
    ///
    /// # Arguments
    /// * `evidence` - The fraud evidence (must be IncorrectTreeUpdate)
    /// * `blobs` - All blobs for this block, in order
    /// * `prior_anchor` - The anchor before this update
    /// * `prior_anchor_blobs` - All blobs for the block containing the prior anchor
    /// * `prior_anchor_field_index` - Global field index of the prior anchor
    /// * `true_anchor` - The correct anchor computed by the challenger
    /// * `zk_proof` - ZK proof of correct computation
    /// * `rollback_target_block` - Block to rollback to after successful challenge
    pub fn build_tree_update_challenge_multi_blob(
        &self,
        evidence: &FraudEvidence,
        blobs: &[BlobWithHash],
        prior_anchor: B256,
        prior_anchor_blobs: &[BlobWithHash],
        prior_anchor_field_index: usize,
        true_anchor: B256,
        zk_proof: Proof,
        rollback_target_block: BlockData,
    ) -> Result<TreeUpdateChallengeParams> {
        if blobs.is_empty() {
            return Err(eyre!("No blobs provided for current block"));
        }
        if prior_anchor_blobs.is_empty() {
            return Err(eyre!("No blobs provided for prior anchor block"));
        }

        let (block_data, update_nr, is_tx) = match evidence {
            FraudEvidence::IncorrectTreeUpdate {
                block_data,
                update_nr,
                is_tx,
                ..
            } => (block_data.clone(), *update_nr, *is_tx),
            _ => return Err(eyre!("Expected IncorrectTreeUpdate fraud evidence")),
        };

        let num_deposits = u256_to_u64(block_data.numDeposits, "numDeposits")?;

        // Calculate region start based on update type and number
        // For tree update challenge, we only need the 4 update fields (3 leaves + new_root)
        let (region_start, region_length) = if is_tx {
            // Transaction update: need the 4 update fields (3 leaves + new_root)
            // These are at offset 11 within the transaction (after 8 proof + 1 anchor + 2 nullifiers)
            let tx_nr = update_nr - num_deposits.div_ceil(3); // Subtract deposit groups
            let tx_start = memory::tx_memory_address(tx_nr, num_deposits) as usize;
            let update_start = tx_start + 11; // Offset to leaves (skip proof[8] + anchor[1] + nullifiers[2])
            (update_start, 4) // 3 leaves + new_root
        } else {
            // Deposit group update: need group data (4 fields: 3 leaves + root)
            let group_start = (update_nr * 4) as usize;
            (group_start, 4)
        };

        // Build region pair (handles boundary crossing)
        let region_pair = self.build_region_with_extension(blobs, region_start, region_length)?;

        // Prior anchor proof - use multi-blob helper for global address
        let (prior_anchor_kzg, _) =
            self.generate_proof_multi_blob(prior_anchor_blobs, prior_anchor_field_index)?;

        Ok(TreeUpdateChallengeParams {
            block_data,
            update_nr,
            is_tx,
            region: region_pair.region,
            extension_region: region_pair.extension,
            prior_anchor,
            prior_anchor_commitment: Bytes::from(prior_anchor_kzg.commitment),
            prior_anchor_proof: Bytes::from(prior_anchor_kzg.proof),
            true_anchor,
            zk_proof,
            rollback_target_block,
        })
    }

    /// Build challenge parameters for a tree update in the first block (genesis case)
    ///
    /// This handles the special case where the prior anchor is the genesis anchor.
    /// The contract doesn't require KZG proof for genesis - it just validates
    /// that the prior anchor equals GENESIS_ANCHOR.
    ///
    /// # Arguments
    /// * `evidence` - The fraud evidence (must be IncorrectTreeUpdate)
    /// * `blobs` - All blobs for this block, in order
    /// * `genesis_anchor` - The genesis anchor value from the contract
    /// * `true_anchor` - The correct anchor computed by the challenger
    /// * `zk_proof` - ZK proof of correct computation
    /// * `rollback_target_block` - Block to rollback to after successful challenge
    pub fn build_tree_update_challenge_genesis(
        &self,
        evidence: &FraudEvidence,
        blobs: &[BlobWithHash],
        genesis_anchor: B256,
        true_anchor: B256,
        zk_proof: Proof,
        rollback_target_block: BlockData,
    ) -> Result<TreeUpdateChallengeParams> {
        if blobs.is_empty() {
            return Err(eyre!("No blobs provided for current block"));
        }

        let (block_data, update_nr, is_tx) = match evidence {
            FraudEvidence::IncorrectTreeUpdate {
                block_data,
                update_nr,
                is_tx,
                ..
            } => (block_data.clone(), *update_nr, *is_tx),
            _ => return Err(eyre!("Expected IncorrectTreeUpdate fraud evidence")),
        };

        // Verify this is actually block 0 and update 0
        if block_data.blockNr != alloy::primitives::U256::ZERO {
            return Err(eyre!("Genesis challenge only valid for block 0"));
        }
        if update_nr != 0 {
            return Err(eyre!(
                "Genesis challenge only valid for first update (update_nr=0)"
            ));
        }

        let num_deposits = u256_to_u64(block_data.numDeposits, "numDeposits")?;

        // Calculate region start based on update type
        let (region_start, region_length) = if is_tx {
            // This shouldn't happen for genesis (first update is always deposit or first tx)
            let tx_start = memory::tx_memory_address(0, num_deposits) as usize;
            let update_start = tx_start + 11;
            (update_start, 4)
        } else {
            // First deposit group: fields 0-3
            (0, 4)
        };

        // Build region pair (handles boundary crossing)
        let region_pair = self.build_region_with_extension(blobs, region_start, region_length)?;

        // For genesis, the contract doesn't use KZG proof - just checks anchor == GENESIS_ANCHOR
        // We provide empty commitment and proof bytes
        Ok(TreeUpdateChallengeParams {
            block_data,
            update_nr,
            is_tx,
            region: region_pair.region,
            extension_region: region_pair.extension,
            prior_anchor: genesis_anchor,
            prior_anchor_commitment: Bytes::new(),
            prior_anchor_proof: Bytes::new(),
            true_anchor,
            zk_proof,
            rollback_target_block,
        })
    }
}

impl Default for ChallengeBuilder {
    fn default() -> Self {
        Self::new().expect("Failed to create challenge builder")
    }
}

/// Submits fraud proof challenges to the blockchain
pub struct ChallengeSubmitter<P> {
    provider: P,
    contract_address: Address,
}

impl<P: Provider + Clone> ChallengeSubmitter<P> {
    /// Create a new challenge submitter
    ///
    /// # Arguments
    /// * `provider` - The Ethereum provider (must support transaction sending)
    /// * `contract_address` - Address of the Entrypoint contract (DepositChallenge is inherited)
    pub fn new(provider: P, contract_address: Address) -> Self {
        Self {
            provider,
            contract_address,
        }
    }

    /// Submit a deposit wrong leaf challenge
    ///
    /// # Arguments
    /// * `params` - Challenge parameters built by ChallengeBuilder
    ///
    /// # Returns
    /// Transaction hash on success
    pub async fn submit_deposit_challenge(&self, params: DepositChallengeParams) -> Result<B256> {
        let contract = DepositChallenge::new(self.contract_address, self.provider.clone());

        info!(
            "Submitting deposit challenge for block {} deposit {}",
            params.block_data.blockNr, params.deposit_nr
        );
        debug!(
            "Challenge params: sequencer_leaf={:?}, commitment_len={}, proof_len={}",
            B256::from(params.sequencer_submitted_leaf),
            params.commitment.len(),
            params.proof.len()
        );

        let tx = contract.challengeDepositWrongLeaf(
            params.block_data,
            U256::from(params.deposit_nr),
            B256::from(params.sequencer_submitted_leaf),
            params.commitment,
            params.proof,
            params.prior_block,
        );

        let pending_tx = tx.send().await?;
        let receipt = pending_tx.get_receipt().await?;

        info!(
            "Challenge submitted successfully, tx hash: {:?}",
            receipt.transaction_hash
        );

        Ok(receipt.transaction_hash)
    }

    /// Submit a nullifier double-spend challenge
    pub async fn submit_nullifier_challenge(
        &self,
        params: NullifierChallengeParams,
    ) -> Result<B256> {
        let contract = NullifierChallenge::new(self.contract_address, self.provider.clone());

        info!(
            "Submitting nullifier challenge for blocks {} and {}, nullifier {:?}",
            params.first_block_data.blockNr,
            params.second_block_data.blockNr,
            params.reused_nullifier
        );

        // Build NullifierLoader structs matching the Solidity contract
        let first_loader = NullifierLoader {
            data: params.first_block_data,
            txNr: U256::from(params.first_tx_number),
            whichNullifier: U256::from(params.first_which),
            commitment: params.first_commitment,
            proof: params.first_proof,
        };

        let second_loader = NullifierLoader {
            data: params.second_block_data,
            txNr: U256::from(params.second_tx_number),
            whichNullifier: U256::from(params.second_which),
            commitment: params.second_commitment,
            proof: params.second_proof,
        };

        let tx = contract.challengeNullifier(
            params.reused_nullifier,
            first_loader,
            second_loader,
            params.prior_block,
        );

        let pending_tx = tx.send().await?;
        let receipt = pending_tx.get_receipt().await?;

        info!(
            "Nullifier challenge submitted, tx hash: {:?}",
            receipt.transaction_hash
        );

        Ok(receipt.transaction_hash)
    }

    /// Submit a transaction ZK challenge
    pub async fn submit_transaction_challenge(
        &self,
        params: TransactionChallengeParams,
    ) -> Result<B256> {
        let contract = TransactionChallenge::new(self.contract_address, self.provider.clone());

        info!(
            "Submitting transaction challenge for block {} tx {}",
            params.block_data.blockNr, params.tx_nr
        );

        let tx = contract.challengeTxZK(
            params.block_data,
            U256::from(params.tx_nr),
            params.region,
            params.extension_region,
            params.anchor,
            params.prior_anchor_block,
            params.prior_anchor_commitment,
            params.prior_anchor_proof,
            params.rollback_target_block,
        );

        let pending_tx = tx.send().await?;
        let receipt = pending_tx.get_receipt().await?;

        info!(
            "Transaction challenge submitted, tx hash: {:?}",
            receipt.transaction_hash
        );

        Ok(receipt.transaction_hash)
    }

    /// Submit a tree update challenge
    pub async fn submit_tree_update_challenge(
        &self,
        params: TreeUpdateChallengeParams,
    ) -> Result<B256> {
        let contract = TreeUpdateChallenge::new(self.contract_address, self.provider.clone());

        info!(
            "Submitting tree update challenge for block {} update {} (is_tx={})",
            params.block_data.blockNr, params.update_nr, params.is_tx
        );

        let tx = contract.challengeTreeUpdate(
            params.block_data,
            U256::from(params.update_nr),
            params.is_tx,
            params.region,
            params.extension_region,
            params.prior_anchor,
            params.prior_anchor_commitment,
            params.prior_anchor_proof,
            params.true_anchor,
            params.zk_proof,
            params.rollback_target_block,
        );

        let pending_tx = tx.send().await?;
        let receipt = pending_tx.get_receipt().await?;

        info!(
            "Tree update challenge submitted, tx hash: {:?}",
            receipt.transaction_hash
        );

        Ok(receipt.transaction_hash)
    }
}

/// Memory address calculations matching BlobData.sol
///
/// All functions use checked arithmetic to prevent overflow.
pub mod memory {
    /// Number of memory slots needed for deposits
    /// Each 3 deposits use 4 slots: [leaf0, leaf1, leaf2, root]
    ///
    /// # Panics
    /// Panics on arithmetic overflow (which would require impossibly large inputs)
    pub fn num_deposits_to_memory_length(num_deposits: u64) -> u64 {
        let rounding = if num_deposits % 3 == 0 { 0 } else { 1 };
        let groups = num_deposits
            .checked_div(3)
            .and_then(|d| d.checked_add(rounding))
            .expect("Deposit group count overflow");
        groups
            .checked_mul(4)
            .expect("Deposit memory length overflow")
    }

    /// Memory address of an anchor (new_root) in a block's blob
    ///
    /// For deposits: Each deposit group is 4 fields (3 leaves + 1 root)
    ///              The root is at position update_nr * 4 + 3
    /// For transactions: Each tx is 15 fields, new_root is the last field
    ///                  Position: deposits_length + tx_nr * 15 + 14
    ///
    /// # Arguments
    /// * `update_nr` - The update number (deposit group or transaction index)
    /// * `num_deposits` - Number of deposits in the block (to compute deposit region length)
    /// * `is_deposit` - Whether this is a deposit update or transaction update
    ///
    /// # Panics
    /// Panics on arithmetic overflow
    pub fn anchor_memory_address(update_nr: u64, num_deposits: u64, is_deposit: bool) -> u64 {
        if is_deposit {
            // Deposit group root: each group is 4 fields, root is at offset 3
            update_nr
                .checked_mul(4)
                .and_then(|addr| addr.checked_add(3))
                .expect("Deposit anchor address overflow")
        } else {
            // Transaction new_root: starts after deposits, each tx is 15 fields, root at offset 14
            let deposits_length = num_deposits_to_memory_length(num_deposits);
            let tx_offset = update_nr
                .checked_mul(15)
                .expect("Transaction offset overflow");
            deposits_length
                .checked_add(tx_offset)
                .and_then(|addr| addr.checked_add(14))
                .expect("Transaction anchor address overflow")
        }
    }

    /// Memory address for a transaction start
    ///
    /// # Panics
    /// Panics on arithmetic overflow
    pub fn tx_memory_address(tx_number: u64, num_deposits: u64) -> u64 {
        let deposits_length = num_deposits_to_memory_length(num_deposits);
        let tx_offset = tx_number
            .checked_mul(15)
            .expect("Transaction number overflow");
        deposits_length
            .checked_add(tx_offset)
            .expect("Transaction address overflow")
    }

    /// Memory address for a leaf (deposit or transaction output)
    ///
    /// # Arguments
    /// * `number` - Deposit index or transaction index
    /// * `num_deposits` - Total deposits in block
    /// * `is_deposit` - True for deposit leaf, false for transaction output
    /// * `which` - Which leaf (0, 1, or 2)
    ///
    /// # Panics
    /// Panics on arithmetic overflow or if `which` >= 3
    pub fn leaf_memory_address(
        number: u64,
        num_deposits: u64,
        is_deposit: bool,
        which: u64,
    ) -> u64 {
        assert!(
            which < 3,
            "Leaf index 'which' must be 0, 1, or 2, got {}",
            which
        );

        if is_deposit {
            // Deposit leaf: number + number/3
            number
                .checked_add(number / 3)
                .expect("Deposit leaf address overflow")
        } else {
            // Transaction output leaf
            let deposits_length = num_deposits_to_memory_length(num_deposits);
            let prior = number
                .checked_mul(15)
                .expect("Transaction prior offset overflow");
            // 8 zk proof + 1 anchor + 2 nullifiers = 11, then leaf0=0, leaf1=1, leaf2=2
            deposits_length
                .checked_add(prior)
                .and_then(|addr| addr.checked_add(11))
                .and_then(|addr| addr.checked_add(which))
                .expect("Transaction leaf address overflow")
        }
    }

    /// Memory address for a nullifier in transaction
    ///
    /// # Arguments
    /// * `tx_number` - Transaction index
    /// * `num_deposits` - Total deposits in block
    /// * `which` - Which nullifier (0 or 1)
    ///
    /// # Panics
    /// Panics on arithmetic overflow or if `which` >= 2
    pub fn nullifier_memory_address(tx_number: u64, num_deposits: u64, which: u64) -> u64 {
        assert!(
            which < 2,
            "Nullifier index 'which' must be 0 or 1, got {}",
            which
        );

        let deposits_length = num_deposits_to_memory_length(num_deposits);
        let prior = tx_number
            .checked_mul(15)
            .expect("Transaction number overflow");
        // 8 zk proof + 1 anchor = 9, then null0=0, null1=1
        deposits_length
            .checked_add(prior)
            .and_then(|addr| addr.checked_add(9))
            .and_then(|addr| addr.checked_add(which))
            .expect("Nullifier address overflow")
    }

    /// Number of field elements per blob (4096)
    pub const FIELDS_PER_BLOB: usize = 4096;

    /// Convert a global memory address to blob index and local field index.
    ///
    /// Memory addresses in PGP are computed as global offsets across all blobs
    /// in a block. This function converts a global address to the specific blob
    /// and the field index within that blob.
    ///
    /// # Arguments
    /// * `global_address` - Memory address across all blobs (0-based)
    ///
    /// # Returns
    /// * `(blob_index, local_field_index)` - Which blob and which field within that blob
    ///
    /// # Examples
    /// - Address 0 → (blob 0, field 0)
    /// - Address 4095 → (blob 0, field 4095)
    /// - Address 4096 → (blob 1, field 0)
    /// - Address 8192 → (blob 2, field 0)
    pub fn global_to_local_address(global_address: usize) -> (usize, usize) {
        let blob_index = global_address / FIELDS_PER_BLOB;
        let local_index = global_address % FIELDS_PER_BLOB;
        (blob_index, local_index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deposit_leaf_memory_address() {
        // Deposit 0 -> address 0
        assert_eq!(ChallengeBuilder::deposit_leaf_memory_address(0), 0);
        // Deposit 1 -> address 1
        assert_eq!(ChallengeBuilder::deposit_leaf_memory_address(1), 1);
        // Deposit 2 -> address 2
        assert_eq!(ChallengeBuilder::deposit_leaf_memory_address(2), 2);
        // Deposit 3 -> address 4 (skips the root at 3)
        assert_eq!(ChallengeBuilder::deposit_leaf_memory_address(3), 4);
        // Deposit 4 -> address 5
        assert_eq!(ChallengeBuilder::deposit_leaf_memory_address(4), 5);
        // Deposit 5 -> address 6
        assert_eq!(ChallengeBuilder::deposit_leaf_memory_address(5), 6);
        // Deposit 6 -> address 8 (skips the root at 7)
        assert_eq!(ChallengeBuilder::deposit_leaf_memory_address(6), 8);
    }

    #[test]
    fn test_num_deposits_to_memory_length() {
        use memory::num_deposits_to_memory_length;

        // 0 deposits -> 0 slots
        assert_eq!(num_deposits_to_memory_length(0), 0);
        // 1 deposit -> 4 slots (partial group)
        assert_eq!(num_deposits_to_memory_length(1), 4);
        // 2 deposits -> 4 slots
        assert_eq!(num_deposits_to_memory_length(2), 4);
        // 3 deposits -> 4 slots (full group)
        assert_eq!(num_deposits_to_memory_length(3), 4);
        // 4 deposits -> 8 slots
        assert_eq!(num_deposits_to_memory_length(4), 8);
        // 6 deposits -> 8 slots
        assert_eq!(num_deposits_to_memory_length(6), 8);
    }

    #[test]
    fn test_tx_memory_address() {
        use memory::tx_memory_address;

        // With 0 deposits, tx 0 starts at 0
        assert_eq!(tx_memory_address(0, 0), 0);
        // With 0 deposits, tx 1 starts at 15
        assert_eq!(tx_memory_address(1, 0), 15);

        // With 3 deposits (4 slots), tx 0 starts at 4
        assert_eq!(tx_memory_address(0, 3), 4);
        // With 3 deposits, tx 1 starts at 19
        assert_eq!(tx_memory_address(1, 3), 19);
    }

    #[test]
    fn test_nullifier_memory_address() {
        use memory::nullifier_memory_address;

        // With 0 deposits, tx 0, null0 is at position 9
        assert_eq!(nullifier_memory_address(0, 0, 0), 9);
        // With 0 deposits, tx 0, null1 is at position 10
        assert_eq!(nullifier_memory_address(0, 0, 1), 10);

        // With 3 deposits (4 slots), tx 0, null0 is at 4+9=13
        assert_eq!(nullifier_memory_address(0, 3, 0), 13);
    }

    #[test]
    fn test_global_to_local_address() {
        use memory::{global_to_local_address, FIELDS_PER_BLOB};

        // Within first blob
        assert_eq!(global_to_local_address(0), (0, 0));
        assert_eq!(global_to_local_address(100), (0, 100));
        assert_eq!(global_to_local_address(4095), (0, 4095));

        // First field of second blob
        assert_eq!(global_to_local_address(4096), (1, 0));
        assert_eq!(global_to_local_address(4096 + 100), (1, 100));
        assert_eq!(global_to_local_address(4096 + 4095), (1, 4095));

        // Third blob
        assert_eq!(global_to_local_address(8192), (2, 0));
        assert_eq!(global_to_local_address(8192 + 500), (2, 500));

        // Verify constant
        assert_eq!(FIELDS_PER_BLOB, 4096);
    }

    #[test]
    fn test_anchor_memory_address() {
        use memory::anchor_memory_address;

        // Deposit anchors (roots) - each deposit group is 4 fields, root is at offset 3
        // Deposit group 0: root at index 3
        assert_eq!(anchor_memory_address(0, 0, true), 3);
        // Deposit group 1: root at index 7
        assert_eq!(anchor_memory_address(1, 0, true), 7);
        // Deposit group 2: root at index 11
        assert_eq!(anchor_memory_address(2, 0, true), 11);

        // Transaction anchors (new_root) - each tx is 15 fields, new_root at offset 14
        // With 0 deposits, tx 0 new_root at 0 + 0*15 + 14 = 14
        assert_eq!(anchor_memory_address(0, 0, false), 14);
        // With 0 deposits, tx 1 new_root at 0 + 1*15 + 14 = 29
        assert_eq!(anchor_memory_address(1, 0, false), 29);

        // With 3 deposits (4 slots), tx 0 new_root at 4 + 0*15 + 14 = 18
        assert_eq!(anchor_memory_address(0, 3, false), 18);
        // With 3 deposits (4 slots), tx 1 new_root at 4 + 1*15 + 14 = 33
        assert_eq!(anchor_memory_address(1, 3, false), 33);

        // With 6 deposits (8 slots), tx 0 new_root at 8 + 0*15 + 14 = 22
        assert_eq!(anchor_memory_address(0, 6, false), 22);
    }

    #[test]
    fn test_leaf_memory_address() {
        use memory::leaf_memory_address;

        // Deposit leaves
        assert_eq!(leaf_memory_address(0, 3, true, 0), 0);
        assert_eq!(leaf_memory_address(1, 3, true, 0), 1);
        assert_eq!(leaf_memory_address(3, 6, true, 0), 4);

        // Transaction output leaves (with 0 deposits)
        // tx 0, leaf0 is at 0+0+11+0=11
        assert_eq!(leaf_memory_address(0, 0, false, 0), 11);
        // tx 0, leaf1 is at 11+1=12
        assert_eq!(leaf_memory_address(0, 0, false, 1), 12);
        // tx 0, leaf2 is at 11+2=13
        assert_eq!(leaf_memory_address(0, 0, false, 2), 13);

        // tx 1, leaf0 is at 0+15+11+0=26
        assert_eq!(leaf_memory_address(1, 0, false, 0), 26);
    }

    #[test]
    fn test_build_region() {
        let builder = ChallengeBuilder::new().unwrap();

        // Create a minimal blob with known data
        // A full blob is 131072 bytes (4096 fields * 32 bytes)
        let mut blob_data = vec![0u8; 131072];

        // Write some known values at specific positions
        let test_value_0 = B256::repeat_byte(0x11);
        let test_value_1 = B256::repeat_byte(0x22);
        let test_value_2 = B256::repeat_byte(0x33);

        blob_data[0..32].copy_from_slice(test_value_0.as_slice());
        blob_data[32..64].copy_from_slice(test_value_1.as_slice());
        blob_data[64..96].copy_from_slice(test_value_2.as_slice());

        let blob_hash = B256::repeat_byte(0xAA);

        // Build a region starting at address 0 with length 3
        let region = builder.build_region(&blob_data, 0, 3, blob_hash).unwrap();

        // Verify region properties
        assert_eq!(region.length, U256::from(3));
        assert_eq!(region.memoryAddress, U256::ZERO);
        assert_eq!(region.data.len(), 3);
        assert_eq!(region.proofs.len(), 3);
        assert_eq!(region.hash, blob_hash);

        // The commitment should be 48 bytes (G1 point)
        assert_eq!(region.commitment.len(), 48);

        // Each proof should be 48 bytes
        for proof in &region.proofs {
            assert_eq!(proof.len(), 48);
        }
    }

    #[test]
    fn test_build_region_at_offset() {
        let builder = ChallengeBuilder::new().unwrap();

        let mut blob_data = vec![0u8; 131072];

        // Write test data at offset 100
        // Use values with first byte < 0x73 to be valid BLS field elements
        let start_offset = 100 * 32; // Field 100
        let value_a = B256::from([
            0x01, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA,
        ]);
        let value_b = B256::from([
            0x02, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB,
        ]);
        blob_data[start_offset..start_offset + 32].copy_from_slice(value_a.as_slice());
        blob_data[start_offset + 32..start_offset + 64].copy_from_slice(value_b.as_slice());

        let blob_hash = B256::repeat_byte(0x0F); // Valid field element

        // Build region at offset 100 with length 2
        let region = builder.build_region(&blob_data, 100, 2, blob_hash).unwrap();

        assert_eq!(region.length, U256::from(2));
        assert_eq!(region.memoryAddress, U256::from(100));
        assert_eq!(region.data.len(), 2);
        assert_eq!(region.proofs.len(), 2);
    }

    #[test]
    fn test_extension_region_detection() {
        // Test the logic for detecting when extension regions are needed
        // A blob has 4096 fields (indices 0-4095)
        // If a transaction (15 fields) starts at position 4090, it needs an extension region

        let blob_size: u64 = 4096;

        // Case 1: Transaction fits in single blob
        let tx_start_1: u64 = 4080;
        let tx_length: u64 = 15;
        let needs_extension_1 = tx_start_1 + tx_length > blob_size;
        assert!(
            !needs_extension_1,
            "Transaction at 4080 should fit in single blob"
        );

        // Case 2: Transaction crosses blob boundary
        let tx_start_2: u64 = 4090;
        let needs_extension_2 = tx_start_2 + tx_length > blob_size;
        assert!(
            needs_extension_2,
            "Transaction at 4090 should need extension region"
        );

        // Calculate split
        if needs_extension_2 {
            let first_blob_count = blob_size - tx_start_2; // Fields in first blob
            let second_blob_count = tx_length - first_blob_count; // Fields in second blob

            assert_eq!(first_blob_count, 6, "First blob should have 6 fields");
            assert_eq!(second_blob_count, 9, "Second blob should have 9 fields");
        }
    }

    #[test]
    fn test_extension_region_memory_calculation() {
        use memory::tx_memory_address;

        // Find a transaction that would cross blob boundary
        // With many deposits, transactions start later in the blob
        // Each deposit group uses 4 slots, and we need enough to push tx near boundary

        // To get a tx starting near position 4090, we need:
        // deposits_length + tx_number * 15 ≈ 4090
        // If we have 1000 deposits: deposits_length = ceil(1000/3) * 4 = 334 * 4 = 1336
        // Then tx 183: 1336 + 183 * 15 = 1336 + 2745 = 4081

        let num_deposits: u64 = 1000;
        let tx_183_addr = tx_memory_address(183, num_deposits);
        assert!(tx_183_addr >= 4081, "TX 183 should be near blob boundary");

        // With 1020 deposits: ceil(1020/3) * 4 = 340 * 4 = 1360
        // TX 182: 1360 + 182 * 15 = 1360 + 2730 = 4090
        let num_deposits_2: u64 = 1020;
        let tx_182_addr = tx_memory_address(182, num_deposits_2);

        // Check if this crosses the blob boundary
        let blob_size: u64 = 4096;
        let tx_length: u64 = 15;
        let crosses_boundary = tx_182_addr + tx_length > blob_size;

        if crosses_boundary {
            let first_count = blob_size.saturating_sub(tx_182_addr);
            let second_count = tx_length.saturating_sub(first_count);

            assert!(first_count > 0, "Should have some fields in first blob");
            assert!(second_count > 0, "Should have some fields in second blob");
            assert_eq!(
                first_count + second_count,
                tx_length,
                "Total should equal tx length"
            );
        }
    }

    #[test]
    fn test_build_region_with_extension_single_blob() {
        let builder = ChallengeBuilder::new().unwrap();

        // Create a blob with valid field elements
        let mut blob_data = vec![0u8; 131072];
        for i in 0..10 {
            let value = B256::from([
                (i % 0x30) as u8,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                (i as u8),
            ]);
            blob_data[i * 32..(i + 1) * 32].copy_from_slice(value.as_slice());
        }

        let blob_hash = B256::repeat_byte(0x01);
        let blobs = vec![BlobWithHash {
            data: &blob_data,
            hash: blob_hash,
        }];

        // Build region that fits in single blob
        let region_pair = builder.build_region_with_extension(&blobs, 0, 5).unwrap();

        // Main region should have 5 fields
        assert_eq!(region_pair.region.length, U256::from(5));
        assert_eq!(region_pair.region.memoryAddress, U256::ZERO);
        assert_eq!(region_pair.region.data.len(), 5);

        // Extension should be empty
        assert_eq!(region_pair.extension.length, U256::ZERO);
        assert!(region_pair.extension.data.is_empty());
    }

    #[test]
    fn test_build_region_with_extension_crosses_boundary() {
        let builder = ChallengeBuilder::new().unwrap();

        // Create two blobs with valid field elements
        let mut blob1 = vec![0u8; 131072];
        let mut blob2 = vec![0u8; 131072];

        // Fill blob1 - write data at the end (near boundary)
        for i in 4090..4096 {
            let value = B256::from([
                0x01,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                (i >> 8) as u8,
                (i & 0xFF) as u8,
            ]);
            blob1[i * 32..(i + 1) * 32].copy_from_slice(value.as_slice());
        }

        // Fill blob2 - write data at the beginning
        for i in 0..10 {
            let value = B256::from([
                0x02,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                (i as u8),
            ]);
            blob2[i * 32..(i + 1) * 32].copy_from_slice(value.as_slice());
        }

        let blob1_hash = B256::repeat_byte(0x01);
        let blob2_hash = B256::repeat_byte(0x02);
        let blobs = vec![
            BlobWithHash {
                data: &blob1,
                hash: blob1_hash,
            },
            BlobWithHash {
                data: &blob2,
                hash: blob2_hash,
            },
        ];

        // Build region starting at 4090 with length 15 (crosses boundary)
        // First blob: fields 4090-4095 (6 fields)
        // Second blob: fields 0-8 (9 fields)
        let region_pair = builder
            .build_region_with_extension(&blobs, 4090, 15)
            .unwrap();

        // Main region should have 6 fields from first blob
        assert_eq!(region_pair.region.length, U256::from(6));
        assert_eq!(region_pair.region.memoryAddress, U256::from(4090));
        assert_eq!(region_pair.region.data.len(), 6);
        assert_eq!(region_pair.region.hash, blob1_hash);

        // Extension region should have 9 fields from second blob
        assert_eq!(region_pair.extension.length, U256::from(9));
        assert_eq!(region_pair.extension.memoryAddress, U256::ZERO);
        assert_eq!(region_pair.extension.data.len(), 9);
        assert_eq!(region_pair.extension.hash, blob2_hash);
    }

    #[test]
    fn test_build_region_with_extension_error_missing_blob() {
        let builder = ChallengeBuilder::new().unwrap();

        let blob_data = vec![0u8; 131072];
        let blob_hash = B256::repeat_byte(0x01);
        let blobs = vec![BlobWithHash {
            data: &blob_data,
            hash: blob_hash,
        }];

        // Try to build region that crosses boundary but only one blob provided
        let result = builder.build_region_with_extension(&blobs, 4090, 15);

        assert!(result.is_err(), "Should fail when second blob is missing");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("second blob not provided"),
            "Error message should mention missing blob: {err}"
        );
    }

    #[test]
    fn test_build_region_with_extension_empty_blobs() {
        let builder = ChallengeBuilder::new().unwrap();

        let blobs: Vec<BlobWithHash> = vec![];

        let result = builder.build_region_with_extension(&blobs, 0, 5);

        assert!(result.is_err(), "Should fail with no blobs");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("No blobs provided"),
            "Error message should mention no blobs: {err}"
        );
    }

    #[test]
    fn test_empty_region() {
        let empty = ChallengeBuilder::empty_region();

        assert_eq!(empty.length, U256::ZERO);
        assert_eq!(empty.memoryAddress, U256::ZERO);
        assert!(empty.data.is_empty());
        assert!(empty.proofs.is_empty());
        assert!(empty.commitment.is_empty());
        assert_eq!(empty.hash, B256::ZERO);
    }

    #[test]
    fn test_blob_field_count_constant() {
        // Verify the constant matches expected blob size
        assert_eq!(BLOB_FIELD_COUNT, 4096);
        assert_eq!(BLOB_FIELD_COUNT * 32, 131072); // Full blob size in bytes
    }
}
