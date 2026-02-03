//! Fraud validators for the challenger.
//!
//! Each validator checks for a specific type of fraud:
//! - `deposit`: Incorrect deposit leaf in blob
//! - `nullifier`: Double-spend detection (same nullifier used twice)
//! - `transaction`: Invalid ZK proof or eth-key authorization
//! - `tree_update`: Incorrect merkle root after update

pub mod deposit;
pub mod nullifier;
pub mod transaction;
pub mod tree_update;

pub use deposit::DepositValidator;
pub use nullifier::NullifierValidator;
pub use transaction::{AnchorLookup, TransactionValidator};
pub use tree_update::{
    compute_anchor_from_path, BlockTreeTracker, HierarchicalRootTracker, RootTreeTracker,
    TreeUpdateValidator, BLOCKS_PER_DAY, BLOCK_IN_DAY_DEPTH, DAY_DEPTH,
};

use alloy::primitives::{Address, B256};
use pgp_common::contracts::BlockData;

/// Merkle proof data needed for tree update ZK proof generation
#[derive(Debug, Clone)]
pub struct TreeUpdateMerkleData {
    /// Block tree root before the update
    pub block_root_before: B256,
    /// Block's position in the root tree (0-indexed)
    pub block_index: u64,
    /// Starting leaf index within the block tree
    pub in_block_index: usize,
    /// Previous non-zero field value (for circuit bounds check)
    pub nonzero_field: B256,
    /// Merkle proofs for the 4 positions being updated in block tree
    /// Each proof has 16 sibling hashes (BLOCK_DEPTH = 16)
    pub block_proofs: [[B256; 16]; 4],
    /// Sibling hashes for the block's position in the root tree
    /// Has 28 elements (ROOT_DEPTH = 28)
    pub root_path: [B256; 28],
}

/// Result of validating a block
#[derive(Debug, Clone)]
pub enum ValidationResult {
    /// Block is valid
    Valid,
    /// Block contains fraud that can be challenged
    Fraud(FraudEvidence),
}

/// Evidence of fraud detected in a block.
/// Uses u64 for block numbers and indices as these are sufficient for practical use.
/// BlockData is included where needed for challenge submission to contracts.
#[derive(Debug, Clone)]
pub enum FraudEvidence {
    /// Deposit leaf mismatch
    DepositWrongLeaf {
        block_data: BlockData,
        deposit_nr: u64,
        expected_leaf: B256,
        submitted_leaf: B256,
    },
    /// Deposit padding not zero - unused slots in deposit group must be zero
    DepositPaddingNotZero {
        block_data: BlockData,
        group_index: u64,
        slot_index: u64,
        submitted_value: B256,
    },
    /// Nullifier double-spend - BlockData must be fetched separately using block numbers
    NullifierDoubleSpend {
        first_block_nr: u64,
        second_block_nr: u64,
        first_tx_number: u32,
        second_tx_number: u32,
        first_which: u8,
        second_which: u8,
        nullifier: B256,
    },
    /// Invalid transaction ZK proof - Groth16 verification failed
    InvalidTransactionProof {
        block_data: BlockData,
        tx_nr: u64,
        /// Anchor reference info (needed for challenge submission)
        anchor_block_nr: u32,
        anchor_update_nr: u32,
        is_deposit: bool,
    },
    /// Invalid anchor reference - blockNr or updateNr out of bounds
    InvalidAnchorReference {
        block_data: BlockData,
        tx_nr: u64,
        anchor_block_nr: u32,
        anchor_update_nr: u32,
        is_deposit: bool,
    },
    /// Missing eth-key authorization - eth-keyed tx not authorized in TransactionRegistry
    MissingEthKeyAuth {
        block_data: BlockData,
        tx_nr: u64,
        eth_key: Address,
        nullifiers: [B256; 2],
        leaves: [B256; 3],
        /// Anchor reference info (needed for challenge submission)
        anchor_block_nr: u32,
        anchor_update_nr: u32,
        is_deposit: bool,
    },
    /// Incorrect tree update - merkle root mismatch after applying leaves
    IncorrectTreeUpdate {
        block_data: BlockData,
        update_nr: u64,
        is_tx: bool,
        expected_anchor: B256,
        submitted_anchor: B256,
        /// Anchor before this update (needed for challenge submission)
        prior_anchor: B256,
        /// The three leaves being inserted
        leaves: [B256; 3],
        /// Block number containing the prior anchor (for KZG proof if from previous block)
        prior_anchor_block_nr: Option<u64>,
        /// Update number of prior anchor (if from same block)
        prior_update_nr: Option<u64>,
        /// Merkle proof data for ZK proof generation
        merkle_data: Option<TreeUpdateMerkleData>,
    },
}

/// Trait for fraud validators
pub trait Validator {
    /// Validate a block and return any fraud evidence found
    fn validate(&self, block_data: &BlockData, blob_data: &[B256]) -> Vec<FraudEvidence>;
}
