//! Error types for the sequencer.

use alloy_primitives::B256;
use thiserror::Error;

/// Errors that can occur in the sequencer.
#[derive(Debug, Error)]
pub enum SequencerError {
    /// Sequencer is not allowed to submit at this time (closed epoch period).
    #[error("Not allowed to submit during closed epoch period")]
    NotAllowed,

    /// Cannot submit an empty block (no deposits and no transactions).
    #[error("Cannot submit empty block (0 deposits and 0 transactions)")]
    EmptyBlock,

    /// Too many deposits for the available blob space.
    #[error("Too many deposits: {0} exceeds maximum {1}")]
    TooManyDeposits(usize, usize),

    /// Too many transactions for the available blob space.
    #[error("Too many transactions: {0} exceeds maximum {1}")]
    TooManyTransactions(usize, usize),

    /// Block submission transaction failed.
    #[error("Block submission failed: {0}")]
    SubmissionFailed(String),

    /// RPC provider error.
    #[error("Provider error: {0}")]
    ProviderError(String),

    /// Contract call error.
    #[error("Contract error: {0}")]
    ContractError(String),

    /// Merkle tree error.
    #[error("Merkle tree error: {0}")]
    MerkleError(String),

    /// KZG commitment error.
    #[error("KZG error: {0}")]
    KzgError(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Transaction signing error.
    #[error("Signing error: {0}")]
    SigningError(String),

    /// Anchor mismatch - expected anchor doesn't match contract state.
    #[error("Anchor mismatch: expected {expected}, got {actual}")]
    AnchorMismatch { expected: B256, actual: B256 },

    /// No deposits available for the target block.
    #[error("No deposits available for block {0}")]
    NoDepositsForBlock(u64),

    /// Timeout waiting for submission window.
    #[error("Timeout waiting for open epoch period")]
    EpochTimeout,
}

impl From<pgp_merkle::MerkleError> for SequencerError {
    fn from(e: pgp_merkle::MerkleError) -> Self {
        SequencerError::MerkleError(e.to_string())
    }
}

impl From<eyre::Report> for SequencerError {
    fn from(e: eyre::Report) -> Self {
        SequencerError::ProviderError(e.to_string())
    }
}
