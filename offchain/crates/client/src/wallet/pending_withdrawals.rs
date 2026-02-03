//! Pending withdrawals storage.
//!
//! Withdrawals are a two-stage process:
//! 1. L2 transfer to publicKey=0 with blinding encoding the L1 recipient
//! 2. L1 withdrawal with KZG proof after the block is confirmed
//!
//! This module tracks pending withdrawals that have completed stage 1
//! but not yet been executed on L1.

use alloy_primitives::{Address, B256, U256};
use eyre::{Result, WrapErr};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// A pending withdrawal waiting to be executed on L1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingWithdrawal {
    /// The L2 transaction ID (optional, for tracking)
    pub tx_id: Option<String>,
    /// The block number the withdrawal was included in
    pub block_nr: u64,
    /// The transaction index within the block
    pub tx_nr: u64,
    /// Which output (0, 1, or 2) is the withdrawal output
    pub output_index: u8,
    /// The asset being withdrawn
    pub asset: Address,
    /// The amount being withdrawn
    pub amount: U256,
    /// The L1 recipient address
    pub recipient: Address,
    /// The leaf commitment (for verification)
    pub leaf_commitment: B256,
    /// Whether this withdrawal has been executed on L1
    pub executed: bool,
    /// The L1 execution transaction hash (if executed)
    pub execution_tx: Option<B256>,
    /// Timestamp when the withdrawal was created
    pub created_at: u64,
}

/// Storage for pending withdrawals.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PendingWithdrawals {
    /// Version for forward compatibility
    pub version: u32,
    /// List of pending withdrawals
    pub withdrawals: Vec<PendingWithdrawal>,
}

impl PendingWithdrawals {
    /// Create a new empty pending withdrawals store.
    pub fn new() -> Self {
        Self {
            version: 1,
            withdrawals: Vec::new(),
        }
    }

    /// Load pending withdrawals from a JSON file.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }

        let contents = fs::read_to_string(path)
            .wrap_err_with(|| format!("Failed to read pending withdrawals: {}", path.display()))?;

        serde_json::from_str(&contents)
            .wrap_err_with(|| format!("Failed to parse pending withdrawals: {}", path.display()))
    }

    /// Save pending withdrawals to a JSON file.
    pub fn save(&self, path: &Path) -> Result<()> {
        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .wrap_err_with(|| format!("Failed to create directory: {}", parent.display()))?;
        }

        let contents = serde_json::to_string_pretty(self)
            .wrap_err("Failed to serialize pending withdrawals")?;

        fs::write(path, contents)
            .wrap_err_with(|| format!("Failed to write pending withdrawals: {}", path.display()))
    }

    /// Add a new pending withdrawal.
    pub fn add(&mut self, withdrawal: PendingWithdrawal) {
        self.withdrawals.push(withdrawal);
    }

    /// Get all unexecuted withdrawals.
    pub fn unexecuted(&self) -> Vec<&PendingWithdrawal> {
        self.withdrawals.iter().filter(|w| !w.executed).collect()
    }

    /// Mark a withdrawal as executed.
    pub fn mark_executed(&mut self, block_nr: u64, tx_nr: u64, output_index: u8, tx_hash: B256) {
        for w in &mut self.withdrawals {
            if w.block_nr == block_nr && w.tx_nr == tx_nr && w.output_index == output_index {
                w.executed = true;
                w.execution_tx = Some(tx_hash);
            }
        }
    }

    /// Get pending withdrawal count.
    pub fn pending_count(&self) -> usize {
        self.withdrawals.iter().filter(|w| !w.executed).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_pending_withdrawals_save_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("pending.json");

        let mut pending = PendingWithdrawals::new();
        pending.add(PendingWithdrawal {
            tx_id: Some("test-tx".to_string()),
            block_nr: 100,
            tx_nr: 5,
            output_index: 0,
            asset: Address::ZERO,
            amount: U256::from(1000u64),
            recipient: Address::repeat_byte(0x42),
            leaf_commitment: B256::repeat_byte(0x11),
            executed: false,
            execution_tx: None,
            created_at: 1234567890,
        });

        pending.save(&path).unwrap();

        let loaded = PendingWithdrawals::load(&path).unwrap();
        assert_eq!(loaded.withdrawals.len(), 1);
        assert_eq!(loaded.withdrawals[0].block_nr, 100);
        assert_eq!(loaded.withdrawals[0].recipient, Address::repeat_byte(0x42));
    }

    #[test]
    fn test_pending_withdrawals_mark_executed() {
        let mut pending = PendingWithdrawals::new();
        pending.add(PendingWithdrawal {
            tx_id: None,
            block_nr: 100,
            tx_nr: 5,
            output_index: 0,
            asset: Address::ZERO,
            amount: U256::from(1000u64),
            recipient: Address::repeat_byte(0x42),
            leaf_commitment: B256::repeat_byte(0x11),
            executed: false,
            execution_tx: None,
            created_at: 0,
        });

        assert_eq!(pending.pending_count(), 1);

        let tx_hash = B256::repeat_byte(0xAA);
        pending.mark_executed(100, 5, 0, tx_hash);

        assert_eq!(pending.pending_count(), 0);
        assert!(pending.withdrawals[0].executed);
        assert_eq!(pending.withdrawals[0].execution_tx, Some(tx_hash));
    }
}
