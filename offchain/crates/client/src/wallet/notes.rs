//! Note tracking for wallet.

use alloy_primitives::{Address, B256, U256};
use pgp_merkle::TreePosition;
use serde::{Deserialize, Serialize};

/// A tracked note (UTXO) in the wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedNote {
    /// Note commitment (leaf hash)
    pub commitment: B256,
    /// Position in the merkle tree
    pub position: TreePosition,
    /// Block number where this note was created
    pub block_nr: u64,
    /// Leaf index within the block
    pub leaf_index: u32,
    /// Asset (ERC20 address, or zero for native token)
    pub asset: Address,
    /// Amount
    pub amount: U256,
    /// Blinding factor (needed to spend)
    pub blinding: B256,
    /// Whether this note has been spent
    pub spent: bool,
    /// Nullifier if spent (for tracking)
    pub nullifier: Option<B256>,
}

impl TrackedNote {
    /// Create a new unspent note.
    pub fn new(
        commitment: B256,
        position: TreePosition,
        block_nr: u64,
        leaf_index: u32,
        asset: Address,
        amount: U256,
        blinding: B256,
    ) -> Self {
        Self {
            commitment,
            position,
            block_nr,
            leaf_index,
            asset,
            amount,
            blinding,
            spent: false,
            nullifier: None,
        }
    }

    /// Mark this note as spent with the given nullifier.
    pub fn mark_spent(&mut self, nullifier: B256) {
        self.spent = true;
        self.nullifier = Some(nullifier);
    }

    /// Check if this note matches an asset filter.
    pub fn matches_asset(&self, asset_filter: Option<Address>) -> bool {
        match asset_filter {
            None => true,
            Some(filter) => self.asset == filter,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracked_note_new() {
        let note = TrackedNote::new(
            B256::repeat_byte(0x11),
            TreePosition::new(1, 2, 3),
            100,
            42,
            Address::ZERO,
            U256::from(1000u64),
            B256::repeat_byte(0x22),
        );

        assert!(!note.spent);
        assert!(note.nullifier.is_none());
        assert_eq!(note.amount, U256::from(1000u64));
    }

    #[test]
    fn test_tracked_note_mark_spent() {
        let mut note = TrackedNote::new(
            B256::repeat_byte(0x11),
            TreePosition::new(1, 2, 3),
            100,
            42,
            Address::ZERO,
            U256::from(1000u64),
            B256::repeat_byte(0x22),
        );

        let nullifier = B256::repeat_byte(0x33);
        note.mark_spent(nullifier);

        assert!(note.spent);
        assert_eq!(note.nullifier, Some(nullifier));
    }

    #[test]
    fn test_tracked_note_matches_asset() {
        let note = TrackedNote::new(
            B256::ZERO,
            TreePosition::new(0, 0, 0),
            0,
            0,
            Address::repeat_byte(0xAB),
            U256::ZERO,
            B256::ZERO,
        );

        // No filter matches everything
        assert!(note.matches_asset(None));

        // Matching asset
        assert!(note.matches_asset(Some(Address::repeat_byte(0xAB))));

        // Non-matching asset
        assert!(!note.matches_asset(Some(Address::repeat_byte(0xCD))));
    }
}
