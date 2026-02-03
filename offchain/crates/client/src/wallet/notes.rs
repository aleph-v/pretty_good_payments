//! Note tracking for wallet.
//!
//! Each note stores its merkle proof components separately based on mutability:
//! - Block proof (16 levels): Immutable once block is committed
//! - Block-in-day proof (13 levels): Immutable once day ends
//! - Day-to-global proof (15 levels): Refreshed on sync (stored in cache, not here)

use alloy_primitives::{Address, B256, U256};
use pgp_merkle::{
    hierarchy::{BLOCK_IN_DAY_DEPTH, BLOCK_TREE_DEPTH, DAY_TREE_DEPTH},
    HierarchicalProof, TreePosition,
};
use serde::{Deserialize, Serialize};

/// Stored merkle proof for a note.
///
/// This contains the static parts of the proof that don't change:
/// - block_siblings: 16 levels from leaf to block root (immutable after block commit)
/// - block_in_day_siblings: 13 levels from block to day root (immutable after day ends)
///
/// The day-to-global path (15 levels) is dynamic and stored in the proof cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredProof {
    /// Block tree siblings (16 levels, from leaf to block root)
    /// Immutable once the block containing this note is committed.
    pub block_siblings: [B256; BLOCK_TREE_DEPTH],

    /// Block root (for verification)
    pub block_root: B256,

    /// Block-in-day tree siblings (13 levels, from block root to day root)
    /// Immutable once the day containing this note ends.
    /// None if the day is still in progress.
    pub block_in_day_siblings: Option<[B256; BLOCK_IN_DAY_DEPTH]>,

    /// Day root (for verification when day is finalized)
    /// None if the day is still in progress.
    pub day_root: Option<B256>,
}

impl StoredProof {
    /// Create a new stored proof with just the block-level proof.
    ///
    /// Used for notes in the current day where the day isn't finalized yet.
    pub fn new_partial(block_siblings: [B256; BLOCK_TREE_DEPTH], block_root: B256) -> Self {
        Self {
            block_siblings,
            block_root,
            block_in_day_siblings: None,
            day_root: None,
        }
    }

    /// Create a new stored proof with complete static components.
    ///
    /// Used for notes in finalized days.
    pub fn new_complete(
        block_siblings: [B256; BLOCK_TREE_DEPTH],
        block_root: B256,
        block_in_day_siblings: [B256; BLOCK_IN_DAY_DEPTH],
        day_root: B256,
    ) -> Self {
        Self {
            block_siblings,
            block_root,
            block_in_day_siblings: Some(block_in_day_siblings),
            day_root: Some(day_root),
        }
    }

    /// Check if this proof is complete (day has been finalized).
    pub fn is_complete(&self) -> bool {
        self.block_in_day_siblings.is_some() && self.day_root.is_some()
    }

    /// Finalize the proof with block-in-day siblings when day ends.
    pub fn finalize_day(
        &mut self,
        block_in_day_siblings: [B256; BLOCK_IN_DAY_DEPTH],
        day_root: B256,
    ) {
        self.block_in_day_siblings = Some(block_in_day_siblings);
        self.day_root = Some(day_root);
    }

    /// Build a complete HierarchicalProof by combining with a day-to-global path.
    ///
    /// Returns None if this proof is incomplete (day not finalized) or if
    /// block_in_day_siblings is missing.
    pub fn to_hierarchical_proof(
        &self,
        position: TreePosition,
        leaf: B256,
        global_siblings: [B256; DAY_TREE_DEPTH],
    ) -> Option<HierarchicalProof> {
        let block_in_day_siblings = self.block_in_day_siblings?;

        Some(HierarchicalProof::new(
            position,
            leaf,
            self.block_siblings,
            block_in_day_siblings,
            global_siblings,
        ))
    }
}

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
    /// Stored merkle proof (static parts that don't change)
    #[serde(default)]
    pub stored_proof: Option<StoredProof>,
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
            stored_proof: None,
        }
    }

    /// Create a new note with a stored proof.
    #[allow(clippy::too_many_arguments)]
    pub fn with_proof(
        commitment: B256,
        position: TreePosition,
        block_nr: u64,
        leaf_index: u32,
        asset: Address,
        amount: U256,
        blinding: B256,
        proof: StoredProof,
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
            stored_proof: Some(proof),
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

    /// Check if this note has a complete stored proof (day finalized).
    pub fn has_complete_proof(&self) -> bool {
        self.stored_proof.as_ref().is_some_and(|p| p.is_complete())
    }

    /// Check if this note has any stored proof.
    pub fn has_stored_proof(&self) -> bool {
        self.stored_proof.is_some()
    }

    /// Build a complete HierarchicalProof by combining stored proof with day path.
    ///
    /// Returns None if stored proof is incomplete or missing.
    pub fn build_hierarchical_proof(
        &self,
        global_siblings: [B256; DAY_TREE_DEPTH],
    ) -> Option<HierarchicalProof> {
        self.stored_proof.as_ref()?.to_hierarchical_proof(
            self.position,
            self.commitment,
            global_siblings,
        )
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
        assert!(!note.has_stored_proof());
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

    #[test]
    fn test_stored_proof_partial() {
        let block_siblings = [B256::repeat_byte(0x11); BLOCK_TREE_DEPTH];
        let block_root = B256::repeat_byte(0x22);

        let proof = StoredProof::new_partial(block_siblings, block_root);

        assert!(!proof.is_complete());
        assert!(proof.block_in_day_siblings.is_none());
        assert!(proof.day_root.is_none());
    }

    #[test]
    fn test_stored_proof_complete() {
        let block_siblings = [B256::repeat_byte(0x11); BLOCK_TREE_DEPTH];
        let block_root = B256::repeat_byte(0x22);
        let block_in_day_siblings = [B256::repeat_byte(0x33); BLOCK_IN_DAY_DEPTH];
        let day_root = B256::repeat_byte(0x44);

        let proof =
            StoredProof::new_complete(block_siblings, block_root, block_in_day_siblings, day_root);

        assert!(proof.is_complete());
        assert!(proof.block_in_day_siblings.is_some());
        assert!(proof.day_root.is_some());
    }

    #[test]
    fn test_stored_proof_finalize_day() {
        let block_siblings = [B256::repeat_byte(0x11); BLOCK_TREE_DEPTH];
        let block_root = B256::repeat_byte(0x22);

        let mut proof = StoredProof::new_partial(block_siblings, block_root);
        assert!(!proof.is_complete());

        let block_in_day_siblings = [B256::repeat_byte(0x33); BLOCK_IN_DAY_DEPTH];
        let day_root = B256::repeat_byte(0x44);

        proof.finalize_day(block_in_day_siblings, day_root);

        assert!(proof.is_complete());
        assert_eq!(proof.block_in_day_siblings, Some(block_in_day_siblings));
        assert_eq!(proof.day_root, Some(day_root));
    }

    #[test]
    fn test_note_with_proof() {
        let block_siblings = [B256::repeat_byte(0x11); BLOCK_TREE_DEPTH];
        let block_root = B256::repeat_byte(0x22);
        let block_in_day_siblings = [B256::repeat_byte(0x33); BLOCK_IN_DAY_DEPTH];
        let day_root = B256::repeat_byte(0x44);

        let proof =
            StoredProof::new_complete(block_siblings, block_root, block_in_day_siblings, day_root);

        let note = TrackedNote::with_proof(
            B256::repeat_byte(0x55),
            TreePosition::new(1, 2, 3),
            100,
            42,
            Address::ZERO,
            U256::from(1000u64),
            B256::repeat_byte(0x66),
            proof,
        );

        assert!(note.has_stored_proof());
        assert!(note.has_complete_proof());
    }

    #[test]
    fn test_note_build_hierarchical_proof() {
        let block_siblings = [B256::ZERO; BLOCK_TREE_DEPTH];
        let block_root = B256::repeat_byte(0x22);
        let block_in_day_siblings = [B256::ZERO; BLOCK_IN_DAY_DEPTH];
        let day_root = B256::repeat_byte(0x44);
        let global_siblings = [B256::ZERO; DAY_TREE_DEPTH];

        let proof =
            StoredProof::new_complete(block_siblings, block_root, block_in_day_siblings, day_root);

        let note = TrackedNote::with_proof(
            B256::repeat_byte(0x55),
            TreePosition::new(1, 2, 3),
            100,
            42,
            Address::ZERO,
            U256::from(1000u64),
            B256::repeat_byte(0x66),
            proof,
        );

        let hierarchical = note.build_hierarchical_proof(global_siblings);
        assert!(hierarchical.is_some());

        let h = hierarchical.unwrap();
        assert_eq!(h.position, note.position);
        assert_eq!(h.leaf, note.commitment);
    }

    #[test]
    fn test_note_build_hierarchical_proof_incomplete() {
        let block_siblings = [B256::ZERO; BLOCK_TREE_DEPTH];
        let block_root = B256::repeat_byte(0x22);

        // Partial proof - day not finalized
        let proof = StoredProof::new_partial(block_siblings, block_root);

        let note = TrackedNote::with_proof(
            B256::repeat_byte(0x55),
            TreePosition::new(1, 2, 3),
            100,
            42,
            Address::ZERO,
            U256::from(1000u64),
            B256::repeat_byte(0x66),
            proof,
        );

        let global_siblings = [B256::ZERO; DAY_TREE_DEPTH];
        let hierarchical = note.build_hierarchical_proof(global_siblings);

        // Should return None because proof is incomplete
        assert!(hierarchical.is_none());
    }
}
