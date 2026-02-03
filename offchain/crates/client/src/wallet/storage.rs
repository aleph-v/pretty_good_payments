//! Wallet storage (encrypted JSON file).

use crate::wallet::keys::{derive_public_key, derive_spending_key};
use crate::wallet::notes::{StoredProof, TrackedNote};
use alloy_primitives::{Address, B256, U256};
use eyre::{Result, WrapErr};
use pgp_merkle::hierarchy::BLOCK_IN_DAY_DEPTH;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// Wallet data structure (stored as JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wallet {
    /// Version for forward compatibility
    pub version: u32,
    /// Seed phrase (in production, this should be encrypted)
    pub seed: String,
    /// Derived spending key
    pub spending_key: B256,
    /// Derived public key
    pub public_key: B256,
    /// Tracked notes (owned UTXOs)
    pub notes: Vec<TrackedNote>,
    /// Spent nullifiers (to prevent double-spend and for tracking)
    pub spent_nullifiers: HashSet<B256>,
    /// Transaction counter for deterministic blinding derivation
    #[serde(default)]
    pub tx_counter: u64,
}

impl Wallet {
    /// Create a new wallet from a seed phrase.
    pub fn new(seed: &str) -> Self {
        let spending_key = derive_spending_key(seed);
        let public_key = derive_public_key(spending_key);

        Self {
            version: 1,
            seed: seed.to_string(),
            spending_key,
            public_key,
            notes: Vec::new(),
            spent_nullifiers: HashSet::new(),
            tx_counter: 0,
        }
    }

    /// Create a wallet directly from a spending key.
    ///
    /// This is useful for testing scenarios where you have a pre-derived key.
    /// The seed is set to an empty string since it's not available.
    pub fn from_spending_key(spending_key: B256) -> Self {
        let public_key = derive_public_key(spending_key);

        Self {
            version: 1,
            seed: String::new(),
            spending_key,
            public_key,
            notes: Vec::new(),
            spent_nullifiers: HashSet::new(),
            tx_counter: 0,
        }
    }

    /// Get the next transaction counter and increment it.
    ///
    /// This is used for deterministic blinding factor derivation.
    /// Each call returns the current value and increments the counter.
    pub fn next_tx_counter(&mut self) -> u64 {
        let counter = self.tx_counter;
        self.tx_counter += 1;
        counter
    }

    /// Load wallet from a JSON file.
    pub fn load(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .wrap_err_with(|| format!("Failed to read wallet file: {}", path.display()))?;

        serde_json::from_str(&contents)
            .wrap_err_with(|| format!("Failed to parse wallet file: {}", path.display()))
    }

    /// Save wallet to a JSON file.
    pub fn save(&self, path: &Path) -> Result<()> {
        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).wrap_err_with(|| {
                format!("Failed to create wallet directory: {}", parent.display())
            })?;
        }

        let contents = serde_json::to_string_pretty(self).wrap_err("Failed to serialize wallet")?;

        fs::write(path, contents)
            .wrap_err_with(|| format!("Failed to write wallet file: {}", path.display()))
    }

    /// Check if wallet file exists.
    pub fn exists(path: &Path) -> bool {
        path.exists()
    }

    /// Get the wallet's public key (for receiving funds).
    pub fn public_key(&self) -> B256 {
        self.public_key
    }

    /// Get the wallet's spending key (for signing transactions).
    pub fn spending_key(&self) -> B256 {
        self.spending_key
    }

    /// Add a new note to the wallet.
    pub fn add_note(&mut self, note: TrackedNote) {
        self.notes.push(note);
    }

    /// Get all unspent notes.
    pub fn unspent_notes(&self) -> Vec<&TrackedNote> {
        self.notes.iter().filter(|n| !n.spent).collect()
    }

    /// Get unspent notes for a specific asset.
    pub fn unspent_notes_for_asset(&self, asset: Address) -> Vec<&TrackedNote> {
        self.notes
            .iter()
            .filter(|n| !n.spent && n.asset == asset)
            .collect()
    }

    /// Calculate total balance for an asset.
    pub fn balance(&self, asset: Option<Address>) -> U256 {
        self.notes
            .iter()
            .filter(|n| !n.spent && n.matches_asset(asset))
            .fold(U256::ZERO, |acc, n| acc + n.amount)
    }

    /// Mark a note as spent by its commitment.
    pub fn mark_note_spent(&mut self, commitment: B256, nullifier: B256) -> bool {
        if let Some(note) = self.notes.iter_mut().find(|n| n.commitment == commitment) {
            note.mark_spent(nullifier);
            self.spent_nullifiers.insert(nullifier);
            true
        } else {
            false
        }
    }

    /// Check if a nullifier has been spent.
    pub fn is_nullifier_spent(&self, nullifier: &B256) -> bool {
        self.spent_nullifiers.contains(nullifier)
    }

    /// Select notes for spending a target amount.
    ///
    /// Returns (selected_notes, change_amount) or None if insufficient balance.
    pub fn select_notes_for_amount(
        &self,
        asset: Address,
        target: U256,
    ) -> Option<(Vec<&TrackedNote>, U256)> {
        let mut available: Vec<_> = self.unspent_notes_for_asset(asset);
        // Sort by amount descending (prefer larger notes to minimize inputs)
        available.sort_by(|a, b| b.amount.cmp(&a.amount));

        let mut selected = Vec::new();
        let mut total = U256::ZERO;

        for note in available {
            if total >= target {
                break;
            }
            selected.push(note);
            total += note.amount;
        }

        if total >= target {
            let change = total - target;
            Some((selected, change))
        } else {
            None
        }
    }

    /// Get all unique assets in the wallet.
    pub fn assets(&self) -> Vec<Address> {
        let mut assets: Vec<_> = self
            .notes
            .iter()
            .filter(|n| !n.spent)
            .map(|n| n.asset)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        assets.sort();
        assets
    }

    /// Get unspent notes that don't have a stored proof yet.
    ///
    /// These notes need their block tree proof fetched and stored.
    pub fn notes_needing_block_proof(&self) -> Vec<&TrackedNote> {
        self.notes
            .iter()
            .filter(|n| !n.spent && !n.has_stored_proof())
            .collect()
    }

    /// Get unspent notes that have partial proofs (day not finalized yet).
    ///
    /// Only returns notes from past days that need block-in-day siblings.
    /// Notes from the current day should remain partial until the day ends.
    pub fn notes_needing_day_finalization(&self, current_day: u16) -> Vec<&TrackedNote> {
        self.notes
            .iter()
            .filter(|n| {
                !n.spent
                    && n.has_stored_proof()
                    && !n.has_complete_proof()
                    && n.position.day < current_day
            })
            .collect()
    }

    /// Store a block proof with a note.
    ///
    /// Called when first syncing a note to store the immutable block tree siblings.
    pub fn store_block_proof(&mut self, commitment: B256, proof: StoredProof) -> bool {
        if let Some(note) = self.notes.iter_mut().find(|n| n.commitment == commitment) {
            note.stored_proof = Some(proof);
            true
        } else {
            false
        }
    }

    /// Finalize day proofs for notes in a completed day.
    ///
    /// Called when a day ends to add the block-in-day siblings to notes.
    pub fn finalize_day_proofs(
        &mut self,
        day: u16,
        block_in_day_siblings: &[(u16, [B256; BLOCK_IN_DAY_DEPTH])],
        day_root: B256,
    ) -> usize {
        let mut finalized = 0;
        for note in self.notes.iter_mut() {
            if !note.spent
                && note.position.day == day
                && note.has_stored_proof()
                && !note.has_complete_proof()
            {
                if let Some(siblings) = block_in_day_siblings
                    .iter()
                    .find(|(b, _)| *b == note.position.block_in_day)
                    .map(|(_, s)| *s)
                {
                    if let Some(ref mut proof) = note.stored_proof {
                        proof.finalize_day(siblings, day_root);
                        finalized += 1;
                    }
                }
            }
        }
        finalized
    }

    /// Get a mutable reference to a note by commitment.
    pub fn get_note_mut(&mut self, commitment: B256) -> Option<&mut TrackedNote> {
        self.notes.iter_mut().find(|n| n.commitment == commitment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp_merkle::TreePosition;
    use tempfile::tempdir;

    fn make_test_note(amount: u64, asset: Address, spent: bool) -> TrackedNote {
        let mut note = TrackedNote::new(
            B256::repeat_byte(amount as u8),
            TreePosition::new(0, 0, 0),
            0,
            0,
            asset,
            U256::from(amount),
            B256::ZERO,
        );
        if spent {
            note.mark_spent(B256::repeat_byte(0xFF));
        }
        note
    }

    #[test]
    fn test_wallet_new() {
        let wallet = Wallet::new("test seed phrase");
        assert_eq!(wallet.version, 1);
        assert!(wallet.notes.is_empty());
        assert!(wallet.spent_nullifiers.is_empty());
    }

    #[test]
    fn test_wallet_key_derivation() {
        let wallet = Wallet::new("test seed phrase");
        assert_ne!(wallet.spending_key, B256::ZERO);
        assert_ne!(wallet.public_key, B256::ZERO);
        assert_ne!(wallet.spending_key, wallet.public_key);
    }

    #[test]
    fn test_wallet_save_load() {
        let dir = tempdir().unwrap();
        let wallet_path = dir.path().join("test_wallet.json");

        let mut wallet = Wallet::new("test seed");
        wallet.add_note(make_test_note(1000, Address::ZERO, false));
        wallet.save(&wallet_path).unwrap();

        let loaded = Wallet::load(&wallet_path).unwrap();
        assert_eq!(loaded.seed, "test seed");
        assert_eq!(loaded.notes.len(), 1);
        assert_eq!(loaded.notes[0].amount, U256::from(1000u64));
    }

    #[test]
    fn test_wallet_balance() {
        let mut wallet = Wallet::new("test");
        let asset = Address::repeat_byte(0x11);

        wallet.add_note(make_test_note(1000, asset, false));
        wallet.add_note(make_test_note(500, asset, false));
        wallet.add_note(make_test_note(200, asset, true)); // Spent

        assert_eq!(wallet.balance(Some(asset)), U256::from(1500u64));
        assert_eq!(wallet.balance(None), U256::from(1500u64));
    }

    #[test]
    fn test_wallet_select_notes() {
        let mut wallet = Wallet::new("test");
        let asset = Address::ZERO;

        wallet.add_note(make_test_note(1000, asset, false));
        wallet.add_note(make_test_note(500, asset, false));
        wallet.add_note(make_test_note(300, asset, false));

        // Select for 1200 - should get 1000 + 500 = 1500, change = 300
        let (selected, change) = wallet
            .select_notes_for_amount(asset, U256::from(1200u64))
            .unwrap();
        assert_eq!(selected.len(), 2);
        assert_eq!(change, U256::from(300u64));

        // Select for 2000 - insufficient
        assert!(wallet
            .select_notes_for_amount(asset, U256::from(2000u64))
            .is_none());
    }

    #[test]
    fn test_wallet_mark_spent() {
        let mut wallet = Wallet::new("test");
        let commitment = B256::repeat_byte(0x11);
        let nullifier = B256::repeat_byte(0x22);

        let mut note = make_test_note(1000, Address::ZERO, false);
        note.commitment = commitment;
        wallet.add_note(note);

        assert!(wallet.mark_note_spent(commitment, nullifier));
        assert!(wallet.is_nullifier_spent(&nullifier));
        assert_eq!(wallet.unspent_notes().len(), 0);
    }

    #[test]
    fn test_wallet_assets() {
        let mut wallet = Wallet::new("test");
        let asset1 = Address::repeat_byte(0x11);
        let asset2 = Address::repeat_byte(0x22);

        wallet.add_note(make_test_note(100, asset1, false));
        wallet.add_note(make_test_note(200, asset2, false));
        wallet.add_note(make_test_note(300, asset1, true)); // Spent, should not appear

        let assets = wallet.assets();
        assert_eq!(assets.len(), 2);
        assert!(assets.contains(&asset1));
        assert!(assets.contains(&asset2));
    }

    #[test]
    fn test_wallet_from_spending_key() {
        use crate::wallet::keys::derive_spending_key;

        let spending_key = derive_spending_key("test seed");
        let wallet = Wallet::from_spending_key(spending_key);

        assert_eq!(wallet.spending_key, spending_key);
        assert_ne!(wallet.public_key, B256::ZERO);
        assert_ne!(wallet.public_key, spending_key);
        assert!(wallet.notes.is_empty());
        assert_eq!(wallet.tx_counter, 0);
    }

    #[test]
    fn test_wallet_next_tx_counter() {
        let mut wallet = Wallet::new("test");

        assert_eq!(wallet.tx_counter, 0);

        let counter0 = wallet.next_tx_counter();
        assert_eq!(counter0, 0);
        assert_eq!(wallet.tx_counter, 1);

        let counter1 = wallet.next_tx_counter();
        assert_eq!(counter1, 1);
        assert_eq!(wallet.tx_counter, 2);

        let counter2 = wallet.next_tx_counter();
        assert_eq!(counter2, 2);
        assert_eq!(wallet.tx_counter, 3);
    }

    #[test]
    fn test_wallet_tx_counter_persists() {
        let dir = tempdir().unwrap();
        let wallet_path = dir.path().join("test_wallet.json");

        let mut wallet = Wallet::new("test seed");
        wallet.next_tx_counter();
        wallet.next_tx_counter();
        assert_eq!(wallet.tx_counter, 2);
        wallet.save(&wallet_path).unwrap();

        let loaded = Wallet::load(&wallet_path).unwrap();
        assert_eq!(loaded.tx_counter, 2);

        // Continue incrementing after load
        let mut loaded = loaded;
        assert_eq!(loaded.next_tx_counter(), 2);
        assert_eq!(loaded.tx_counter, 3);
    }

    #[test]
    fn test_notes_needing_block_proof() {
        use crate::wallet::notes::StoredProof;
        use pgp_merkle::hierarchy::BLOCK_TREE_DEPTH;

        let mut wallet = Wallet::new("test");

        // Add note without stored proof
        let mut note1 = make_test_note(1000, Address::ZERO, false);
        note1.commitment = B256::repeat_byte(0x01);
        wallet.add_note(note1);

        // Add note with stored proof
        let mut note2 = make_test_note(2000, Address::ZERO, false);
        note2.commitment = B256::repeat_byte(0x02);
        note2.stored_proof = Some(StoredProof::new_partial(
            [B256::ZERO; BLOCK_TREE_DEPTH],
            B256::repeat_byte(0x33),
        ));
        wallet.add_note(note2);

        let needing_proof = wallet.notes_needing_block_proof();
        assert_eq!(needing_proof.len(), 1);
        assert_eq!(needing_proof[0].commitment, B256::repeat_byte(0x01));
    }

    #[test]
    fn test_notes_needing_day_finalization() {
        use crate::wallet::notes::StoredProof;
        use pgp_merkle::hierarchy::{BLOCK_IN_DAY_DEPTH, BLOCK_TREE_DEPTH};

        let mut wallet = Wallet::new("test");
        let current_day = 5;

        // Note in past day with partial proof (needs finalization)
        let mut note1 = TrackedNote::new(
            B256::repeat_byte(0x01),
            TreePosition::new(3, 0, 0), // Day 3, past
            0,
            0,
            Address::ZERO,
            U256::from(1000u64),
            B256::ZERO,
        );
        note1.stored_proof = Some(StoredProof::new_partial(
            [B256::ZERO; BLOCK_TREE_DEPTH],
            B256::repeat_byte(0x11),
        ));
        wallet.add_note(note1);

        // Note in current day with partial proof (should NOT need finalization yet)
        let mut note2 = TrackedNote::new(
            B256::repeat_byte(0x02),
            TreePosition::new(5, 0, 0), // Day 5, current
            0,
            1,
            Address::ZERO,
            U256::from(2000u64),
            B256::ZERO,
        );
        note2.stored_proof = Some(StoredProof::new_partial(
            [B256::ZERO; BLOCK_TREE_DEPTH],
            B256::repeat_byte(0x22),
        ));
        wallet.add_note(note2);

        // Note in past day with complete proof (already finalized)
        let mut note3 = TrackedNote::new(
            B256::repeat_byte(0x03),
            TreePosition::new(2, 0, 0), // Day 2, past
            0,
            2,
            Address::ZERO,
            U256::from(3000u64),
            B256::ZERO,
        );
        note3.stored_proof = Some(StoredProof::new_complete(
            [B256::ZERO; BLOCK_TREE_DEPTH],
            B256::repeat_byte(0x33),
            [B256::ZERO; BLOCK_IN_DAY_DEPTH],
            B256::repeat_byte(0x44),
        ));
        wallet.add_note(note3);

        let needing_finalization = wallet.notes_needing_day_finalization(current_day);
        assert_eq!(needing_finalization.len(), 1);
        assert_eq!(needing_finalization[0].commitment, B256::repeat_byte(0x01));
    }

    #[test]
    fn test_store_block_proof() {
        use crate::wallet::notes::StoredProof;
        use pgp_merkle::hierarchy::BLOCK_TREE_DEPTH;

        let mut wallet = Wallet::new("test");
        let commitment = B256::repeat_byte(0x42);

        let mut note = make_test_note(1000, Address::ZERO, false);
        note.commitment = commitment;
        wallet.add_note(note);

        assert!(!wallet.notes[0].has_stored_proof());

        let proof = StoredProof::new_partial(
            [B256::repeat_byte(0x11); BLOCK_TREE_DEPTH],
            B256::repeat_byte(0x22),
        );

        let result = wallet.store_block_proof(commitment, proof);
        assert!(result);
        assert!(wallet.notes[0].has_stored_proof());
        assert!(!wallet.notes[0].has_complete_proof());
    }

    #[test]
    fn test_finalize_day_proofs() {
        use crate::wallet::notes::StoredProof;
        use pgp_merkle::hierarchy::{BLOCK_IN_DAY_DEPTH, BLOCK_TREE_DEPTH};

        let mut wallet = Wallet::new("test");

        // Add two notes in the same day, different blocks
        let mut note1 = TrackedNote::new(
            B256::repeat_byte(0x01),
            TreePosition::new(3, 10, 0),
            0,
            0,
            Address::ZERO,
            U256::from(1000u64),
            B256::ZERO,
        );
        note1.stored_proof = Some(StoredProof::new_partial(
            [B256::ZERO; BLOCK_TREE_DEPTH],
            B256::repeat_byte(0x11),
        ));
        wallet.add_note(note1);

        let mut note2 = TrackedNote::new(
            B256::repeat_byte(0x02),
            TreePosition::new(3, 20, 0),
            0,
            1,
            Address::ZERO,
            U256::from(2000u64),
            B256::ZERO,
        );
        note2.stored_proof = Some(StoredProof::new_partial(
            [B256::ZERO; BLOCK_TREE_DEPTH],
            B256::repeat_byte(0x22),
        ));
        wallet.add_note(note2);

        // Finalize day 3
        let block_paths = vec![
            (10, [B256::repeat_byte(0xAA); BLOCK_IN_DAY_DEPTH]),
            (20, [B256::repeat_byte(0xBB); BLOCK_IN_DAY_DEPTH]),
        ];
        let day_root = B256::repeat_byte(0xDD);

        let finalized = wallet.finalize_day_proofs(3, &block_paths, day_root);
        assert_eq!(finalized, 2);

        assert!(wallet.notes[0].has_complete_proof());
        assert!(wallet.notes[1].has_complete_proof());
        assert_eq!(
            wallet.notes[0].stored_proof.as_ref().unwrap().day_root,
            Some(day_root)
        );
    }
}
