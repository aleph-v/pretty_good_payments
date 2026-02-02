//! Wallet storage (encrypted JSON file).

use crate::wallet::keys::{derive_public_key, derive_spending_key};
use crate::wallet::notes::TrackedNote;
use alloy_primitives::{Address, B256, U256};
use eyre::{Result, WrapErr};
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
        }
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
            fs::create_dir_all(parent)
                .wrap_err_with(|| format!("Failed to create wallet directory: {}", parent.display()))?;
        }

        let contents = serde_json::to_string_pretty(self)
            .wrap_err("Failed to serialize wallet")?;

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
}
