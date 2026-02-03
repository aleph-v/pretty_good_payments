//! Key derivation for PGP wallets.

use alloy_primitives::B256;
use pgp_merkle::poseidon2;
use sha2::{Digest, Sha256};

/// Domain separator for public key derivation
const PUBLIC_KEY_DOMAIN: &[u8] = b"PGP_PUBLIC_KEY_V1";

/// Domain separator for deterministic blinding derivation
const BLINDING_DOMAIN: &[u8] = b"PGP_BLINDING_V1";

/// Derive a spending key from a seed phrase.
///
/// Uses SHA256 to derive a 256-bit key from the seed phrase.
/// The result is reduced to fit within the BN254 scalar field.
pub fn derive_spending_key(seed: &str) -> B256 {
    let mut hasher = Sha256::new();
    hasher.update(b"PGP_SPENDING_KEY_V1");
    hasher.update(seed.as_bytes());
    let hash = hasher.finalize();

    // Ensure the key is within the BN254 scalar field by clearing top bits
    // BN254 modulus starts with 0x30, so we use 0x1F mask to ensure < 2^253
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&hash);
    key_bytes[0] &= 0x1F;

    B256::from(key_bytes)
}

/// Derive the public key from a spending key.
///
/// public_key = Poseidon(domain, spending_key)
pub fn derive_public_key(spending_key: B256) -> B256 {
    // Create domain hash
    let mut hasher = Sha256::new();
    hasher.update(PUBLIC_KEY_DOMAIN);
    let domain_hash = hasher.finalize();

    let mut domain_bytes = [0u8; 32];
    domain_bytes.copy_from_slice(&domain_hash);
    // BN254 modulus starts with 0x30, so we use 0x1F mask to ensure < 2^253
    domain_bytes[0] &= 0x1F;
    let domain = B256::from(domain_bytes);

    poseidon2(domain, spending_key)
}

/// Generate a random blinding factor.
pub fn generate_blinding() -> B256 {
    use sha2::Sha256;

    // In production, use a proper CSPRNG
    // For now, use timestamp + random seed
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let mut hasher = Sha256::new();
    hasher.update(b"PGP_BLINDING");
    hasher.update(&now.to_le_bytes());
    // Add some entropy from the process
    hasher.update(&std::process::id().to_le_bytes());
    let hash = hasher.finalize();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    // BN254 modulus starts with 0x30, so we use 0x1F mask to ensure < 2^253
    bytes[0] &= 0x1F;

    B256::from(bytes)
}

/// Derive a deterministic blinding factor.
///
/// Enables "note search" - can scan chain for notes by re-deriving blindings.
/// The blinding is derived from: SHA256(DOMAIN || spending_key || domain_separator || index)
///
/// # Arguments
/// * `spending_key` - The wallet's spending key
/// * `domain_separator` - A string to separate different use cases (e.g., "transfer", "genesis")
/// * `index` - A unique index for this blinding (e.g., tx_counter, leaf index)
///
/// # Returns
/// A deterministic blinding factor within the BN254 scalar field
pub fn derive_blinding(spending_key: B256, domain_separator: &str, index: u64) -> B256 {
    let mut hasher = Sha256::new();
    hasher.update(BLINDING_DOMAIN);
    hasher.update(spending_key.as_slice());
    hasher.update(domain_separator.as_bytes());
    hasher.update(&index.to_le_bytes());
    let hash = hasher.finalize();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    // BN254 modulus starts with 0x30, so we use 0x1F mask to ensure < 2^253
    bytes[0] &= 0x1F;

    B256::from(bytes)
}

/// Compute the actual blinding factor for a transfer output note.
///
/// The circuit enforces: `blinding = Poseidon(random, hashLeavesIn)`
/// This function computes that relationship.
///
/// # Arguments
/// * `random` - The random value (from `derive_blinding`)
/// * `leaves_in_hash` - Hash of input leaves: `Poseidon(leaf0, leaf1)` or `Poseidon(leaf0, 0)` if single input
///
/// # Returns
/// The blinding factor that satisfies the circuit constraint
pub fn compute_transfer_blinding(random: B256, leaves_in_hash: B256) -> B256 {
    pgp_merkle::poseidon2(random, leaves_in_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_spending_key_deterministic() {
        let seed = "test seed phrase for wallet";
        let key1 = derive_spending_key(seed);
        let key2 = derive_spending_key(seed);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_spending_key_different_seeds() {
        let key1 = derive_spending_key("seed one");
        let key2 = derive_spending_key("seed two");
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_public_key_deterministic() {
        let spending_key = derive_spending_key("test seed");
        let pub1 = derive_public_key(spending_key);
        let pub2 = derive_public_key(spending_key);
        assert_eq!(pub1, pub2);
    }

    #[test]
    fn test_derive_public_key_different_from_spending() {
        let spending_key = derive_spending_key("test seed");
        let public_key = derive_public_key(spending_key);
        assert_ne!(spending_key, public_key);
    }

    #[test]
    fn test_key_within_field() {
        let key = derive_spending_key("any seed");
        // Top byte should have top 3 bits cleared (0x1F mask)
        assert!(key.0[0] <= 0x1F, "Key should be within BN254 field");
    }

    #[test]
    fn test_generate_blinding_unique() {
        let b1 = generate_blinding();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let b2 = generate_blinding();
        // Should be different (very high probability)
        assert_ne!(b1, b2);
    }

    #[test]
    fn test_derive_blinding_deterministic() {
        let spending_key = derive_spending_key("test seed phrase");
        let b1 = derive_blinding(spending_key, "transfer", 0);
        let b2 = derive_blinding(spending_key, "transfer", 0);
        assert_eq!(b1, b2, "Same inputs should produce same blinding");
    }

    #[test]
    fn test_derive_blinding_different_indices() {
        let spending_key = derive_spending_key("test seed phrase");
        let b1 = derive_blinding(spending_key, "transfer", 0);
        let b2 = derive_blinding(spending_key, "transfer", 1);
        assert_ne!(
            b1, b2,
            "Different indices should produce different blindings"
        );
    }

    #[test]
    fn test_derive_blinding_different_domains() {
        let spending_key = derive_spending_key("test seed phrase");
        let b1 = derive_blinding(spending_key, "transfer", 0);
        let b2 = derive_blinding(spending_key, "genesis", 0);
        assert_ne!(
            b1, b2,
            "Different domains should produce different blindings"
        );
    }

    #[test]
    fn test_derive_blinding_different_keys() {
        let key1 = derive_spending_key("seed one");
        let key2 = derive_spending_key("seed two");
        let b1 = derive_blinding(key1, "transfer", 0);
        let b2 = derive_blinding(key2, "transfer", 0);
        assert_ne!(b1, b2, "Different keys should produce different blindings");
    }

    #[test]
    fn test_derive_blinding_within_field() {
        let spending_key = derive_spending_key("test seed");
        let blinding = derive_blinding(spending_key, "transfer", 12345);
        // Top 3 bits should be cleared (0x1F mask)
        assert!(
            blinding.0[0] <= 0x1F,
            "Blinding should be within BN254 field"
        );
    }

    #[test]
    fn test_compute_transfer_blinding_deterministic() {
        // Use small values that are definitely within BN254 field
        let random = B256::from([1u8; 32]);
        let leaves_hash = B256::from([2u8; 32]);
        let b1 = compute_transfer_blinding(random, leaves_hash);
        let b2 = compute_transfer_blinding(random, leaves_hash);
        assert_eq!(b1, b2, "Same inputs should produce same blinding");
    }

    #[test]
    fn test_compute_transfer_blinding_different_inputs() {
        // Use small values that are definitely within BN254 field
        let random = B256::from([1u8; 32]);
        let leaves_hash1 = B256::from([2u8; 32]);
        let leaves_hash2 = B256::from([3u8; 32]);
        let b1 = compute_transfer_blinding(random, leaves_hash1);
        let b2 = compute_transfer_blinding(random, leaves_hash2);
        assert_ne!(
            b1, b2,
            "Different leaves hashes should produce different blindings"
        );
    }
}
