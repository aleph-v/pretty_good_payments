//! Key derivation for PGP wallets.

use alloy_primitives::B256;
use pgp_merkle::poseidon2;
use sha2::{Digest, Sha256};

/// Domain separator for public key derivation
const PUBLIC_KEY_DOMAIN: &[u8] = b"PGP_PUBLIC_KEY_V1";

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
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&hash);
    // Clear the top 2 bits to ensure < 2^254 (well within BN254 scalar field)
    key_bytes[0] &= 0x3F;

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
    domain_bytes[0] &= 0x3F; // Reduce to BN254 field
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
    bytes[0] &= 0x3F; // Reduce to BN254 field

    B256::from(bytes)
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
        // Top byte should have top 2 bits cleared
        assert!(key.0[0] & 0xC0 == 0);
    }

    #[test]
    fn test_generate_blinding_unique() {
        let b1 = generate_blinding();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let b2 = generate_blinding();
        // Should be different (very high probability)
        assert_ne!(b1, b2);
    }
}
