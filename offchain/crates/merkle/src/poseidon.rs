//! Poseidon hash implementation using light-poseidon (circomlib-compatible).
//!
//! Parameters must match circomlib/circuits/poseidon.circom exactly:
//! - Field: BN254 scalar field
//! - 2 inputs: t=3, RF=8, RP=56
//! - 3 inputs: t=4, RF=8, RP=57
//! - 4 inputs: t=5, RF=8, RP=60
//!
//! Uses thread-local caching to avoid repeated hasher allocation, significantly
//! reducing stack usage in hot paths like merkle tree operations.

use alloy_primitives::B256;
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use std::cell::RefCell;
use thiserror::Error;

/// Errors that can occur during Poseidon hashing
#[derive(Debug, Error)]
pub enum PoseidonError {
    #[error("Invalid number of inputs: expected {expected}, got {actual}")]
    InvalidInputCount { expected: usize, actual: usize },

    #[error("Hash computation failed")]
    HashFailed,
}

// Thread-local cached Poseidon hashers to avoid repeated allocation
thread_local! {
    static POSEIDON2: RefCell<Poseidon<ark_bn254::Fr>> = RefCell::new(
        Poseidon::<ark_bn254::Fr>::new_circom(2).expect("Failed to create Poseidon hasher")
    );
    static POSEIDON3: RefCell<Poseidon<ark_bn254::Fr>> = RefCell::new(
        Poseidon::<ark_bn254::Fr>::new_circom(3).expect("Failed to create Poseidon hasher")
    );
    static POSEIDON4: RefCell<Poseidon<ark_bn254::Fr>> = RefCell::new(
        Poseidon::<ark_bn254::Fr>::new_circom(4).expect("Failed to create Poseidon hasher")
    );
}

/// Compute Poseidon hash with 2 inputs (used for merkle tree internal nodes)
pub fn poseidon2(left: B256, right: B256) -> B256 {
    POSEIDON2.with(|hasher| {
        let mut hasher = hasher.borrow_mut();
        let left_bytes: &[u8] = left.as_slice();
        let right_bytes: &[u8] = right.as_slice();
        let inputs: &[&[u8]] = &[left_bytes, right_bytes];
        let hash = hasher.hash_bytes_be(inputs).expect("Poseidon hash failed");
        B256::from_slice(&hash)
    })
}

/// Compute Poseidon hash with 3 inputs (used for nullifier computation)
pub fn poseidon3(a: B256, b: B256, c: B256) -> B256 {
    POSEIDON3.with(|hasher| {
        let mut hasher = hasher.borrow_mut();
        let a_bytes: &[u8] = a.as_slice();
        let b_bytes: &[u8] = b.as_slice();
        let c_bytes: &[u8] = c.as_slice();
        let inputs: &[&[u8]] = &[a_bytes, b_bytes, c_bytes];
        let hash = hasher.hash_bytes_be(inputs).expect("Poseidon hash failed");
        B256::from_slice(&hash)
    })
}

/// Compute Poseidon hash with 4 inputs (used for leaf hash)
pub fn poseidon4(a: B256, b: B256, c: B256, d: B256) -> B256 {
    POSEIDON4.with(|hasher| {
        let mut hasher = hasher.borrow_mut();
        let a_bytes: &[u8] = a.as_slice();
        let b_bytes: &[u8] = b.as_slice();
        let c_bytes: &[u8] = c.as_slice();
        let d_bytes: &[u8] = d.as_slice();
        let inputs: &[&[u8]] = &[a_bytes, b_bytes, c_bytes, d_bytes];
        let hash = hasher.hash_bytes_be(inputs).expect("Poseidon hash failed");
        B256::from_slice(&hash)
    })
}

/// Compute leaf hash from note components
/// leaf_hash = Poseidon4(asset, amount, blinding, public_key)
pub fn compute_leaf_hash(
    asset: alloy_primitives::Address,
    amount: alloy_primitives::U256,
    blinding: B256,
    public_key: B256,
) -> B256 {
    // Asset is right-aligned in field (low 160 bits)
    let asset_field = B256::from(alloy_primitives::U256::from_be_slice(asset.as_slice()));
    // Amount is right-aligned in field
    let amount_field = B256::from(amount.to_be_bytes());

    poseidon4(asset_field, amount_field, blinding, public_key)
}

/// Compute nullifier from private key, blinding factor, and merkle index
/// nullifier = Poseidon3(private_key, blinding, index)
pub fn compute_nullifier(private_key: B256, blinding: B256, index: u64) -> B256 {
    let index_field = B256::from(alloy_primitives::U256::from(index).to_be_bytes());
    poseidon3(private_key, blinding, index_field)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon2_deterministic() {
        let a = B256::from([1u8; 32]);
        let b = B256::from([2u8; 32]);

        let hash1 = poseidon2(a, b);
        let hash2 = poseidon2(a, b);

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, B256::ZERO);
    }

    #[test]
    fn test_poseidon2_different_inputs() {
        let a = B256::from([1u8; 32]);
        let b = B256::from([2u8; 32]);
        let c = B256::from([3u8; 32]);

        let hash_ab = poseidon2(a, b);
        let hash_ac = poseidon2(a, c);
        let hash_ba = poseidon2(b, a);

        assert_ne!(hash_ab, hash_ac);
        assert_ne!(hash_ab, hash_ba);
    }

    #[test]
    fn test_poseidon3_deterministic() {
        let a = B256::from([1u8; 32]);
        let b = B256::from([2u8; 32]);
        let c = B256::from([3u8; 32]);

        let hash1 = poseidon3(a, b, c);
        let hash2 = poseidon3(a, b, c);

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, B256::ZERO);
    }

    #[test]
    fn test_poseidon4_deterministic() {
        let a = B256::from([1u8; 32]);
        let b = B256::from([2u8; 32]);
        let c = B256::from([3u8; 32]);
        let d = B256::from([4u8; 32]);

        let hash1 = poseidon4(a, b, c, d);
        let hash2 = poseidon4(a, b, c, d);

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, B256::ZERO);
    }

    #[test]
    fn test_poseidon2_zero_inputs() {
        let hash = poseidon2(B256::ZERO, B256::ZERO);
        // Hash of zeros should be non-zero
        assert_ne!(hash, B256::ZERO);
    }

    #[test]
    fn test_compute_nullifier() {
        // Use values within BN254 scalar field (< 2^254)
        // First byte must be < 0x30 to stay well within the field
        let mut priv_key_bytes = [0u8; 32];
        priv_key_bytes[1..].fill(0xAB); // Keep first byte as 0
        let priv_key = B256::from(priv_key_bytes);

        let mut blinding_bytes = [0u8; 32];
        blinding_bytes[1..].fill(0xCD);
        let blinding = B256::from(blinding_bytes);

        let index = 42u64;

        let null1 = compute_nullifier(priv_key, blinding, index);
        let null2 = compute_nullifier(priv_key, blinding, index);

        assert_eq!(null1, null2);

        // Different index should give different nullifier
        let null3 = compute_nullifier(priv_key, blinding, 43);
        assert_ne!(null1, null3);
    }

    #[test]
    fn test_compute_leaf_hash() {
        use alloy_primitives::{Address, U256};

        let asset = Address::repeat_byte(0x12);
        let amount = U256::from(1000u64);

        // Use values within BN254 scalar field (< 2^254)
        let mut blinding_bytes = [0u8; 32];
        blinding_bytes[1..].fill(0xAB);
        let blinding = B256::from(blinding_bytes);

        let mut public_key_bytes = [0u8; 32];
        public_key_bytes[1..].fill(0xCD);
        let public_key = B256::from(public_key_bytes);

        let hash1 = compute_leaf_hash(asset, amount, blinding, public_key);
        let hash2 = compute_leaf_hash(asset, amount, blinding, public_key);

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, B256::ZERO);
    }

    #[test]
    fn test_poseidon_caching_works() {
        // Test that caching doesn't break correctness with many calls
        let a = B256::from([1u8; 32]);
        let b = B256::from([2u8; 32]);

        // Call many times to ensure caching works correctly
        let mut results = Vec::new();
        for _ in 0..100 {
            results.push(poseidon2(a, b));
        }

        // All results should be identical
        let first = results[0];
        for result in &results {
            assert_eq!(*result, first);
        }
    }
}
