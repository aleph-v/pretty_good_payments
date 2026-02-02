//! ZK proof builder (placeholder).
//!
//! In production, this would integrate with a native Groth16 prover (e.g., circom-prover).

use crate::proof::witness::TransferWitness;
use alloy_primitives::B256;
use eyre::Result;
use pgp_common::types::Groth16Proof;

/// Build a Groth16 proof from a transfer witness.
///
/// This is a placeholder - actual implementation would:
/// 1. Convert witness to circuit input format
/// 2. Call native prover (e.g., circom-prover with rust-witness)
/// 3. Return the generated proof
pub async fn build_transfer_proof(_witness: &TransferWitness) -> Result<Groth16Proof> {
    // TODO: Implement using circom-prover with rust-witness (like challenger does for update proofs)
    eyre::bail!("Proof generation not implemented - requires circom-prover integration")
}

/// Compute nullifier for a note.
///
/// nullifier = Poseidon3(spending_key, blinding, index)
pub fn compute_nullifier(spending_key: B256, blinding: B256, index: u64) -> B256 {
    pgp_merkle::compute_nullifier(spending_key, blinding, index)
}

/// Compute leaf hash for a note.
///
/// leaf = Poseidon4(asset, amount, blinding, public_key)
pub fn compute_leaf_hash(
    asset: alloy_primitives::Address,
    amount: alloy_primitives::U256,
    blinding: B256,
    public_key: B256,
) -> B256 {
    pgp_merkle::compute_leaf_hash(asset, amount, blinding, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};

    #[test]
    fn test_compute_nullifier() {
        let spending_key = B256::repeat_byte(0x11);
        let blinding = B256::repeat_byte(0x22);
        let index = 42u64;

        let null1 = compute_nullifier(spending_key, blinding, index);
        let null2 = compute_nullifier(spending_key, blinding, index);

        // Should be deterministic
        assert_eq!(null1, null2);

        // Different index should give different result
        let null3 = compute_nullifier(spending_key, blinding, 43);
        assert_ne!(null1, null3);
    }

    #[test]
    fn test_compute_leaf_hash() {
        let asset = Address::ZERO;
        let amount = U256::from(1000u64);
        let blinding = B256::repeat_byte(0x11);
        let public_key = B256::repeat_byte(0x22);

        let leaf1 = compute_leaf_hash(asset, amount, blinding, public_key);
        let leaf2 = compute_leaf_hash(asset, amount, blinding, public_key);

        // Should be deterministic
        assert_eq!(leaf1, leaf2);

        // Different amount should give different result
        let leaf3 = compute_leaf_hash(asset, U256::from(2000u64), blinding, public_key);
        assert_ne!(leaf1, leaf3);
    }
}
