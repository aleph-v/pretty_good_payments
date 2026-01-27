//! KZG proof generation for blob field validation.
//!
//! This module provides functionality to generate KZG proofs for specific
//! field indices within EIP-4844 blobs, which are required when submitting
//! fraud challenges.

use alloy_primitives::{B256, U256};
use c_kzg::{Blob, Bytes32, KzgSettings};
use eyre::{eyre, Result};

/// BLS12-381 scalar field modulus
const BLS_MODULUS: U256 = U256::from_limbs([
    0xFFFFFFFF00000001,
    0x53BDA402FFFE5BFE,
    0x3339D80809A1D805,
    0x73EDA753299D7D48,
]);

/// Number of field elements per blob (4096)
const FIELD_ELEMENTS_PER_BLOB: usize = 4096;

/// Computes the primitive 4096th root of unity for the BLS12-381 scalar field.
/// ROOT = 7^((BLS_MODULUS - 1) / 4096) mod BLS_MODULUS
fn compute_root_of_unity() -> U256 {
    let base = U256::from(7);
    let exponent = (BLS_MODULUS - U256::from(1)) / U256::from(FIELD_ELEMENTS_PER_BLOB);
    mod_exp(base, exponent, BLS_MODULUS)
}

/// Modular exponentiation: base^exp mod modulus
fn mod_exp(base: U256, exp: U256, modulus: U256) -> U256 {
    if modulus == U256::ZERO {
        return U256::ZERO;
    }
    if exp == U256::ZERO {
        return U256::from(1);
    }

    let mut result = U256::from(1);
    let mut base = base % modulus;
    let mut exp = exp;

    while exp > U256::ZERO {
        if exp & U256::from(1) == U256::from(1) {
            result = result.mul_mod(base, modulus);
        }
        exp >>= 1;
        base = base.mul_mod(base, modulus);
    }

    result
}

/// Reverses the bits of a number and returns the top 12 bits.
/// This matches the Solidity implementation: (reverseBits(i) >> 244)
fn bit_reverse_index(index: usize) -> u64 {
    // Reverse all bits of the index (treated as 12-bit number for 4096 elements)
    let mut reversed = 0u64;
    let mut i = index as u64;
    for _ in 0..12 {
        reversed = (reversed << 1) | (i & 1);
        i >>= 1;
    }
    reversed
}

/// Computes the evaluation point (z) for a given field index.
/// z = ROOT^(bit_reversed_index) mod BLS_MODULUS
fn compute_evaluation_point(index: usize) -> B256 {
    let root = compute_root_of_unity();
    let reversed = bit_reverse_index(index);
    let z = mod_exp(root, U256::from(reversed), BLS_MODULUS);
    B256::from(z)
}

/// KZG proof generator for blob field validation.
pub struct KzgProver {
    settings: &'static KzgSettings,
}

impl KzgProver {
    /// Create a new KZG prover with the Ethereum mainnet trusted setup.
    pub fn new() -> Result<Self> {
        // 0 means no precomputation (faster startup, slightly slower proofs)
        let settings = c_kzg::ethereum_kzg_settings(0);
        Ok(Self { settings })
    }

    /// Generate a KZG proof for a specific field index within a blob.
    ///
    /// # Arguments
    /// * `blob_data` - The raw blob data (131072 bytes)
    /// * `field_index` - The index of the field to prove (0-4095)
    ///
    /// # Returns
    /// * `commitment` - 48-byte KZG commitment for the blob
    /// * `proof` - 48-byte KZG proof for the field at the given index
    /// * `value` - The 32-byte value at the field index
    pub fn generate_proof(&self, blob_data: &[u8], field_index: usize) -> Result<KzgFieldProof> {
        if blob_data.len() != c_kzg::BYTES_PER_BLOB {
            return Err(eyre!(
                "Invalid blob size: expected {}, got {}",
                c_kzg::BYTES_PER_BLOB,
                blob_data.len()
            ));
        }

        if field_index >= FIELD_ELEMENTS_PER_BLOB {
            return Err(eyre!(
                "Field index out of range: {} >= {}",
                field_index,
                FIELD_ELEMENTS_PER_BLOB
            ));
        }

        // Convert blob data to c-kzg Blob type
        let blob = Blob::from_bytes(blob_data).map_err(|e| eyre!("Invalid blob: {:?}", e))?;

        // Compute the blob commitment
        let commitment = self
            .settings
            .blob_to_kzg_commitment(&blob)
            .map_err(|e| eyre!("Failed to compute commitment: {:?}", e))?;

        // Compute the evaluation point (z) for this field index
        let z = compute_evaluation_point(field_index);
        let z_bytes =
            Bytes32::from_bytes(z.as_slice()).map_err(|e| eyre!("Invalid z bytes: {:?}", e))?;

        // Generate the KZG proof
        let (proof, y_bytes) = self
            .settings
            .compute_kzg_proof(&blob, &z_bytes)
            .map_err(|e| eyre!("Failed to compute proof: {:?}", e))?;

        // Extract the field value from the blob
        let field_start = field_index * 32;
        let mut value = [0u8; 32];
        value.copy_from_slice(&blob_data[field_start..field_start + 32]);

        Ok(KzgFieldProof {
            commitment: commitment.to_bytes().to_vec(),
            proof: proof.to_bytes().to_vec(),
            value: B256::from(value),
            y_value: B256::from_slice(y_bytes.as_slice()),
        })
    }

    /// Compute the blob commitment for a given blob.
    pub fn compute_commitment(&self, blob_data: &[u8]) -> Result<Vec<u8>> {
        if blob_data.len() != c_kzg::BYTES_PER_BLOB {
            return Err(eyre!(
                "Invalid blob size: expected {}, got {}",
                c_kzg::BYTES_PER_BLOB,
                blob_data.len()
            ));
        }

        let blob = Blob::from_bytes(blob_data).map_err(|e| eyre!("Invalid blob: {:?}", e))?;
        let commitment = self
            .settings
            .blob_to_kzg_commitment(&blob)
            .map_err(|e| eyre!("Failed to compute commitment: {:?}", e))?;

        Ok(commitment.to_bytes().to_vec())
    }
}

impl Default for KzgProver {
    fn default() -> Self {
        Self::new().expect("Failed to create KZG prover with default settings")
    }
}

/// Result of generating a KZG proof for a field.
#[derive(Debug, Clone)]
pub struct KzgFieldProof {
    /// 48-byte KZG commitment for the blob
    pub commitment: Vec<u8>,
    /// 48-byte KZG proof for the field
    pub proof: Vec<u8>,
    /// The 32-byte value at the field index (from blob data)
    pub value: B256,
    /// The y value from the KZG proof computation (should match value)
    pub y_value: B256,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_reverse_index() {
        // Index 0 should stay 0
        assert_eq!(bit_reverse_index(0), 0);
        // Index 1 (binary: 000000000001) reversed (12-bit) = 100000000000 = 2048
        assert_eq!(bit_reverse_index(1), 2048);
        // Index 2 (binary: 000000000010) reversed = 010000000000 = 1024
        assert_eq!(bit_reverse_index(2), 1024);
        // Index 4095 (binary: 111111111111) reversed = 111111111111 = 4095
        assert_eq!(bit_reverse_index(4095), 4095);
    }

    #[test]
    fn test_compute_root_of_unity() {
        let root = compute_root_of_unity();
        // ROOT^4096 should equal 1 (mod BLS_MODULUS)
        let root_to_4096 = mod_exp(root, U256::from(4096), BLS_MODULUS);
        assert_eq!(root_to_4096, U256::from(1));
    }

    #[test]
    fn test_kzg_prover_creation() {
        let prover = KzgProver::new();
        assert!(prover.is_ok());
    }

    #[test]
    fn test_generate_proof_for_zero_blob() {
        let prover = KzgProver::new().unwrap();
        let blob_data = vec![0u8; c_kzg::BYTES_PER_BLOB];

        let result = prover.generate_proof(&blob_data, 0);
        assert!(result.is_ok());

        let proof = result.unwrap();
        assert_eq!(proof.commitment.len(), 48);
        assert_eq!(proof.proof.len(), 48);
    }
}
