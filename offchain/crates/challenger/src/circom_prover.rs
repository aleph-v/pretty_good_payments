//! Pure Rust Circom proof generation using circom-prover.
//!
//! This module provides fast Groth16 proof generation using the mopro circom-prover
//! crate with the Arkworks backend.
//!
//! See: https://zkmopro.org/docs/crates/circom-prover

use alloy::primitives::{B256, U256};
use circom_prover::{
    prover::{CircomProof, ProofLib},
    witness::WitnessFn,
    CircomProver,
};
use eyre::{eyre, Result, WrapErr};
use num_bigint::BigUint;
use serde::Serialize;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

use pgp_common::contracts::Proof;

/// Pure Rust Circom prover using circom-prover crate
///
/// Uses mopro's circom-prover for fast proof generation entirely in Rust
/// with the Arkworks backend.
pub struct RustCircomProver {
    /// Path to circuit zkey file
    zkey_path: PathBuf,
}

// Include the rust-witness macro for the predictableUpdate circuit
// This generates a function named `predictableUpdate_witness`
rust_witness::witness!(predictableUpdate);

impl RustCircomProver {
    /// Create a new prover
    ///
    /// # Arguments
    /// * `zkey_path` - Path to the circuit's proving key (zkey file)
    pub fn new(zkey_path: &Path) -> Self {
        Self {
            zkey_path: zkey_path.to_path_buf(),
        }
    }

    /// Generate a proof for the predictableUpdate circuit
    ///
    /// # Arguments
    /// * `anchor_before` - Merkle root before update
    /// * `block_root_before` - Block tree root before update
    /// * `leaves` - Three leaves to insert
    /// * `block_index` - Block index in root tree
    /// * `in_block_index` - Starting index within block tree
    /// * `nonzero_field` - Previous non-zero field (for bounds check)
    /// * `block_proofs` - Merkle proofs for block tree (4 proofs of 16 elements each)
    /// * `root_path` - Merkle proof for root tree (28 elements)
    ///
    /// # Returns
    /// Tuple of (anchor_after, proof)
    pub async fn generate_update_proof(
        &self,
        anchor_before: B256,
        block_root_before: B256,
        leaves: [B256; 3],
        block_index: u64,
        in_block_index: u64,
        nonzero_field: B256,
        block_proofs: [[B256; 16]; 4],
        root_path: [B256; 28],
    ) -> Result<(B256, Proof)> {
        debug!("Preparing circuit inputs...");

        // Build input JSON
        // Note: All scalar values must be wrapped in single-element arrays for rust-witness
        let input = UpdateInput {
            anchor_before: vec![b256_to_decimal(anchor_before)],
            block_root_before: vec![b256_to_decimal(block_root_before)],
            updates: leaves.map(b256_to_decimal).to_vec(),
            block_index: vec![block_index.to_string()],
            in_block_index: vec![in_block_index.to_string()],
            nonzero_field: vec![b256_to_decimal(nonzero_field)],
            // Flatten 2D block_proofs to 1D in row-major order: [row0[0..16], row1[0..16], ...]
            block_proofs: block_proofs
                .iter()
                .flat_map(|row| row.iter().map(|h| b256_to_decimal(*h)))
                .collect(),
            root_path: root_path.iter().map(|h| b256_to_decimal(*h)).collect(),
        };

        let input_json = serde_json::to_string(&input).wrap_err("Failed to serialize input")?;

        debug!("Input JSON: {}", &input_json[..input_json.len().min(500)]);
        debug!("Generating proof with Arkworks backend...");

        // Generate proof using circom-prover
        let result = self.prove(&input_json)?;

        // Convert the result to our contract format
        let proof = self.convert_proof(&result)?;
        let anchor_after = self.extract_anchor_after(&result)?;

        info!(
            "Proof generated successfully, anchor_after={:?}",
            anchor_after
        );

        Ok((anchor_after, proof))
    }

    /// Internal prove function
    fn prove(&self, input_json: &str) -> Result<CircomProof> {
        let zkey_path = self
            .zkey_path
            .to_str()
            .ok_or_else(|| eyre!("Invalid zkey path"))?
            .to_string();

        debug!("Using zkey path: {}", zkey_path);
        debug!("Input JSON length: {} bytes", input_json.len());

        let result = CircomProver::prove(
            ProofLib::Arkworks,
            WitnessFn::RustWitness(predictableUpdate_witness),
            input_json.to_string(),
            zkey_path,
        );

        match &result {
            Ok(proof) => {
                debug!("Proof generation succeeded");
                debug!("Proof.a: ({}, {})", proof.proof.a.x, proof.proof.a.y);
                debug!("Public inputs count: {}", proof.pub_inputs.0.len());
            }
            Err(e) => {
                debug!("Proof generation failed: {:?}", e);
            }
        }

        result.map_err(|e| eyre!("Proof generation failed: {:?}", e))
    }

    /// Convert CircomProof to contract Proof format
    fn convert_proof(&self, result: &CircomProof) -> Result<Proof> {
        let proof = &result.proof;

        // Convert G1 point (a) - x and y coordinates
        let p_a = [biguint_to_u256(&proof.a.x)?, biguint_to_u256(&proof.a.y)?];

        // Convert G2 point (b) - each coordinate is [real, imag] in circom-prover
        // EVM pairing precompile expects [imag, real] order, so we swap
        let p_b = [
            [
                biguint_to_u256(&proof.b.x[1])?, // x_imag
                biguint_to_u256(&proof.b.x[0])?, // x_real
            ],
            [
                biguint_to_u256(&proof.b.y[1])?, // y_imag
                biguint_to_u256(&proof.b.y[0])?, // y_real
            ],
        ];

        // Convert G1 point (c) - x and y coordinates
        let p_c = [biguint_to_u256(&proof.c.x)?, biguint_to_u256(&proof.c.y)?];

        Ok(Proof {
            _pA: p_a,
            _pB: p_b,
            _pC: p_c,
        })
    }

    /// Extract anchor_after from public signals
    fn extract_anchor_after(&self, result: &CircomProof) -> Result<B256> {
        // PublicInputs wraps Vec<BigUint>
        // Public signals order: [anchorAfter, anchorBefore, updates[0], updates[1], updates[2], blockIndex]
        let public_inputs = &result.pub_inputs.0;

        info!(
            "Public inputs count: {}, first 10 values: {:?}",
            public_inputs.len(),
            public_inputs
                .iter()
                .take(10)
                .map(|x| format!("{}", x))
                .collect::<Vec<_>>()
        );

        if public_inputs.len() >= 6 {
            let anchor = biguint_to_b256(&public_inputs[0])?;
            info!("Extracted anchor_after: {:?}", anchor);
            Ok(anchor)
        } else {
            Err(eyre!(
                "Invalid public signals count: {}",
                public_inputs.len()
            ))
        }
    }
}

/// Input format for predictableUpdate circuit
/// Note: All values must be arrays (even scalars) for rust-witness compatibility.
/// For 2D arrays like blockProofs[4][16], they must be flattened to 1D in row-major order.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateInput {
    anchor_before: Vec<String>,     // Single-element array for scalar
    block_root_before: Vec<String>, // Single-element array for scalar
    updates: Vec<String>,           // Already an array
    block_index: Vec<String>,       // Single-element array for scalar
    in_block_index: Vec<String>,    // Single-element array for scalar
    nonzero_field: Vec<String>,     // Single-element array for scalar
    block_proofs: Vec<String>,      // Flattened 2D array (4*16=64 elements in row-major order)
    root_path: Vec<String>,         // 1D array
}

/// Convert B256 to decimal string (for circuit JSON input)
fn b256_to_decimal(value: B256) -> String {
    let u = U256::from_be_bytes(value.0);
    u.to_string()
}

/// Convert BigUint to B256
fn biguint_to_b256(value: &BigUint) -> Result<B256> {
    let bytes = value.to_bytes_be();
    if bytes.len() > 32 {
        return Err(eyre!("BigUint too large for B256"));
    }
    // Pad to 32 bytes
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(B256::from(padded))
}

/// Convert BigUint to U256
fn biguint_to_u256(value: &BigUint) -> Result<U256> {
    let bytes = value.to_bytes_be();
    if bytes.len() > 32 {
        return Err(eyre!("BigUint too large for U256"));
    }
    // Pad to 32 bytes
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(U256::from_be_bytes(padded))
}

/// Generate a tree update proof (convenience function)
///
/// This function creates a prover and generates a proof in one call.
pub async fn generate_tree_update_proof(
    zkey_path: &Path,
    anchor_before: B256,
    block_root_before: B256,
    leaves: [B256; 3],
    block_index: u64,
    in_block_index: u64,
    nonzero_field: B256,
    block_proofs: [[B256; 16]; 4],
    root_path: [B256; 28],
) -> Result<(B256, Proof)> {
    let prover = RustCircomProver::new(zkey_path);

    prover
        .generate_update_proof(
            anchor_before,
            block_root_before,
            leaves,
            block_index,
            in_block_index,
            nonzero_field,
            block_proofs,
            root_path,
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_b256_to_decimal() {
        let zero = B256::ZERO;
        assert_eq!(b256_to_decimal(zero), "0");

        let one = B256::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);
        assert_eq!(b256_to_decimal(one), "1");
    }

    #[test]
    fn test_biguint_to_b256() {
        let zero = BigUint::from(0u32);
        assert_eq!(biguint_to_b256(&zero).unwrap(), B256::ZERO);

        let one = BigUint::from(1u32);
        let expected = B256::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);
        assert_eq!(biguint_to_b256(&one).unwrap(), expected);
    }

    #[test]
    fn test_update_input_serialization() {
        let input = UpdateInput {
            anchor_before: vec!["12345".to_string()],
            block_root_before: vec!["67890".to_string()],
            updates: vec!["1".to_string(), "2".to_string(), "3".to_string()],
            block_index: vec!["100".to_string()],
            in_block_index: vec!["0".to_string()],
            nonzero_field: vec!["0".to_string()],
            block_proofs: vec!["0".to_string(); 64], // Flattened 4*16 = 64 elements
            root_path: vec!["0".to_string(); 28],
        };

        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("anchorBefore"));
        assert!(json.contains("blockRootBefore"));
        assert!(json.contains("updates"));
        // Verify scalars are serialized as arrays
        assert!(json.contains("\"anchorBefore\":[\"12345\"]"));
    }
}
