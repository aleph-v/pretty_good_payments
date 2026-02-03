//! ZK proof builder for transfer transactions.
//!
//! Uses circom-prover with rust-witness for native Groth16 proof generation.

use crate::proof::witness::TransferWitness;
use alloy_primitives::{Address, B256, U256};
use circom_prover::{
    prover::{CircomProof, ProofLib},
    witness::WitnessFn,
    CircomProver,
};
use eyre::{eyre, Result, WrapErr};
use num_bigint::BigUint;
use pgp_common::types::Groth16Proof;
use serde::Serialize;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

// Include the rust-witness macro for the transfer circuit
// This generates a function named `transfer_witness`
rust_witness::witness!(transfer);

/// Transfer proof prover using circom-prover.
///
/// Generates Groth16 proofs for transfer transactions using the transfer.circom circuit.
pub struct TransferProver {
    /// Path to the transfer circuit zkey file
    zkey_path: PathBuf,
}

impl TransferProver {
    /// Create a new transfer prover.
    ///
    /// # Arguments
    /// * `zkey_path` - Path to the transfer circuit proving key (transfer.zkey)
    pub fn new(zkey_path: &Path) -> Self {
        Self {
            zkey_path: zkey_path.to_path_buf(),
        }
    }

    /// Generate a transfer proof.
    ///
    /// # Arguments
    /// * `witness` - The transfer witness containing inputs, outputs, and proofs
    ///
    /// # Returns
    /// A tuple of (proof, nullifiers, output_leaves) where:
    /// - proof: The Groth16 proof
    /// - nullifiers: Array of 2 nullifiers for the input notes
    /// - output_leaves: Array of 3 output leaf commitments
    pub async fn generate_proof(
        &self,
        witness: &TransferWitness,
    ) -> Result<(Groth16Proof, [B256; 2], [B256; 3])> {
        // Validate the witness
        witness
            .validate()
            .map_err(|e| eyre!("Invalid witness: {}", e))?;

        debug!("Preparing transfer circuit inputs...");

        // Build the circuit input
        let input = self.build_circuit_input(witness)?;
        let input_json = serde_json::to_string(&input).wrap_err("Failed to serialize input")?;

        debug!(
            "Input JSON (truncated): {}",
            &input_json[..input_json.len().min(500)]
        );
        debug!("Generating proof with Arkworks backend...");

        // Generate the proof
        let result = self.prove(&input_json)?;

        // Convert the result
        let proof = self.convert_proof(&result)?;
        let (nullifiers, output_leaves) = self.extract_public_signals(&result)?;

        info!(
            "Transfer proof generated: nullifiers=[{:?}, {:?}], leaves=[{:?}, {:?}, {:?}]",
            nullifiers[0], nullifiers[1], output_leaves[0], output_leaves[1], output_leaves[2]
        );

        Ok((proof, nullifiers, output_leaves))
    }

    /// Build the circuit input JSON from the witness.
    fn build_circuit_input(&self, witness: &TransferWitness) -> Result<TransferInput> {
        // We need exactly 2 inputs (pad with dummy if needed)
        let input0 = witness
            .inputs
            .first()
            .ok_or_else(|| eyre!("At least one input required"))?;
        let input1 = witness.inputs.get(1);

        // We need exactly 3 outputs (pad with zero-value notes if needed)
        let output0 = witness
            .outputs
            .first()
            .ok_or_else(|| eyre!("At least one output required"))?;
        let output1 = witness.outputs.get(1);
        let output2 = witness.outputs.get(2);

        // Get the flat proof format for inputs
        let (path0, index0) = input0.proof.to_circuit_format();
        let (path1, index1) = if let Some(inp) = input1 {
            inp.proof.to_circuit_format()
        } else {
            // Dummy proof for unused second input
            ([B256::ZERO; 44], 0)
        };

        // Build notes arrays
        // Note format: [asset, amount, blinding, public_key]
        let note_in_0 = [
            address_to_decimal(input0.asset),
            u256_to_decimal(input0.amount),
            b256_to_decimal(input0.blinding),
            b256_to_decimal(input0.public_key),
        ];

        let note_in_1 = if let Some(inp) = input1 {
            [
                address_to_decimal(inp.asset),
                u256_to_decimal(inp.amount),
                b256_to_decimal(inp.blinding),
                b256_to_decimal(inp.public_key),
            ]
        } else {
            // Dummy note with zero value - asset must match for circuit constraints
            [
                address_to_decimal(input0.asset),
                "0".to_string(),
                b256_to_decimal(B256::ZERO),
                b256_to_decimal(B256::ZERO),
            ]
        };

        let note_out_0 = [
            address_to_decimal(output0.asset),
            u256_to_decimal(output0.amount),
            b256_to_decimal(output0.blinding),
            b256_to_decimal(output0.public_key),
        ];

        // For zero-value outputs, the public_key is 0 which makes it a "withdrawal"
        // In this case, the blinding factor check is bypassed (handled by isWithdraw logic)
        let note_out_1 = if let Some(out) = output1 {
            [
                address_to_decimal(out.asset),
                u256_to_decimal(out.amount),
                b256_to_decimal(out.blinding),
                b256_to_decimal(out.public_key),
            ]
        } else {
            // Zero-value output note (public_key = 0 means withdrawal, bypasses blinding check)
            [
                address_to_decimal(output0.asset),
                "0".to_string(),
                b256_to_decimal(B256::ZERO),
                b256_to_decimal(B256::ZERO),
            ]
        };

        let note_out_2 = if let Some(out) = output2 {
            [
                address_to_decimal(out.asset),
                u256_to_decimal(out.amount),
                b256_to_decimal(out.blinding),
                b256_to_decimal(out.public_key),
            ]
        } else {
            // Zero-value output note (public_key = 0 means withdrawal, bypasses blinding check)
            [
                address_to_decimal(output0.asset),
                "0".to_string(),
                b256_to_decimal(B256::ZERO),
                b256_to_decimal(B256::ZERO),
            ]
        };

        // Random values for blinding factor derivation in the circuit
        // These are used to compute: blinding = Poseidon(random, hash(leaf0, leaf1))
        // For transfers (not withdrawals), this must match the blinding in the output note
        // We need to derive the randoms that produce our desired blindings
        let randoms = self.compute_randoms(witness)?;

        // Private keys (spending keys)
        // The second one should be a specific constant if the second input is unused
        let private_key_0 = b256_to_decimal(witness.spending_key);
        let private_key_1 = if input1.is_some() {
            b256_to_decimal(witness.spending_key) // Same key owns both inputs
        } else {
            // Circuit requires this specific constant when second input is unused
            // This is the RANDOM_CONSTANT from the circuit
            "0x4cc1de474cacd406eea434351d2907cfea08fece7e38ebebff463599ffa252a7".to_string()
        };

        Ok(TransferInput {
            anchor: vec![b256_to_decimal(witness.anchor)],
            indices: vec![index0.to_string(), index1.to_string()],
            // Flatten paths: [path0[0..44], path1[0..44]]
            paths: path0
                .iter()
                .chain(path1.iter())
                .map(|h| b256_to_decimal(*h))
                .collect(),
            // Flatten notes_in: [note0[0..4], note1[0..4]]
            notes_in: note_in_0.iter().chain(note_in_1.iter()).cloned().collect(),
            // Flatten notes_out: [note0[0..4], note1[0..4], note2[0..4]]
            notes_out: note_out_0
                .iter()
                .chain(note_out_1.iter())
                .chain(note_out_2.iter())
                .cloned()
                .collect(),
            randoms,
            private_keys: vec![private_key_0, private_key_1],
            eth_key: vec!["0".to_string()], // Zero for non-ETH-keyed transactions
        })
    }

    /// Extract the random values from the witness outputs.
    ///
    /// The circuit enforces: blinding = Poseidon(random, hashLeavesIn)
    /// The caller must have computed the blindings correctly using the randoms.
    fn compute_randoms(&self, witness: &TransferWitness) -> Result<Vec<String>> {
        let mut randoms = Vec::with_capacity(3);
        for i in 0..3 {
            if let Some(output) = witness.outputs.get(i) {
                // For withdrawals (public_key == 0), the blinding is the ETH address
                // and random doesn't matter, but we still pass it
                randoms.push(b256_to_decimal(output.random));
            } else {
                // Unused output - random doesn't matter
                randoms.push("0".to_string());
            }
        }

        Ok(randoms)
    }

    /// Internal prove function using circom-prover
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
            WitnessFn::RustWitness(transfer_witness),
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

    /// Convert CircomProof to our Groth16Proof format
    fn convert_proof(&self, result: &CircomProof) -> Result<Groth16Proof> {
        let proof = &result.proof;

        // Convert G1 point (a) - x and y coordinates
        let a_x = biguint_to_b256(&proof.a.x)?;
        let a_y = biguint_to_b256(&proof.a.y)?;

        // Convert G2 point (b) - each coordinate is [real, imag] in circom-prover
        // EVM pairing precompile expects [imag, real] order, so we swap
        let b_x0 = biguint_to_b256(&proof.b.x[1])?; // x_imag
        let b_x1 = biguint_to_b256(&proof.b.x[0])?; // x_real
        let b_y0 = biguint_to_b256(&proof.b.y[1])?; // y_imag
        let b_y1 = biguint_to_b256(&proof.b.y[0])?; // y_real

        // Convert G1 point (c) - x and y coordinates
        let c_x = biguint_to_b256(&proof.c.x)?;
        let c_y = biguint_to_b256(&proof.c.y)?;

        Ok(Groth16Proof {
            a_x,
            a_y,
            b_x0,
            b_x1,
            b_y0,
            b_y1,
            c_x,
            c_y,
        })
    }

    /// Extract public signals (nullifiers and output leaves) from the proof
    fn extract_public_signals(&self, result: &CircomProof) -> Result<([B256; 2], [B256; 3])> {
        // Public signals order from transfer.circom:
        // output nullifiers[2];
        // output leavesOut[3];
        // public inputs: anchor, ethKey
        //
        // So the order is: [nullifiers[0], nullifiers[1], leavesOut[0], leavesOut[1], leavesOut[2], anchor, ethKey]
        let public_inputs = &result.pub_inputs.0;

        info!(
            "Public inputs count: {}, first values: {:?}",
            public_inputs.len(),
            public_inputs
                .iter()
                .take(7)
                .map(|x| format!("{x}"))
                .collect::<Vec<_>>()
        );

        if public_inputs.len() < 5 {
            return Err(eyre!(
                "Invalid public signals count: {}",
                public_inputs.len()
            ));
        }

        let nullifiers = [
            biguint_to_b256(&public_inputs[0])?,
            biguint_to_b256(&public_inputs[1])?,
        ];

        let output_leaves = [
            biguint_to_b256(&public_inputs[2])?,
            biguint_to_b256(&public_inputs[3])?,
            biguint_to_b256(&public_inputs[4])?,
        ];

        Ok((nullifiers, output_leaves))
    }
}

/// Input format for transfer circuit.
/// Note: All values must be arrays for rust-witness compatibility.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TransferInput {
    anchor: Vec<String>,       // [1] - public
    indices: Vec<String>,      // [2] - leaf indices
    paths: Vec<String>,        // [2][44] flattened to [88]
    notes_in: Vec<String>,     // [2][4] flattened to [8]
    notes_out: Vec<String>,    // [3][4] flattened to [12]
    randoms: Vec<String>,      // [3] - random values for blinding
    private_keys: Vec<String>, // [2] - spending keys
    eth_key: Vec<String>,      // [1] - ETH key for authorization (public)
}

/// Build a Groth16 proof from a transfer witness.
///
/// This is a convenience function that creates a prover and generates a proof.
pub async fn build_transfer_proof(
    witness: &TransferWitness,
    zkey_path: &Path,
) -> Result<(Groth16Proof, [B256; 2], [B256; 3])> {
    let prover = TransferProver::new(zkey_path);
    prover.generate_proof(witness).await
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
pub fn compute_leaf_hash(asset: Address, amount: U256, blinding: B256, public_key: B256) -> B256 {
    pgp_merkle::compute_leaf_hash(asset, amount, blinding, public_key)
}

// Helper functions for conversion

/// Convert B256 to decimal string
fn b256_to_decimal(value: B256) -> String {
    let u = U256::from_be_bytes(value.0);
    u.to_string()
}

/// Convert U256 to decimal string
fn u256_to_decimal(value: U256) -> String {
    value.to_string()
}

/// Convert Address to decimal string (right-aligned in field)
fn address_to_decimal(addr: Address) -> String {
    let mut bytes = [0u8; 32];
    bytes[12..].copy_from_slice(addr.as_slice());
    let u = U256::from_be_bytes(bytes);
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_address_to_decimal() {
        let zero = Address::ZERO;
        assert_eq!(address_to_decimal(zero), "0");

        // Address with some bytes set
        let addr = Address::repeat_byte(0x01);
        let result = address_to_decimal(addr);
        // Should be non-zero
        assert_ne!(result, "0");
    }

    #[test]
    fn test_transfer_input_serialization() {
        let input = TransferInput {
            anchor: vec!["12345".to_string()],
            indices: vec!["0".to_string(), "1".to_string()],
            paths: vec!["0".to_string(); 88],     // 2 * 44
            notes_in: vec!["0".to_string(); 8],   // 2 * 4
            notes_out: vec!["0".to_string(); 12], // 3 * 4
            randoms: vec!["0".to_string(); 3],
            private_keys: vec!["111".to_string(), "222".to_string()],
            eth_key: vec!["0".to_string()],
        };

        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("anchor"));
        assert!(json.contains("indices"));
        assert!(json.contains("paths"));
        assert!(json.contains("notesIn"));
        assert!(json.contains("notesOut"));
        assert!(json.contains("randoms"));
        assert!(json.contains("privateKeys"));
        assert!(json.contains("ethKey"));
    }
}
