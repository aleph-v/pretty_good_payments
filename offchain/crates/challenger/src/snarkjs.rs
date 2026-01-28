//! Snarkjs-based ZK proof generation.
//!
//! This module provides proof generation by shelling out to snarkjs.
//! Used for generating proofs needed in TreeUpdateChallenge submissions.

use alloy::primitives::B256;
use eyre::{eyre, Result, WrapErr};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;
use tracing::{debug, info};

use alloy::primitives::U256;
use pgp_common::contracts::Proof;

/// Snarkjs-based proof generator
///
/// Generates ZK proofs by shelling out to snarkjs CLI.
/// Used for TreeUpdateChallenge where the challenger must prove the correct anchor.
pub struct SnarkjsProver {
    /// Path to snarkjs command (e.g., "npx snarkjs" or absolute path)
    snarkjs_path: String,
    /// Path to circuit WASM file
    wasm_path: PathBuf,
    /// Path to circuit zkey file
    zkey_path: PathBuf,
}

impl SnarkjsProver {
    /// Create a new snarkjs prover
    ///
    /// # Arguments
    /// * `snarkjs_path` - Path to snarkjs command (e.g., "npx snarkjs")
    /// * `wasm_path` - Path to compiled circuit WASM
    /// * `zkey_path` - Path to proving key (zkey)
    pub fn new(snarkjs_path: &str, wasm_path: &Path, zkey_path: &Path) -> Self {
        Self {
            snarkjs_path: snarkjs_path.to_string(),
            wasm_path: wasm_path.to_path_buf(),
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
        // Create temp directory for snarkjs files
        let temp_dir = TempDir::new().wrap_err("Failed to create temp directory")?;
        let input_path = temp_dir.path().join("input.json");
        let witness_path = temp_dir.path().join("witness.wtns");
        let proof_path = temp_dir.path().join("proof.json");
        let public_path = temp_dir.path().join("public.json");

        // Build input JSON
        let input = UpdateInput {
            anchor_before: b256_to_decimal(anchor_before),
            block_root_before: b256_to_decimal(block_root_before),
            updates: leaves.map(b256_to_decimal).to_vec(),
            block_index: block_index.to_string(),
            in_block_index: in_block_index.to_string(),
            nonzero_field: b256_to_decimal(nonzero_field),
            block_proofs: block_proofs
                .iter()
                .map(|p| p.iter().map(|h| b256_to_decimal(*h)).collect())
                .collect(),
            root_path: root_path.iter().map(|h| b256_to_decimal(*h)).collect(),
        };

        let input_json =
            serde_json::to_string_pretty(&input).wrap_err("Failed to serialize input")?;
        std::fs::write(&input_path, &input_json).wrap_err("Failed to write input.json")?;

        debug!("Generating witness...");

        // Run witness calculation
        self.run_snarkjs_witness(&input_path, &witness_path)?;

        debug!("Generating proof...");

        // Run proof generation
        self.run_snarkjs_prove(&witness_path, &proof_path, &public_path)?;

        // Parse outputs
        let proof = self.parse_proof(&proof_path)?;
        let public_signals = self.parse_public_signals(&public_path)?;

        // Extract anchor_after from public signals
        // Public signals order (based on circuit declaration: public [anchorBefore, updates, blockIndex]):
        // [anchorAfter, anchorBefore, updates[0], updates[1], updates[2], blockIndex]
        // Output (anchorAfter) comes first, then public inputs in declaration order
        let anchor_after = if public_signals.len() >= 6 {
            decimal_to_b256(&public_signals[0])?
        } else {
            return Err(eyre!(
                "Invalid public signals count: {}",
                public_signals.len()
            ));
        };

        info!(
            "Proof generated successfully, anchor_after={:?}",
            anchor_after
        );

        Ok((anchor_after, proof))
    }

    /// Parse the snarkjs command path into program and initial arguments
    /// Handles cases like "npx snarkjs" or "/usr/local/bin/snarkjs"
    fn parse_snarkjs_command(&self) -> Result<(String, Vec<String>)> {
        let parts: Vec<&str> = self.snarkjs_path.split_whitespace().collect();
        if parts.is_empty() {
            return Err(eyre!("Empty snarkjs_path configured"));
        }
        let program = parts[0].to_string();
        let initial_args: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();
        Ok((program, initial_args))
    }

    /// Run snarkjs witness calculation
    /// Uses direct argument passing to avoid shell injection vulnerabilities
    fn run_snarkjs_witness(&self, input_path: &Path, witness_path: &Path) -> Result<()> {
        let (program, mut args) = self.parse_snarkjs_command()?;

        // Add snarkjs subcommand and arguments
        args.extend([
            "wtns".to_string(),
            "calculate".to_string(),
            self.wasm_path.to_string_lossy().to_string(),
            input_path.to_string_lossy().to_string(),
            witness_path.to_string_lossy().to_string(),
        ]);

        let output = Command::new(&program)
            .args(&args)
            .output()
            .wrap_err_with(|| format!("Failed to execute {program} {args:?}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(eyre!(
                "snarkjs witness failed (exit code {:?}):\nstderr: {}\nstdout: {}",
                output.status.code(),
                stderr,
                stdout
            ));
        }

        Ok(())
    }

    /// Run snarkjs proof generation
    /// Uses direct argument passing to avoid shell injection vulnerabilities
    fn run_snarkjs_prove(
        &self,
        witness_path: &Path,
        proof_path: &Path,
        public_path: &Path,
    ) -> Result<()> {
        let (program, mut args) = self.parse_snarkjs_command()?;

        // Add snarkjs subcommand and arguments
        args.extend([
            "groth16".to_string(),
            "prove".to_string(),
            self.zkey_path.to_string_lossy().to_string(),
            witness_path.to_string_lossy().to_string(),
            proof_path.to_string_lossy().to_string(),
            public_path.to_string_lossy().to_string(),
        ]);

        let output = Command::new(&program)
            .args(&args)
            .output()
            .wrap_err_with(|| format!("Failed to execute {program} {args:?}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(eyre!(
                "snarkjs prove failed (exit code {:?}):\nstderr: {}\nstdout: {}",
                output.status.code(),
                stderr,
                stdout
            ));
        }

        Ok(())
    }

    /// Parse the proof.json output
    fn parse_proof(&self, proof_path: &Path) -> Result<Proof> {
        let content = std::fs::read_to_string(proof_path).wrap_err("Failed to read proof.json")?;
        let raw: SnarkjsProof =
            serde_json::from_str(&content).wrap_err("Failed to parse proof.json")?;

        // Convert to contract Proof format
        // snarkjs outputs proof in format:
        // { pi_a: [x, y, 1], pi_b: [[x_real, x_imag], [y_real, y_imag], [1, 0]], pi_c: [x, y, 1] }
        //
        // The EVM pairing precompile (EIP-197) expects G2 points as (x_imag, x_real, y_imag, y_real).
        // The Solidity verifier passes _pB[0][0], _pB[0][1], _pB[1][0], _pB[1][1] to the precompile.
        // So we need: _pB[0] = [x_imag, x_real], _pB[1] = [y_imag, y_real]
        // snarkjs gives: pi_b[0] = [x_real, x_imag], pi_b[1] = [y_real, y_imag]
        // Therefore we need to swap within each pair.

        let p_a = [
            decimal_to_u256(&raw.pi_a[0])?,
            decimal_to_u256(&raw.pi_a[1])?,
        ];

        // Swap coordinate order within each Fp2 pair for G2 point
        // snarkjs: [[x_real, x_imag], [y_real, y_imag]] -> verifier: [[x_imag, x_real], [y_imag, y_real]]
        let p_b = [
            [
                decimal_to_u256(&raw.pi_b[0][1])?, // x_imag (was index 1)
                decimal_to_u256(&raw.pi_b[0][0])?, // x_real (was index 0)
            ],
            [
                decimal_to_u256(&raw.pi_b[1][1])?, // y_imag (was index 1)
                decimal_to_u256(&raw.pi_b[1][0])?, // y_real (was index 0)
            ],
        ];

        let p_c = [
            decimal_to_u256(&raw.pi_c[0])?,
            decimal_to_u256(&raw.pi_c[1])?,
        ];

        Ok(Proof {
            _pA: p_a,
            _pB: p_b,
            _pC: p_c,
        })
    }

    /// Parse the public.json output
    fn parse_public_signals(&self, public_path: &Path) -> Result<Vec<String>> {
        let content =
            std::fs::read_to_string(public_path).wrap_err("Failed to read public.json")?;
        let signals: Vec<String> =
            serde_json::from_str(&content).wrap_err("Failed to parse public.json")?;
        Ok(signals)
    }
}

/// Input format for predictableUpdate circuit
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateInput {
    anchor_before: String,
    block_root_before: String,
    updates: Vec<String>,
    block_index: String,
    in_block_index: String,
    nonzero_field: String,
    block_proofs: Vec<Vec<String>>,
    root_path: Vec<String>,
}

/// Snarkjs proof output format
#[derive(Debug, Deserialize)]
struct SnarkjsProof {
    pi_a: Vec<String>,
    pi_b: Vec<Vec<String>>,
    pi_c: Vec<String>,
    #[allow(dead_code)]
    protocol: String,
    #[allow(dead_code)]
    curve: String,
}

/// Convert B256 to decimal string (for snarkjs JSON input)
fn b256_to_decimal(value: B256) -> String {
    let u = U256::from_be_bytes(value.0);
    u.to_string()
}

/// Convert decimal string to B256
fn decimal_to_b256(s: &str) -> Result<B256> {
    let u = U256::from_str_radix(s, 10).map_err(|e| eyre!("Failed to parse decimal: {}", e))?;
    Ok(B256::from(u.to_be_bytes()))
}

/// Convert decimal string to U256
fn decimal_to_u256(s: &str) -> Result<U256> {
    U256::from_str_radix(s, 10).map_err(|e| eyre!("Failed to parse decimal: {}", e))
}

/// Generate a tree update proof with full merkle path data
///
/// This function requires all merkle tree path data to be provided.
/// Use this for production challenge submissions where you have the actual tree state.
///
/// # Arguments
/// * `snarkjs_path` - Path to snarkjs command (e.g., "npx snarkjs")
/// * `wasm_path` - Path to compiled circuit WASM
/// * `zkey_path` - Path to proving key (zkey)
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
pub async fn generate_tree_update_proof(
    snarkjs_path: &str,
    wasm_path: &Path,
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
    let prover = SnarkjsProver::new(snarkjs_path, wasm_path, zkey_path);

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
    fn test_decimal_to_b256() {
        let zero = decimal_to_b256("0").unwrap();
        assert_eq!(zero, B256::ZERO);

        let one = decimal_to_b256("1").unwrap();
        let expected = B256::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);
        assert_eq!(one, expected);
    }

    #[test]
    fn test_roundtrip() {
        let original = B256::repeat_byte(0x42);
        let decimal = b256_to_decimal(original);
        let recovered = decimal_to_b256(&decimal).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_update_input_serialization() {
        let input = UpdateInput {
            anchor_before: "12345".to_string(),
            block_root_before: "67890".to_string(),
            updates: vec!["1".to_string(), "2".to_string(), "3".to_string()],
            block_index: "100".to_string(),
            in_block_index: "0".to_string(),
            nonzero_field: "0".to_string(),
            block_proofs: vec![vec!["0".to_string(); 16]; 4],
            root_path: vec!["0".to_string(); 28],
        };

        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("anchorBefore"));
        assert!(json.contains("blockRootBefore"));
        assert!(json.contains("updates"));
    }
}
