//! Groth16 verification using ark-groth16.
//!
//! This module provides Rust-native Groth16 verification for bn254/BN128 proofs,
//! compatible with snarkjs-generated verification keys and proofs.

use alloy::primitives::{Address, B256, U256};
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{PrimeField, Zero};
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use eyre::{eyre, Result};
use serde::Deserialize;
use std::path::Path;

use pgp_common::types::Groth16Proof as BlobGroth16Proof;

/// Snarkjs verification key JSON format
#[derive(Debug, Deserialize)]
struct SnarkjsVK {
    protocol: String,
    curve: String,
    #[allow(dead_code)]
    #[serde(rename = "nPublic")]
    n_public: usize,
    vk_alpha_1: Vec<String>,
    vk_beta_2: Vec<Vec<String>>,
    vk_gamma_2: Vec<Vec<String>>,
    vk_delta_2: Vec<Vec<String>>,
    #[allow(dead_code)]
    vk_alphabeta_12: Vec<Vec<Vec<String>>>,
    #[allow(dead_code)]
    #[serde(rename = "IC")]
    ic: Vec<Vec<String>>,
}

/// Public inputs for the transfer circuit (7 signals)
#[derive(Debug, Clone)]
pub struct TransferPublicInputs {
    /// The merkle root anchor
    pub anchor: B256,
    /// Ethereum key for authorization (0 if ZK-only)
    pub eth_key: Address,
    /// First nullifier
    pub nullifier0: B256,
    /// Second nullifier
    pub nullifier1: B256,
    /// First output leaf
    pub leaf0: B256,
    /// Second output leaf
    pub leaf1: B256,
    /// Third output leaf
    pub leaf2: B256,
}

impl TransferPublicInputs {
    /// Convert to field elements for verification
    /// Order matches circuit: outputs first (nullifiers, leaves), then public inputs (anchor, ethKey)
    /// From transfer.circom: signal output nullifiers[2]; signal output leavesOut[3];
    /// component main {public [anchor, ethKey]} = Transfer();
    pub fn to_field_elements(&self) -> Vec<Fr> {
        vec![
            b256_to_fr(self.nullifier0),
            b256_to_fr(self.nullifier1),
            b256_to_fr(self.leaf0),
            b256_to_fr(self.leaf1),
            b256_to_fr(self.leaf2),
            b256_to_fr(self.anchor),
            address_to_fr(self.eth_key),
        ]
    }
}

/// Public inputs for the predictableUpdate circuit (6 signals)
#[derive(Debug, Clone)]
pub struct UpdatePublicInputs {
    /// Merkle root before update
    pub anchor_before: B256,
    /// Block index in the root tree
    pub block_index: u64,
    /// Three leaf updates
    pub updates: [B256; 3],
    /// Merkle root after update (output)
    pub anchor_after: B256,
}

impl UpdatePublicInputs {
    /// Convert to field elements for verification
    /// Order matches snarkjs output (verified by integration tests with real ZK proofs):
    /// [anchorAfter, anchorBefore, updates[0], updates[1], updates[2], blockIndex]
    ///
    /// Note: This order differs from what one might expect from the circom declaration
    /// `component main {public [anchorBefore, blockIndex, updates]}` due to how snarkjs
    /// orders public signals. The order here matches TreeUpdateChallenge.sol:98-99.
    pub fn to_field_elements(&self) -> Vec<Fr> {
        vec![
            b256_to_fr(self.anchor_after),
            b256_to_fr(self.anchor_before),
            b256_to_fr(self.updates[0]),
            b256_to_fr(self.updates[1]),
            b256_to_fr(self.updates[2]),
            Fr::from(self.block_index),
        ]
    }
}

/// Groth16 verifier for transfer and update proofs
pub struct Groth16Verifier {
    transfer_vk: PreparedVerifyingKey<Bn254>,
    update_vk: PreparedVerifyingKey<Bn254>,
}

impl Groth16Verifier {
    /// Create a new verifier from verification key files
    pub fn new(transfer_vk_path: &Path, update_vk_path: &Path) -> Result<Self> {
        let transfer_vk = load_snarkjs_vk(transfer_vk_path)?;
        let update_vk = load_snarkjs_vk(update_vk_path)?;

        Ok(Self {
            transfer_vk: prepare_verifying_key(&transfer_vk),
            update_vk: prepare_verifying_key(&update_vk),
        })
    }

    /// Create a verifier from raw JSON bytes
    pub fn from_json(transfer_vk_json: &[u8], update_vk_json: &[u8]) -> Result<Self> {
        let transfer_vk = parse_snarkjs_vk(transfer_vk_json)?;
        let update_vk = parse_snarkjs_vk(update_vk_json)?;

        Ok(Self {
            transfer_vk: prepare_verifying_key(&transfer_vk),
            update_vk: prepare_verifying_key(&update_vk),
        })
    }

    /// Verify a transfer proof
    ///
    /// Returns Ok(true) if valid, Ok(false) if invalid proof, Err if verification failed
    pub fn verify_transfer_proof(
        &self,
        proof: &BlobGroth16Proof,
        public_inputs: &TransferPublicInputs,
    ) -> Result<bool> {
        let ark_proof = blob_proof_to_ark(proof)?;
        let inputs = public_inputs.to_field_elements();

        Groth16::<Bn254>::verify_with_processed_vk(&self.transfer_vk, &inputs, &ark_proof)
            .map_err(|e| eyre!("Groth16 verification error: {}", e))
    }

    /// Verify an update proof
    ///
    /// Returns Ok(true) if valid, Ok(false) if invalid proof, Err if verification failed
    pub fn verify_update_proof(
        &self,
        proof: &BlobGroth16Proof,
        public_inputs: &UpdatePublicInputs,
    ) -> Result<bool> {
        let ark_proof = blob_proof_to_ark(proof)?;
        let inputs = public_inputs.to_field_elements();

        Groth16::<Bn254>::verify_with_processed_vk(&self.update_vk, &inputs, &ark_proof)
            .map_err(|e| eyre!("Groth16 verification error: {}", e))
    }
}

/// Load a snarkjs verification key from a file
pub fn load_snarkjs_vk(path: &Path) -> Result<VerifyingKey<Bn254>> {
    let json_bytes = std::fs::read(path)?;
    parse_snarkjs_vk(&json_bytes)
}

/// Parse a snarkjs verification key from JSON bytes
pub fn parse_snarkjs_vk(json_bytes: &[u8]) -> Result<VerifyingKey<Bn254>> {
    let vk: SnarkjsVK = serde_json::from_slice(json_bytes)?;

    if vk.protocol != "groth16" {
        return Err(eyre!("Expected groth16 protocol, got {}", vk.protocol));
    }
    if vk.curve != "bn128" {
        return Err(eyre!("Expected bn128 curve, got {}", vk.curve));
    }

    // Parse alpha (G1)
    let alpha_g1 = parse_g1_point(&vk.vk_alpha_1)?;

    // Parse beta (G2)
    let beta_g2 = parse_g2_point(&vk.vk_beta_2)?;

    // Parse gamma (G2)
    let gamma_g2 = parse_g2_point(&vk.vk_gamma_2)?;

    // Parse delta (G2)
    let delta_g2 = parse_g2_point(&vk.vk_delta_2)?;

    // Parse IC points
    let mut gamma_abc_g1 = Vec::with_capacity(vk.ic.len());
    for ic_point in &vk.ic {
        gamma_abc_g1.push(parse_g1_point(ic_point)?);
    }

    Ok(VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    })
}

/// Convert a blob Groth16 proof to ark-groth16 proof format
pub fn blob_proof_to_ark(proof: &BlobGroth16Proof) -> Result<Proof<Bn254>> {
    // Parse A (G1 point)
    let a = g1_from_xy(
        U256::from_be_bytes(proof.a_x.0),
        U256::from_be_bytes(proof.a_y.0),
    )?;

    // Parse B (G2 point) - Note: snarkjs/solidity uses swapped coordinates
    // The blob format stores [b_x0, b_x1, b_y0, b_y1] where (x0, x1) is the x coordinate
    // and (y0, y1) is the y coordinate in Fp2
    let b = g2_from_xy(
        (
            U256::from_be_bytes(proof.b_x0.0),
            U256::from_be_bytes(proof.b_x1.0),
        ),
        (
            U256::from_be_bytes(proof.b_y0.0),
            U256::from_be_bytes(proof.b_y1.0),
        ),
    )?;

    // Parse C (G1 point)
    let c = g1_from_xy(
        U256::from_be_bytes(proof.c_x.0),
        U256::from_be_bytes(proof.c_y.0),
    )?;

    Ok(Proof { a, b, c })
}

// Helper functions for parsing

fn parse_g1_point(coords: &[String]) -> Result<G1Affine> {
    if coords.len() < 2 {
        return Err(eyre!("G1 point requires at least 2 coordinates"));
    }
    let x = parse_field_element(&coords[0])?;
    let y = parse_field_element(&coords[1])?;
    g1_from_fr(x, y)
}

fn parse_g2_point(coords: &[Vec<String>]) -> Result<G2Affine> {
    if coords.len() < 2 {
        return Err(eyre!("G2 point requires at least 2 coordinate pairs"));
    }
    if coords[0].len() < 2 || coords[1].len() < 2 {
        return Err(eyre!("G2 coordinate pairs must have 2 elements each"));
    }

    // snarkjs uses (c0, c1) format for Fp2
    let x0 = parse_field_element(&coords[0][0])?;
    let x1 = parse_field_element(&coords[0][1])?;
    let y0 = parse_field_element(&coords[1][0])?;
    let y1 = parse_field_element(&coords[1][1])?;

    g2_from_fr((x0, x1), (y0, y1))
}

fn parse_field_element(s: &str) -> Result<ark_bn254::Fq> {
    let bytes = decimal_string_to_bytes(s)?;
    ark_bn254::Fq::deserialize_uncompressed(&bytes[..])
        .map_err(|e| eyre!("Failed to parse field element: {}", e))
}

fn decimal_string_to_bytes(s: &str) -> Result<Vec<u8>> {
    // Parse decimal string to big integer, then to little-endian bytes
    let value: num_bigint::BigUint = s.parse().map_err(|e| eyre!("Invalid decimal: {}", e))?;
    let mut bytes = value.to_bytes_le();
    // Pad to 32 bytes
    bytes.resize(32, 0);
    Ok(bytes)
}

fn g1_from_fr(x: ark_bn254::Fq, y: ark_bn254::Fq) -> Result<G1Affine> {
    // Check for point at infinity
    if x.is_zero() && y.is_zero() {
        return Ok(G1Affine::zero());
    }

    let point = G1Affine::new_unchecked(x, y);

    // Verify point is on the curve
    if !point.is_on_curve() {
        return Err(eyre!("G1 point is not on curve"));
    }

    Ok(point)
}

fn g1_from_xy(x: U256, y: U256) -> Result<G1Affine> {
    let x_bytes = x.to_le_bytes::<32>();
    let y_bytes = y.to_le_bytes::<32>();

    let x_fq = ark_bn254::Fq::deserialize_uncompressed(&x_bytes[..])
        .map_err(|e| eyre!("Failed to parse G1 x: {}", e))?;
    let y_fq = ark_bn254::Fq::deserialize_uncompressed(&y_bytes[..])
        .map_err(|e| eyre!("Failed to parse G1 y: {}", e))?;

    g1_from_fr(x_fq, y_fq)
}

fn g2_from_fr(
    x: (ark_bn254::Fq, ark_bn254::Fq),
    y: (ark_bn254::Fq, ark_bn254::Fq),
) -> Result<G2Affine> {
    // Construct Fp2 elements
    let x_fp2 = ark_bn254::Fq2::new(x.0, x.1);
    let y_fp2 = ark_bn254::Fq2::new(y.0, y.1);

    // Check for point at infinity
    if x_fp2.is_zero() && y_fp2.is_zero() {
        return Ok(G2Affine::zero());
    }

    let point = G2Affine::new_unchecked(x_fp2, y_fp2);

    // Verify point is on the curve
    if !point.is_on_curve() {
        return Err(eyre!("G2 point is not on curve"));
    }

    Ok(point)
}

fn g2_from_xy(x: (U256, U256), y: (U256, U256)) -> Result<G2Affine> {
    let x0_bytes = x.0.to_le_bytes::<32>();
    let x1_bytes = x.1.to_le_bytes::<32>();
    let y0_bytes = y.0.to_le_bytes::<32>();
    let y1_bytes = y.1.to_le_bytes::<32>();

    let x0 = ark_bn254::Fq::deserialize_uncompressed(&x0_bytes[..])
        .map_err(|e| eyre!("Failed to parse G2 x0: {}", e))?;
    let x1 = ark_bn254::Fq::deserialize_uncompressed(&x1_bytes[..])
        .map_err(|e| eyre!("Failed to parse G2 x1: {}", e))?;
    let y0 = ark_bn254::Fq::deserialize_uncompressed(&y0_bytes[..])
        .map_err(|e| eyre!("Failed to parse G2 y0: {}", e))?;
    let y1 = ark_bn254::Fq::deserialize_uncompressed(&y1_bytes[..])
        .map_err(|e| eyre!("Failed to parse G2 y1: {}", e))?;

    g2_from_fr((x0, x1), (y0, y1))
}

/// Convert B256 to Fr field element
fn b256_to_fr(value: B256) -> Fr {
    // B256 is big-endian, Fr expects little-endian
    let be_bytes = value.0;
    let mut le_bytes = [0u8; 32];
    for (i, b) in be_bytes.iter().enumerate() {
        le_bytes[31 - i] = *b;
    }

    Fr::from_le_bytes_mod_order(&le_bytes)
}

/// Convert Address to Fr field element
fn address_to_fr(addr: Address) -> Fr {
    // Address is 20 bytes, pad to 32 bytes (right-aligned = low bits)
    let mut bytes = [0u8; 32];
    bytes[12..32].copy_from_slice(addr.as_slice());
    // Convert BE to LE
    bytes.reverse();
    Fr::from_le_bytes_mod_order(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_snarkjs_vk() {
        let vk_json = include_bytes!("../../../../circuits/outputs/transfer/transferVKey.json");
        let vk = parse_snarkjs_vk(vk_json);
        assert!(vk.is_ok(), "Failed to parse transfer VK: {:?}", vk.err());

        let vk = vk.unwrap();
        assert_eq!(vk.gamma_abc_g1.len(), 8); // nPublic + 1
    }

    #[test]
    fn test_parse_update_vk() {
        let vk_json = include_bytes!(
            "../../../../circuits/outputs/predictableUpdate/predictableUpdateVKey.json"
        );
        let vk = parse_snarkjs_vk(vk_json);
        assert!(vk.is_ok(), "Failed to parse update VK: {:?}", vk.err());

        let vk = vk.unwrap();
        assert_eq!(vk.gamma_abc_g1.len(), 7); // nPublic + 1
    }

    #[test]
    fn test_b256_to_fr() {
        let value = B256::from([0u8; 32]);
        let fr = b256_to_fr(value);
        assert!(fr.is_zero());

        let value = B256::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);
        let fr = b256_to_fr(value);
        assert_eq!(fr, Fr::from(1u64));
    }

    #[test]
    fn test_address_to_fr() {
        let addr = Address::ZERO;
        let fr = address_to_fr(addr);
        assert!(fr.is_zero());

        let addr = Address::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let fr = address_to_fr(addr);
        assert_eq!(fr, Fr::from(1u64));
    }

    #[test]
    fn test_transfer_public_inputs() {
        let inputs = TransferPublicInputs {
            anchor: B256::ZERO,
            eth_key: Address::ZERO,
            nullifier0: B256::ZERO,
            nullifier1: B256::ZERO,
            leaf0: B256::ZERO,
            leaf1: B256::ZERO,
            leaf2: B256::ZERO,
        };

        let field_elements = inputs.to_field_elements();
        assert_eq!(field_elements.len(), 7);
    }

    #[test]
    fn test_update_public_inputs() {
        let inputs = UpdatePublicInputs {
            anchor_before: B256::ZERO,
            block_index: 0,
            updates: [B256::ZERO; 3],
            anchor_after: B256::ZERO,
        };

        let field_elements = inputs.to_field_elements();
        assert_eq!(field_elements.len(), 6);
    }
}
