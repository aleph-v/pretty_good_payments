//! Transaction ZK proof validation.
//!
//! This validator checks:
//! 1. Invalid anchor references (blockNr/updateNr out of bounds)
//! 2. Invalid ZK proofs (Groth16 verification fails)
//! 3. Missing eth-key authorization (eth-keyed tx not authorized in TransactionRegistry)

use alloy::primitives::{Address, B256};
use alloy::providers::Provider;
use eyre::Result;
use std::collections::HashMap;
use tracing::{debug, warn};

use crate::groth16::{Groth16Verifier, TransferPublicInputs};
use crate::validators::FraudEvidence;
use pgp_common::blob::ParsedBlock;
use pgp_common::contracts::BlockData;
use pgp_common::types::DecodedAnchorInfo;

/// Lookup table for anchors from previous blocks
///
/// Maps (block_nr, update_nr, is_deposit) -> anchor value
/// Integrates with StateManager for persistence across restarts.
#[derive(Debug, Clone, Default)]
pub struct AnchorLookup {
    /// In-memory cache: (block_nr, update_nr, is_deposit) -> anchor
    anchors: HashMap<(u32, u32, bool), B256>,
    /// Current block number being processed
    current_block_nr: u64,
    /// Maximum update_nr cache per (block_nr, is_deposit)
    max_update_nrs: HashMap<(u32, bool), u32>,
}

impl AnchorLookup {
    /// Create a new empty anchor lookup
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the current block number being validated
    pub fn set_current_block(&mut self, block_nr: u64) {
        self.current_block_nr = block_nr;
    }

    /// Get the current block number
    pub fn current_block_nr(&self) -> u64 {
        self.current_block_nr
    }

    /// Insert an anchor from a previous block
    pub fn insert(&mut self, block_nr: u32, update_nr: u32, is_deposit: bool, anchor: B256) {
        self.anchors
            .insert((block_nr, update_nr, is_deposit), anchor);

        // Update max_update_nr cache
        let key = (block_nr, is_deposit);
        let current_max = self.max_update_nrs.get(&key).copied();
        match current_max {
            Some(max) if update_nr <= max => {
                // No update needed
            }
            _ => {
                // Either no entry exists or update_nr is larger
                self.max_update_nrs.insert(key, update_nr);
            }
        }
    }

    /// Batch insert anchors (more efficient for loading from database)
    pub fn insert_batch(&mut self, anchors: &[(u32, u32, bool, B256)]) {
        for (block_nr, update_nr, is_deposit, anchor) in anchors {
            self.insert(*block_nr, *update_nr, *is_deposit, *anchor);
        }
    }

    /// Lookup an anchor by block_nr, update_nr, and is_deposit flag
    pub fn get(&self, block_nr: u32, update_nr: u32, is_deposit: bool) -> Option<B256> {
        self.anchors
            .get(&(block_nr, update_nr, is_deposit))
            .copied()
    }

    /// Check if an anchor reference is valid (within bounds)
    pub fn is_valid_reference(&self, block_nr: u32, update_nr: u32, is_deposit: bool) -> bool {
        // Block must not be in the future
        if (block_nr as u64) > self.current_block_nr {
            return false;
        }

        // Check update_nr bounds using cached max values
        if let Some(max_update) = self.max_update_nrs.get(&(block_nr, is_deposit)) {
            if update_nr > *max_update {
                return false;
            }
        }

        true
    }

    /// Get the number of updates for a given block (for bounds checking)
    pub fn get_max_update_nr(&self, block_nr: u32, is_deposit: bool) -> Option<u32> {
        self.max_update_nrs.get(&(block_nr, is_deposit)).copied()
    }

    /// Remove all anchors from a specific block onwards (for rollback)
    pub fn rollback_from(&mut self, from_block: u32) {
        self.anchors.retain(|(b, _, _), _| *b < from_block);
        self.max_update_nrs.retain(|(b, _), _| *b < from_block);
    }

    /// Get all anchors as a vector (for persistence)
    pub fn all_anchors(&self) -> Vec<(u32, u32, bool, B256)> {
        self.anchors
            .iter()
            .map(|((b, u, d), a)| (*b, *u, *d, *a))
            .collect()
    }

    /// Get the count of anchors in the lookup
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Check if the lookup is empty
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

/// Transaction validator for ZK proof and authorization checking
pub struct TransactionValidator {
    verifier: Groth16Verifier,
}

impl TransactionValidator {
    /// Create a new transaction validator with the given verification key
    pub fn new(verifier: Groth16Verifier) -> Self {
        Self { verifier }
    }

    /// Validate all transactions in a block
    ///
    /// This performs three types of checks:
    /// 1. Anchor reference validity (blockNr <= current, updateNr in bounds)
    /// 2. Groth16 proof verification
    /// 3. Eth-key authorization (if applicable)
    ///
    /// Returns fraud evidence for any invalid transactions.
    pub async fn validate_block<P: Provider + Clone>(
        &self,
        provider: &P,
        registry_address: Address,
        block_data: &BlockData,
        block: &ParsedBlock,
        anchor_lookup: &AnchorLookup,
    ) -> Result<Vec<FraudEvidence>> {
        let mut fraud = Vec::new();
        let current_block_nr = anchor_lookup.current_block_nr();

        for (tx_idx, tx) in block.transactions.iter().enumerate() {
            let tx_nr = tx_idx as u64;

            // 1. Decode anchor info
            let anchor_info = DecodedAnchorInfo::decode(tx.anchor_info);
            debug!(
                "Validating tx {} with anchor: block={}, update={}, is_deposit={}, eth_key={}",
                tx_nr,
                anchor_info.block_nr,
                anchor_info.update_nr,
                anchor_info.is_deposit,
                anchor_info.eth_key
            );

            // 2. Check anchor reference bounds
            if (anchor_info.block_nr as u64) > current_block_nr {
                warn!(
                    "Invalid anchor reference: block {} > current {}",
                    anchor_info.block_nr, current_block_nr
                );
                fraud.push(FraudEvidence::InvalidAnchorReference {
                    block_data: block_data.clone(),
                    tx_nr,
                    anchor_block_nr: anchor_info.block_nr,
                    anchor_update_nr: anchor_info.update_nr,
                    is_deposit: anchor_info.is_deposit,
                });
                continue;
            }

            // Check update_nr bounds
            if let Some(max_update) =
                anchor_lookup.get_max_update_nr(anchor_info.block_nr, anchor_info.is_deposit)
            {
                if anchor_info.update_nr > max_update {
                    warn!(
                        "Invalid anchor reference: update {} > max {} for block {}",
                        anchor_info.update_nr, max_update, anchor_info.block_nr
                    );
                    fraud.push(FraudEvidence::InvalidAnchorReference {
                        block_data: block_data.clone(),
                        tx_nr,
                        anchor_block_nr: anchor_info.block_nr,
                        anchor_update_nr: anchor_info.update_nr,
                        is_deposit: anchor_info.is_deposit,
                    });
                    continue;
                }
            }

            // 3. Look up the anchor value
            let anchor = match anchor_lookup.get(
                anchor_info.block_nr,
                anchor_info.update_nr,
                anchor_info.is_deposit,
            ) {
                Some(a) => a,
                None => {
                    warn!(
                        "Anchor not found: block={}, update={}, is_deposit={}",
                        anchor_info.block_nr, anchor_info.update_nr, anchor_info.is_deposit
                    );
                    // If we don't have the anchor, we can't validate the proof
                    // This could be a data availability issue rather than fraud
                    continue;
                }
            };

            // 4. Verify Groth16 proof
            let public_inputs = TransferPublicInputs {
                anchor,
                eth_key: anchor_info.eth_key,
                nullifier0: tx.nullifier0,
                nullifier1: tx.nullifier1,
                leaf0: tx.leaf0,
                leaf1: tx.leaf1,
                leaf2: tx.leaf2,
            };

            let proof_valid = match self
                .verifier
                .verify_transfer_proof(&tx.proof, &public_inputs)
            {
                Ok(valid) => valid,
                Err(e) => {
                    // Verification infrastructure error - log and treat as invalid
                    // This distinguishes from a cleanly invalid proof
                    warn!("ZK proof verification error for tx {}: {}", tx_nr, e);
                    false
                }
            };

            if !proof_valid {
                warn!("Invalid ZK proof for tx {}", tx_nr);
                fraud.push(FraudEvidence::InvalidTransactionProof {
                    block_data: block_data.clone(),
                    tx_nr,
                    anchor_block_nr: anchor_info.block_nr,
                    anchor_update_nr: anchor_info.update_nr,
                    is_deposit: anchor_info.is_deposit,
                });
                continue;
            }

            // 5. Check eth-key authorization (only if proof is valid and eth_key != 0)
            if proof_valid && anchor_info.eth_key != Address::ZERO {
                match check_eth_key_authorization(
                    provider,
                    registry_address,
                    anchor_info.eth_key,
                    [tx.nullifier0, tx.nullifier1, tx.leaf0, tx.leaf1, tx.leaf2],
                )
                .await
                {
                    Ok(true) => {
                        // Authorized, continue
                    }
                    Ok(false) => {
                        warn!(
                            "Missing eth-key authorization for tx {} from {}",
                            tx_nr, anchor_info.eth_key
                        );
                        fraud.push(FraudEvidence::MissingEthKeyAuth {
                            block_data: block_data.clone(),
                            tx_nr,
                            eth_key: anchor_info.eth_key,
                            nullifiers: [tx.nullifier0, tx.nullifier1],
                            leaves: [tx.leaf0, tx.leaf1, tx.leaf2],
                            anchor_block_nr: anchor_info.block_nr,
                            anchor_update_nr: anchor_info.update_nr,
                            is_deposit: anchor_info.is_deposit,
                        });
                    }
                    Err(e) => {
                        // Network/RPC error - don't treat as fraud, but propagate error
                        // so caller can decide whether to retry or skip this block
                        return Err(e.wrap_err(format!(
                            "Failed to check eth-key authorization for tx {tx_nr}"
                        )));
                    }
                }
            }
        }

        Ok(fraud)
    }

    /// Validate a single transaction (useful for testing)
    ///
    /// Returns Ok(true) if valid, Ok(false) if invalid, Err on verification error
    pub fn validate_transaction_proof(
        &self,
        tx: &pgp_common::types::ParsedTransaction,
        anchor: B256,
    ) -> Result<bool> {
        let anchor_info = DecodedAnchorInfo::decode(tx.anchor_info);

        let public_inputs = TransferPublicInputs {
            anchor,
            eth_key: anchor_info.eth_key,
            nullifier0: tx.nullifier0,
            nullifier1: tx.nullifier1,
            leaf0: tx.leaf0,
            leaf1: tx.leaf1,
            leaf2: tx.leaf2,
        };

        self.verifier
            .verify_transfer_proof(&tx.proof, &public_inputs)
    }
}

/// Query the TransactionRegistry to check if an eth-key has authorized a transaction
///
/// The registry stores authorizations as hash(ethKey, [nullifier0, nullifier1, leaf0, leaf1, leaf2])
///
/// Returns:
/// - Ok(true) if authorized
/// - Ok(false) if not authorized
/// - Err if network/RPC error (caller should handle appropriately)
async fn check_eth_key_authorization<P: Provider + Clone>(
    provider: &P,
    registry_address: Address,
    eth_key: Address,
    fields: [B256; 5],
) -> Result<bool> {
    // If the registry address is zero, skip authorization (not configured)
    if registry_address == Address::ZERO {
        debug!("TransactionRegistry not configured, skipping eth-key auth check");
        return Ok(true);
    }

    // Build the call to TransactionRegistry.query(ethKey, fields)
    // The registry stores a mapping of hash(ethKey, fields) => authorized
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface TransactionRegistry {
            function query(
                address ethKey,
                bytes32[5] calldata fields
            ) external view returns (bool);
        }
    }

    let registry = TransactionRegistry::new(registry_address, provider.clone());

    let result = registry
        .query(eth_key, fields)
        .call()
        .await
        .map_err(|e| eyre::eyre!("TransactionRegistry query failed: {}", e))?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anchor_lookup() {
        let mut lookup = AnchorLookup::new();
        lookup.set_current_block(100);

        let anchor = B256::repeat_byte(0x11);
        lookup.insert(50, 0, false, anchor);
        lookup.insert(50, 1, false, B256::repeat_byte(0x22));
        lookup.insert(50, 0, true, B256::repeat_byte(0x33));

        // Test lookup
        assert_eq!(lookup.get(50, 0, false), Some(anchor));
        assert_eq!(lookup.get(50, 1, false), Some(B256::repeat_byte(0x22)));
        assert_eq!(lookup.get(50, 0, true), Some(B256::repeat_byte(0x33)));
        assert_eq!(lookup.get(99, 0, false), None);

        // Test max update_nr
        assert_eq!(lookup.get_max_update_nr(50, false), Some(1));
        assert_eq!(lookup.get_max_update_nr(50, true), Some(0));
        assert_eq!(lookup.get_max_update_nr(99, false), None);
    }

    #[test]
    fn test_decoded_anchor_info() {
        let info = DecodedAnchorInfo {
            block_nr: 100,
            update_nr: 5,
            is_deposit: true,
            eth_key: Address::repeat_byte(0xAB),
        };

        let encoded = info.encode();
        let decoded = DecodedAnchorInfo::decode(encoded);

        assert_eq!(decoded.block_nr, 100);
        assert_eq!(decoded.update_nr, 5);
        assert!(decoded.is_deposit);
        assert_eq!(decoded.eth_key, Address::repeat_byte(0xAB));
    }
}
