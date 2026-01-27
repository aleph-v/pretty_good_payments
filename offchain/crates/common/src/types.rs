//! Common types used across the PGP off-chain components.

use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};

/// Constants matching the Solidity contracts
pub mod constants {
    /// BLS12-381 scalar field modulus (used in KZG proofs)
    pub const BLS_MODULUS: &str =
        "52435875175126190479447740508185965837690552500527637822603658699938581184513";

    /// BN254 scalar field modulus (used in Groth16 proofs)
    pub const BN254_SCALAR_FIELD: &str =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617";

    /// Maximum transactions per block
    pub const MAX_TX: usize = 4096;

    /// Maximum deposits per block
    pub const MAX_DEPOSITS: usize = 3072;

    /// Merkle tree total depth
    pub const TREE_DEPTH: usize = 40;

    /// Block tree depth (within a single block)
    pub const BLOCK_DEPTH: usize = 12;

    /// Root tree depth (across blocks)
    pub const ROOT_DEPTH: usize = 28;

    /// Elements per blob
    pub const BLOB_SIZE: usize = 4096;

    /// Transaction size in blob fields (8 proof + 1 anchor info + 2 nullifiers + 3 leaves + 1 root)
    pub const TX_SIZE: usize = 15;

    /// Deposit group size in blob fields (3 leaves + 1 root)
    pub const DEPOSIT_GROUP_SIZE: usize = 4;

    /// Challenge period in blocks
    pub const CHALLENGE_PERIOD: u64 = 100;

    /// Seconds per day
    pub const DAY_SECONDS: u64 = 86400;

    /// Blocks per day (2^13)
    pub const BLOCKS_PER_DAY: u64 = 8192;
}

/// A parsed transaction from blob data
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedTransaction {
    /// Groth16 proof (8 fields)
    pub proof: Groth16Proof,
    /// Encoded anchor info (blockNr, updateNr, isDeposit, ethKey)
    pub anchor_info: B256,
    /// First nullifier
    pub nullifier0: B256,
    /// Second nullifier
    pub nullifier1: B256,
    /// First output leaf hash
    pub leaf0: B256,
    /// Second output leaf hash
    pub leaf1: B256,
    /// Third output leaf hash
    pub leaf2: B256,
    /// New merkle root after this transaction
    pub new_root: B256,
}

/// Decoded anchor info from a transaction
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedAnchorInfo {
    /// Block number referenced
    pub block_nr: u32,
    /// Update number within the block
    pub update_nr: u32,
    /// Whether this references a deposit update
    pub is_deposit: bool,
    /// Ethereum address for authorization (zero if ZK-only)
    pub eth_key: Address,
}

impl DecodedAnchorInfo {
    /// Decode anchor info from a bytes32 field
    ///
    /// Matches Solidity's decodeTxInfo in TransactionChallenge.sol:
    /// - Bit 254 = isDeposit flag
    /// - Bits 253:222 = blockNr (32 bits) - extracted via (data << 2) >> 224
    /// - Bits 221:190 = updateNr (32 bits) - extracted via (data << 34) >> 224
    /// - Bits 159:0 = ethAddress (160 bits)
    pub fn decode(data: B256) -> Self {
        let bytes = data.0;
        let value = U256::from_be_bytes(bytes);

        // Bit 254 = isDeposit flag (0x40 in byte 0)
        // Matches Solidity: data & bytes32(uint256(1) << 254) != bytes32(0)
        let is_deposit = (bytes[0] & 0x40) != 0;

        // Bits 253:222 = blockNr (32 bits)
        // Solidity: uint256((data << 2) >> 224) - shift left 2 then right 224 = extract bits 253:222
        let block_nr_val: U256 = (value >> 222) & U256::from(0xFFFFFFFFu64);
        let block_nr = block_nr_val.to_be_bytes::<32>()[28..]
            .try_into()
            .map(u32::from_be_bytes)
            .unwrap_or(0);

        // Bits 221:190 = updateNr (32 bits)
        // Solidity: uint256((data << 34) >> 224) - shift left 34 then right 224 = extract bits 221:190
        let update_nr_val: U256 = (value >> 190) & U256::from(0xFFFFFFFFu64);
        let update_nr = update_nr_val.to_be_bytes::<32>()[28..]
            .try_into()
            .map(u32::from_be_bytes)
            .unwrap_or(0);

        // ethAddress at bits 159:0 (160 bits)
        // Solidity: address(uint160((uint256)((data << 77) >> 77)))
        let eth_key_value = value & U256::from_be_slice(&[0xFF; 20]);
        let mut eth_bytes = [0u8; 20];
        eth_bytes.copy_from_slice(&eth_key_value.to_be_bytes::<32>()[12..]);
        let eth_key = Address::from(eth_bytes);

        Self {
            block_nr,
            update_nr,
            is_deposit,
            eth_key,
        }
    }

    /// Encode anchor info into a bytes32 field
    ///
    /// Matches Solidity's encodeTxIntoBytes32 in TransactionChallenge.sol:
    /// - Bit 254 = isDeposit flag (1 << 254)
    /// - Bits 253:222 = blockNr (blockNr << 222)
    /// - Bits 221:190 = updateNr (updateNr << 190)
    /// - Bits 159:0 = ethAddress
    pub fn encode(&self) -> B256 {
        let mut value = U256::ZERO;

        // Bit 254 = isDeposit flag
        // Matches Solidity: (bytes32)(uint256(1) << 254)
        if self.is_deposit {
            value |= U256::from(1u64) << 254;
        }

        // Bits 253:222 = blockNr (32 bits)
        // Matches Solidity: (uint256(blockNr) << 222)
        value |= U256::from(self.block_nr) << 222;
        // Bits 221:190 = updateNr (32 bits)
        // Matches Solidity: (uint256(updateNr) << 190)
        value |= U256::from(self.update_nr) << 190;
        // Bits 159:0 = ethAddress (160 bits)
        value |= U256::from_be_slice(self.eth_key.as_slice());

        B256::from(value.to_be_bytes())
    }
}

/// A Groth16 proof (8 fields, matching blob layout)
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Groth16Proof {
    /// Point A, X coordinate
    pub a_x: B256,
    /// Point A, Y coordinate
    pub a_y: B256,
    /// Point B, first X coordinate (swapped for Solidity)
    pub b_x0: B256,
    /// Point B, second X coordinate (swapped for Solidity)
    pub b_x1: B256,
    /// Point B, first Y coordinate (swapped for Solidity)
    pub b_y0: B256,
    /// Point B, second Y coordinate (swapped for Solidity)
    pub b_y1: B256,
    /// Point C, X coordinate
    pub c_x: B256,
    /// Point C, Y coordinate
    pub c_y: B256,
}

impl Groth16Proof {
    /// Parse proof from 8 blob fields
    pub fn from_fields(fields: &[B256]) -> Option<Self> {
        if fields.len() < 8 {
            return None;
        }
        Some(Self {
            a_x: fields[0],
            a_y: fields[1],
            b_x0: fields[2],
            b_x1: fields[3],
            b_y0: fields[4],
            b_y1: fields[5],
            c_x: fields[6],
            c_y: fields[7],
        })
    }

    /// Convert to the contract's Proof struct format
    pub fn to_contract_format(&self) -> ([U256; 2], [[U256; 2]; 2], [U256; 2]) {
        let p_a = [
            U256::from_be_bytes(self.a_x.0),
            U256::from_be_bytes(self.a_y.0),
        ];
        let p_b = [
            [
                U256::from_be_bytes(self.b_x0.0),
                U256::from_be_bytes(self.b_x1.0),
            ],
            [
                U256::from_be_bytes(self.b_y0.0),
                U256::from_be_bytes(self.b_y1.0),
            ],
        ];
        let p_c = [
            U256::from_be_bytes(self.c_x.0),
            U256::from_be_bytes(self.c_y.0),
        ];
        (p_a, p_b, p_c)
    }
}

/// A parsed deposit group from blob data (3 leaves + 1 root)
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedDepositGroup {
    /// First leaf hash
    pub leaf0: B256,
    /// Second leaf hash
    pub leaf1: B256,
    /// Third leaf hash
    pub leaf2: B256,
    /// New merkle root after these deposits
    pub new_root: B256,
}

/// Note (leaf) data structure
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    /// Asset ID (ERC20 address, right-aligned in field)
    pub asset: Address,
    /// Amount (180 bits max)
    pub amount: U256,
    /// Blinding factor (252 bits)
    pub blinding: B256,
    /// Public key (252 bits, 0 for withdrawal)
    pub public_key: B256,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anchor_info_roundtrip() {
        let info = DecodedAnchorInfo {
            block_nr: 12345,
            update_nr: 42,
            is_deposit: true,
            eth_key: Address::repeat_byte(0xAB),
        };

        let encoded = info.encode();
        let decoded = DecodedAnchorInfo::decode(encoded);

        assert_eq!(decoded.block_nr, info.block_nr);
        assert_eq!(decoded.update_nr, info.update_nr);
        assert_eq!(decoded.is_deposit, info.is_deposit);
        assert_eq!(decoded.eth_key, info.eth_key);
    }

    #[test]
    fn test_anchor_info_decode_not_deposit() {
        let info = DecodedAnchorInfo {
            block_nr: 100,
            update_nr: 5,
            is_deposit: false,
            eth_key: Address::ZERO,
        };

        let encoded = info.encode();
        let decoded = DecodedAnchorInfo::decode(encoded);

        assert!(!decoded.is_deposit);
        assert_eq!(decoded.block_nr, 100);
        assert_eq!(decoded.update_nr, 5);
    }
}
