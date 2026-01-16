// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {LibBit} from "solady/utils/LibBit.sol";
import {InvalidLeafWhich, InvalidNullifierWhich, InvalidDepositNumber, RegionDataLengthMismatch} from "./Errors.sol";

// We implement a protocol which does kzg opening against blob commitments.
// In the simplest version it just proves that the commitment evaluated at the bit reversed root of unity
// for an index is equal to the the claimed data.
// We might be able to highly optimize by doing a multi point opening.

// Blobs are structured as follows:
// [deposits range][transactions range]
// each deposit is [leaf1, leaf2, leaf3, new_root] and each leaf must match the deposit leaf in the array for this block
// each transaction is [[zk proof], anchor id, nullifier0, nullifier1, leaf0, leaf1, leaf2, new_root]
// The transaction is expected to be 15, 32 byte commitment leaves. 8 leaves for the zk proof, then 7 with 6 for inputs and 1 for new root.

// Has to be a contract because libs can't do immutables
contract BlobData {
    uint256 constant BLS_MODULUS = 52435875175126190479447740508185965837690552500527637822603658699938581184513;
    uint256 immutable ROOT = exp(7, (BLS_MODULUS - 1) / 4096);

    uint256 constant TREE_DEPTH = 40;
    uint256 constant DAY_DEPTH = 12;
    uint256 constant BLOCK_DEPTH = 12;

    // Used to validate an opening of a region of memory
    struct Region {
        uint256 length;
        uint256 memoryAddress;
        bytes32[] data;
        bytes[] proofs;
        bytes commitment;
        bytes32 hash;
    }

    // Region has to be encoded

    /// @notice Calculates blob memory length required for deposits
    /// @dev Each 3 deposits use 4 slots (3 leaves + 1 root). Rounds up for partial groups.
    /// @param num Number of deposits
    /// @return Memory slots required: ceil(num/3) * 4
    function numDepositsToMemoryLength(uint256 num) internal pure returns (uint256) {
        uint256 depositRounding = num % 3 == 0 ? 0 : 1;
        return ((num / 3 + depositRounding) * 4);
    }

    /// @notice Calculates the starting memory address for a transaction in blob data
    /// @param txNumber Transaction index (0-indexed)
    /// @param numDeposits Total number of deposits in the block (to skip deposit region)
    /// @return Absolute memory address where the transaction data begins
    function txMemoryAddress(uint256 txNumber, uint256 numDeposits) internal pure returns (uint256) {
        // Each deposit is a single leaf
        uint256 depositsLength = numDepositsToMemoryLength(numDeposits);
        uint256 prior = txNumber * 15;
        // TODO - Might be 0 indexed?
        return (depositsLength + prior);
    }

    /// @notice Calculates memory address for a specific leaf (output) in blob data
    /// @param number For deposits: deposit index [0, numDeposits). For tx: transaction index [0, numTx).
    /// @param numDeposits Total deposits in block (to calculate offset for transactions)
    /// @param isDeposit True for deposit leaf, false for transaction output leaf
    /// @param which Output index within the update [0, 3). For tx: leaf0=0, leaf1=1, leaf2=2.
    /// @return Absolute memory address of the leaf
    function leafMemoryAddress(uint256 number, uint256 numDeposits, bool isDeposit, uint256 which)
        internal
        pure
        returns (uint256)
    {
        if (which >= 3) revert InvalidLeafWhich();
        if (isDeposit) {
            // Each deposit number is one field, but each three fields we include a root.
            return (number + number / 3);
        } else {
            uint256 depositsLength = numDepositsToMemoryLength(numDeposits);
            uint256 prior = number * 15;
            // 4 entries per deposit, 15 per prior tx, 11 (8 zk, 1 root, 2 nullifiers)
            return (depositsLength + prior + 11 + which);
        }
    }

    /// @notice Calculates memory address for a nullifier in transaction blob data
    /// @param txNumber Transaction index (0-indexed)
    /// @param numDeposits Total deposits in block (to calculate offset)
    /// @param which Nullifier index [0, 2). nullifier0=0, nullifier1=1.
    /// @return Absolute memory address of the nullifier
    function nullifierMemoryAddress(uint256 txNumber, uint256 numDeposits, uint256 which)
        internal
        pure
        returns (uint256)
    {
        uint256 deposits = numDepositsToMemoryLength(numDeposits);
        uint256 prior = txNumber * 15;
        if (which >= 2) revert InvalidNullifierWhich();
        // 4 entries per deposit, 15 per prior tx, 11 (8 zk, 1 root, 2 nullifiers)
        return (deposits + prior + 9 + which);
    }

    /// @notice Calculates memory address of the prior root (anchor before this update)
    /// @dev For deposits, number is the group index (each group = 3 deposits). For tx, number is tx index.
    ///      Returns address of the root field BEFORE this update (i.e., at index number*4-1 for deposits).
    /// @param number Update group index. For deposits: [1, ceil(numDeposits/3)]. For tx: [1, numTx].
    ///        Must be >= 1 (use validatePriorAnchor for first update which references prior block).
    /// @param isDeposit True for deposit update, false for transaction
    /// @param numDeposits Total deposits in block. For deposits: must satisfy number <= (numDeposits-1)/3.
    /// @return Absolute memory address of the prior root
    function priorRootMemoryLocation(uint256 number, bool isDeposit, uint256 numDeposits)
        internal
        pure
        returns (uint256)
    {
        if (isDeposit) {
            // Since we are using update groups we need to subtract one to get the update group memory location
            if (number > (numDeposits - 1) / 3) revert InvalidDepositNumber();
            return (number * 4 - 1);
        } else {
            uint256 deposits = numDepositsToMemoryLength(numDeposits);
            return (deposits + number * 15 - 1);
        }
    }

    /// @notice Validates multiple KZG proof openings against a blob commitment
    /// @dev Iterates through all indices and validates each opening individually
    /// @param rootHash The versioned blob hash (from blobhash opcode)
    /// @param commitment The 48-byte KZG commitment to the blob polynomial
    /// @param dataIndicies Array of memory indices to validate [0, 4096)
    /// @param data Array of expected values at each index (must match dataIndicies length)
    /// @param kzgProofs Array of 48-byte KZG proofs (must match dataIndicies length)
    function validateDataOpenings(
        bytes32 rootHash,
        bytes calldata commitment,
        uint256[] memory dataIndicies,
        bytes32[] memory data,
        bytes[] calldata kzgProofs
    ) internal view {
        // TODO we could optimize the memory use here by overwriting the last one in assembly
        for (uint256 i = 0; i < dataIndicies.length; i++) {
            validateSingle(rootHash, commitment, dataIndicies[i], data[i], kzgProofs[i]);
        }
    }

    /// @notice Validates KZG proofs for a contiguous region of blob memory
    /// @dev Region.length must equal region.data.length and region.proofs.length
    /// @param region Contains blob hash, commitment, starting memoryAddress, and arrays of data/proofs
    function validateRegionOpening(Region calldata region) internal view {
        if (region.length != region.data.length || region.length != region.proofs.length) {
            revert RegionDataLengthMismatch();
        }
        uint256 memoryAddress = region.memoryAddress;
        for (uint256 i = 0; i < region.data.length; i++) {
            validateSingle(region.hash, region.commitment, memoryAddress, region.data[i], region.proofs[i]);
            memoryAddress++;
        }
    }

    /// @notice Validates a single KZG proof opening using the point evaluation precompile
    /// @dev Costs ~54k gas. Reverts with InvalidProof() if verification fails.
    /// @param rootHash The versioned blob hash
    /// @param commitment 48-byte KZG commitment
    /// @param index Memory index in blob [0, 4096)
    /// @param data Expected value at the index
    /// @param proof 48-byte KZG proof
    function validateSingle(
        bytes32 rootHash,
        bytes calldata commitment,
        uint256 index,
        bytes32 data,
        bytes calldata proof
    ) internal view virtual {
        // To do a single validation we use the point open precompile and prove that the polynomial at
        // the bit reversed root of unity for that index is equal to the data field
        uint256 evalRoot = bitReversedRoot(index);

        assembly ("memory-safe") {
            let ptr := mload(0x40)
            // Load the inputs for the point evaluation precompile into memory. The inputs to the point evaluation
            // precompile are packed, and not supposed to be ABI-encoded.
            mstore(ptr, rootHash)
            mstore(add(ptr, 0x20), evalRoot)
            mstore(add(ptr, 0x40), data)
            calldatacopy(add(ptr, 0x60), commitment.offset, 0x30)
            calldatacopy(add(ptr, 0x90), proof.offset, 0x30)

            // Verify the KZG proof by calling the point evaluation precompile. If the proof is invalid, the precompile
            // will revert.
            let success :=
                staticcall(
                    gas(), // forward all gas
                    0x0A, // point evaluation precompile address
                    ptr, // input ptr
                    0xC0, // input size = 192 bytes
                    0x00, // output ptr
                    0x40 // output size
                )
            if iszero(success) {
                // Store the "InvalidProof()" error selector.
                mstore(0x00, 0x09bde339)
                // revert with "InvalidProof()"
                revert(0x1C, 0x04)
            }
        }
    }

    /// @notice Computes the evaluation point for KZG proof at a given blob index
    /// @dev Uses bit-reversal permutation on 12-bit index, then exponentiates the root of unity
    /// @param i Blob memory index [0, 4096)
    /// @return The evaluation point (root of unity raised to bit-reversed index power) mod BLS_MODULUS
    function bitReversedRoot(uint256 i) internal view returns (uint256) {
        uint256 reversed = LibBit.reverseBits(i);
        reversed = (reversed >> 244);
        // TODO - Check that this is the right offset
        return (exp(ROOT, reversed));
    }

    /// @notice Computes modular exponentiation b^e mod BLS_MODULUS using square-and-multiply
    /// @dev Optimized for small exponents (e < 4096) compared to modexp precompile
    /// @param b Base value
    /// @param e Exponent
    /// @return b^e mod BLS_MODULUS
    function exp(uint256 b, uint256 e) internal pure returns (uint256) {
        if (e == 0) {
            return (1);
        }
        uint256 ret = 1;
        while (e != 0) {
            if (e % 2 == 1) {
                ret = mulmod(ret, b, BLS_MODULUS);
            }
            e = e >> 1;
            b = mulmod(b, b, BLS_MODULUS);
        }
        return (ret);
    }
}
