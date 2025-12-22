// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {LibBit} from "solady/utils/LibBit.sol";
import {console} from "forge-std/console.sol";

// We implement a protocol which does kzg opening against blob commitments.
// In the simplest version it just proves that the commitment evaluated at the bit revevered root of unity
// for an index is equal to the the claimed data.
// We might be able to highly optimise by doing a multi point opening.

// Blobs are structured as follows:
// [deposits range][transactions range]
// each desposit is [leaf1, leaf2, leaf3, new_root] and each leaf must match the deposit leaf in the array for this block
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

    // Next we want some functions related to the actual blob layout

    function parseIndexInfo(uint256 index) internal pure returns (uint256, uint256, uint256) {
        require(index < 2 ** TREE_DEPTH);
        uint256 day = index >> DAY_DEPTH + BLOCK_DEPTH;
        uint256 blockNr = (index >> BLOCK_DEPTH) & ((2 ** DAY_DEPTH) - 1);
        uint256 txNr = index & ((2 ** BLOCK_DEPTH) - 1);
        return (day, blockNr, txNr);
    }

    // Each deposit is a single field but for each 3 deposits we have to include a root.
    function numDepositsToMemoryLength(uint256 num) private pure returns (uint256) {
        uint256 depositRounding = num % 3 == 0 ? 0 : 1;
        return (num + num / 3 + depositRounding);
    }

    function txMemoryAddress(uint256 txNumber, uint256 numDeposits) internal pure returns (uint256) {
        // Each deposit is a single leaf
        uint256 depositsLength = numDepositsToMemoryLength(numDeposits);
        uint256 prior = (txNumber - 1) * 15;
        // TODO - Might be 0 indexed?
        return (depositsLength + prior);
    }

    function leafMemoryAddress(uint256 number, uint256 numDeposits, bool isDeposit, uint256 which)
        internal
        pure
        returns (uint256)
    {
        assert(which < 3);
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

    function nullifierMemoryAddress(uint256 txNumber, uint256 numDeposits, uint256 which)
        internal
        pure
        returns (uint256)
    {
        uint256 deposits = numDepositsToMemoryLength(numDeposits);
        uint256 prior = txNumber * 15;
        assert(which < 2);
        // 4 entries per deposit, 15 per prior tx, 11 (8 zk, 1 root, 2 nullifiers)
        return (deposits + prior + 9 + which);
    }

    // Returns the root for the BEFORE root reverts on the 0 deposit
    // Here we use number = update number, meaning if a its a deposit its each group of three leaves or if transaction
    // each transaction
    function priorRootMemoryLocation(uint256 number, bool isDeposit, uint256 numDeposits)
        internal
        pure
        returns (uint256)
    {
        if (isDeposit) {
            assert(number <= numDeposits / 3);
            return (number * 4 - 1);
        } else {
            uint256 deposits = numDepositsToMemoryLength(numDeposits);
            return (deposits + number * 15 - 1);
        }
    }

    /// @dev Checks that the kzg proof validates that the polynomial interpolates data at the roots of unity indexed by the bitreversed
    ///      roots of unity
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

    // Validate a contigious region of memory in a blob starting at a memory address
    function validateRegionOpening(Region calldata region) internal view {
        assert(region.length == region.data.length);
        uint256 memoryAddress = region.memoryAddress;
        for (uint256 i = 0; i < region.data.length; i++) {
            validateSingle(region.hash, region.commitment, memoryAddress, region.data[i], region.proofs[i]);
            memoryAddress++;
        }
    }

    // takes 54k gas based on testing.
    function validateSingle(
        bytes32 rootHash,
        bytes calldata commitment,
        uint256 index,
        bytes32 data,
        bytes calldata proof
    ) internal view {
        // To do a single validation we use the point open precompile and prove that the polynomial at
        // the bit reversed root of unity for that index is equal to the data field
        uint256 evalRoot = bitReversedRoot(index);

        assembly {
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

    // Computes the bit reverse of i as if it is a 12 bit number (ie less than 4096)
    function bitReversedRoot(uint256 i) internal view returns (uint256) {
        uint256 reversed = LibBit.reverseBits(i);
        reversed = (reversed >> 244);
        // TODO - Check that this is the right offset
        return (exp(ROOT, reversed));
    }

    // Should give good preformance for our exp < 4096 compared to modexp
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
